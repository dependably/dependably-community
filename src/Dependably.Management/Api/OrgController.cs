using Dependably.Api.Setup;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Slim tenant-scoped controller for the resources that didn't fit a dedicated controller:
/// packages, stats, and the setup-recipe endpoint. Most tenant-scoped surface has been
/// split out into <see cref="OrgSettingsController"/>, <see cref="OrgTokensController"/>,
/// <see cref="OrgInvitesController"/>, <see cref="OrgUsersController"/>,
/// <see cref="OrgListsController"/>, <see cref="OrgAuditController"/>, and
/// <c>OrgAuthConfigController</c>.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgController : OrgScopedControllerBase
{
    // Maximum page size for package list responses.
    private const int MaxPackagePageSize = 200;

    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly PackageVersionFilesRepository _versionFiles;
    private readonly NuGetSymbolIndexRepository _symbolIndex;
    private readonly PackageAnalyticsRepository _packageAnalytics;
    private readonly StatsSnapshotRepository _statsSnapshots;
    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;
    private readonly TieredBlobStorage _blobStorage;
    private readonly OciOrphanBlobDeleter _orphanBlobs;
    private readonly LicenseRepository _licenses;
    private readonly VulnerabilityRepository _vulns;
    private readonly ArtifactInventoryRepository _inventory;
    private readonly IPublicUrlBuilder _urls;
    private readonly ILogger<OrgController> _logger;
    private readonly MetadataInvalidationCoordinator _invalidation;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly TenantArtifactAccessRepository _tenantAccess;
    private readonly TimeProvider _time;
    private readonly Dependably.Infrastructure.OciScan.IOciScanCoverage? _ociCoverage;
    private readonly Dependably.Infrastructure.OciScan.OciScanRepository? _ociScans;

    public OrgController(OrgControllerServices svc)
    {
        _orgs = svc.Orgs;
        _packages = svc.Packages;
        _versionFiles = svc.VersionFiles;
        _symbolIndex = svc.SymbolIndex;
        _packageAnalytics = svc.PackageAnalytics;
        _statsSnapshots = svc.StatsSnapshots;
        _audit = svc.Audit;
        _guard = svc.Guard;
        _blobStorage = svc.BlobStorage;
        _orphanBlobs = svc.OrphanBlobs;
        _licenses = svc.Licenses;
        _vulns = svc.Vulns;
        _inventory = svc.Inventory;
        _urls = svc.Urls;
        _logger = svc.Logger;
        _invalidation = svc.Invalidation;
        _cacheArtifacts = svc.CacheArtifacts;
        _tenantAccess = svc.TenantAccess;
        _time = svc.Time;
        _ociCoverage = svc.OciCoverage;
        _ociScans = svc.OciScans;
    }

    // Org CRUD lives on SystemController (/api/v1/system/tenants). Tenant users have no
    // authority to list, create, or delete orgs — those are operator concerns.

    // ── Packages ──────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /api/v1/orgs/{org}/packages.
    /// The <c>search</c> term matches any substring of the package name, case-insensitively:
    /// names that carry a prefix the user does not type — npm scopes, Maven groupId:artifactId
    /// coordinates, OCI repository paths — are found by the part they do ('core' matches
    /// '@babel/core'). '%' and '_' in the term are matched literally, not as wildcards.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages in addition to the
    // class-level JWT session, mirroring the yank override below.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/packages")]
    public async Task<IActionResult> ListPackages(
        [FromQuery] int limit = 50,
        [FromQuery] int page = 1,
        [FromQuery] string? ecosystem = null,
        [FromQuery] string? search = null,
        [FromQuery] string sortBy = "created",
        [FromQuery] string sortDir = "asc",
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        limit = Math.Clamp(limit, 1, MaxPackagePageSize);
        int offset = PaginationHelper.ComputeOffset(page, limit);

        var (items, total) = await _packages.ListPaginatedAsync(
            new PackageListQuery(orgId, limit, offset, ecosystem, search, sortBy, sortDir), ct);
        await AttachOciScanRollupsAsync(orgId, items, ct);
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        string versionOverwritePolicy = settings?.VersionOverwritePolicy ?? "block";
        return Ok(new { items, total, limit, offset, versionOverwritePolicy });
    }

    // An OCI package's findings live in this org's own scan results, not in package_version_vulns,
    // which a proxied image never gets. The page's OCI packages get the worst scan state across
    // the images the org holds, from the same facts and coverage the version page reads.
    private async Task AttachOciScanRollupsAsync(
        string orgId, IReadOnlyList<Package> items, CancellationToken ct)
    {
        var oci = items.Where(p => p.Ecosystem == "oci").ToList();
        if (oci.Count == 0)
        {
            return;
        }

        bool live = _ociCoverage is { Enabled: true } && _ociScans is not null;
        bool covered = live && await _ociCoverage!.IsCoveredAsync(orgId, ct);
        var held = live
            ? await _ociScans!.GetHeldImageFactsAsync(orgId, oci.Select(p => p.Id).ToList(), ct)
            : null;
        foreach (var pkg in oci)
        {
            var images = new List<Dependably.Infrastructure.OciScan.OciScanFacts?>();
            if (held is not null && held.TryGetValue(pkg.Id, out var facts))
            {
                images.AddRange(facts);
            }

            pkg.OciScan = Dependably.Infrastructure.OciScan.OciScanProjection.RollUp(images, covered);
        }
    }

    /// <summary>GET /api/v1/orgs/{org}/packages/{ecosystem}/{name}</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/packages/{ecosystem}/{name}")]
    public async Task<IActionResult> GetPackage(string ecosystem, string name, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        // The identity query above carries no aggregates, so a package that has only proxied
        // versions (no package_versions rows) would otherwise serialize zero counts beside a
        // non-empty versions list. Take them from the projection the packages list uses.
        var aggregates = await _packages.GetWithAggregatesAsync(orgId, pkg.Id, ct);
        if (aggregates is not null)
        {
            pkg.VersionCount = aggregates.VersionCount;
            pkg.TotalDownloads = aggregates.TotalDownloads;
            pkg.CriticalCount = aggregates.CriticalCount;
            pkg.HighCount = aggregates.HighCount;
            pkg.MediumCount = aggregates.MediumCount;
            pkg.LowCount = aggregates.LowCount;
            pkg.HasMaliciousVersion = aggregates.HasMaliciousVersion;
            pkg.HasKevVersion = aggregates.HasKevVersion;
        }

        var versions = await LoadCombinedVersionsForOrgAsync(orgId, pkg.Id, ecosystem, AsPurlName(ecosystem, name), ct);
        // OCI: load the digest → tags lookup so each version row surfaces its associated tags.
        var ociTagsByDigest = ecosystem == "oci"
            ? await _packages.GetOciTagsByDigestAsync(orgId, pkg.PurlName, ct)
            : null;
        // License map: uploaded versions key by package_version_id; proxy versions key by
        // cache_artifact_id. Merge both lookups into one dictionary.
        var uploadedIds = versions.Where(v => v.Origin != "proxy").Select(v => v.Id).ToList();
        var proxyIds = versions.Where(v => v.Origin == "proxy").Select(v => v.Id).ToList();
        var uploadedLicenses = uploadedIds.Count > 0
            ? await _licenses.GetSpdxForVersionsAsync(uploadedIds, ct)
            : Enumerable.Empty<(string, string)>().ToLookup(r => r.Item1, r => r.Item2);
        var proxyLicenses = proxyIds.Count > 0
            ? await _licenses.GetSpdxForCacheArtifactsAsync(proxyIds, ct)
            : Enumerable.Empty<(string, string)>().ToLookup(r => r.Item1, r => r.Item2);
        var scoreMap = await BuildVersionScoreMapAsync(uploadedIds, proxyIds, ct);
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        double tolerance = settings?.MaxOsvScoreTolerance ?? 10.0;
        string blockDeprecatedMode = settings?.BlockDeprecated ?? "off";

        // NuGet symbols: which hosted versions carry a .snupkg, and how many PDBs each has
        // indexed. Both batched — this view renders every version at once. Null for every other
        // ecosystem, none of which has a symbol surface.
        var symbolFacts = ecosystem == "nuget"
            ? await LoadSymbolFactsAsync(orgId, uploadedIds, ct)
            : null;

        // Per-file rows for hosted multi-file versions (NuGet .nupkg + .snupkg, PyPI sdist +
        // wheels). Expanded HERE rather than in artifact_inventory: that view also feeds the NuGet
        // registration index, the flatcontainer version list and the npm packument, all of which
        // are version-level and would list a multi-file version twice if it went file-level.
        // Proxy versions already arrive per-file from cache_artifact, so they carry no rows here
        // and pass through unchanged.
        var filesByVersion = await _versionFiles.GetByPackageAsync(pkg.Id, ct);

        var ociScan = ecosystem == "oci"
            ? await LoadOciScanStateAsync(orgId, versions.Select(v => v.Id).ToList(), ct) with
            {
                ScoreEnforced = settings?.OciScanEnforcement == "block",
            }
            : null;

        var viewContext = new PackageVersionViewContext(
            ecosystem, pkg.Name, scoreMap, tolerance, blockDeprecatedMode,
            uploadedLicenses, proxyLicenses, ociTagsByDigest, symbolFacts, ociScan);
        var versionsWithLicenses = versions.SelectMany(v =>
            ExpandToFiles(v, filesByVersion).Select(file => ProjectVersionView(v, file, viewContext)));
        return Ok(new { package = pkg, versions = versionsWithLicenses });
    }

    // Symbol presence and indexed-PDB counts for a page of hosted NuGet versions. Two batched
    // queries rather than per-row lookups. Proxy versions are excluded by construction: the symbol
    // index and package_version_files are both hosted-only.
    private async Task<SymbolFacts> LoadSymbolFactsAsync(
        string orgId, List<string> uploadedIds, CancellationToken ct)
    {
        var withPackage = await _versionFiles.GetVersionIdsWithExtensionAsync(
            orgId, uploadedIds, MultiFileEcosystems.NuGetSymbolExtension, ct);
        var indexedCounts = await _symbolIndex.CountByVersionsAsync(orgId, uploadedIds, ct);
        return new SymbolFacts(withPackage, indexedCounts);
    }

    // One entry per artifact the version should render as. A version with fewer than two file
    // rows yields a single null — "project the version row itself", exactly as before — so
    // single-file versions and every ecosystem without a file plane are untouched.
    private static IEnumerable<PackageVersionFile?> ExpandToFiles(
        PackageVersion v, ILookup<string, PackageVersionFile> filesByVersion)
    {
        var files = filesByVersion[v.Id].ToList();
        return files.Count < 2 ? new PackageVersionFile?[] { null } : files;
    }

    // Bundled so ProjectVersionView stays within the parameter-count threshold (S107).
    private sealed record SymbolFacts(
        HashSet<string> VersionsWithSymbolPackage, Dictionary<string, int> IndexedPdbCounts);

    /// <summary>
    /// The view-rendering inputs that are constant across every version/file of one package —
    /// resolved once per <c>GetPackage</c> request and threaded unchanged through the per-version
    /// <see cref="ProjectVersionView"/> calls in the expansion loop, so the per-call surface is
    /// just the two things that actually vary: the version and its (optional) file override.
    /// </summary>
    private sealed record PackageVersionViewContext(
        string Ecosystem,
        string PackageName,
        Dictionary<string, double> ScoreMap,
        double Tolerance,
        string BlockDeprecatedMode,
        ILookup<string, string> UploadedLicenses,
        ILookup<string, string> ProxyLicenses,
        ILookup<string, string>? OciTagsByDigest,
        SymbolFacts? SymbolFacts,
        OciScanState? OciScan);

    /// <summary>
    /// This org's view of its OCI images: whether its scanner is live, the scan facts of each
    /// image it has a result for, and whether its pulls are refused on those facts
    /// (<c>oci_scan_enforcement = block</c>). Null outside OCI.
    /// </summary>
    private sealed record OciScanState(
        bool Covered, IReadOnlyDictionary<string, Dependably.Infrastructure.OciScan.OciScanFacts> Facts,
        bool ScoreEnforced = false);

    private async Task<OciScanState> LoadOciScanStateAsync(string orgId, List<string> versionIds, CancellationToken ct)
    {
        return _ociCoverage is null || _ociScans is null || !_ociCoverage.Enabled
            ? new OciScanState(false, new Dictionary<string, Dependably.Infrastructure.OciScan.OciScanFacts>())
            : new OciScanState(
                await _ociCoverage.IsCoveredAsync(orgId, ct),
                await _ociScans.GetFactsAsync(orgId, versionIds, ct));
    }

    // Merges per-version OSV scores from uploaded versions (keyed by package_version_id) and proxy
    // versions (keyed by cache_artifact_id) into a single id → max-CVSS map.
    private async Task<Dictionary<string, double>> BuildVersionScoreMapAsync(
        List<string> uploadedIds, List<string> proxyIds, CancellationToken ct)
    {
        var uploadedScores = uploadedIds.Count > 0
            ? await _vulns.GetMaxScoresForVersionsAsync(uploadedIds, ct)
            : new Dictionary<string, double>();
        var proxySignals = proxyIds.Count > 0
            ? await _vulns.GetGateSignalsBatchForCacheArtifactsAsync(proxyIds, ct)
            : new Dictionary<string, VulnGateSignals>();
        var scoreMap = new Dictionary<string, double>(uploadedScores);
        foreach (var (id, sig) in proxySignals)
        {
            if (sig.MaxCvss.HasValue)
            {
                scoreMap[id] = sig.MaxCvss.Value;
            }
        }
        return scoreMap;
    }

    // Projects a package version into the API view model: merges its license lookup, OSV score,
    // computed gate status, and (for OCI) the tags pointing at its digest.
    private static object ProjectVersionView(
        PackageVersion v,
        // Non-null when the version renders as one of several files. Overrides only the
        // artifact-level facts; everything else is a property of the VERSION and is identical
        // across siblings.
        PackageVersionFile? file,
        PackageVersionViewContext ctx)
    {
        bool hasMax = ctx.ScoreMap.TryGetValue(v.Id, out double maxScore);
        string status;
        string? matchedAt = null;
        Dependably.Infrastructure.OciScan.OciScanView? ociScanView = null;
        if (ctx.OciScan is { } oci)
        {
            // An OCI image's status comes from this org's own scan of it, never from the version
            // row: a proxied image's row is shared by every tenant that pulled it.
            var facts = oci.Facts.GetValueOrDefault(v.Id);
            matchedAt = facts?.MatchedAt;
            hasMax = facts?.MaxScore is not null;
            maxScore = facts?.MaxScore ?? 0;
            status = PackageVersionStatus.ComputeOciVersionStatus(
                v, facts, oci.Covered, ctx.Tolerance, ctx.BlockDeprecatedMode, oci.ScoreEnforced);
            ociScanView = Dependably.Infrastructure.OciScan.OciScanProjection.Project(facts, oci.Covered);
        }
        else
        {
            status = PackageVersionStatus.ComputeVersionStatus(
                v, ctx.Ecosystem, hasMax ? maxScore : (double?)null, ctx.Tolerance, ctx.BlockDeprecatedMode);
        }
        string? redactedUpstreamUrl = UpstreamUrlValidator.StripCredentials(v.UpstreamUrl);
        return new
        {
            v.Id,
            v.PackageId,
            v.Version,
            v.Purl,
            // BlobKey is deliberately omitted: it embeds the object-store layout and the raw org
            // UUID, which members otherwise never see. No route accepts a blob key as input; the
            // frontend downloads via the /download endpoint.
            Filename = file?.Filename ?? v.Filename,
            SizeBytes = file?.SizeBytes ?? v.SizeBytes,
            ChecksumSha256 = file?.ChecksumSha256 ?? v.ChecksumSha256,
            v.ChecksumSha1,
            v.Yanked,
            v.YankReason,
            v.FirstFetch,
            v.DownloadCount,
            v.CreatedAt,
            v.UpdatedAt,
            v.VulnCheckedAt,
            v.PublishedAt,
            v.ManualBlockState,
            v.Deprecated,
            v.RevokedAt,
            v.VersionsBehind,
            v.Origin,
            // Strip any embedded user:pass@ credential before it reaches a read:packages caller.
            // Save-time validation rejects userinfo on new rows; this defends legacy rows written
            // before that gate existed so the projection never leaks an upstream credential.
            UpstreamUrl = redactedUpstreamUrl,
            // Public registry page (npmjs.com/pypi.org/…) reconstructed only when the recorded
            // upstream host is a known public registry; null (link hidden) for private upstreams.
            RegistryPageUrl = RegistryPageUrl.ForVersion(ctx.Ecosystem, v.Purl, ctx.PackageName, v.Version, redactedUpstreamUrl),
            v.UpstreamIntegrityValue,
            v.UpstreamIntegrityAlgorithm,
            v.IsMalicious,
            v.HasInstallScript,
            v.InstallScriptKind,
            v.ProvenanceStatus,
            v.ProvenanceSigner,
            MaxOsvScore = hasMax ? maxScore : (double?)null,
            Status = status,
            // OCI only: when this org's stored scan of the image was last matched against OSV,
            // the oldest across its platforms. A stale match leaves the status as stored.
            MatchedAt = matchedAt,
            OciScan = ociScanView,
            Licenses = (v.Origin == "proxy" ? ctx.ProxyLicenses[v.Id] : ctx.UploadedLicenses[v.Id]).ToArray(),
            Tags = ctx.OciTagsByDigest != null && ctx.OciTagsByDigest.Contains(v.Version)
                ? ctx.OciTagsByDigest[v.Version].ToArray()
                : Array.Empty<string>(),
            // NuGet symbols. Deliberately two fields rather than one count: a version that carries
            // a .snupkg but indexed zero PDBs (native-only symbols, or indexing that failed at
            // push) is the actionable state, and a bare count of 0 cannot be told apart from
            // "no symbol package at all".
            HasSymbolPackage = ctx.SymbolFacts?.VersionsWithSymbolPackage.Contains(v.Id) ?? false,
            IndexedPdbCount = ctx.SymbolFacts is null
                ? (int?)null
                : ctx.SymbolFacts.IndexedPdbCounts.GetValueOrDefault(v.Id)
        };
    }

    // Combines uploaded (package_versions) and global-plane proxy (cache_artifact) versions for
    // a package. Proxy entries whose version already appears in uploaded versions are
    // deduplicated so a name that was cached before upload does not double-list a version.
    // The synthesized proxy PackageVersion rows carry per-tenant download_count from
    // tenant_artifact_access via CacheArtifactIndexFacts.DownloadCount.
    //
    // This page is version-level. NuGet's sidecar rows (.nuspec, .sha512) are metadata noise —
    // detached hash/manifest files with no independent size or content of their own — that a
    // version-level view must collapse to the one row (.nupkg) that actually represents the
    // artifact. Maven (jar/pom/sources/javadoc) and multi-file PyPI (sdist + each wheel) also
    // cast multiple cache_artifact rows per proxied version, but those rows are distinct real
    // files with their own meaningful filename/size/hash, so they are deliberately left per-row
    // here rather than collapsed.
    private async Task<IReadOnlyList<PackageVersion>> LoadCombinedVersionsForOrgAsync(
        string orgId, string packageId, string ecosystem, string purlName, CancellationToken ct)
    {
        var versions = await _inventory.ListServeableVersionsAsync(orgId, packageId, ecosystem, purlName, ct: ct);
        return ArtifactInventoryRepository.CollapseSidecarProxyRows(ecosystem, versions);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/packages/{ecosystem}/{name}/{version}</summary>
    // Delete accepts both JWT sessions (UI) and API tokens (automation/scripted yank).
    // The class-level [Authorize] covers JWT; this method-level override unions in the
    // ApiToken scheme so a PAT carrying the per-ecosystem yank cap can reach the endpoint.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpDelete("api/v1/packages/{ecosystem}/{name}/{version}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteVersion(string ecosystem, string name, string version, CancellationToken ct)
    {
        // Per-ecosystem yank capability — admin/owner role sets enumerate yank:* leaves.
        // Unknown ecosystem names fail the lookup below, but we 404 here so an invalid path
        // doesn't read as 403. Authorisation outcomes for *known* ecosystems remain semantic:
        // missing capability → 403 (via AuthorizeCapAsync), missing package/version → 404.
        string? yankCap = ecosystem switch
        {
            "npm" => Capabilities.YankNpm,
            "pypi" => Capabilities.YankPypi,
            "nuget" => Capabilities.YankNuget,
            "maven" => Capabilities.YankMaven,
            "rpm" => Capabilities.YankRpm,
            "oci" => Capabilities.YankOci,
            _ => null
        };
        if (yankCap is null)
        {
            return NotFound();
        }

        var result = await _guard.AuthorizeCapAsync(User, HttpContext, yankCap, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var ver = await _packages.ResolveHostedVersionAsync(pkg.Id, ecosystem, version, ct);
        if (ver is null)
        {
            // Proxy/cache-plane versions have no package_versions row — see DownloadVersion's
            // identical fallback further down.
            return await DeleteCachePlaneVersionAsync(orgId, ecosystem, pkg, version, ct);
        }

        if (ecosystem == "oci")
        {
            // OCI manifests are content-addressed with no org segment — one oci_blobs row per
            // (digest, org) is shared by every repository and both write paths, and a manifest
            // casts oci_blobs / oci_tags sidecars the generic delete below never cleans. Delete the
            // version row FIRST so it cannot count as its own surviving claim, then release this
            // org's claim: the oci_blobs row (and its bytes) come off only when NO other claim on
            // the digest survives anywhere in this org — a live oci_tags row under another
            // repository, or a hosted package_versions row on the same digest, keeps them. The
            // resolved uploaded blob is handed to the shared deleter, which removes the file only
            // under the per-key lock a concurrent push holds and only when this org held the last
            // cross-org reference. The naive generic path (delete ver.BlobKey directly) would 404
            // every other repository's image and strand the sidecars.
            await _packages.DeleteVersionAsync(ver.Id, ct);
            string? uploadedManifestBlob = await _packages.ReleaseOciDigestClaimAsync(
                orgId, pkg.PurlName, ver.Version, ct);
            if (uploadedManifestBlob is not null)
            {
                await _orphanBlobs.DeleteIfUnreferencedAsync(uploadedManifestBlob, ct);
            }
        }
        else
        {
            // A PyPI version may hold several distribution files (wheel + sdist), each its own
            // blob; delete them all, deduped against the version row's primary key so single-file
            // versions and non-PyPI ecosystems delete exactly once.
            var blobKeys = new HashSet<string>(StringComparer.Ordinal) { ver.BlobKey };
            foreach (string fileBlobKey in await _versionFiles.GetBlobKeysForVersionAsync(ver.Id, ct))
            {
                blobKeys.Add(fileBlobKey);
            }
            // Uploaded-plane versions are published bytes, stored in the registry tier.
            foreach (string key in blobKeys)
            {
                await _blobStorage.Registry.DeleteAsync(BlobKeys.StoreKey(key), ct);
            }
            await _packages.DeleteVersionAsync(ver.Id, ct);
        }

        // GC the parent row when this was the last version. Orphan packages rows otherwise
        // accumulate across delete/republish cycles and cause "empty package" UI cards.
        // Atomic NOT EXISTS guard handles the race against a concurrent publish.
        await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct);

        ProtocolMetadataEviction.Evict(_invalidation, orgId, ecosystem, pkg, ver.Version);

        // Activity is the right sink for a per-version operator action — audit_log is for
        // tenant-level config/security events. Never dual-write the same event to both.
        await _audit.LogActivityAsync(orgId, ecosystem, ver.Purl, "delete", GetUserId(),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>
    /// Deletes a proxy version that lives only on the global cache plane (no
    /// <c>package_versions</c> row — see <see cref="LoadCombinedVersionsForOrgAsync"/>). Removes
    /// this org's <c>tenant_artifact_access</c> claim; the (global, cross-tenant)
    /// <c>cache_artifact</c> row and its Cache-tier blob are removed only once no other org
    /// retains access — <c>cache_artifact</c> is shared across every org that has pulled the
    /// same coordinate, so an unconditional delete here would remove the artifact out from under
    /// other tenants.
    ///
    /// OCI additionally releases this org's claim on the digest (repository-scoped
    /// <c>oci_tags</c>, and the org's <c>oci_blobs</c> row once no claim anywhere in the org
    /// survives) via <see cref="PackageRepository.ReleaseOciDigestClaimAsync"/> — the SAME
    /// claims-based, cross-org-refcounted check the hosted branch above uses, because OCI's
    /// content-addressed <c>oci_blobs.blob_key</c> is shared with hosted pushes and is NOT
    /// protected by the generic <c>tenant_artifact_access</c> refcount below (that refcount only
    /// sees this org's OWN cache-plane catalog row, not a same-org hosted claim or another
    /// repository's claim on the identical digest). OCI's physical bytes are therefore governed
    /// exclusively by <see cref="PackageRepository.ReleaseOciDigestClaimAsync"/>'s own gate; the
    /// generic <c>cache_artifact</c> cross-org refcount below still removes OCI's cache-plane
    /// catalog ROW when it hits zero (dashboard hygiene) but never deletes Cache-tier bytes for
    /// OCI — those are addressed by the same content-addressed key an unrelated repository or
    /// org may still depend on.
    ///
    /// Every other proxy ecosystem's blob key IS safely covered by the generic
    /// <c>tenant_artifact_access</c> refcount: <c>BlobKeys.Proxy</c> (<c>proxy/{sha256}</c>) and
    /// the hosted <c>BlobKeys.Hosted</c>/<c>HostedArtifact</c> (<c>hosted/{orgId}/…</c>)
    /// namespaces are disjoint, and Go/Cargo/Apk proxy keys carry their own <c>{orgId}</c>
    /// segment — none of them can collide with a hosted claim the way OCI's can.
    ///
    /// Deliberately does not call <see cref="PackageRepository.DeletePackageIfEmptyAsync"/>
    /// itself — the caller does, after this returns, exactly as it does for the hosted branch.
    /// </summary>
    private async Task<IActionResult> DeleteCachePlaneVersionAsync(
        string orgId, string ecosystem, Package pkg, string version, CancellationToken ct)
    {
        var proxyEntries = await _cacheArtifacts.ListServeFactsForNameAsync(orgId, ecosystem, pkg.PurlName, ct);
        var facts = proxyEntries.FirstOrDefault(e => e.Version == version)
            ?? proxyEntries.FirstOrDefault(e => VersionIdentity.Equal(ecosystem, e.Version, version));
        if (facts is null)
        {
            return NotFound();
        }

        // Read before the access row goes: facts.BlobKey is this org's own binding resolved
        // binding-first, and the shared key is what the coordinate itself points at. They differ
        // when this org's upstream served other content, and each is reclaimed on its own
        // condition — the org's bytes as soon as its access row is gone, the coordinate's only
        // when no tenant retains access at all.
        string? sharedBlobKey = await _cacheArtifacts.GetSharedBlobKeyAsync(facts.Id, ct);

        await _tenantAccess.DeleteAsync(orgId, facts.Id, ct);

        if (ecosystem == "oci")
        {
            // Release this org's claim on the shared oci_blobs row (repository-scoped oci_tags, and
            // the org's oci_blobs row once no claim anywhere in the org survives). A proxy-pulled
            // digest is origin='proxy', so this resolves no uploaded candidate and the Cache-tier
            // bytes are left for cache GC; a hand-off is still routed through the shared locked
            // deleter for the rare uploaded case so no OCI blob delete ever bypasses the refcount.
            string? uploadedManifestBlob = await _packages.ReleaseOciDigestClaimAsync(
                orgId, pkg.PurlName, facts.Version, ct);
            if (uploadedManifestBlob is not null)
            {
                await _orphanBlobs.DeleteIfUnreferencedAsync(uploadedManifestBlob, ct);
            }
        }

        long remaining = await _tenantAccess.CountRemainingAsync(facts.Id, ct);
        if (remaining == 0)
        {
            // OCI bytes are governed exclusively by the oci_blobs refcount above — the
            // cache_artifact row is still global catalog metadata worth GC'ing, but its blob_key
            // is the same content-addressed oci/{algo}/{hex} key oci_blobs guards, so a second,
            // narrower-visibility delete here would risk exactly the shared-bytes destruction
            // ReleaseOciDigestClaimAsync exists to prevent.
            if (ecosystem != "oci")
            {
                await _blobStorage.Cache.DeleteAsync(
                    BlobKeys.StoreKey(sharedBlobKey ?? facts.BlobKey), ct);
            }

            await _cacheArtifacts.DeleteAsync(facts.Id, ct);
        }

        // This org's own bytes, when its upstream served content other than the coordinate's. No
        // cache_artifact row anywhere names that key, so the access row just deleted was its last
        // reference from here and no reclamation path would ever find it again. Excluding nothing
        // from the refcount is deliberate: another tenant with a binding on this same row that
        // resolved the same divergent bytes must keep its blob.
        if (ecosystem != "oci"
            && sharedBlobKey is not null
            && !string.Equals(facts.BlobKey, sharedBlobKey, StringComparison.Ordinal)
            && !await _cacheArtifacts.BlobKeyReferencedElsewhereAsync(facts.BlobKey, string.Empty, ct))
        {
            await _blobStorage.Cache.DeleteAsync(BlobKeys.StoreKey(facts.BlobKey), ct);
        }

        await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct);

        ProtocolMetadataEviction.Evict(_invalidation, orgId, ecosystem, pkg, version);

        if (facts.Purl is not null)
        {
            await _audit.LogActivityAsync(orgId, ecosystem, facts.Purl, "delete", GetUserId(),
                actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        }

        return NoContent();
    }

    /// <summary>GET /api/v1/packages/{ecosystem}/{name}/{version}/download — stream one artifact to the UI</summary>
    // The optional `file` query selects one artifact when a version maps to several files: Maven
    // ships a .jar + .pom + sidecars under one coordinate, PyPI a wheel + sdist per release, NuGet
    // a .nupkg + its .snupkg. It is matched against the version's own files on the hosted plane and
    // against the cached files on the proxy plane. A `file` that matches nothing is a 404 — serving
    // the primary artifact instead would hand back different bytes than were asked for, and succeed
    // while doing it. When omitted, the version's primary artifact is served.
    [HttpGet("api/v1/packages/{ecosystem}/{name}/{version}/download")]
    public async Task<IActionResult> DownloadVersion(string ecosystem, string name, string version, CancellationToken ct, [FromQuery] string? file = null)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadArtifact, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var ver = await _packages.ResolveHostedVersionAsync(pkg.Id, ecosystem, version, ct);
        // Hosted versions still have a package_versions row; a proxy version that has aged out of
        // it falls back to the global-plane cache_artifact lookup.
        return ver is not null
            ? await DownloadHostedVersionAsync(orgId, ecosystem, ver, file, ct)
            : await DownloadProxyVersionAsync(orgId, ecosystem, name, version, file, ct);
    }

    private async Task<IActionResult> DownloadHostedVersionAsync(
        string orgId, string ecosystem, PackageVersion ver, string? file, CancellationToken ct)
    {
        // A multi-file version (NuGet .nupkg + .snupkg, PyPI sdist + wheels) is downloadable
        // per file. An unmatched `file` is a 404, never a fall back to the primary artifact:
        // substituting a different artifact for the one asked for succeeds silently and hands
        // back the wrong bytes — the same rule the flatcontainer serve path follows.
        PackageVersionFile? requested = null;
        if (!string.IsNullOrEmpty(file))
        {
            requested = await _versionFiles.GetByVersionAndFilenameAsync(ver.Id, file, ct);
            if (requested is null)
            {
                return NotFound();
            }
        }

        // Route by per-version origin: proxy artifacts live on the eviction-friendly cache
        // tier, uploaded artifacts on the durable registry tier. Under split storage these
        // are distinct backends, so picking the wrong tier would 404 or serve wrong bytes.
        var store = ver.Origin == "proxy" ? _blobStorage.Cache : _blobStorage.Registry;
        var stream = await store.GetAsync(BlobKeys.StoreKey(requested?.BlobKey ?? ver.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        // Count the UI download the same way protocol pulls are counted, and log it as a
        // 'download' activity so it also appears on the dashboard chart — the UI is just
        // another download surface.
        await _audit.LogActivityAsync(orgId, ecosystem, ver.Purl, "download", GetUserId(),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _packages.IncrementDownloadCountAsync(ver.Id, ct);

        string filename = requested?.Filename ?? ver.BlobKey.Split('/').Last();
        return File(stream, "application/octet-stream", filename);
    }

    // Global-plane fallback: proxy versions no longer have a package_versions row.
    // Look up the artifact in cache_artifact (joined to tenant_artifact_access for org
    // scoping) and serve from the cache tier.
    private async Task<IActionResult> DownloadProxyVersionAsync(
        string orgId, string ecosystem, string name, string version, string? file, CancellationToken ct)
    {
        var proxyEntries = await _cacheArtifacts.ListServeFactsForNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        bool FileMatches(CacheArtifactIndexFacts e) =>
            string.IsNullOrEmpty(file) || string.Equals(e.Filename, file, StringComparison.OrdinalIgnoreCase);

        // The exact version string wins: two spellings of one PyPI release can be separate rows,
        // and an action on one must not reach the other. A spelling with no exact row still
        // resolves through the ecosystem's version identity.
        var facts = proxyEntries.FirstOrDefault(e => e.Version == version && FileMatches(e))
            ?? proxyEntries.FirstOrDefault(e => VersionIdentity.Equal(ecosystem, e.Version, version) && FileMatches(e));
        if (facts is null)
        {
            return NotFound();
        }

        var proxyStream = await _blobStorage.Cache.GetAsync(BlobKeys.StoreKey(facts.BlobKey), ct);
        if (proxyStream is null)
        {
            return NotFound();
        }

        if (facts.Purl is not null)
        {
            await _audit.LogActivityAsync(orgId, ecosystem, facts.Purl, "download", GetUserId(),
                actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        }
        // Enqueued off the request path — the row already exists (seeded durably at first-fetch).
        await _tenantAccess.RecordDownloadHitAsync(orgId, facts.Id, _time.GetUtcNow(), ct);

        // Proxy blob keys are content-addressed (last segment is the SHA-256), so the download
        // filename comes from the recorded artifact filename, not the blob-key suffix.
        string proxyFilename = string.IsNullOrEmpty(facts.Filename)
            ? facts.BlobKey.Split('/').Last()
            : facts.Filename;
        return File(proxyStream, "application/octet-stream", proxyFilename);
    }

    /// <summary>
    /// PATCH /api/v1/packages/{ecosystem}/{name}/version-overwrite
    /// Sets or clears the per-package same-version-push override. Requires TenantConfigure.
    /// Body: { "override": "allow" | "block" | null }
    /// </summary>
    [HttpPatch("api/v1/packages/{ecosystem}/{name}/version-overwrite")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetPackageVersionOverwrite(
        string ecosystem, string name,
        [FromBody] SetPackageVersionOverwriteRequest req,
        CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (req.Override is { } ov && ov is not ("allow" or "block"))
        {
            return BadRequest(new { error = "override", detail = "Must be 'allow', 'block', or null." });
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        await _packages.SetSameVersionPushOverrideAsync(pkg.Id, orgId, req.Override, ct);

        string? actorId = GetUserId();
        string detail = System.Text.Json.JsonSerializer.Serialize(new
        {
            ecosystem,
            purl_name = pkg.PurlName,
            override_value = req.Override,
        }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogAsync("package.override.set", orgId, actorId, ActorKinds.User,
            ecosystem, pkg.PurlName, detail, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _audit.LogActivityAsync(orgId, ecosystem, pkg.PurlName, "package.override.set",
            actorId, actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/stats</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/stats")]
    public async Task<IActionResult> GetStats(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();

        // Serve the pre-computed snapshot kept warm by StatsRefreshService rather than running
        // the live aggregate queries per request. Deserialize and return through Ok() so
        // the MVC pipeline is the single serialization authority — the cached and live paths
        // produce byte-identical shape/casing, and the read tolerates any stored casing. Cache
        // miss (new org, or before the first refresh pass) falls back to a live compute so the
        // first load is never blank.
        var snapshot = await _statsSnapshots.GetSnapshotAsync(orgId, ct);
        if (snapshot is not null)
        {
            try
            {
                var cached = System.Text.Json.JsonSerializer.Deserialize<OrgStats>(
                    snapshot.StatsJson, JsonContracts.Web);
                if (cached is not null)
                {
                    return Ok(cached);
                }
            }
            catch (System.Text.Json.JsonException ex)
            {
                // A corrupt snapshot row (truncated write, hand-edited DB, format drift) must not
                // 500 the dashboard — fall through to a live compute, which also overwrites the
                // bad row on the next refresh pass.
                _logger.LogWarning(ex,
                    "Discarding malformed stats snapshot for org {OrgId}; recomputing live. TraceId={TraceId}",
                    orgId, System.Diagnostics.Activity.Current?.TraceId);
            }
        }

        var stats = await _packageAnalytics.GetOrgStatsAsync(orgId, ct);
        return Ok(stats);
    }

    // ── Setup recipes ─────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/setup/{ecosystem}</summary>
    // Read-only: accepts a PAT/service token carrying read:packages. Recipes contain
    // host-derived URLs and a literal <token> placeholder only — no secrets. The page
    // pairs them with a token it mints itself; the server never sees that pairing.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/setup/{ecosystem}")]
    public async Task<IActionResult> GetSetup(string ecosystem, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        // Tenant-implicit URLs: every request is already on the tenant's host (multi mode) or
        // the single-tenant install, so the recipes use the request's host directly.
        string baseUrl = _urls.BaseUrl(HttpContext);

        // Hex recipes embed the org's signing public key, which every Hex client must register
        // the repository with. Creating the key here is the same lazy first-use path the read
        // plane takes; when signing is impossible (no master key) the recipe carries a
        // placeholder that names where the key would be served.
        HexSetupContext? hex = null;
        if (ecosystem == "hex"
            && HttpContext.RequestServices.GetService(typeof(Infrastructure.Hex.HexSigningKeyRepository))
                is Infrastructure.Hex.HexSigningKeyRepository hexKeys)
        {
            using var key = await hexKeys.GetOrCreateAsync(CurrentTenantId(), ct);
            hex = new HexSetupContext(key?.PublicKeyPem);
        }

        var recipes = SetupRecipeCatalog.Build(ecosystem, baseUrl, hex);
        return recipes is null ? NotFound() : Ok(recipes);
    }

    // The UI encodes '/' as %2F for every ecosystem (npm scopes, OCI image
    // namespaces like library/ubuntu, etc.); ASP.NET keeps %2F encoded in route
    // values to prevent path splitting, so decode it back before lookup. PyPI
    // additionally requires PEP 503 normalization (case, -/_/. all equivalent) since
    // that's the form package rows are stored under (PurlNormalizer.PyPiName, applied
    // by every PyPI publish/lookup path) — without it, a non-canonical spelling here
    // resolves to a different (or no) package row than the one a publish matches.
    internal static string AsPurlName(string ecosystem, string name)
    {
        string decoded = NpmRouteHelper.DecodeRouteName(name);
        return ecosystem == "pypi" ? PurlNormalizer.PyPiName(decoded) : decoded;
    }
}
