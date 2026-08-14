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
/// packages, stats, and the setup-snippet generator. Most tenant-scoped surface has been
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
    private readonly IBlobStore _blobs;
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
        _blobs = svc.Blobs;
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
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        string versionOverwritePolicy = settings?.VersionOverwritePolicy ?? "block";
        return Ok(new { items, total, limit, offset, versionOverwritePolicy });
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

        var viewContext = new PackageVersionViewContext(
            ecosystem, pkg.Name, scoreMap, tolerance, blockDeprecatedMode,
            uploadedLicenses, proxyLicenses, ociTagsByDigest, symbolFacts);
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
        SymbolFacts? SymbolFacts);

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
        string status = ComputeVersionStatus(
            v, ctx.Ecosystem, hasMax ? maxScore : (double?)null, ctx.Tolerance, ctx.BlockDeprecatedMode);
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
        var versions = await _inventory.ListServeableVersionsAsync(orgId, packageId, ecosystem, purlName, ct);
        return ArtifactInventoryRepository.CollapseSidecarProxyRows(ecosystem, versions);
    }

    private static string ComputeVersionStatus(
        PackageVersion v, string ecosystem, double? maxScore, double tolerance, string blockDeprecatedMode = "off")
    {
        if (v.ManualBlockState == "blocked")
        {
            return "blocked";
        }
        // Only block_all denies an already-cached deprecated version; under block_new the cached
        // version keeps serving, so it surfaces as "deprecated" below. Legacy 'block' == block_all.
        if (v.Deprecated is not null && blockDeprecatedMode is "block_all" or "block")
        {
            return "blocked";
        }

        bool autoBlocked = v.VulnCheckedAt is not null && maxScore.HasValue && maxScore.Value > tolerance;
        return (v.ManualBlockState, autoBlocked) switch
        {
            // Manual allow over an advisory the gate would otherwise auto-block.
            ("allowed", true) => "allowed",
            // Any non-allowed version above tolerance is auto-blocked.
            (_, true) => "blocked",
            _ when v.Deprecated is not null => "deprecated",
            // OSV publishes no feed this ecosystem's artefacts could match, so neither a stamped
            // nor an absent vuln_checked_at says anything about them: an empty advisory list is
            // the only answer a lookup can return. Reported as its own state so the absence of
            // coverage is visible instead of reading as a clean screening — "nothing to scan
            // against" and "not scanned yet" call for different operator action. Conditioned on
            // HasAdvisory so a row that did acquire advisory links keeps its vulnerable label.
            _ when !v.HasAdvisory && !OsvFeedCoverage.HasAdvisoryFeed(ecosystem)
                => OsvFeedCoverage.NoFeedStatus,
            _ when v.VulnCheckedAt is null => "unscanned",
            // Scanned and servable, but carries at least one advisory below the block
            // tolerance (or an unscored/MAL advisory the score aggregate never saw). Reported
            // distinctly so it is never labelled "clean" — only an advisory-free scanned
            // version earns that label.
            _ when v.HasAdvisory => "vulnerable",
            _ => "clean",
        };
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

        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
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
                orgId, pkg.PurlName, version, ct);
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
            foreach (string key in blobKeys)
            {
                await _blobs.DeleteAsync(BlobKeys.StoreKey(key), ct);
            }
            await _packages.DeleteVersionAsync(ver.Id, ct);
        }

        // GC the parent row when this was the last version. Orphan packages rows otherwise
        // accumulate across delete/republish cycles and cause "empty package" UI cards.
        // Atomic NOT EXISTS guard handles the race against a concurrent publish.
        await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct);

        EvictProtocolMetadataCache(orgId, ecosystem, pkg, version);

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
        var facts = proxyEntries.FirstOrDefault(
            e => string.Equals(e.Version, version, StringComparison.OrdinalIgnoreCase));
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

        EvictProtocolMetadataCache(orgId, ecosystem, pkg, version);

        if (facts.Purl is not null)
        {
            await _audit.LogActivityAsync(orgId, ecosystem, facts.Purl, "delete", GetUserId(),
                actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        }

        return NoContent();
    }

    /// <summary>
    /// Invalidates any cached metadata for <paramref name="pkg"/> so a just-deleted version stops
    /// being served from cache. Shared by both <see cref="DeleteVersion"/> branches (hosted and
    /// cache-plane) so eviction never drifts between the two delete paths, and routed through
    /// <see cref="MetadataInvalidationCoordinator"/> so it expands the identical variant matrix
    /// the protocol-plane publish paths use — and reaches peer replicas the same way.
    /// </summary>
    private void EvictProtocolMetadataCache(string orgId, string ecosystem, Package pkg, string version)
    {
        var invalidation = ecosystem switch
        {
            "npm" => MetadataInvalidation.ForNpm(orgId, pkg.PurlName),
            "pypi" => MetadataInvalidation.ForPyPi(orgId, pkg.PurlName),
            "nuget" => MetadataInvalidation.ForNuGet(orgId, pkg.PurlName),
            // Maven package rows carry "groupId:artifactId" as their PURL name; a deleted
            // SNAPSHOT also changes the version-level build-list document.
            "maven" => MavenInvalidation(orgId, pkg.PurlName, version),
            "rpm" => MetadataInvalidation.ForRpm(orgId),
            _ => null,
        };

        if (invalidation is not null)
        {
            _invalidation.Invalidate(invalidation);
        }
    }

    // Splits a Maven package row's "groupId:artifactId" PURL name back into its coordinates.
    // Returns null for a malformed name rather than inventing an empty groupId.
    private static MetadataInvalidation? MavenInvalidation(string orgId, string purlName, string version)
    {
        int separator = purlName.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == purlName.Length - 1)
        {
            return null;
        }

        bool isSnapshot = version.EndsWith("-SNAPSHOT", StringComparison.Ordinal);
        return MetadataInvalidation.ForMaven(
            orgId, purlName[..separator], purlName[(separator + 1)..], isSnapshot ? version : null);
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

        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
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
        var facts = proxyEntries.FirstOrDefault(
            e => string.Equals(e.Version, version, StringComparison.OrdinalIgnoreCase)
                 && (string.IsNullOrEmpty(file) || string.Equals(e.Filename, file, StringComparison.OrdinalIgnoreCase)));
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

    // ── Setup snippets ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/setup/{ecosystem}</summary>
    // Read-only: accepts a PAT/service token carrying read:packages. Snippets contain
    // host-derived URLs and a literal <token> placeholder only — no secrets.
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
        // the single-tenant install. Snippets use the request's host directly.
        string baseUrl = _urls.BaseUrl(HttpContext);
        string slug = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantSlug ?? "";

        string? snippet = ecosystem switch
        {
            "pypi" => GeneratePyPiSnippet(baseUrl, slug),
            "npm" => GenerateNpmSnippet(baseUrl, slug),
            "nuget" => GenerateNuGetSnippet(baseUrl, slug),
            "maven" => GenerateMavenSnippet(baseUrl, slug),
            "rpm" => GenerateRpmSnippet(baseUrl, slug),
            "oci" => GenerateOciSnippet(baseUrl, slug),
            "golang" => GenerateGoSnippet(baseUrl, slug),
            "cargo" => GenerateCargoSnippet(baseUrl, slug),
            "apk" => GenerateApkSnippet(baseUrl, slug),
            "terraform" => GenerateTerraformSnippet(baseUrl, slug),
            _ => null
        };

        return snippet is null ? NotFound() : Ok(new { ecosystem, snippet });
    }

    // Snippet generators emit tenant-implicit URLs (host-relative). The slug parameter is
    // unused at the URL level today but kept so the future-multi-mode form `slug.apex/simple/`
    // could be reconstructed if needed; the request's host already carries the tenant.
    private static string GeneratePyPiSnippet(string baseUrl, string slug)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        string trustedHost = uri.Scheme == "http" ? $" --trusted-host {uri.Host}" : "";
        string indexUrl = $"{baseUrl}/simple/";
        return $"""
            # pip.conf / pyproject.toml
            [global]
            index-url = {indexUrl}

            # ~/.netrc — auth (the username is ignored; the token is the password):
            machine {uri.Host} login <user> password <token>

            # One-liner install example:
            pip install <package>==<version> --index-url {indexUrl}{trustedHost} --no-deps
            """;
    }

    private static string GenerateNpmSnippet(string baseUrl, string slug)
    {
        _ = slug;
        string registryUrl = $"{baseUrl}/npm/";
        // npm keys the auth token by the registry URL with the scheme stripped.
        string authKey = registryUrl[(registryUrl.IndexOf("://", StringComparison.Ordinal) + 3)..];
        return $"""
            # .npmrc
            registry={registryUrl}
            //{authKey}:_authToken=<token>
            """;
    }

    private static string GenerateNuGetSnippet(string baseUrl, string slug)
    {
        _ = slug;
        return $"""
            <!-- nuget.config -->
            <configuration>
              <packageSources>
                <add key="dependably" value="{baseUrl}/nuget/v3/index.json" />
              </packageSources>
              <packageSourceCredentials>
                <dependably>
                  <add key="Username" value="your-username" />
                  <add key="ClearTextPassword" value="your-token" />
                </dependably>
              </packageSourceCredentials>
            </configuration>

            <!-- Publish (push uses an API key, not the credentials above): -->
            <!-- dotnet nuget push pkg.nupkg --api-key your-token --source dependably -->
            <!-- An adjacent pkg.snupkg is pushed with it and its Portable PDBs are indexed. -->

            <!-- Symbol server (SSQP). Add as a symbol source in Visual Studio under -->
            <!-- Options > Debugging > Symbols, or pass to dotnet-symbol --server-path: -->
            <!-- {baseUrl}/nuget/symbols -->
            """;
    }

    // Maven snippet bundles both publish (distributionManagement, used by `mvn deploy`) and
    // consume (repositories, used at resolution time). A Gradle variant follows the Maven XML
    // section; credentials are stored once in gradle.properties and referenced by both DSLs.
    private static string GenerateMavenSnippet(string baseUrl, string slug)
    {
        _ = slug;
        return GenerateMavenXmlSnippet(baseUrl) + GenerateGradleFragment(baseUrl);
    }

    // Gradle DSL blocks contain literal { }, so use $$ raw strings where {{ }} are literal
    // braces and {{baseUrl}} interpolates the variable.
    private static string GenerateGradleFragment(string baseUrl) => $$"""


            # --- Gradle (Groovy DSL) ---

            # ~/.gradle/gradle.properties — store credentials outside build scripts:
            dependablyUser=your-username
            dependablyToken=your-token

            # build.gradle — consume and publish:
            repositories {
                maven {
                    url '{{baseUrl}}/maven/'
                    credentials {
                        username = findProperty('dependablyUser')
                        password = findProperty('dependablyToken')
                    }
                }
            }
            publishing {
                repositories {
                    maven {
                        url '{{baseUrl}}/maven/'
                        credentials {
                            username = findProperty('dependablyUser')
                            password = findProperty('dependablyToken')
                        }
                    }
                }
            }

            # --- Gradle (Kotlin DSL) ---

            # build.gradle.kts — same gradle.properties credentials; only syntax differs:
            repositories {
                maven {
                    url = uri("{{baseUrl}}/maven/")
                    credentials {
                        username = findProperty("dependablyUser") as String?
                        password = findProperty("dependablyToken") as String?
                    }
                }
            }
            publishing {
                repositories {
                    maven {
                        url = uri("{{baseUrl}}/maven/")
                        credentials {
                            username = findProperty("dependablyUser") as String?
                            password = findProperty("dependablyToken") as String?
                        }
                    }
                }
            }
            """;

    private static string GenerateMavenXmlSnippet(string baseUrl) => $"""
        <!-- ~/.m2/settings.xml — publish + consume -->
        <settings>
          <servers>
            <server>
              <id>dependably</id>
              <username>your-username</username>
              <password>your-token</password>
            </server>
          </servers>
          <profiles>
            <profile>
              <id>dependably</id>
              <repositories>
                <repository>
                  <id>dependably</id>
                  <url>{baseUrl}/maven/</url>
                </repository>
              </repositories>
            </profile>
          </profiles>
          <activeProfiles><activeProfile>dependably</activeProfile></activeProfiles>
        </settings>

        <!-- In your project pom.xml, for `mvn deploy`: -->
        <distributionManagement>
          <repository>
            <id>dependably</id>
            <url>{baseUrl}/maven/</url>
          </repository>
        </distributionManagement>
        """;

    // RPM .repo file pointing at the yum/dnf-compatible directory layout, plus a curl one-liner
    // for the push side. gpgcheck=0 by default — operators turn it on once signing is wired.
    private static string GenerateRpmSnippet(string baseUrl, string slug)
    {
        _ = slug;
        return $"""
            # /etc/yum.repos.d/dependably.repo
            [dependably]
            name=dependably
            baseurl={baseUrl}/rpm/
            enabled=1
            gpgcheck=0
            username=<user>
            password=<token>

            # Push an RPM:
            curl -u <user>:<token> --upload-file pkg.rpm {baseUrl}/rpm/upload
            """;
    }

    private static string GenerateOciSnippet(string baseUrl, string slug)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        string host = uri.Host;
        // Plain-HTTP registries require an insecure-registries entry in the Docker daemon config;
        // HTTPS registries use the default TLS trust chain and need no extra daemon configuration.
        string daemonFragment = uri.Scheme == "http" ? $$"""


            # /etc/docker/daemon.json — Docker needs this to use a plain-HTTP registry:
            { "insecure-registries": ["{{host}}"] }
            # Restart the daemon after editing (systemctl restart docker).
            """ : "";
        return $"""
            # Docker / OCI — login, pull, push
            docker login {host}
            docker pull  {host}/<image>:<tag>
            docker push  {host}/<image>:<tag>
            """ + daemonFragment;
    }

    // Go is proxy-only (no hosted publish) — GOPROXY points the toolchain at the registry, and a
    // .netrc entry carries credentials for authenticated proxies. GOPRIVATE/GONOSUMDB exempt a
    // private module path from the public checksum database.
    private static string GenerateGoSnippet(string baseUrl, string slug)
    {
        _ = slug;
        string host = new Uri(baseUrl).Host;
        return $"""
            # Point the Go toolchain at the registry proxy:
            export GOPROXY={baseUrl}/go

            # ~/.netrc — credentials for an authenticated proxy:
            machine {host} login <user> password <token>

            # For a private module path, skip the public checksum DB:
            export GONOSUMDB=example.com/private/*
            export GOPRIVATE=example.com/private/*
            """;
    }

    // Cargo snippet covers both consume (sparse index in config.toml) and publish (`cargo publish
    // --registry dependably`).
    private static string GenerateCargoSnippet(string baseUrl, string slug)
    {
        _ = slug;
        return $"""
            # ~/.cargo/config.toml — consume + publish
            [registries.dependably]
            index = "sparse+{baseUrl}/cargo/"

            # Authenticate (writes the token into Cargo's credentials store):
            cargo login --registry dependably
            # ...or set it directly in config.toml / credentials.toml:
            [registries.dependably]
            token = "<token>"

            # Publish a crate:
            cargo publish --registry dependably
            """;
    }

    // Terraform is proxy-only and is configured in the CLI configuration rather than per-project:
    // provider_installation applies to every provider a configuration requests, so there is no
    // per-repository file to edit and no change to required_providers blocks. The mirror URL must
    // be https — terraform rejects an http: mirror while parsing this file, before any request is
    // made — so a plain-HTTP deployment cannot serve this ecosystem. Credentials carry in the
    // URL's userinfo, like the apk snippet: the network mirror client has no separate credentials
    // field, but url.ResolveReference (used to resolve the relative archive URL from a version
    // document) preserves userinfo, and Go's net/http emits it as an Authorization: Basic header —
    // so one userinfo-bearing URL authenticates both the metadata and archive requests.
    private static string GenerateTerraformSnippet(string baseUrl, string slug)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        string userinfoUrl = $"{uri.Scheme}://<user>:<token>@{uri.Authority}/terraform/";
        // Unlike every other ecosystem, a plain-HTTP mirror URL is not merely discouraged here:
        // Terraform rejects it while parsing this file, before any request is made, so the snippet
        // below cannot work as-is. There is no client-side workaround (no equivalent of Docker's
        // insecure-registries) — TLS must be terminated in front of Dependably. Say so in-product
        // rather than letting the operator discover it as an opaque CLI config-parse error.
        string httpWarning = uri.Scheme == "http"
            ? "# WARNING: Terraform rejects an http:// network-mirror URL at config-parse time.\n"
              + "# This instance is serving over plain HTTP, so terraform init will fail with\n"
              + "# \"Cannot use ... as a URL for a network provider mirror\". Terminate TLS in front\n"
              + "# of Dependably and use an https:// URL below before this snippet will work.\n\n"
            : "";
        return httpWarning + $$"""
            # ~/.terraformrc (Linux/macOS) or %APPDATA%\terraform.rc (Windows)
            provider_installation {
              network_mirror {
                url = "{{userinfoUrl}}"
              }
            }

            # Point Terraform at that file from CI, where $HOME may not be the runner's:
            export TF_CLI_CONFIG_FILE=/path/to/terraformrc

            # Existing .terraform.lock.hcl files keep working: Terraform recomputes each
            # provider's h1 hash from the archive it downloads and verifies it against the lock.
            terraform init
            """;
    }

    // apk is proxy-only (no hosted push, like Go), so the snippet is a read-only mirror
    // rewrite: sed /etc/apk/repositories to swap dl-cdn.alpinelinux.org for this proxy, with
    // credentials carried in the userinfo (the apk client's only auth mechanism).
    private static string GenerateApkSnippet(string baseUrl, string slug)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        string userinfoUrl = $"{uri.Scheme}://<user>:<token>@{uri.Authority}/apk";
        return $"""
            # /etc/apk/repositories — point at this proxy instead of dl-cdn.alpinelinux.org
            # (same release/repo layout, so only the host changes):
            {userinfoUrl}/v3.22/main
            {userinfoUrl}/v3.22/community

            # One-liner rewrite of an existing repositories file:
            sed -i "s#https://dl-cdn.alpinelinux.org/alpine#{userinfoUrl}#" /etc/apk/repositories

            apk update
            """;
    }

    // The UI encodes '/' as %2F for every ecosystem (npm scopes, OCI image
    // namespaces like library/ubuntu, etc.); ASP.NET keeps %2F encoded in route
    // values to prevent path splitting, so decode it back before lookup. PyPI
    // additionally requires PEP 503 normalization (case, -/_/. all equivalent) since
    // that's the form package rows are stored under (PurlNormalizer.PyPiName, applied
    // by every PyPI publish/lookup path) — without it, a non-canonical spelling here
    // resolves to a different (or no) package row than the one a publish matches.
    private static string AsPurlName(string ecosystem, string name)
    {
        string decoded = NpmRouteHelper.DecodeRouteName(name);
        return ecosystem == "pypi" ? PurlNormalizer.PyPiName(decoded) : decoded;
    }
}
