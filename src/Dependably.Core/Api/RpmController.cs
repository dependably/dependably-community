using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// RPM repository surface. Implements the <c>dnf</c>/<c>yum</c> contract:
/// HTTP PUT a <c>.rpm</c> to upload, GET <c>/rpm/packages/{file}</c> to download, GET
/// <c>/rpm/repodata/{file}</c> to drive package resolution (repomd.xml passthrough when
/// <c>Rpm:Upstream</c> is configured), and GET <c>/rpm/repodata/RPM-GPG-KEY</c> for the
/// upstream GPG public key.
///
/// Passthrough mode (default when <c>Rpm:Upstream</c> is set):
///   - <c>repomd.xml</c> / <c>repomd.xml.asc</c>: forwarded with TTL (<see cref="Rpm:RepomdTtl"/>).
///   - Hash-prefixed metadata files: cached permanently in blob store (content-addressed).
///   - Package downloads: resolved via <c>primary.xml.gz</c>, fetched, checksum-verified,
///     and recorded on the cache plane as <c>cache_artifact</c> + <c>rpm_metadata</c> rows,
///     with per-tenant access tracked in <c>tenant_artifact_access</c>.
///   - PUT upload refused with 409 — shadowing upstream content is not allowed in passthrough mode.
/// </summary>
[ApiController]
public sealed partial class RpmController : OrgScopedControllerBase
{
    private readonly RpmControllerServices _svc;

    public RpmController(RpmControllerServices svc) => _svc = svc;

    // Route-level hard ceiling for RPM uploads (500 MiB).
    private const long RpmUploadSizeLimitBytes = 500L * 1024 * 1024;

    // ── Upload ────────────────────────────────────────────────────────────────

    /// <summary>PUT /rpm/upload — RPM upload (body = .rpm bytes).</summary>
    [HttpPut("/rpm/upload")]
    [HttpPost("/rpm/upload")]
    [Authorize(AuthenticationSchemes = "Bearer," + Dependably.Security.TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishRpm)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(RpmUploadSizeLimitBytes)]
    // The staged file path is a server-generated GUID under the operator-configured staging root;
    // the request body reaches the file content, not the file name. SCS's taint from Request.Body
    // into staged.Path is a false positive.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0018",
        Justification = "Staging path is a server-generated GUID under the operator-configured root, not user input.")]
    public async Task<IActionResult> Upload(CancellationToken ct)
    {
        // Fail-closed on an edge node: RPM upload writes the registry tier directly (outside the
        // shared publish service), so the edge guard is applied here at the choke point.
        if (_svc.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        string orgId = CurrentTenantId();

        // Refuse uploads when upstream passthrough is effective for this org — a locally published
        // package would silently shadow upstream content and break dep-resolution for dnf clients.
        // Effective passthrough = effective mode is 'passthrough' AND the org has ≥1 rpm registry.
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        if (IsRpmPassthroughEffective(settings)
            && (await _svc.Registries.ResolveAsync(orgId, "rpm", ct)).Count > 0)
        {
            return Conflict(new ProblemDetails
            {
                Title = "Cannot publish under passthrough proxy mode",
                Detail = "This org has a configured rpm upstream registry and its RPM upstream mode is " +
                         "'passthrough'. Publishing would silently shadow upstream content. Set the RPM " +
                         "upstream mode to 'merged' under Settings → Proxy, or remove the org's rpm " +
                         "upstream registry, to enable hosted publishing.",
                Status = StatusCodes.Status409Conflict,
            });
        }

        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Resolve the size cap BEFORE reading the body so the tenant cap gates the stream itself
        // and an oversize upload is rejected (413) before any bytes reach the blob store. When no
        // tenant/instance cap is configured, the route-level ceiling still bounds the read.
        long? sizeCap = await ResolveSizeCapAsync(orgId, ct);
        long effectiveCap = sizeCap ?? RpmUploadSizeLimitBytes;

        // Stream the request body to a staging temp file with SHA-256 computed inline, instead of
        // the old growing-MemoryStream + ToArray double buffer that peaked at ~2x the body and
        // only checked the cap afterward.
        RequestBodyStager.StagedBody staged;
        try
        {
            staged = await RequestBodyStager.StageAsync(
                Request.Body, _svc.Staging.Path, effectiveCap, withMavenDigests: false, ct);
        }
        catch (InvalidDataException)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge,
                $"RPM upload exceeds size limit ({effectiveCap} bytes).");
        }

        try
        {
            return await ValidateAndPublishStagedRpmAsync(orgId, settings, token, staged, ct);
        }
        finally
        {
            RequestBodyStager.TryDelete(staged.Path);
        }
    }

    // Validates the staged RPM, then stores the blob and persists the version/repodata rows.
    // Split out of Upload to keep the dispatcher method within the line-count threshold (S138).
    private async Task<IActionResult> ValidateAndPublishStagedRpmAsync(
        string orgId, OrgSettings? settings, TokenRecord token, RequestBodyStager.StagedBody staged, CancellationToken ct)
    {
        if (staged.Size < RpmArtifactValidator.MinimumValidSize)
        {
            return BadRequest("RPM upload too small.");
        }

        // RpmArtifactValidator and scriptlet detection parse the RPM header (at the file
        // start) from a byte[]. Read the staged file — bounded by the tenant cap enforced
        // above — rather than holding the body in two live buffers.
        // staged.Path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        byte[] bytes = await System.IO.File.ReadAllBytesAsync(staged.Path, ct);

        RpmHeaderInfo header;
        try
        {
            header = RpmArtifactValidator.Validate(bytes);
        }
        catch (RpmParseException ex)
        {
            return BadRequest(ex.Message);
        }

        // NEVRA filename convention; dnf clients expect this exact shape.
        string filename = $"{header.Name}-{header.Version}-{header.Release}.{header.Arch}.rpm";
        string purlName = header.Name.ToLowerInvariant();
        string version = $"{header.Version}-{header.Release}";
        string purl = PurlNormalizer.Rpm(header.Name, header.Version, header.Release, header.Arch, header.Epoch ?? 0);

        // Content-addressed hosted key: the artefact's SHA-256 (computed inline while the
        // body streamed to the staging file) is a key segment, so the bytes under a key
        // always hash to the digest the key names. Two concurrent uploads of one NEVRA
        // carrying different bytes therefore address disjoint keys and cannot overwrite
        // one another — the committed package_versions row's (blob_key, checksum_sha256)
        // pair stays true of the stored bytes with no lock and no ordering constraint
        // between the blob write and the metadata write. Readers resolve the key from the
        // stored blob_key (never by rebuilding the coordinate), so rows written under the
        // older coordinate-only key shape keep resolving unchanged.
        string blobKey = BlobKeys.HostedArtifact(orgId, "rpm", purlName, version, staged.Sha256, filename);

        // Install/lifecycle-script detection on the staged bytes. Best-effort: the artifact
        // already passed validation, so a parse failure here must not fail the upload.
        var scriptResult = ScriptDetectionService.Detect("rpm", filename, bytes);

        // License hard-block. RPM publishes write the registry tier and version row
        // directly (outside IPackagePublishService's shared pipeline), so the gate is
        // applied here at the choke point, before any blob or metadata write — mirroring
        // the "no version row on block" invariant the shared pipeline gives every other
        // hosted-push ecosystem. Strictly guarded by 'block': under 'warn'/'off' this reads
        // nothing extra.
        if (await EvaluateRpmLicenseGateAsync(orgId, settings, header.License, ct) is { } licenseReject)
        {
            return licenseReject;
        }

        // Name-level publish authorization. Keys on the authenticated token principal (never the
        // RPM header), so a token holding only publish:rpm cannot shadow a package name (e.g.
        // glibc) a different principal already owns. No-op unless PUBLISH_NAME_BINDING=on.
        var namePrincipal = Dependably.Infrastructure.NamePrincipal.FromToken(token);
        if (_svc.NameBinding is { } nameGate
            && !await nameGate.IsPublishAuthorizedAsync(orgId, "rpm", purlName, namePrincipal, ct))
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                $"Publishing to '{purlName}' is not permitted: the name is owned by a different " +
                "principal in this org and you hold no publish grant for it.");
        }

        // Store the verified artifact by streaming the staged file into the blob store.
        // staged.Path is under the operator-configured staging root — no user input reaches the path.
        await using (var artifactStream = new FileStream(
            staged.Path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true))
        {
            await _svc.BlobStore.Registry.PutAsync(blobKey, artifactStream, ct);
        }

        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "rpm", header.Name, purlName, isProxy: false, ct);
        await PersistRpmVersionAsync(new RpmVersionArgs(orgId, pkg, version, purl, blobKey, filename, bytes.Length, staged.Sha256, header,
            HasInstallScript: scriptResult.HasScript, InstallScriptKind: scriptResult.Kind), ct);

        // Record first-publisher ownership now that the artefact and its rows are durably stored.
        if (_svc.NameBinding is { } ownerGate)
        {
            await ownerGate.RecordOwnershipAsync(orgId, "rpm", purlName, namePrincipal, ct);
        }

        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "push",
            actorId: token.AuditActorId, actorKind: token.ActorKind, actorLabel: token.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        Response.Headers["X-Dependably-PURL"] = purl;
        return StatusCode(StatusCodes.Status201Created);
    }

    // Cohesive set of values for a newly published RPM version, bundled to keep
    // PersistRpmVersionAsync within the parameter-count threshold (S107).
    private sealed record RpmVersionArgs(
        string OrgId, Package Pkg, string Version, string Purl,
        string BlobKey, string Filename, int SizeBytes, string Sha256, RpmHeaderInfo Header,
        bool HasInstallScript, string? InstallScriptKind);

    // Upserts the package_versions and rpm_metadata rows for a newly published RPM, marks
    // the per-arch repodata dirty, and evicts both the merged and local repodata caches.
    //
    // The package_versions row is written once per (package, version) and its artefact columns
    // are never repointed: an upload of a NEVRA the tenant already holds keeps the committed
    // row — and therefore the bytes the repodata's sealed checksum names and the download path
    // serves — intact. Because the hosted key is content-addressed, the re-uploaded bytes land
    // on their own key rather than over the committed row's, so the row can never end up
    // advertising a digest the blob beneath it no longer has; the unreferenced bytes are
    // reclaimed by the orphan reconciler.
    private async Task PersistRpmVersionAsync(RpmVersionArgs a, CancellationToken ct)
    {
        // xtenant: a.Pkg.Id came from GetOrCreateAsync(a.OrgId, ...); inserts against it
        // inherit tenant scope via the packages.org_id FK chain.
        await using var conn = await _svc.Db.OpenAsync(ct);
        string? existing = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = a.Pkg.Id, version = a.Version });

        string versionId = existing ?? Guid.NewGuid().ToString("N");
        if (existing is null)
        {
            // xtenant: a.Pkg.Id came from GetOrCreateAsync(a.OrgId, ...); inherits tenant scope.
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions
                    (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
                VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes, @sha256, 'uploaded')
                """,
                new
                {
                    id = versionId,
                    pkgId = a.Pkg.Id,
                    version = a.Version,
                    purl = a.Purl,
                    blobKey = a.BlobKey,
                    filename = a.Filename,
                    sizeBytes = (long)a.SizeBytes,
                    sha256 = a.Sha256,
                });
        }

        await UpsertRpmMetadataAsync(conn, versionId, a.Header);
        await MirrorRpmLicenseAsync(versionId, cacheArtifactId: null, a.Header.License, ct);
        await MarkRepodataDirtyAsync(conn, a.OrgId, a.Header.Arch);
        EvictRepodataCaches(a.OrgId);

        // Persist the install-script signal whether or not the version row is new — a
        // republished, now-script-free artefact must clear any stale flag from a prior upload.
        await _svc.Packages.UpdateInstallScriptAsync(versionId, a.HasInstallScript, a.InstallScriptKind, ct);
    }

    // Upserts the rpm_metadata row for a package version (owner_kind='package_version' arm).
    // xtenant: package_version_id is already bound to the tenant.
    private static async Task UpsertRpmMetadataAsync(
        System.Data.IDbConnection conn, string versionId, RpmHeaderInfo header)
    {
        await conn.ExecuteAsync(
            """
            INSERT INTO rpm_metadata
                (id, package_version_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, build_host, build_time, packager, vendor,
                 rpm_group, source_rpm, url, installed_size, archive_size,
                 header_start, header_end,
                 requires_json, provides_json, conflicts_json, obsoletes_json,
                 files_json, changelogs_json, rpm_license)
            VALUES
                (lower(hex(randomblob(16))), @pvId, 'package_version',
                 @name, @epoch, @ver, @rel, @arch,
                 @summary, @description, @buildHost, @buildTime, @packager, @vendor,
                 @rpmGroup, @sourceRpm, @url, @installedSize, @archiveSize,
                 @headerStart, @headerEnd,
                 @requires, @provides, @conflicts, @obsoletes,
                 @files, @changelogs, @license)
            ON CONFLICT(package_version_id) WHERE owner_kind = 'package_version' DO UPDATE SET
                rpm_name = excluded.rpm_name,
                epoch = excluded.epoch,
                rpm_version = excluded.rpm_version,
                rpm_release = excluded.rpm_release,
                arch = excluded.arch,
                summary = excluded.summary,
                description = excluded.description
            """,
            new
            {
                pvId = versionId,
                name = header.Name,
                epoch = header.Epoch ?? 0,
                ver = header.Version,
                rel = header.Release,
                arch = header.Arch,
                summary = header.Summary,
                description = header.Description,
                buildHost = header.BuildHost,
                buildTime = header.BuildTime,
                packager = header.Packager,
                vendor = header.Vendor,
                rpmGroup = header.Group,
                sourceRpm = header.SourceRpm,
                url = header.Url,
                installedSize = header.InstalledSize,
                archiveSize = header.ArchiveSize,
                headerStart = header.HeaderStart,
                headerEnd = header.HeaderEnd,
                requires = JsonSerializer.Serialize(header.Requires),
                provides = JsonSerializer.Serialize(header.Provides),
                conflicts = JsonSerializer.Serialize(header.Conflicts),
                obsoletes = JsonSerializer.Serialize(header.Obsoletes),
                files = JsonSerializer.Serialize(header.Files),
                changelogs = JsonSerializer.Serialize(header.Changelogs),
                license = header.License,
            });
    }

    /// <summary>
    /// License hard-block for hosted RPM uploads, governed by the existing
    /// <c>org_settings.license_enforcement_mode</c> ('off'/'warn'/'block'). RPM publish writes
    /// the registry tier and version row directly (it does not funnel through
    /// <c>IPackagePublishService</c>), so this is the pre-persist choke point mirroring the
    /// shared pipeline's license arm. Maps the raw tag through <see cref="RpmLicenseMapper"/>
    /// the same way <see cref="MirrorRpmLicenseAsync"/> does, so the policy check speaks the
    /// same vocabulary as the persisted review-queue entry. Only 'block' can reject; 'warn'/'off'
    /// or a null/blank/implausible license never read the policy tables.
    /// </summary>
    private async Task<IActionResult?> EvaluateRpmLicenseGateAsync(
        string orgId, OrgSettings? settings, string? rawLicense, CancellationToken ct)
    {
        if (settings?.LicenseEnforcementMode != "block" || string.IsNullOrWhiteSpace(rawLicense))
        {
            return null;
        }

        string mapped = RpmLicenseMapper.ToSpdx(rawLicense);
        if (!LicenseExtractor.IsPlausibleSpdx(mapped))
        {
            return null;
        }

        var verdict = await _svc.Licenses.CheckPolicyAsync(orgId, "block", [mapped], ct);
        return verdict.Allowed
            ? null
            : new ObjectResult(new ProblemDetails
            {
                Detail = $"License '{verdict.BlockedLicense}' is not permitted by this org's license policy.",
                Status = StatusCodes.Status403Forbidden,
            })
            { StatusCode = StatusCodes.Status403Forbidden };
    }

    /// <summary>
    /// Mirrors an RPM header/primary.xml <c>License</c> tag into license governance
    /// (<c>package_version_licenses</c>), mapping the Fedora/RHEL short tag to its
    /// SPDX identifier via <see cref="RpmLicenseMapper"/> first so the review queue
    /// speaks the same vocabulary as every other ecosystem. Exactly one of
    /// <paramref name="versionId"/> (hosted upload) or <paramref name="cacheArtifactId"/>
    /// (proxy first-fetch) is non-null per call site. Best-effort: a null/blank
    /// license, a mapped value that fails the SPDX shape gate, or a DB failure never
    /// fails the surrounding ingest — the artifact has already been (or is about to
    /// be) stored/served regardless of whether the license mirrors cleanly.
    /// </summary>
    private async Task MirrorRpmLicenseAsync(
        string? versionId, string? cacheArtifactId, string? rawLicense, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rawLicense))
        {
            return;
        }

        string mapped = RpmLicenseMapper.ToSpdx(rawLicense);
        if (!LicenseExtractor.IsPlausibleSpdx(mapped))
        {
            return;
        }

        try
        {
            string[] spdx = [mapped];
            if (versionId is not null)
            {
                await _svc.Licenses.SetLicensesAsync(versionId, spdx, "upstream", ct);
            }

            if (cacheArtifactId is not null)
            {
                await _svc.Licenses.SetLicensesForCacheArtifactAsync(cacheArtifactId, spdx, "upstream", ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Logger.LogWarning(ex,
                "RPM license mirror failed: {ExceptionType}", ex.GetType().Name);
        }
    }

    // Marks the per-arch repodata row dirty so the background rebuild service picks it up.
    // xtenant: composite PK (org_id, arch); explicit org_id parameter.
    private static async Task MarkRepodataDirtyAsync(
        System.Data.IDbConnection conn, string orgId, string arch)
    {
        await conn.ExecuteAsync(
            """
            INSERT INTO rpm_repodata_state (org_id, arch, dirty)
            VALUES (@orgId, @arch, 1)
            ON CONFLICT(org_id, arch) DO UPDATE SET dirty = 1
            """,
            new { orgId, arch });
    }

    // Invalidates the merged and local-mode repodata caches so a newly published RPM appears
    // immediately without waiting out the TTL. RPM repodata is tenant-wide, so the coordinates
    // stop at the org and the coordinator expands every local document plus the merged tuple.
    private void EvictRepodataCaches(string orgId)
    {
        _svc.Invalidation.Invalidate(MetadataInvalidation.ForRpm(orgId));
    }


    // ── NEVRA parsing ─────────────────────────────────────────────────────────

    /// <summary>
    /// Parses a NEVRA filename <c>{name}-{epoch:version}-{release}.{arch}.rpm</c>.
    /// Epoch is optional in the filename (defaults to 0 when absent).
    /// Returns null for malformed filenames.
    /// </summary>
    internal static (string Name, int Epoch, string Version, string Release, string Arch)? ParseNevra(string filename)
    {
        if (!filename.EndsWith(".rpm", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string stem = filename[..^4];

        // Each separator must sit strictly inside its substring — never at position 0 or at
        // the last index — so the dash/dot split alone can never resolve to an empty Name,
        // Version, Release, or Arch (mirrors ApkController.ParseApkFilename's verDash guard).
        // Version can still end up empty after the epoch-colon strip below, so that step
        // carries its own guard.
        int archDot = stem.LastIndexOf('.');
        if (archDot <= 0 || archDot == stem.Length - 1)
        {
            return null;
        }

        string arch = stem[(archDot + 1)..];
        string nameVerRel = stem[..archDot];

        int relDash = nameVerRel.LastIndexOf('-');
        if (relDash <= 0 || relDash == nameVerRel.Length - 1)
        {
            return null;
        }

        string release = nameVerRel[(relDash + 1)..];
        string nameVer = nameVerRel[..relDash];

        int verDash = nameVer.LastIndexOf('-');
        if (verDash <= 0 || verDash == nameVer.Length - 1)
        {
            return null;
        }

        string version = nameVer[(verDash + 1)..];
        string name = nameVer[..verDash];

        int epoch = 0;
        int colon = version.IndexOf(':');
        if (colon > 0 && int.TryParse(version[..colon], out int e))
        {
            epoch = e;
            version = version[(colon + 1)..];

            // The epoch strip can itself empty the remaining Version (e.g. "pkg-1:-1.x86_64.rpm"
            // has verDash sitting inside "pkg-1:", so the boundary guard above never sees it).
            // Reject rather than let an empty Version reach the PURL and cache_artifact.
            if (version.Length == 0)
            {
                return null;
            }
        }

        return (name, epoch, version, release, arch);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private ILogger<RpmController> Logger => HttpContext.RequestServices
        .GetRequiredService<ILogger<RpmController>>();

    /// <summary>
    /// Records a proxy RPM first-fetch into the global cache plane. The per-tenant
    /// <c>packages</c> row is created for discoverability; the per-version data lives in
    /// <c>cache_artifact</c> + <c>tenant_artifact_access</c>. No <c>package_versions</c> row
    /// is inserted for proxy artifacts — the global plane is authoritative for proxy versions.
    /// RPM header metadata (from <c>primary.xml</c>) is written to <c>rpm_metadata</c> keyed
    /// by <c>cache_artifact_id</c> so repodata builders can include it without a PV row.
    ///
    /// Returns the <c>cache_artifact</c> id, or null when the cache plane could not record the
    /// artefact. The caller treats null as ungateable and refuses the serve — every block-gate arm
    /// reads that row.
    /// </summary>
    private async Task<string?> CacheProxyPackageAsync(ProxyCachePackage p, CancellationToken ct)
    {
        // Ensure per-tenant packages row so the RPM appears in this org's listings.
        await _svc.Packages.GetOrCreateAsync(
            p.OrgId, "rpm", p.Resolution.Name, p.Resolution.Name.ToLowerInvariant(), isProxy: true, ct);

        // Record the fetch into the global cache plane. Best-effort — swallowed by the recorder.
        // name is lowercased so ca.name = p.purl_name joins hold for mixed-case RPM names
        // (e.g. 'perl-AutoLoader' normalizes to 'perl-autoloader', matching packages.purl_name).
        string? cacheArtifactId = await _svc.CacheRecorder.RecordAccessAsync(
            new CacheAccess(p.OrgId, "rpm", p.Resolution.Name.ToLowerInvariant(), p.Ver, p.Filename,
                p.Resolution.Sha256, p.SizeBytes, BlobKeys.Proxy(p.Resolution.Sha256),
                p.Resolution.PackageUrl,
                // The hash comes from the repodata this org's own upstream resolution produced and
                // the fetch is verified against it, so it identifies the bytes this org fetched.
                CacheAccessOrigin.FirstFetch), ct);

        if (cacheArtifactId is not null)
        {
            await _svc.TenantAccess.UpsertStateAsync(p.OrgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);

            // Install/lifecycle-script detection on the freshly-cached blob. Best-effort:
            // the artifact already streamed to the client, so any read or parse failure
            // leaves has_install_script at its 0 default without affecting the response.
            bool hasScript = false;
            string? scriptKind = null;
            try
            {
                await using var blobStream = await _svc.BlobStore.Cache.GetAsync(
                    BlobKeys.Proxy(p.Resolution.Sha256), ct);
                if (blobStream is not null)
                {
                    var scriptResult = await ScriptDetectionService.DetectAsync("rpm", p.Filename, blobStream, ct);
                    hasScript = scriptResult.HasScript;
                    scriptKind = scriptResult.Kind;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Swallowed: detection is advisory; the cached version still serves.
                // Serilog RenderedCompactJsonFormatter JSON-encodes {Filename}, neutralising newline/control-char injection.
                Logger.LogWarning(ex,
                    "RPM proxy: install-script detection failed for {Filename}: {ExceptionType}",
                    p.Filename, ex.GetType().Name);
            }

            string? provStatus = Dependably.Protocol.Provenance.ProvenanceStatuses.ToColumn(
                p.ProvenanceResult.Status);
            await _svc.CacheArtifacts.UpdateGlobalFactsAsync(
                cacheArtifactId,
                purl: p.Purl,
                checksumSha1: null,
                publishedAt: null,
                deprecated: null,
                hasInstallScript: hasScript,
                installScriptKind: scriptKind,
                provenanceStatus: provStatus,
                provenanceSigner: p.ProvenanceResult.Signer,
                upstreamIntegrityValue: p.Resolution.Sha256,
                upstreamIntegrityAlgorithm: "sha256",
                ct: ct);

            // Write rpm_metadata against the global cache_artifact row so repodata renderers
            // have structured NEVRA/summary/description available without a package_versions row.
            // xtenant: cache_artifact is global; keyed by id returned from the recorder above.
            await using var conn = await _svc.Db.OpenAsync(ct);
            await conn.ExecuteAsync(
                """
                INSERT INTO rpm_metadata
                    (id, cache_artifact_id, owner_kind,
                     rpm_name, epoch, rpm_version, rpm_release, arch,
                     summary, description, rpm_license)
                VALUES (lower(hex(randomblob(16))), @caId, 'cache_artifact',
                        @name, @epoch, @ver, @rel, @arch, @summary, @desc, @license)
                ON CONFLICT(cache_artifact_id) WHERE owner_kind = 'cache_artifact' DO NOTHING
                """,
                new
                {
                    caId = cacheArtifactId,
                    name = p.Nevra.Name,
                    epoch = p.Nevra.Epoch,
                    ver = p.Nevra.Version,
                    rel = p.Nevra.Release,
                    arch = p.Nevra.Arch,
                    summary = p.Resolution.Summary,
                    desc = p.Resolution.Description,
                    license = p.Resolution.License,
                });

            await MirrorRpmLicenseAsync(versionId: null, cacheArtifactId, p.Resolution.License, ct);
        }

        return cacheArtifactId;
    }

    private sealed record ProxyCachePackage(
        string OrgId,
        string Filename,
        PackageResolution Resolution,
        (string Name, int Epoch, string Version, string Release, string Arch) Nevra,
        string Ver,
        string Purl,
        string DbBlobKey,
        long SizeBytes,
        Dependably.Protocol.Provenance.ProvenanceResult ProvenanceResult);

    private async Task<long?> ResolveSizeCapAsync(string orgId, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        if (settings is null)
        {
            return null;
        }
        // xtenant: keyed by org_id directly.
        await using var conn = await _svc.Db.OpenAsync(ct);
        long? rpmCap = await conn.ExecuteScalarAsync<long?>(
            "SELECT max_upload_bytes_rpm FROM org_settings WHERE org_id = @orgId",
            new { orgId });
        return rpmCap ?? settings.MaxUploadBytes;
    }
}

/// <summary>Scoped DI bundle for the RPM controller.</summary>
public sealed record RpmControllerServices(
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    TieredBlobStorage BlobStore,
    IMetadataStore Db,
    RpmRepodataService Repodata,
    UpstreamRegistryResolver Registries,
    MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache> MergedRepodataCache,
    RenderedResponseCache<RpmLocalRepodataKey> LocalRepodataCache,
    MetadataInvalidationCoordinator Invalidation,
    TimeProvider Time,
    CacheAccessRecorder CacheRecorder,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    Dependably.Protocol.Provenance.RpmProvenanceVerifier RpmProvenance,
    Dependably.Infrastructure.Edge.EdgePublishGuard EdgeGuard,
    Dependably.Protocol.BlockGateService BlockGate,
    VulnerabilityScanService Scanner,
    Dependably.Infrastructure.StagingOptions Staging,
    LicenseRepository Licenses,
    Dependably.Security.NameBindingGate? NameBinding = null,
    UpstreamClient? UpstreamClient = null,
    IRpmUpstreamProxy? Proxy = null,
    Dependably.Infrastructure.IPerOrgTrustAnchorStore? TrustStore = null);
