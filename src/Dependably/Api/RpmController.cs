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
///     and cached as <c>origin='proxy'</c> rows.
///   - PUT upload refused with 409 — shadowing upstream content is not allowed in passthrough mode.
/// </summary>
[ApiController]
public sealed class RpmController : OrgScopedControllerBase
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
    public async Task<IActionResult> Upload(CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        // Refuse uploads when upstream passthrough is active for this org — a locally published
        // package would silently shadow upstream content and break dep-resolution for dnf clients.
        // Effective passthrough = instance mode is 'passthrough' AND the org has ≥1 rpm registry.
        if (_svc.Proxy is { IsPassthroughModeSelected: true }
            && (await _svc.Registries.ResolveAsync(orgId, "rpm", ct)).Count > 0)
        {
            return Conflict(new ProblemDetails
            {
                Title = "Cannot publish under passthrough proxy mode",
                Detail = "This org has a configured rpm upstream registry and Rpm:UpstreamMode=passthrough. " +
                         "Publishing would silently shadow upstream content. Switch Rpm:UpstreamMode " +
                         "to 'merged' or remove the org's rpm upstream registry to enable hosted publishing.",
                Status = StatusCodes.Status409Conflict,
            });
        }

        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms, ct);
        byte[] bytes = ms.ToArray();
        if (bytes.Length < RpmArtifactValidator.MinimumValidSize)
        {
            return BadRequest("RPM upload too small.");
        }

        RpmHeaderInfo header;
        try
        {
            header = RpmArtifactValidator.Validate(bytes);
        }
        catch (RpmParseException ex)
        {
            return BadRequest(ex.Message);
        }

        // Size cap: per-tenant override → instance global.
        long? sizeCap = await ResolveSizeCapAsync(orgId, ct);
        if (sizeCap is { } cap && bytes.LongLength > cap)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge, $"RPM upload exceeds size limit ({cap} bytes).");
        }

        // NEVRA filename convention; dnf clients expect this exact shape.
        string filename = $"{header.Name}-{header.Version}-{header.Release}.{header.Arch}.rpm";
        string purlName = header.Name.ToLowerInvariant();
        string version = $"{header.Version}-{header.Release}";
        string purl = PurlNormalizer.Rpm(header.Name, header.Version, header.Release, header.Arch, header.Epoch ?? 0);
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Hosted(orgId, "rpm", purlName, version, filename);

        await _svc.BlobStore.Registry.PutAsync(blobKey, new MemoryStream(bytes), ct);

        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "rpm", header.Name, purlName, isProxy: false, ct);
        await PersistRpmVersionAsync(new RpmVersionArgs(orgId, pkg, version, purl, blobKey, filename, bytes.Length, sha256, header), ct);

        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "push",
            actorId: token.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        Response.Headers["X-Dependably-PURL"] = purl;
        return StatusCode(StatusCodes.Status201Created);
    }

    // Cohesive set of values for a newly published RPM version, bundled to keep
    // PersistRpmVersionAsync within the parameter-count threshold (S107).
    private sealed record RpmVersionArgs(
        string OrgId, Package Pkg, string Version, string Purl,
        string BlobKey, string Filename, int SizeBytes, string Sha256, RpmHeaderInfo Header);

    // Upserts the package_versions and rpm_metadata rows for a newly published RPM, marks
    // the per-arch repodata dirty, and evicts both the merged and local repodata caches.
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
        await MarkRepodataDirtyAsync(conn, a.OrgId, a.Header.Arch);
        EvictRepodataCaches(a.OrgId);
    }

    // Upserts the rpm_metadata row for a package version.
    // xtenant: PK on package_version_id which is already bound to the tenant.
    private static async Task UpsertRpmMetadataAsync(
        System.Data.IDbConnection conn, string versionId, RpmHeaderInfo header)
    {
        await conn.ExecuteAsync(
            """
            INSERT INTO rpm_metadata
                (package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, build_host, build_time, packager, vendor,
                 rpm_group, source_rpm, url, installed_size, archive_size,
                 header_start, header_end,
                 requires_json, provides_json, conflicts_json, obsoletes_json,
                 files_json, changelogs_json, rpm_license)
            VALUES
                (@pvId, @name, @epoch, @ver, @rel, @arch,
                 @summary, @description, @buildHost, @buildTime, @packager, @vendor,
                 @rpmGroup, @sourceRpm, @url, @installedSize, @archiveSize,
                 @headerStart, @headerEnd,
                 @requires, @provides, @conflicts, @obsoletes,
                 @files, @changelogs, @license)
            ON CONFLICT(package_version_id) DO UPDATE SET
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

    // Evicts the merged and local-mode repodata caches so a newly published RPM appears
    // immediately without waiting out the TTL.
    private void EvictRepodataCaches(string orgId)
    {
        _svc.MergedRepodataCache.Evict(new RpmMergedRepodataKey(orgId));
        _svc.LocalRepodataCache.Evict(new RpmLocalRepodataKey(orgId, "primary"));
        _svc.LocalRepodataCache.Evict(new RpmLocalRepodataKey(orgId, "filelists"));
        _svc.LocalRepodataCache.Evict(new RpmLocalRepodataKey(orgId, "other"));
    }

    // ── Download ──────────────────────────────────────────────────────────────

    /// <summary>GET /rpm/packages/{file} — download an RPM by NEVRA filename.</summary>
    [HttpGet("/rpm/packages/{file}")]
    [HttpHead("/rpm/packages/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Download(string file, CancellationToken ct)
    {
        var pathCheck = PathSafeValidator.Validate(file, "file");
        if (!pathCheck.IsValid)
        {
            return BadRequest(pathCheck.Message);
        }

        if (!file.EndsWith(".rpm", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("RPM filename must end with .rpm.");
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var versionMatch = await _svc.Packages.FindVersionByBlobKeySuffixAsync(orgId, "rpm", file, ct);

        if (versionMatch is not null)
        {
            return await ServePackageFromCacheAsync(orgId, file, versionMatch.Value, token, ct);
        }

        // Cache MISS — attempt upstream proxy if configured.
        if (_svc.Proxy is null || _svc.UpstreamClient is null)
        {
            return NotFound();
        }

        if (settings is null || !settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        // Per-org upstream: top-priority configured rpm registry. Empty ⇒ proxying disabled.
        var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
        return bases.Count == 0 ? NotFound() : await ProxyDownloadAsync(orgId, bases[0], file, token, ct);
    }

    private async Task<IActionResult> ServePackageFromCacheAsync(
        string orgId, string file,
        (Package Package, PackageVersion Version) versionMatch,
        TokenRecord? token, CancellationToken ct)
    {
        string blobKey = BlobKeys.StoreKey(versionMatch.Version.BlobKey);
        var hitStore = versionMatch.Version.Origin == "proxy"
            ? _svc.BlobStore.Cache
            : _svc.BlobStore.Registry;
        var stream = await hitStore.GetAsync(blobKey, ct);
        if (stream is null)
        {
            return NotFound();
        }

        Response.Headers["X-Cache"] = "HIT";
        if (versionMatch.Version.ChecksumSha256 is not null)
        {
            Response.Headers.ETag = $"\"sha256:{versionMatch.Version.ChecksumSha256}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await _svc.Audit.LogActivityAsync(orgId, "rpm", versionMatch.Version.Purl, "download",
            token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _svc.Packages.IncrementDownloadCountAsync(versionMatch.Version.Id, ct);
        return File(stream, "application/x-rpm", file);
    }

    private async Task<IActionResult> ProxyDownloadAsync(
        string orgId, string upstreamBase, string file, TokenRecord? token, CancellationToken ct)
    {
        // 1. Negative cache
        if (await _svc.Proxy!.IsNegativelyCachedAsync(file, ct))
        {
            return NotFound();
        }

        // 2. Resolve package URL from primary.xml.gz
        var resolution = await TryResolveUpstreamPackageAsync(upstreamBase, file, ct);
        if (resolution is null)
        {
            await _svc.Proxy.RecordNegativeAsync(file, ct);
            return NotFound();
        }

        // 3. Parse NEVRA from filename
        var nevra = ParseNevra(file);
        if (nevra is null)
        {
            return NotFound();
        }

        var (name, epoch, rpmVersion, release, arch) = nevra.Value;
        string ver = $"{rpmVersion}-{release}";
        string purl = PurlNormalizer.Rpm(name, rpmVersion, release, arch, epoch);
        string blobStoreKey = BlobKeys.Proxy(resolution.Sha256);

        // 4. Fetch from upstream via UpstreamClient (checksum-verified, cached on Cache tier)
        Stream body;
        bool isHit;
        try
        {
            (body, isHit) = await _svc.UpstreamClient!.GetOrFetchStreamAsync(
                blobStoreKey, resolution.PackageUrl,
                new ChecksumSpec(ChecksumAlgorithm.Sha256, resolution.Sha256),
                "rpm", orgId, purl, ct);
        }
        catch (ChecksumException)
        {
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream checksum mismatch; package not served.");
        }

        // 5. Persist DB row (package_versions + rpm_metadata) on first fetch
        string dbBlobKey = $"proxy/{resolution.Sha256}/{file}"; // StoreKey strips the filename suffix
        // Use Content-Length if the stream knows it; otherwise fall back to 0 (updated async).
        int contentLength = body.CanSeek ? (int)body.Length : 0;
        await CacheProxyPackageAsync(
            new ProxyCachePackage(orgId, file, resolution, nevra.Value, ver, purl, dbBlobKey, contentLength),
            ct);

        Response.Headers["X-Cache"] = isHit ? "HIT" : "MISS";
        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "download",
            token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _svc.Packages.IncrementDownloadCountByPurlAsync(purl, ct);
        return File(body, "application/x-rpm", file);
    }

    private async Task<PackageResolution?> TryResolveUpstreamPackageAsync(string upstreamBase, string file, CancellationToken ct)
    {
        try
        {
            return await _svc.Proxy!.ResolvePackageUrlAsync(upstreamBase, file, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            // deepcode ignore LogForging: Serilog RenderedCompactJsonFormatter JSON-encodes {Filename}, neutralising newline/control-char injection.
            Logger.LogWarning(ex,
                "RPM proxy: ResolvePackageUrlAsync failed for {Filename}: {ExceptionType}",
                file, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// GET /rpm/Packages/{bucket}/{file} — download an RPM by the *nested*
    /// path that upstream repodata advertises in its <c>&lt;location href&gt;</c>
    /// (e.g. <c>Packages/t/tree-2.1.0-5.fc40.x86_64.rpm</c>).
    /// </summary>
    /// <remarks>
    /// In passthrough mode the proxy forwards upstream's <c>primary.xml</c> verbatim —
    /// its hashes are sealed by <c>repomd.xml</c>, so the location hrefs cannot be
    /// rewritten to the flat <c>/rpm/packages/{file}</c> form without breaking dnf's
    /// metadata integrity check. dnf therefore composes <c>baseurl + href</c> and
    /// requests the nested path. This route maps that request to the same
    /// flat-filename download flow (the proxy resolves packages by NEVRA filename,
    /// not by mirror layout) — <paramref name="bucket"/> (the Fedora/EPEL first-letter
    /// directory) is ignored. The fixed two-segment shape keeps it distinct from the
    /// single-segment flat route, so there is no ambiguous-route conflict.
    /// </remarks>
    [HttpGet("/rpm/Packages/{bucket}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> DownloadNested(string bucket, string file, CancellationToken ct)
        => Download(file, ct);

    // ── Repodata ──────────────────────────────────────────────────────────────

    /// <summary>GET /rpm/repodata/{file} — repomd.xml or compressed XML docs.</summary>
    [HttpGet("/rpm/repodata/{file}")]
    [HttpHead("/rpm/repodata/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Repodata(string file, CancellationToken ct)
    {
        var pathCheck = PathSafeValidator.Validate(file, "file");
        if (!pathCheck.IsValid)
        {
            return BadRequest(pathCheck.Message);
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Proxy modes (passthrough / merged) delegate to upstream before local generation; both
        // fall through to local on a null result (unrecognised filename / upstream 404).
        var proxied = await TryServeRepodataFromProxyAsync(orgId, settings!, file, ct);
        return proxied ?? await ServeRepodataLocallyAsync(orgId, file, ct);
    }

    /// <summary>
    /// Serves repodata from the configured RPM proxy when proxying is effective for the org.
    /// Passthrough mode forwards upstream's repomd/compressed docs verbatim; merged mode serves a
    /// combined local ∪ upstream index. Effective engagement = org passthrough effective
    /// (air-gap-aware) AND ≥1 rpm registry; the top-priority registry (bases[0]) is the whole-repo
    /// source. Returns null when proxying is not effective, no rpm registry is configured, or the
    /// upstream result is null — the caller then falls back to local generation.
    /// </summary>
    private async Task<IActionResult?> TryServeRepodataFromProxyAsync(string orgId, OrgSettings settings, string file, CancellationToken ct)
    {
        if (!settings.ProxyPassthroughEffective)
        {
            return null;
        }

        if (_svc.Proxy is { IsPassthroughModeSelected: true })
        {
            var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
            return bases.Count > 0 ? await TryServeRepodataFromUpstreamAsync(bases[0], file, ct) : null;
        }

        if (_svc.Proxy is { IsMergedModeSelected: true })
        {
            var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
            return bases.Count > 0 ? await TryServeMergedRepodataAsync(orgId, bases[0], file, ct) : null;
        }

        return null;
    }

    /// <summary>
    /// Serves <c>repomd.xml</c>, <c>primary.xml.gz</c>, and <c>filelists.xml.gz</c> as a merge
    /// of the tenant's locally published RPMs and the upstream repo's packages. The gzipped
    /// documents are memoised per org (short TTL, evicted on upload) so the <c>repomd.xml</c>
    /// request and the follow-up document requests return byte-identical content — otherwise the
    /// SHA-256 checksums the repomd seals would not match what dnf downloads.
    ///
    /// Upstream non-primary repomd entries (other, group, modules, updateinfo, …) with
    /// hash-prefixed (content-addressed) hrefs are passed through verbatim in the merged repomd;
    /// entries with plain hrefs are dropped at build time (see <see cref="BuildMergedRepodataAsync"/>)
    /// because this dispatch cannot proxy them. When dnf follows an advertised hash-prefixed href,
    /// the request arrives here as a hash-prefixed filename and is proxied upstream via
    /// <see cref="TryServeRepodataFromUpstreamAsync"/> (the same caching + checksum path
    /// passthrough mode uses) — so every href the merged repomd advertises resolves here.
    ///
    /// Group (comps) and module (modulemd) metadata: Dependably does not generate comps or
    /// modulemd documents for locally published RPMs. Group definitions and module streams are
    /// authored independently of RPM packages and require operator-supplied metadata outside
    /// the scope of the artifact registry. Upstream group/module entries with hash-prefixed
    /// hrefs are forwarded verbatim (including locally published packages that happen to match
    /// a group defined upstream), but locally published packages absent from the upstream
    /// repo's group/module documents do not appear in any comps or modulemd. Plain-named group
    /// entries (e.g. <c>comps.xml.gz</c>) are dropped from the merged repomd so no unreachable
    /// href is advertised — dnf treats absent supplemental metadata as non-fatal.
    /// <c>dnf install</c> and direct package installs work for all published RPMs; <c>dnf group
    /// install</c> and modular stream installs work only for packages with upstream definitions.
    ///
    /// Returns null when the upstream primary can't be fetched (caller then falls back to local-only),
    /// or when a hash-prefixed upstream fetch also returns null (caller 404s).
    /// </summary>
    private async Task<IActionResult?> TryServeMergedRepodataAsync(string orgId, string upstreamBase, string file, CancellationToken ct)
    {
        bool isRepomd = file.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase);
        bool isPrimary = file.Equals("primary.xml.gz", StringComparison.OrdinalIgnoreCase);
        bool isFilelists = file.Equals("filelists.xml.gz", StringComparison.OrdinalIgnoreCase);

        // Hash-prefixed filenames are upstream non-primary blobs (other, updateinfo, group, modules,
        // etc.) advertised in the merged repomd. Proxy them through the upstream fetch path so they
        // are reachable — the same caching + checksum verification used by passthrough mode applies.
        if (!isRepomd && !isPrimary && !isFilelists)
        {
            return RpmUpstreamProxy.IsHashPrefixedFilename(file)
                ? await TryServeRepodataFromUpstreamAsync(upstreamBase, file, ct)
                : null;
        }

        var merged = await BuildMergedRepodataAsync(orgId, upstreamBase, ct);
        if (merged is null)
        {
            return null;
        }

        if (isPrimary)
        {
            return File(merged.PrimaryGz, "application/x-gzip", "primary.xml.gz");
        }

        if (isFilelists)
        {
            return File(merged.FilelistsGz, "application/x-gzip", "filelists.xml.gz");
        }

        // repomd.xml: local primary + filelists entries sealed by their checksums, plus upstream's
        // hash-prefixed non-primary entries (other, group, modules, updateinfo) forwarded verbatim.
        // Plain-named upstream entries (e.g. comps.xml.gz from classic createrepo) were dropped at
        // build time because they are not content-addressed and cannot be proxied here.
        // No locally-generated comps/modulemd is produced — group and module metadata is upstream-only.
        string repomd = RpmRepodataService.BuildRepomd(
            merged.PrimaryGz,
            _svc.Time.GetUtcNow(),
            merged.FilelistsGz,
            otherGz: null,
            extraEntries: merged.UpstreamNonPrimaryEntries);
        return File(System.Text.Encoding.UTF8.GetBytes(repomd), "application/xml", "repomd.xml");
    }

    /// <summary>
    /// Builds (and caches) the gzipped combined documents for merged mode. Returns null when the
    /// upstream primary can't be fetched/verified so the caller degrades to local-only.
    /// </summary>
    private async Task<MergedRepodataCache?> BuildMergedRepodataAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        var cacheKey = new RpmMergedRepodataKey(orgId);
        if (_svc.MergedRepodataCache.TryGet(cacheKey, out var cached) && cached is not null)
        {
            return cached;
        }

        byte[]? upstreamPrimaryGz;
        try
        {
            upstreamPrimaryGz = await _svc.Proxy!.GetUpstreamPrimaryXmlGzAsync(upstreamBase, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex,
                "RPM merged mode: upstream primary fetch failed for {UpstreamBase}: {ExceptionType}",
                upstreamBase, ex.GetType().Name);
            return null;
        }
        if (upstreamPrimaryGz is null)
        {
            return null;
        }

        // Fetch upstream filelists for merging; a missing upstream filelists is non-fatal —
        // local filelists is still generated and served.
        byte[]? upstreamFilelistsGz = null;
        try
        {
            upstreamFilelistsGz = await _svc.Proxy!.GetUpstreamFilelistsXmlGzAsync(upstreamBase, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex,
                "RPM merged mode: upstream filelists fetch failed for {UpstreamBase}: {ExceptionType}",
                upstreamBase, ex.GetType().Name);
        }

        // Fetch upstream non-primary repomd entries to pass through verbatim.
        IReadOnlyList<System.Xml.Linq.XElement> upstreamExtras = Array.Empty<System.Xml.Linq.XElement>();
        try
        {
            upstreamExtras = await _svc.Proxy!.GetUpstreamNonPrimaryRepomdEntriesAsync(upstreamBase, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex,
                "RPM merged mode: upstream repomd entry fetch failed for {UpstreamBase}: {ExceptionType}",
                upstreamBase, ex.GetType().Name);
        }

        // Build merged primary.
        string mergedPrimary = await _svc.Repodata.BuildMergedPrimaryAsync(orgId, upstreamPrimaryGz, ct);
        byte[] primaryGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(mergedPrimary));

        // Build merged filelists: local entries from stored files_json merged with upstream entries.
        byte[] filelistsGz;
        if (upstreamFilelistsGz is not null)
        {
            string mergedFilelists = await _svc.Repodata.BuildMergedFilelistsAsync(orgId, upstreamFilelistsGz, ct);
            filelistsGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(mergedFilelists));
        }
        else
        {
            string localFilelists = await _svc.Repodata.BuildFilelistsAsync(orgId, ct);
            filelistsGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(localFilelists));
        }

        // Filter upstream extras down to entries the merged repo can actually serve. The
        // upstream filelists entry is dropped because a merged local+upstream filelists is
        // generated above — advertising upstream's as well would make dnf parse two
        // conflicting filelists documents. Entries whose advertised href is not hash-prefixed
        // are also dropped: the repodata dispatch only proxies content-addressed
        // (64-hex-prefixed) filenames upstream, so a plain-named entry (e.g. an
        // uncompressed comps group file from classic createrepo) would 404 when dnf
        // follows it. dnf treats absent supplemental metadata as non-fatal, so dropping the
        // entry degrades gracefully instead of advertising an unreachable href.
        var filteredExtras = upstreamExtras
            .Where(e => (string?)e.Attribute("type") != "filelists")
            .Where(HasProxyableHref)
            .ToArray();

        var result = new MergedRepodataCache(primaryGz, filelistsGz, filteredExtras);
        _svc.MergedRepodataCache.Set(cacheKey, result, MergedRepodataTtl, primaryGz.Length + filelistsGz.Length);
        return result;
    }

    /// <summary>
    /// True when an upstream repomd <c>&lt;data&gt;</c> entry's advertised
    /// <c>&lt;location href&gt;</c> names a hash-prefixed (content-addressed) file — the only
    /// upstream repodata filenames the merged-mode dispatch can proxy. Entries failing this
    /// check are excluded from the merged repomd so every advertised href resolves.
    /// </summary>
    private static bool HasProxyableHref(System.Xml.Linq.XElement entry)
    {
        // The repomd XML namespace identifier — an opaque match string, never fetched over the network.
#pragma warning disable S5332
        System.Xml.Linq.XNamespace ns = "http://linux.duke.edu/metadata/repo";
#pragma warning restore S5332
        string? href = (string?)entry.Element(ns + "location")?.Attribute("href");
        if (href is null)
        {
            return false;
        }

        string filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;
        return RpmUpstreamProxy.IsHashPrefixedFilename(filename);
    }

    // Keep the repomd/primary/filelists tuple consistent across a single dnf sync while
    // still picking up new upstream content within a minute — matches the repomd passthrough TTL.
    private static readonly TimeSpan MergedRepodataTtl = TimeSpan.FromSeconds(60);

    private async Task<IActionResult?> TryServeRepodataFromUpstreamAsync(string upstreamBase, string file, CancellationToken ct)
    {
        string? ifNoneMatch = Request.Headers.IfNoneMatch.FirstOrDefault();
        string? ifModifiedSince = Request.Headers.IfModifiedSince.FirstOrDefault();

        RepodataResult? upstreamResult;
        try
        {
            upstreamResult = await _svc.Proxy!.GetRepodataAsync(upstreamBase, file, ifNoneMatch, ifModifiedSince, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            // deepcode ignore LogForging: Serilog RenderedCompactJsonFormatter JSON-encodes {Filename}, neutralising newline/control-char injection.
            Logger.LogWarning(ex,
                "RPM proxy: GetRepodataAsync failed for {Filename}: {ExceptionType}",
                file, ex.GetType().Name);
            return null;
        }

        if (upstreamResult is null)
        {
            return null;
        }

        if (upstreamResult.NotModified)
        {
            return StatusCode(StatusCodes.Status304NotModified);
        }

        if (upstreamResult.ETag is not null)
        {
            Response.Headers.ETag = upstreamResult.ETag;
        }

        if (upstreamResult.LastModified is not null)
        {
            Response.Headers.LastModified = upstreamResult.LastModified;
        }

        // Honor range requests for hash-prefixed (zchunk-capable) metadata files.
        if (RpmUpstreamProxy.IsHashPrefixedFilename(file) && Request.Headers.Range.Count > 0)
        {
            Response.Headers.AcceptRanges = "bytes";
        }

        return File(upstreamResult.Body, upstreamResult.ContentType);
    }

    // Short TTL keeps the local repodata fresh while amortising per-request builds over
    // a dnf metadata refresh burst. Eviction on upload provides immediate consistency.
    private static readonly TimeSpan LocalRepodataTtl = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Serves locally generated repodata when no upstream proxy is active (no configured rpm
    /// registry, or proxy passthrough disabled). Generates and serves <c>repomd.xml</c>,
    /// <c>primary.xml.gz</c>, <c>filelists.xml.gz</c>, and <c>other.xml.gz</c> from the
    /// locally published RPMs stored in the database.
    ///
    /// Group (comps) and module (modulemd) documents are not generated in local or hosted mode.
    /// Group definitions and module streams are authored independently of RPM packages; the
    /// registry stores only the package artifact and its header metadata. Any request for
    /// <c>comps.xml.gz</c>, <c>modules.yaml</c>, or similar supplemental metadata returns
    /// 404 — no empty or malformed document is served. <c>dnf install</c> works for all
    /// published packages; <c>dnf group install</c> and modular workflows require upstream
    /// group/module definitions that Dependably does not produce.
    /// </summary>
    private async Task<IActionResult> ServeRepodataLocallyAsync(string orgId, string file, CancellationToken ct)
    {
        if (file.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase))
        {
            // repomd.xml seals the SHA-256 checksums of primary/filelists/other — the three
            // compressed documents must be byte-identical to what was used to compute those
            // checksums. Fetch or rebuild each from the same per-document cache entries so
            // concurrent repomd.xml and primary.xml.gz requests always agree.
            byte[] primaryGz = await GetOrRebuildLocalDocAsync(orgId, "primary",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildPrimaryAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            byte[] filelistsGz = await GetOrRebuildLocalDocAsync(orgId, "filelists",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildFilelistsAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            byte[] otherGz = await GetOrRebuildLocalDocAsync(orgId, "other",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildOtherAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            string repomd = RpmRepodataService.BuildRepomd(primaryGz, _svc.Time.GetUtcNow(), filelistsGz, otherGz);
            return File(System.Text.Encoding.UTF8.GetBytes(repomd), "application/xml", "repomd.xml");
        }
        if (file.Equals("primary.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            byte[] gz = await GetOrRebuildLocalDocAsync(orgId, "primary",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildPrimaryAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            return File(gz, "application/x-gzip", "primary.xml.gz");
        }
        if (file.Equals("filelists.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            byte[] gz = await GetOrRebuildLocalDocAsync(orgId, "filelists",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildFilelistsAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            return File(gz, "application/x-gzip", "filelists.xml.gz");
        }
        if (file.Equals("other.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            byte[] gz = await GetOrRebuildLocalDocAsync(orgId, "other",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildOtherAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            return File(gz, "application/x-gzip", "other.xml.gz");
        }

        return NotFound();
    }

    // Retrieves the gzip-compressed document bytes from the per-document cache, or rebuilds
    // them under single-flight (concurrent callers for the same key share one rebuild). The
    // rebuild lambda always produces bytes (RPM documents are unconditionally generated from
    // stored rows), so the nullable result is converted to non-null by the call site.
    private async Task<byte[]> GetOrRebuildLocalDocAsync(
        string orgId, string docType,
        Func<CancellationToken, Task<byte[]>> build,
        CancellationToken ct)
    {
        var key = new RpmLocalRepodataKey(orgId, docType);
        // The lambda always returns non-null bytes; null-forgiving is safe here because
        // the RPM build methods always produce a complete XML document even for an empty repo.
        return (await _svc.LocalRepodataCache.GetOrRebuildAsync(
            key, LocalRepodataTtl,
            async rebuildCt => await build(rebuildCt),
            ct))!;
    }

    // ── GPG key ───────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /rpm/repodata/RPM-GPG-KEY or /rpm/repodata/repomd.xml.key — upstream GPG key.
    /// Both routes alias the same handler so <c>dnf</c> succeeds regardless of which path
    /// the upstream <c>.repo</c> file specifies for <c>gpgkey=</c>.
    /// </summary>
    [HttpGet("/rpm/repodata/RPM-GPG-KEY")]
    [HttpGet("/rpm/repodata/repomd.xml.key")]
    [HttpHead("/rpm/repodata/RPM-GPG-KEY")]
    [HttpHead("/rpm/repodata/repomd.xml.key")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GpgKey(CancellationToken ct)
    {
        if (_svc.Proxy is null)
        {
            return NotFound();
        }

        // Per-org upstream: top-priority configured rpm registry. Empty ⇒ proxying disabled.
        string orgId = CurrentTenantId();
        var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
        if (bases.Count == 0)
        {
            return NotFound();
        }

        byte[]? key;
        try
        {
            key = await _svc.Proxy.GetGpgKeyAsync(bases[0], ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex, "RPM proxy: GetGpgKeyAsync failed: {ExceptionType}", ex.GetType().Name);
            return NotFound();
        }

        return key is null ? NotFound() : File(key, "application/pgp-keys");
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

        int archDot = stem.LastIndexOf('.');
        if (archDot < 0)
        {
            return null;
        }

        string arch = stem[(archDot + 1)..];
        string nameVerRel = stem[..archDot];

        int relDash = nameVerRel.LastIndexOf('-');
        if (relDash < 0)
        {
            return null;
        }

        string release = nameVerRel[(relDash + 1)..];
        string nameVer = nameVerRel[..relDash];

        int verDash = nameVer.LastIndexOf('-');
        if (verDash < 0)
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
        }

        return (name, epoch, version, release, arch);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private ILogger<RpmController> Logger => HttpContext.RequestServices
        .GetRequiredService<ILogger<RpmController>>();

    /// <summary>
    /// Inserts <c>package_versions</c> + <c>rpm_metadata</c> rows for a proxied RPM.
    /// Idempotent — skips silently if the row already exists (concurrent-fetch race).
    /// </summary>
    private async Task CacheProxyPackageAsync(ProxyCachePackage p, CancellationToken ct)
    {
        var pkg = await _svc.Packages.GetOrCreateAsync(
            p.OrgId, "rpm", p.Resolution.Name, p.Resolution.Name.ToLowerInvariant(), isProxy: true, ct);

        await using var conn = await _svc.Db.OpenAsync(ct);
        string? existing = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE package_id = @pkgId AND version = @ver",
            new { pkgId = pkg.Id, ver = p.Ver });

        if (existing is not null)
        {
            return;
        }

        string versionId = Guid.NewGuid().ToString("N");
        // xtenant: pkg.Id from GetOrCreateAsync(orgId,...); inherits tenant scope.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @pkgId, @ver, @purl, @blobKey, @filename, @sizeBytes, @sha256, 'proxy')
            """,
            new
            {
                id = versionId,
                pkgId = pkg.Id,
                ver = p.Ver,
                purl = p.Purl,
                blobKey = p.DbBlobKey,
                filename = p.Filename,
                sizeBytes = p.SizeBytes,
                sha256 = p.Resolution.Sha256,
            });

        // rpm_metadata from primary.xml — no binary header parse needed for proxied packages.
        // xtenant: PK on package_version_id bound above.
        await conn.ExecuteAsync(
            """
            INSERT OR IGNORE INTO rpm_metadata
                (package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, rpm_license)
            VALUES (@pvId, @name, @epoch, @ver, @rel, @arch, @summary, @desc, @license)
            """,
            new
            {
                pvId = versionId,
                name = p.Nevra.Name,
                epoch = p.Nevra.Epoch,
                ver = p.Nevra.Version,
                rel = p.Nevra.Release,
                arch = p.Nevra.Arch,
                summary = p.Resolution.Summary,
                desc = p.Resolution.Description,
                license = p.Resolution.License,
            });
    }

    private sealed record ProxyCachePackage(
        string OrgId,
        string Filename,
        PackageResolution Resolution,
        (string Name, int Epoch, string Version, string Release, string Arch) Nevra,
        string Ver,
        string Purl,
        string DbBlobKey,
        long SizeBytes);

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
    TimeProvider Time,
    UpstreamClient? UpstreamClient = null,
    IRpmUpstreamProxy? Proxy = null);
