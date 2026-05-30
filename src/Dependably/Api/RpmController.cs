using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

/// <summary>
/// RPM repository surface (#100 + #102). Implements the <c>dnf</c>/<c>yum</c> contract:
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

    // ── Upload ────────────────────────────────────────────────────────────────

    /// <summary>PUT /o/{org}/rpm/upload — twine-style upload (body = .rpm bytes).</summary>
    [HttpPut("/rpm/upload")]
    [HttpPost("/rpm/upload")]
    [Authorize(AuthenticationSchemes = "Bearer," + Dependably.Security.TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishRpm)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(500 * 1024 * 1024)]
    public async Task<IActionResult> Upload(CancellationToken ct)
    {
        // Refuse uploads when upstream passthrough is active — a locally published package
        // would silently shadow upstream content and break dep-resolution for dnf clients.
        if (_svc.Proxy is { IsPassthroughMode: true })
            return Conflict(new ProblemDetails
            {
                Title = "Cannot publish under passthrough proxy mode",
                Detail = "This org is configured with Rpm:Upstream and Rpm:UpstreamMode=passthrough. " +
                         "Publishing would silently shadow upstream content. Switch Rpm:UpstreamMode " +
                         "to 'merged' (deferred) or unset Rpm:Upstream to enable hosted publishing.",
                Status = 409,
            });

        var orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms, ct);
        var bytes = ms.ToArray();
        if (bytes.Length < RpmArtifactValidator.MinimumValidSize)
            return BadRequest("RPM upload too small.");

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
        var sizeCap = await ResolveSizeCapAsync(orgId, ct);
        if (sizeCap is { } cap && bytes.LongLength > cap)
            return StatusCode(413, $"RPM upload exceeds size limit ({cap} bytes).");

        // NEVRA filename convention; dnf clients expect this exact shape.
        var filename = $"{header.Name}-{header.Version}-{header.Release}.{header.Arch}.rpm";
        var purlName = header.Name.ToLowerInvariant();
        var version = $"{header.Version}-{header.Release}";
        var purl = PurlNormalizer.Rpm(header.Name, header.Version, header.Release, header.Arch, header.Epoch ?? 0);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var blobKey = BlobKeys.Hosted(orgId, "rpm", purlName, version, filename);

        await _svc.BlobStore.Registry.PutAsync(blobKey, new MemoryStream(bytes), ct);

        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "rpm", header.Name, purlName, isProxy: false, ct);

        // xtenant: pkg.Id came from GetOrCreateAsync(orgId, ...); inserts against it
        // inherit tenant scope via the packages.org_id FK chain.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var existing = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = pkg.Id, version });

        string versionId = existing ?? Guid.NewGuid().ToString("N");
        if (existing is null)
        {
            // xtenant: pkg.Id came from GetOrCreateAsync(orgId, ...); inherits tenant scope.
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions
                    (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
                VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes, @sha256, 'uploaded')
                """,
                new
                {
                    id = versionId,
                    pkgId = pkg.Id,
                    version,
                    purl,
                    blobKey,
                    filename,
                    sizeBytes = (long)bytes.Length,
                    sha256,
                });
        }

        // Upsert rpm_metadata. xtenant: PK on package_version_id which we just bound to the tenant.
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

        // Mark the per-arch repodata as dirty so the rebuild service picks it up.
        // xtenant: composite PK (org_id, arch); explicit org_id parameter.
        await conn.ExecuteAsync(
            """
            INSERT INTO rpm_repodata_state (org_id, arch, dirty)
            VALUES (@orgId, @arch, 1)
            ON CONFLICT(org_id, arch) DO UPDATE SET dirty = 1
            """,
            new { orgId, arch = header.Arch });

        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "push",
            actorId: token.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        Response.Headers["X-Dependably-PURL"] = purl;
        return StatusCode(201);
    }

    // ── Download ──────────────────────────────────────────────────────────────

    /// <summary>GET /o/{org}/rpm/packages/{file} — download an RPM by NEVRA filename.</summary>
    [HttpGet("/rpm/packages/{file}")]
    [HttpHead("/rpm/packages/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Download(string file, CancellationToken ct)
    {
        var pathCheck = PathSafeValidator.Validate(file, "file");
        if (!pathCheck.IsValid) return BadRequest(pathCheck.Message);
        if (!file.EndsWith(".rpm", StringComparison.OrdinalIgnoreCase))
            return BadRequest("RPM filename must end with .rpm.");

        var orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var versionMatch = await _svc.Packages.FindVersionByBlobKeySuffixAsync(orgId, "rpm", file, ct);

        if (versionMatch is not null)
            return await ServePackageFromCacheAsync(orgId, file, versionMatch.Value, token, ct);

        // Cache MISS — attempt upstream proxy if configured.
        if (_svc.Proxy is null || _svc.UpstreamClient is null) return NotFound();
        if (settings is null || !settings.ProxyPassthroughEnabled) return NotFound();

        return await ProxyDownloadAsync(orgId, file, token, ct);
    }

    private async Task<IActionResult> ServePackageFromCacheAsync(
        string orgId, string file,
        (Package Package, PackageVersion Version) versionMatch,
        TokenRecord? token, CancellationToken ct)
    {
        var blobKey = BlobKeys.StoreKey(versionMatch.Version.BlobKey);
        var hitStore = versionMatch.Version.Origin == "proxy"
            ? _svc.BlobStore.Cache
            : _svc.BlobStore.Registry;
        var stream = await hitStore.GetAsync(blobKey, ct);
        if (stream is null) return NotFound();

        Response.Headers["X-Cache"] = "HIT";
        await _svc.Audit.LogActivityAsync(orgId, "rpm", versionMatch.Version.Purl, "download",
            token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(stream, "application/x-rpm", file);
    }

    private async Task<IActionResult> ProxyDownloadAsync(
        string orgId, string file, TokenRecord? token, CancellationToken ct)
    {
        // 1. Negative cache
        if (await _svc.Proxy!.IsNegativelyCachedAsync(file, ct)) return NotFound();

        // 2. Resolve package URL from primary.xml.gz
        var resolution = await TryResolveUpstreamPackageAsync(file, ct);
        if (resolution is null)
        {
            await _svc.Proxy.RecordNegativeAsync(file, ct);
            return NotFound();
        }

        // 3. Parse NEVRA from filename
        var nevra = ParseNevra(file);
        if (nevra is null) return NotFound();
        var (name, epoch, rpmVersion, release, arch) = nevra.Value;
        var ver = $"{rpmVersion}-{release}";
        var purl = PurlNormalizer.Rpm(name, rpmVersion, release, arch, epoch);
        var blobStoreKey = BlobKeys.Proxy(resolution.Sha256);

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
            return StatusCode(502, "Upstream checksum mismatch; package not served.");
        }

        // 5. Persist DB row (package_versions + rpm_metadata) on first fetch
        var dbBlobKey = $"proxy/{resolution.Sha256}/{file}"; // StoreKey strips the filename suffix
        // Use Content-Length if the stream knows it; otherwise fall back to 0 (updated async).
        var contentLength = body.CanSeek ? (int)body.Length : 0;
        await CacheProxyPackageAsync(
            new ProxyCachePackage(orgId, file, resolution, nevra.Value, ver, purl, dbBlobKey, contentLength),
            ct);

        Response.Headers["X-Cache"] = isHit ? "HIT" : "MISS";
        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "download",
            token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(body, "application/x-rpm", file);
    }

    private async Task<PackageResolution?> TryResolveUpstreamPackageAsync(string file, CancellationToken ct)
    {
        try
        {
            return await _svc.Proxy!.ResolvePackageUrlAsync(file, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            _logger.LogWarning(ex,
                "RPM proxy: ResolvePackageUrlAsync failed for {Filename}: {ExceptionType}",
                file, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// GET /o/{org}/rpm/Packages/{bucket}/{file} — download an RPM by the *nested*
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

    /// <summary>GET /o/{org}/rpm/repodata/{file} — repomd.xml or compressed XML docs.</summary>
    [HttpGet("/rpm/repodata/{file}")]
    [HttpHead("/rpm/repodata/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Repodata(string file, CancellationToken ct)
    {
        var pathCheck = PathSafeValidator.Validate(file, "file");
        if (!pathCheck.IsValid) return BadRequest(pathCheck.Message);

        var orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Passthrough mode: delegate repodata to upstream proxy.
        if (_svc.Proxy is { IsPassthroughMode: true } && settings!.ProxyPassthroughEnabled)
        {
            var passthrough = await TryServeRepodataFromUpstreamAsync(file, ct);
            if (passthrough is not null) return passthrough;
            // Fall through to local generation on null (unrecognised filename / upstream 404).
        }

        return await ServeRepodataLocallyAsync(orgId, file, ct);
    }

    private async Task<IActionResult?> TryServeRepodataFromUpstreamAsync(string file, CancellationToken ct)
    {
        var ifNoneMatch = Request.Headers.IfNoneMatch.FirstOrDefault();
        var ifModifiedSince = Request.Headers.IfModifiedSince.FirstOrDefault();

        RepodataResult? upstreamResult;
        try
        {
            upstreamResult = await _svc.Proxy!.GetRepodataAsync(file, ifNoneMatch, ifModifiedSince, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            _logger.LogWarning(ex,
                "RPM proxy: GetRepodataAsync failed for {Filename}: {ExceptionType}",
                file, ex.GetType().Name);
            return null;
        }

        if (upstreamResult is null) return null;
        if (upstreamResult.NotModified) return StatusCode(304);

        if (upstreamResult.ETag is not null)
            Response.Headers.ETag = upstreamResult.ETag;
        if (upstreamResult.LastModified is not null)
            Response.Headers.LastModified = upstreamResult.LastModified;

        // Honor range requests for hash-prefixed (zchunk-capable) metadata files.
        if (RpmUpstreamProxy.IsHashPrefixedFilename(file) && Request.Headers.Range.Count > 0)
            Response.Headers.AcceptRanges = "bytes";

        return File(upstreamResult.Body, upstreamResult.ContentType);
    }

    private async Task<IActionResult> ServeRepodataLocallyAsync(string orgId, string file, CancellationToken ct)
    {
        if (file.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase))
        {
            var primary = await _svc.Repodata.BuildPrimaryAsync(orgId, ct);
            var primaryGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(primary));
            var repomd = RpmRepodataService.BuildRepomd(primaryGz);
            return File(System.Text.Encoding.UTF8.GetBytes(repomd), "application/xml", "repomd.xml");
        }
        if (file.Equals("primary.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            var primary = await _svc.Repodata.BuildPrimaryAsync(orgId, ct);
            return File(RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(primary)),
                "application/x-gzip", "primary.xml.gz");
        }

        return NotFound();
    }

    // ── GPG key ───────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /o/{org}/rpm/repodata/RPM-GPG-KEY or .../repomd.xml.key — upstream GPG key.
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
        if (_svc.Proxy is null) return NotFound();

        byte[]? key;
        try
        {
            key = await _svc.Proxy.GetGpgKeyAsync(ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            _logger.LogWarning(ex, "RPM proxy: GetGpgKeyAsync failed: {ExceptionType}", ex.GetType().Name);
            return NotFound();
        }

        if (key is null) return NotFound();
        return File(key, "application/pgp-keys");
    }

    // ── NEVRA parsing ─────────────────────────────────────────────────────────

    /// <summary>
    /// Parses a NEVRA filename <c>{name}-{epoch:version}-{release}.{arch}.rpm</c>.
    /// Epoch is optional in the filename (defaults to 0 when absent).
    /// Returns null for malformed filenames.
    /// </summary>
    internal static (string Name, int Epoch, string Version, string Release, string Arch)? ParseNevra(string filename)
    {
        if (!filename.EndsWith(".rpm", StringComparison.OrdinalIgnoreCase)) return null;
        var stem = filename[..^4];

        var archDot = stem.LastIndexOf('.');
        if (archDot < 0) return null;
        var arch = stem[(archDot + 1)..];
        var nameVerRel = stem[..archDot];

        var relDash = nameVerRel.LastIndexOf('-');
        if (relDash < 0) return null;
        var release = nameVerRel[(relDash + 1)..];
        var nameVer = nameVerRel[..relDash];

        var verDash = nameVer.LastIndexOf('-');
        if (verDash < 0) return null;
        var version = nameVer[(verDash + 1)..];
        var name = nameVer[..verDash];

        int epoch = 0;
        var colon = version.IndexOf(':');
        if (colon > 0 && int.TryParse(version[..colon], out var e))
        {
            epoch = e;
            version = version[(colon + 1)..];
        }

        return (name, epoch, version, release, arch);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private ILogger<RpmController> _logger => HttpContext.RequestServices
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
        var existing = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE package_id = @pkgId AND version = @ver",
            new { pkgId = pkg.Id, ver = p.Ver });

        if (existing is not null) return;

        var versionId = Guid.NewGuid().ToString("N");
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
        if (settings is null) return null;
        // xtenant: keyed by org_id directly.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var rpmCap = await conn.ExecuteScalarAsync<long?>(
            "SELECT max_upload_bytes_rpm FROM org_settings WHERE org_id = @orgId",
            new { orgId });
        return rpmCap ?? settings.MaxUploadBytes;
    }
}

/// <summary>Scoped DI bundle for the RPM controller (#100 + #102).</summary>
public sealed record RpmControllerServices(
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    TieredBlobStorage BlobStore,
    IMetadataStore Db,
    RpmRepodataService Repodata,
    UpstreamClient? UpstreamClient = null,
    IRpmUpstreamProxy? Proxy = null);
