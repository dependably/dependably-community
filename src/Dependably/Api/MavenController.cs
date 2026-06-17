using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;

namespace Dependably.Api;

/// <summary>
/// Maven 2/3 repository surface — local serving and upstream proxy. Implements the file-tree
/// contract Gradle / Maven clients expect — every artifact lives at
/// <c>/{groupId-as-path}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{extension}</c>
/// — plus the <c>maven-metadata.xml</c> documents that drive version resolution and
/// SNAPSHOT lookup.
///
/// Proxy: on a local cache miss the controller falls through to the configured upstream
/// (default Maven Central). Locally published artifacts always win over upstream — dependency
/// confusion protection per spec §11. GroupId prefixes reserved in the shared
/// <c>reserved_namespace</c> table (ecosystem 'maven') never consult upstream. SNAPSHOT
/// artifacts resolve through upstream version-level metadata before the fetch so the
/// timestamped filename is stored consistently in <c>maven_version_files</c>.
///
/// Maven differs from npm/PyPI/NuGet in that a single coordinate can carry multiple files
/// (JAR + POM + sources JAR + javadoc + checksum sidecars). The <c>package_versions</c>
/// row stays one-per-version; <c>maven_version_files</c> tracks the per-file blob mapping
/// so a GET for any filename suffix resolves to the right blob.
/// </summary>
// Maven sidecar checksums require MD5 and SHA-1 for client compatibility — not used for
// security decisions, just to match what mvn / gradle expect.
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0006",
    Justification = "MD5/SHA-1 used only for Maven sidecar compatibility, not authentication.")]
[ApiController]
public sealed class MavenController : OrgScopedControllerBase
{
    // Proxy-merged metadata may include upstream versions; short TTL so new upstream releases
    // propagate. Local-only metadata is stable; a longer TTL is appropriate. These bound the
    // in-memory rendered-body cache and match the npm/PyPI/NuGet metadata-cache TTLs.
    private static readonly TimeSpan MetadataProxyTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MetadataLocalTtl = TimeSpan.FromMinutes(10);

    // SHA-256 hex digest prefix length used for ETags (16 hex chars = 64 bits of entropy).
    private const int ETagHexPrefixLength = 16;

    // Default maximum OSV score tolerance when the org setting is absent.
    private const double DefaultMaxOsvScoreTolerance = 10.0;

    // Route-level hard ceiling for Maven artifact uploads (500 MiB).
    private const long MavenUploadSizeLimitBytes = 500L * 1024 * 1024;

    private readonly MavenControllerServices _svc;

    public MavenController(MavenControllerServices svc) => _svc = svc;

    /// <summary>GET /maven/{**path} — artifact, sidecar, or metadata download.</summary>
    [HttpGet("/maven/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Download(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return NotFound();
        }

        var coords = MavenPathParser.Parse(path);
        if (coords is null)
        {
            return BadRequest("Invalid Maven path.");
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);

        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        return coords.IsMetadata ? await ServeMetadataAsync(orgId, coords, ct) : await ServeArtifactAsync(orgId, coords, settings, token, ct);
    }

    /// <summary>HEAD /maven/{**path} — existence check.</summary>
    [HttpHead("/maven/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Head(string path, CancellationToken ct)
    {
        // Reuse the GET implementation, then drop the body. Stays consistent with the
        // existing-not-existing answer the client cares about; the small extra work to
        // compute checksum sidecars on-the-fly is fine on the HEAD path.
        var result = await Download(path, ct);
        if (result is FileContentResult fc)
        {
            return new ContentResult { StatusCode = StatusCodes.Status200OK, ContentType = fc.ContentType };
        }

        if (result is FileStreamResult fs)
        {
            fs.FileStream.Dispose();
            return new ContentResult { StatusCode = StatusCodes.Status200OK, ContentType = fs.ContentType };
        }
        return result;
    }

    /// <summary>PUT /maven/{**path} — publish an artifact, sidecar, or metadata file.</summary>
    [HttpPut("/maven/{**path}")]
    [Authorize(AuthenticationSchemes = "Bearer," + Dependably.Security.TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishMaven)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(MavenUploadSizeLimitBytes)]
    public async Task<IActionResult> Publish(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return BadRequest();
        }

        var coords = MavenPathParser.Parse(path);
        if (coords is null)
        {
            return BadRequest("Invalid Maven path.");
        }

        if (coords.Version is null && !coords.IsMetadata)
        {
            return BadRequest("Maven artifact publishes require a version segment.");
        }

        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Path-traversal / control-character defence: reject anything PathSafeValidator
        // wouldn't let into a blob key. Maven's slashed group form lands as path
        // segments so we validate each one separately.
        foreach (string seg in path.Split('/'))
        {
            var r = PathSafeValidator.Validate(seg, "path");
            if (!r.IsValid)
            {
                return BadRequest(r.Message);
            }
        }

        // Buffer the request body. Maven uploads are typically small — JARs a few MB,
        // POMs a few KB. The 500 MB ceiling above is the absolute cap.
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms, ct);
        byte[] bytes = ms.ToArray();

        // Per-tenant Maven cap → instance Maven cap → instance global cap → reject.
        long? sizeCap = await ResolveSizeCapAsync(orgId, ct);
        if (sizeCap is { } cap && bytes.LongLength > cap)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge, $"Maven upload exceeds size limit ({cap} bytes).");
        }

        // Metadata uploads (maven-metadata.xml) are deploy-time bookkeeping the client
        // computes locally. We accept and discard — the metadata we serve is generated
        // server-side from package_versions / maven_version_files so trusting client
        // input here would let a misbehaving client poison the index for everyone.
        return coords.IsMetadata ? StatusCode(StatusCodes.Status201Created) : await StoreFileAsync(orgId, coords!, bytes, token, ct);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task<IActionResult> ServeArtifactAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // Sidecar lookup: the controller resolves to the primary artifact's row in
        // maven_version_files; the sidecar's bytes are computed from the stored
        // checksum_* columns. This means we don't have to store sidecars as their own
        // blobs and the answer stays consistent even when the client uploaded only the
        // primary file.
        string primaryFilename = coords.IsChecksumSidecar
            ? MavenPathParser.PrimaryFilename(coords.Filename)
            : coords.Filename;

        // Determine whether this is a literal SNAPSHOT request (filename uses the
        // "-SNAPSHOT" literal, not a timestamped form like "lib-1.0-20240101.120000-3.jar").
        // Literal SNAPSHOT requests require a freshness re-check on every cache hit because
        // SNAPSHOT artifacts are mutable — upstream may publish a newer timestamped build
        // under the same -SNAPSHOT version at any time.
        bool isLiteralSnapshot = coords.IsSnapshot && coords.SnapshotTimestamp is null
            && coords.Extension is not null && !coords.IsMetadata;

        await using var conn = await _svc.Db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<MavenFileRow>(
            """
            SELECT mvf.id AS Id, mvf.package_version_id AS PackageVersionId,
                   mvf.filename AS Filename,
                   mvf.extension AS Extension, mvf.blob_key AS BlobKey,
                   mvf.checksum_sha256 AS ChecksumSha256,
                   mvf.checksum_sha1 AS ChecksumSha1, mvf.checksum_md5 AS ChecksumMd5,
                   mvf.origin AS Origin,
                   pv.purl AS Purl, pv.manual_block_state AS ManualBlockState,
                   pv.vuln_checked_at AS VulnCheckedAt, pv.published_at AS PublishedAt,
                   pv.deprecated AS Deprecated
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName
              AND pv.version = @version
              AND mvf.filename = @filename
            LIMIT 1
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = primaryFilename,
            });

        // ── Literal SNAPSHOT freshness check ──────────────────────────────────
        // Proxy rows under the literal -SNAPSHOT name may point at a stale timestamped build.
        // Re-resolve from upstream metadata; when a newer build exists, fetch and update the
        // alias. Uploaded SNAPSHOTs are pinned locally and skip this block entirely.
        if (isLiteralSnapshot && row is not null && row.Origin != "uploaded" && _svc.Upstream is not null)
        {
            var freshnessResult = await CheckSnapshotFreshnessAsync(orgId, coords, conn, settings, token, ct);
            if (freshnessResult is not null)
            {
                return freshnessResult;
            }
        }

        // ── Cache hit: serve from local blob store ─────────────────────────────
        if (row is not null)
        {
            return await ServeCachedArtifactAsync(orgId, coords, settings, token, row, ct);
        }

        // ── Cache miss: proxy upstream ──────────────────────────────────
        return await ProxyFetchAndCacheAsync(orgId, coords, settings, token, ct);
    }

    // Checks whether the literal SNAPSHOT alias row is still current by re-resolving the
    // current timestamped filename from upstream metadata. Returns non-null when the proxy
    // should be called to fetch a newer build; returns null when the cached alias is current
    // or when upstream metadata is unreachable (in which case the stale alias is served).
    private async Task<IActionResult?> CheckSnapshotFreshnessAsync(
        string orgId, MavenCoordinates coords, System.Data.Common.DbConnection conn,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        string? currentTimestampedFilename = await ResolveCurrentSnapshotFilenameAsync(orgId, coords, ct);
        if (currentTimestampedFilename is null)
        {
            // Upstream metadata is unreachable — serve the stale alias as a fallback.
            _svc.Log.LogWarning(
                "Maven SNAPSHOT upstream metadata unreachable for {Purl}; serving cached alias as stale fallback",
                PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version ?? "unknown"));
            return null;
        }

        // Check whether the resolved timestamped artifact is already in cache.
        bool timestampedIsCached = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(1) FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName
              AND pv.version = @version
              AND mvf.filename = @filename
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = currentTimestampedFilename,
            }) > 0;

        // Upstream has a newer build — fetch and update the alias.
        if (!timestampedIsCached)
        {
            return await ProxyFetchAndCacheAsync(orgId, coords, settings, token, ct);
        }

        // Resolved timestamped build is already cached — the alias is current.
        return null;
    }

    // Auth + block-gate checks for a cached Maven artifact row, then dispatches to the
    // checksum-sidecar or primary-file serve path.
    private async Task<IActionResult> ServeCachedArtifactAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token,
        MavenFileRow row, CancellationToken ct)
    {
        // Per-version origin gate: uploaded artifacts require a token carrying
        // ReadArtifact even when AnonymousPull is enabled. Proxy-cached artifacts
        // remain anonymously servable under AnonymousPull. Mirrors the per-origin
        // routing PyPI/npm/NuGet apply on their cache-hit paths.
        if (row.Origin == "uploaded")
        {
            if (token is null)
            {
                Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return Unauthorized();
            }
            if (!token.HasCapability(Capabilities.ReadArtifact))
            {
                return Forbid();
            }
        }
        else if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Vulnerability / manual-block gate runs before we serve cached bytes —
        // including the checksum sidecar, so a blocked artifact's hashes don't leak
        // either. Mirrors the inline gate PyPI/npm/NuGet run on their cache-hit paths.
        if (await _svc.BlockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "maven", row.Purl, row.PackageVersionId,
                    row.ManualBlockState, row.VulnCheckedAt,
                    token?.UserId, settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScoreTolerance,
                    HttpContext.GetNormalizedRemoteIp(),
                    MinReleaseAgeHours: settings?.MinReleaseAgeHours,
                    PublishedAt: row.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: row.Deprecated,
                    BlockDeprecatedMode: settings?.BlockDeprecated,
                    BlockMaliciousMode: settings?.BlockMalicious,
                    BlockKevMode: settings?.BlockKev,
                    MaxEpssTolerance: settings?.MaxEpssTolerance), ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        Response.Headers["X-Cache"] = "HIT";

        return coords.IsChecksumSidecar
            ? await ServeChecksumSidecarAsync(coords, row, ct)
            : await ServePrimaryFromCacheAsync(orgId, coords, token?.UserId, row, ct);
    }

    private async Task<IActionResult> ServeChecksumSidecarAsync(
        MavenCoordinates coords, MavenFileRow row, CancellationToken ct)
    {
        string? hex = coords.ChecksumAlgorithm switch
        {
            "sha512" => null, // not stored; computed on the fly below
            "sha256" => row.ChecksumSha256,
            "sha1" => row.ChecksumSha1,
            "md5" => row.ChecksumMd5,
            _ => null,
        };
        if (hex is null && coords.ChecksumAlgorithm is { } algo)
        {
            // Compute from the primary artifact's bytes — costs one blob read; cached
            // results would be nice but live in a follow-up if it shows up in profiles.
            var blob = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
            if (blob is null)
            {
                return NotFound();
            }

            hex = await ComputeChecksumAsync(blob, algo, ct);
        }

        return hex is null
            ? NotFound()
            : new ContentResult
            {
                Content = hex,
                ContentType = "text/plain",
                StatusCode = StatusCodes.Status200OK,
            };
    }

    private async Task<IActionResult> ServePrimaryFromCacheAsync(
        string orgId, MavenCoordinates coords, string? actorId, MavenFileRow row, CancellationToken ct)
    {
        var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version ?? "unknown");
        if (row.ChecksumSha256 is not null)
        {
            Response.Headers.ETag = $"\"sha256:{row.ChecksumSha256}\"";
            Response.Headers.CacheControl = coords.IsSnapshot
                ? "private, max-age=60"
                : "private, max-age=31536000, immutable";
        }
        await _svc.Audit.LogActivityAsync(
            orgId, "maven", purl,
            "download", actorId,
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);
        await _svc.Packages.IncrementDownloadCountByPurlAsync(purl, ct);

        return File(stream, ContentTypeFor(coords.Extension), coords.Filename);
    }

    /// <summary>
    /// Handles a Maven artifact cache miss by fetching from the org's configured upstream
    /// registries in priority order (first reachable wins); an empty list disables proxying.
    /// Dep-confusion protection: reserved groupId prefixes never consult upstream.
    ///
    /// SNAPSHOT versions: resolves the timestamped artifact filename via the version-level
    /// <c>maven-metadata.xml</c> before proxying, so the stored filename and cached key match
    /// what the upstream actually served.
    ///
    /// Sidecar-before-primary: when a checksum sidecar is requested for a primary not yet
    /// in the local cache, fetches and caches the primary first, then serves the sidecar from
    /// the stored checksum columns — closing the deferred recursive-primary-fetch path.
    /// </summary>
    private async Task<IActionResult> ProxyFetchAndCacheAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // No upstream service registered — treat as local-only.
        if (_svc.Upstream is null)
        {
            return NotFound();
        }

        // Resolve the org's priority-ordered upstream registries. Empty ⇒ proxying disabled.
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        if (bases.Count == 0)
        {
            return NotFound();
        }

        // Dep-confusion guard: locally-reserved prefixes never go upstream.
        if (await _svc.ReservedNamespaces.IsReservedAsync(orgId, "maven", coords.GroupId, ct))
        {
            return NotFound();
        }

        // For sidecar-before-primary: fetch and cache the primary first, then serve the
        // sidecar from its stored checksum columns.
        if (coords.IsChecksumSidecar)
        {
            return await ProxySidecarViaPrimaryAsync(orgId, coords, settings, token, ct);
        }

        // Build the upstream path: convert groupId dots to slashes for the URL.
        string groupPath = coords.GroupId.Replace('.', '/');

        // SNAPSHOT versions: resolve the timestamped artifact filename via the upstream
        // version-level maven-metadata.xml. Falls back to the -SNAPSHOT literal when no
        // timestamped name is resolvable (some upstream repos serve the literal directly).
        var resolvedCoords = coords.IsSnapshot
            ? await ResolveSnapshotCoordsAsync(coords, groupPath, bases, ct)
            : coords;

        string upstreamPath = $"{groupPath}/{resolvedCoords.ArtifactId}/{resolvedCoords.Version}/{resolvedCoords.Filename}";

        string? purlForLog = resolvedCoords.Version is not null
            ? PurlNormalizer.Maven(resolvedCoords.GroupId, resolvedCoords.ArtifactId, resolvedCoords.Version)
            : null;

        // Walk the configured upstreams in priority order; the first that yields the
        // artifact wins. A single configured registry behaves identically to before.
        MavenArtifactFetchResult? result = null;
        foreach (string upstreamBase in bases)
        {
            try
            {
                result = await _svc.Upstream.FetchArtifactAsync(
                    upstreamBase, upstreamPath, ct, orgId: orgId, purl: purlForLog);
            }
            catch (ChecksumException)
            {
                return StatusCode(StatusCodes.Status502BadGateway);
            }

            if (result is not null)
            {
                break;
            }
        }

        return result is null
            ? NotFound()
            : await RecordScanAndServeAsync(orgId, resolvedCoords, result, settings, token, ct);
    }

    // Records the artifact in the proxy pipeline (package_versions row, OSV scan, block gate)
    // and serves the artifact bytes. Returns 403 when the gate blocks, or a File result.
    private async Task<IActionResult> RecordScanAndServeAsync(
        string orgId, MavenCoordinates resolvedCoords, MavenArtifactFetchResult result,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        string purl = PurlNormalizer.Maven(resolvedCoords.GroupId, resolvedCoords.ArtifactId, resolvedCoords.Version!);

        // Run the shared proxy pipeline: record the package_versions row, synchronously
        // scan OSV, and evaluate the block gate so a vulnerable artifact is refused on the
        // very first fetch — the same record→scan→gate sequence PyPI/npm/NuGet use. The
        // blob already lives at result.BlobKey (UpstreamClient hash-and-staged it during
        // FetchArtifactAsync); OpenAsync is only consulted for licence extraction or a
        // non-sha256 re-verify, neither of which Maven requests, so it stays unused here.
        var blob = new BlobHandle(result.BlobKey, result.Sha256, result.Bytes.LongLength,
            async openCt => await _svc.Blobs.GetAsync(BlobKeys.StoreKey(result.BlobKey), openCt)
                ?? (Stream)new MemoryStream(result.Bytes, writable: false));

        var fetch = await _svc.ProxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: orgId, Ecosystem: "maven",
            PackageName: resolvedCoords.PackageName, PurlName: resolvedCoords.PackageName,
            Version: resolvedCoords.Version!, Purl: purl, File: resolvedCoords.Filename, Blob: blob,
            ExtractLicenses: null,
            UserId: token?.UserId,
            ActorKind: token?.ActorKind,
            SourceIp: HttpContext.GetNormalizedRemoteIp(),
            MaxOsvScoreTolerance: settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScoreTolerance,
            CacheAccess: null,
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            Sha1Hex: result.Sha1,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            MaxEpssTolerance: settings?.MaxEpssTolerance), ct);

        if (fetch.Decision == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // The shared pipeline owns package_versions + the first_fetch activity; Maven owns
        // its per-file mapping. Record it only when the gate allowed the artifact — a
        // refused version never gets a serve-row, and a later attempt re-fetches + re-gates.
        if (fetch.VersionId is not null)
        {
            await RecordMavenFileAsync(fetch.VersionId, resolvedCoords, result, ct);
        }

        Response.Headers["X-Cache"] = "MISS";
        return File(result.Bytes, ContentTypeFor(resolvedCoords.Extension), resolvedCoords.Filename);
    }

    // Sidecar-before-primary path: the primary artifact is fetched and cached first (via a
    // recursive ProxyFetchAndCacheAsync call), then the sidecar is served from the checksum
    // columns of the newly-cached primary row. The block gate and scan run exactly once,
    // on the primary, and are not re-run for the sidecar.
    private async Task<IActionResult> ProxySidecarViaPrimaryAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        string primaryFilename = MavenPathParser.PrimaryFilename(coords.Filename);
        var primaryCoords = coords with { Filename = primaryFilename, IsChecksumSidecar = false, ChecksumAlgorithm = null };
        var primaryResult = await ProxyFetchAndCacheAsync(orgId, primaryCoords, settings, token, ct);

        // If the primary fetch failed (e.g. 404, 403, 502) propagate without serving the sidecar.
        if (primaryResult is not FileContentResult and not FileStreamResult)
        {
            return primaryResult;
        }

        // Primary is now cached — re-query the DB row so we can serve the sidecar from
        // the stored checksum columns. The row was written by the recursive call above.
        await using var sidecarConn = await _svc.Db.OpenAsync(ct);
        var row = await sidecarConn.QuerySingleOrDefaultAsync<MavenFileRow>(
            """
            SELECT mvf.id AS Id, mvf.package_version_id AS PackageVersionId,
                   mvf.filename AS Filename,
                   mvf.extension AS Extension, mvf.blob_key AS BlobKey,
                   mvf.checksum_sha256 AS ChecksumSha256,
                   mvf.checksum_sha1 AS ChecksumSha1, mvf.checksum_md5 AS ChecksumMd5,
                   mvf.origin AS Origin,
                   pv.purl AS Purl, pv.manual_block_state AS ManualBlockState,
                   pv.vuln_checked_at AS VulnCheckedAt, pv.published_at AS PublishedAt,
                   pv.deprecated AS Deprecated
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName
              AND pv.version = @version
              AND mvf.filename = @filename
            LIMIT 1
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = primaryFilename,
            });

        return row is null
            ? NotFound()
            : await ServeChecksumSidecarAsync(coords, row, ct);
    }

    /// <summary>
    /// Records the <c>maven_version_files</c> row for a proxied artifact against the
    /// <c>package_versions</c> id the shared proxy pipeline already created. Idempotent on
    /// (package_version_id, filename) so a second file of the same coordinate — or a
    /// concurrent first-fetch — doesn't collide.
    ///
    /// For SNAPSHOT artifacts resolved to a timestamped filename, an alias row under the
    /// literal <c>-SNAPSHOT</c> filename is also written so clients requesting either
    /// the timestamped or the literal form both hit the cache on a subsequent request.
    /// </summary>
    private async Task RecordMavenFileAsync(
        string versionId, MavenCoordinates coords, MavenArtifactFetchResult result, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);

        // xtenant: maven_version_files FK chain: package_version_id → package_versions → packages.org_id.
        // versionId came from ProxyFetchService's GetOrCreate(orgId,...) chain, so it is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'proxy')
            ON CONFLICT(package_version_id, filename) DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename = coords.Filename,
                classifier = coords.Classifier,
                extension = coords.Extension ?? "",
                blobKey = result.BlobKey,
                sizeBytes = (long)result.Bytes.Length,
                sha256 = result.Sha256,
                sha1 = result.Sha1,
                md5 = result.Md5,
            });

        // For SNAPSHOT artifacts where the filename was resolved to a timestamped form
        // (e.g. lib-1.0-20240101.120000-3.jar), also write an alias row under the
        // literal -SNAPSHOT filename (e.g. lib-1.0-SNAPSHOT.jar). The alias uses
        // DO UPDATE so that when upstream publishes a newer build the alias is refreshed
        // to point at the new blob_key and checksums. The freshness re-check in
        // ServeArtifactAsync guarantees literal SNAPSHOT requests always re-resolve the
        // current timestamped build before accepting a cache hit, so the alias is kept
        // current and the literal path never serves a stale build.
        if (coords.IsSnapshot && coords.Extension is not null)
        {
            string classifierPart = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string literalFilename = $"{coords.ArtifactId}-{coords.Version}{classifierPart}.{coords.Extension}";
            if (!string.Equals(literalFilename, coords.Filename, StringComparison.Ordinal))
            {
                // xtenant: same FK chain as the primary insert above; same versionId.
                await conn.ExecuteAsync(
                    """
                    INSERT INTO maven_version_files
                        (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                         checksum_sha256, checksum_sha1, checksum_md5, origin)
                    VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                            @sha256, @sha1, @md5, 'proxy')
                    ON CONFLICT(package_version_id, filename) DO UPDATE SET
                        blob_key         = excluded.blob_key,
                        size_bytes       = excluded.size_bytes,
                        checksum_sha256  = excluded.checksum_sha256,
                        checksum_sha1    = excluded.checksum_sha1,
                        checksum_md5     = excluded.checksum_md5
                    """,
                    new
                    {
                        id = Guid.NewGuid().ToString("N"),
                        pvId = versionId,
                        filename = literalFilename,
                        classifier = coords.Classifier,
                        extension = coords.Extension,
                        blobKey = result.BlobKey,
                        sizeBytes = (long)result.Bytes.Length,
                        sha256 = result.Sha256,
                        sha1 = result.Sha1,
                        md5 = result.Md5,
                    });
            }
        }
    }

    // Resolves the SNAPSHOT coordinates to a timestamped filename by fetching the upstream
    // version-level maven-metadata.xml. Prefers the explicit snapshotVersions list (Maven 3);
    // falls back to the top-level timestamp + buildNumber (Maven 2). Returns the original
    // coords unchanged when metadata is unreachable or no timestamped name resolves.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<MavenCoordinates> ResolveSnapshotCoordsAsync(
        MavenCoordinates coords, string groupPath, IReadOnlyList<string> bases, CancellationToken ct)
    {
        MavenSnapshotMetadata? snapMeta = null;
        foreach (string upstreamBase in bases)
        {
            snapMeta = await _svc.Upstream!.FetchSnapshotMetadataAsync(
                upstreamBase, groupPath, coords.ArtifactId, coords.Version!, ct);
            if (snapMeta is not null)
            {
                break;
            }
        }

        if (snapMeta is null || coords.Extension is null)
        {
            return coords;
        }

        // Prefer the explicit snapshotVersions list (Maven 3 metadata).
        string? timestampedValue = snapMeta.ResolveTimestampedValue(coords.Extension, coords.Classifier);
        if (timestampedValue is not null)
        {
            string classifier = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string timestampedFilename = $"{coords.ArtifactId}-{timestampedValue}{classifier}.{coords.Extension}";
            return coords with { Filename = timestampedFilename };
        }

        // Fall back to the top-level <snapshot> timestamp + buildNumber (Maven 2 style).
        if (snapMeta.Timestamp is not null && snapMeta.BuildNumber is not null)
        {
            string classifier = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string baseVer = coords.Version![..^"-SNAPSHOT".Length];
            string tsFilename = $"{coords.ArtifactId}-{baseVer}-{snapMeta.Timestamp}-{snapMeta.BuildNumber}{classifier}.{coords.Extension}";
            return coords with { Filename = tsFilename };
        }

        return coords;
    }

    /// <summary>
    /// Resolves the current upstream timestamped filename for a literal SNAPSHOT coordinate
    /// (e.g. <c>lib-1.0-SNAPSHOT.jar</c>) by fetching the version-level
    /// <c>maven-metadata.xml</c> from the org's configured upstreams. Returns the resolved
    /// timestamped filename (e.g. <c>lib-1.0-20240101.120000-3.jar</c>), or null when
    /// upstream metadata is unreachable or does not contain a matching entry.
    /// </summary>
    private async Task<string?> ResolveCurrentSnapshotFilenameAsync(
        string orgId, MavenCoordinates coords, CancellationToken ct)
    {
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        if (bases.Count == 0 || coords.Extension is null)
        {
            return null;
        }

        string groupPath = coords.GroupId.Replace('.', '/');
        MavenSnapshotMetadata? snapMeta = null;
        foreach (string upstreamBase in bases)
        {
            snapMeta = await _svc.Upstream.FetchSnapshotMetadataAsync(
                upstreamBase, groupPath, coords.ArtifactId, coords.Version!, ct);
            if (snapMeta is not null)
            {
                break;
            }
        }

        if (snapMeta is null)
        {
            return null;
        }

        // Prefer the explicit snapshotVersions list (Maven 3 metadata).
        string? timestampedValue = snapMeta.ResolveTimestampedValue(coords.Extension, coords.Classifier);
        if (timestampedValue is not null)
        {
            string classifierPart = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            return $"{coords.ArtifactId}-{timestampedValue}{classifierPart}.{coords.Extension}";
        }

        // Fall back to the top-level <snapshot> timestamp + buildNumber (Maven 2 style).
        if (snapMeta.Timestamp is not null && snapMeta.BuildNumber is not null)
        {
            string classifierPart = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string baseVer = coords.Version![..^"-SNAPSHOT".Length];
            return $"{coords.ArtifactId}-{baseVer}-{snapMeta.Timestamp}-{snapMeta.BuildNumber}{classifierPart}.{coords.Extension}";
        }

        return null;
    }

    private async Task<IActionResult> ServeMetadataAsync(
        string orgId, MavenCoordinates coords, CancellationToken ct)
    {
        var cacheKey = new MavenMetadataKey(orgId, coords.GroupId, coords.ArtifactId);

        // Decide proxy-vs-local up front from the cheap checks: a configured upstream registry
        // and a non-reserved groupId. This drives both the in-memory cache TTL and the HTTP
        // Cache-Control header. On a cache HIT the rebuild below is skipped, so the only work
        // these incur is a registry resolve + reserved-namespace lookup (DB/registry reads,
        // not the upstream HTTP fetch that the cache exists to avoid).
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        bool useUpstream = _svc.Upstream is not null &&
            bases.Count > 0 &&
            !await _svc.ReservedNamespaces.IsReservedAsync(orgId, "maven", coords.GroupId, ct);
        var ttl = useUpstream ? MetadataProxyTtl : MetadataLocalTtl;

        // Both the metadata response and the checksum sidecar must read the SAME rendered bytes —
        // the sidecar hashes the document we serve. Producing the body once through the cache
        // guarantees the .sha1/.md5 can't diverge from the served XML.
        byte[]? bodyBytes = await _svc.MetadataCache.GetOrRebuildAsync(
            cacheKey, ttl,
            rebuildCt => BuildMavenMetadataBytesAsync(orgId, coords, bases, useUpstream, rebuildCt),
            ct);

        if (bodyBytes is null)
        {
            return NotFound();
        }

        if (coords.IsChecksumSidecar)
        {
            // Hash the SAME cached bytes the metadata path serves.
            string hex = ComputeHex(coords.ChecksumAlgorithm!, bodyBytes);
            return new ContentResult
            {
                Content = hex,
                ContentType = "text/plain",
                StatusCode = StatusCodes.Status200OK,
            };
        }

        string metaETag = ComputeETagFromBytes(bodyBytes);
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == metaETag)
        {
            Response.Headers.ETag = metaETag;
            return StatusCode(StatusCodes.Status304NotModified);
        }
        Response.Headers.ETag = metaETag;
        // HTTP cache header (distinct from the in-memory TTL): proxy-merged responses may include
        // upstream versions, so a short max-age; local-only responses are stable, so longer.
        Response.Headers.CacheControl = useUpstream
            ? "private, max-age=60"
            : "private, max-age=300";
        return Content(Encoding.UTF8.GetString(bodyBytes), "application/xml", Encoding.UTF8);
    }

    // Builds the maven-metadata.xml bytes from local DB rows merged with upstream versions.
    // Returns null when the version list is empty (caller surfaces as 404).
    // Used as the GetOrRebuildAsync factory inside ServeMetadataAsync.
    private async Task<byte[]?> BuildMavenMetadataBytesAsync(
        string orgId, MavenCoordinates coords, IReadOnlyList<string> bases,
        bool useUpstream, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);
        var localRows = (await conn.QueryAsync<(string Version, string CreatedAt)>(
            """
            SELECT pv.version, pv.created_at
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven' AND p.purl_name = @purlName
            ORDER BY pv.created_at ASC
            """,
            new { orgId, purlName = coords.PackageName })).ToList();
        var localVersions = localRows.Select(r => r.Version).ToList();

        // lastUpdated comes from the newest local publish, not the wall clock — the metadata
        // body must be byte-stable for a given version set so the ETag honours If-None-Match
        // and the generated checksum sidecars match the document clients fetched.
        DateTimeOffset? lastUpdated = localRows.Count > 0
            ? DateTimeOffset.Parse(
                localRows[^1].CreatedAt, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
            : null;

        // Merge upstream versions when proxying is live for this coordinate. An empty
        // registry list (proxying disabled) or a reserved groupId leaves it local-only.
        var mergedVersions = localVersions;
        if (useUpstream)
        {
            string groupPath = coords.GroupId.Replace('.', '/');
            string artifactPath = $"{groupPath}/{coords.ArtifactId}";

            // Walk upstreams in priority order; the first that returns versions wins.
            foreach (string upstreamBase in bases)
            {
                var upstreamVersions = await _svc.Upstream!.FetchUpstreamVersionsAsync(upstreamBase, artifactPath, ct);
                if (upstreamVersions is { Count: > 0 })
                {
                    // Union: local wins on collision; preserve order (local first, then upstream-only additions).
                    var localSet = new HashSet<string>(localVersions, StringComparer.OrdinalIgnoreCase);
                    mergedVersions = [.. localVersions, .. upstreamVersions.Where(v => !localSet.Contains(v))];
                    break;
                }
            }
        }

        // Null caches nothing and surfaces as the empty-version-set 404 below.
        if (mergedVersions.Count == 0)
        {
            return null;
        }

        string body = MavenMetadataBuilder.Build(coords.GroupId, coords.ArtifactId, mergedVersions, lastUpdated);
        return Encoding.UTF8.GetBytes(body);
    }

    private async Task<IActionResult> StoreFileAsync(
        string orgId, MavenCoordinates coords, byte[] bytes, TokenRecord token, CancellationToken ct)
    {
        // Sidecar checksums: clients upload them next to the primary. We don't store the
        // sidecar bytes — we accept, validate that the hex matches what we'd compute,
        // and discard. This keeps sidecars consistent with the primary artifact in the
        // happy case and rejects a deliberately mismatched upload.
        if (coords.IsChecksumSidecar)
        {
            return await ValidateAndAcknowledgeSidecarAsync(orgId, coords, bytes, ct);
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version!);
        string sha256Hex = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        // deepcode ignore InsecureHash: Maven repo spec requires .sha1/.md5 sidecar files for
        // mvn/gradle client compatibility — these are not used for security decisions.
        string sha1Hex = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        // deepcode ignore InsecureHash: Maven repo spec requires .md5 sidecar files.
        string md5Hex = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

        string blobKey = BlobKeys.Hosted(
            orgId, "maven",
            coords.PackageName.Replace(':', '/'),  // groupId/artifactId in the blob path
            coords.Version!,
            coords.Filename);

        // PackageRepository.GetOrCreateAsync + manual package_versions / maven_version_files
        // because Maven's multi-file shape doesn't fit IPackagePublishService's
        // one-blob-one-version contract. The package_versions row is shared across all
        // files of a version; maven_version_files carries the per-file mapping.
        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "maven", coords.PackageName, coords.PackageName, isProxy: false, ct);

        await _svc.Blobs.PutAsync(blobKey, new MemoryStream(bytes), ct);

        await using var conn = await _svc.Db.OpenAsync(ct);

        // xtenant: pkg.Id came from GetOrCreateAsync(orgId, ...), so this lookup is keyed
        // by a tenant-scoped FK target. package_versions joins through packages.org_id.
        // Get-or-create the package_versions row.
        var (Id, _) = await conn.QuerySingleOrDefaultAsync<(string Id, string BlobKey)>(
            "SELECT id AS Id, blob_key AS BlobKey FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = pkg.Id, version = coords.Version });

        string versionId;
        if (Id is null)
        {
            versionId = Guid.NewGuid().ToString("N");
            // xtenant: package_id was just obtained via GetOrCreateAsync(orgId,...), so the
            // FK to packages(id) carries the tenant binding. Inserting against that id is
            // implicitly tenant-scoped.
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, checksum_sha1, origin)
                VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes, @sha256, @sha1, 'uploaded')
                """,
                new
                {
                    id = versionId,
                    pkgId = pkg.Id,
                    version = coords.Version,
                    purl,
                    blobKey,
                    filename = coords.Filename,
                    sizeBytes = (long)bytes.Length,
                    sha256 = sha256Hex,
                    sha1 = sha1Hex,
                });
        }
        else
        {
            versionId = Id;
        }

        // xtenant: maven_version_files FKs into package_versions(id), which FKs into
        // packages(id) — the org_id is reachable transitively. The package_version_id
        // we're inserting against came from a tenant-scoped GetOrCreateAsync chain above.
        // Insert / replace maven_version_files row. ON CONFLICT(package_version_id, filename)
        // overwrites so a republished file gets the new hash.
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'uploaded')
            ON CONFLICT(package_version_id, filename) DO UPDATE SET
                blob_key = @blobKey,
                size_bytes = @sizeBytes,
                checksum_sha256 = @sha256,
                checksum_sha1 = @sha1,
                checksum_md5 = @md5
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename = coords.Filename,
                classifier = coords.Classifier,
                extension = coords.Extension ?? "",
                blobKey,
                sizeBytes = (long)bytes.Length,
                sha256 = sha256Hex,
                sha1 = sha1Hex,
                md5 = md5Hex,
            });

        await _svc.Audit.LogActivityAsync(orgId, "maven", purl, "push",
            actorId: token.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // A real-artifact publish changed this coordinate's version set; evict the rendered
        // maven-metadata.xml so a publish-then-resolve sees the new version immediately instead
        // of waiting out the TTL. (The metadata-acknowledge path changes no versions and is
        // handled before StoreFileAsync, so it never reaches here.)
        _svc.MetadataCache.Evict(new MavenMetadataKey(orgId, coords.GroupId, coords.ArtifactId));

        Response.Headers["X-Dependably-PURL"] = purl;
        return StatusCode(StatusCodes.Status201Created);
    }

    private async Task<IActionResult> ValidateAndAcknowledgeSidecarAsync(
        string orgId, MavenCoordinates coords, byte[] bytes, CancellationToken ct)
    {
        // We don't persist sidecar bytes — they're a function of the primary file's
        // content, which we already store. But we DO sanity-check the hex matches our
        // record so a mismatched sidecar can't pollute the index.
        string primaryFilename = MavenPathParser.PrimaryFilename(coords.Filename);
        await using var conn = await _svc.Db.OpenAsync(ct);
        var (Sha256, Sha1, Md5) = await conn.QuerySingleOrDefaultAsync<(string Sha256, string? Sha1, string? Md5)>(
            """
            SELECT mvf.checksum_sha256 AS Sha256, mvf.checksum_sha1 AS Sha1, mvf.checksum_md5 AS Md5
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName AND pv.version = @version
              AND mvf.filename = @filename
            LIMIT 1
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = primaryFilename,
            });

        if (Sha256 is null)
        {
            // No primary yet — Maven clients usually upload the primary first, but we
            // accept the sidecar order-of-arrival anyway. The next primary upload will
            // compute and store the real checksum; this sidecar is informational only.
            return StatusCode(StatusCodes.Status201Created);
        }

        string uploadedHex = Encoding.UTF8.GetString(bytes).Trim().ToLowerInvariant();
        // Some Maven clients prefix or suffix the hex with garbage; pull out the first
        // continuous hex run.
        string hex = ExtractHex(uploadedHex);
        string? expected = coords.ChecksumAlgorithm switch
        {
            "sha256" => Sha256,
            "sha1" => Sha1,
            "md5" => Md5,
            _ => null,
        };
        return expected is not null && !string.Equals(hex, expected, StringComparison.OrdinalIgnoreCase)
            ? BadRequest("Maven checksum sidecar mismatch.")
            : StatusCode(StatusCodes.Status201Created);
    }

    private async Task<long?> ResolveSizeCapAsync(string orgId, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        if (settings is null)
        {
            return null;
        }

        // Read max_upload_bytes_maven dynamically because the column was added after the
        // strongly-typed OrgSettings model, which doesn't surface it yet.
        await using var conn = await _svc.Db.OpenAsync(ct);
        long? orgMaven = await conn.ExecuteScalarAsync<long?>(
            "SELECT max_upload_bytes_maven FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        return orgMaven ?? settings.MaxUploadBytes;
    }

    private static async Task<string?> ComputeChecksumAsync(Stream stream, string algorithm, CancellationToken ct)
    {
        using HashAlgorithm hasher = algorithm switch
        {
            "sha512" => SHA512.Create(),
            "sha256" => SHA256.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "sha1" => SHA1.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "md5" => MD5.Create(),
            _ => SHA256.Create(),
        };
        await using (stream.ConfigureAwait(false))
        {
            byte[] hash = await hasher.ComputeHashAsync(stream, ct);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }

    private static string ComputeHex(string algorithm, byte[] bytes)
    {
        using HashAlgorithm hasher = algorithm switch
        {
            "sha512" => SHA512.Create(),
            "sha256" => SHA256.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "sha1" => SHA1.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "md5" => MD5.Create(),
            _ => SHA256.Create(),
        };
        return Convert.ToHexString(hasher.ComputeHash(bytes)).ToLowerInvariant();
    }

    private static string ExtractHex(string input)
    {
        var sb = new StringBuilder();
        foreach (char c in input)
        {
            if (Uri.IsHexDigit(c))
            {
                sb.Append(c);
            }
            else if (sb.Length > 0)
            {
                break;
            }
        }
        return sb.ToString();
    }

    private static string ComputeETagFromBytes(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }

    private static string ContentTypeFor(string? extension) => extension switch
    {
        "jar" or "war" or "ear" or "aar" => "application/java-archive",
        "pom" or "xml" => "application/xml",
        "module" => "application/json",
        _ => "application/octet-stream",
    };

    private sealed record MavenFileRow(
        string Id,
        string PackageVersionId,
        string Filename,
        string Extension,
        string BlobKey,
        string? ChecksumSha256,
        string? ChecksumSha1,
        string? ChecksumMd5,
        string Origin,
        string Purl,
        string? ManualBlockState,
        DateTimeOffset? VulnCheckedAt,
        DateTimeOffset? PublishedAt,
        string? Deprecated);
}

/// <summary>Scoped DI bundle for the Maven controller — mirrors the npm/PyPI shape.</summary>
public sealed record MavenControllerServices(
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    IBlobStore Blobs,
    IMetadataStore Db,
    MavenUpstreamFetcher Upstream,
    IConfiguration Config,
    ProxyFetchService ProxyFetch,
    BlockGateService BlockGate,
    ReservedNamespaceService ReservedNamespaces,
    UpstreamRegistryResolver Registries,
    RenderedResponseCache<MavenMetadataKey> MetadataCache,
    ILogger<MavenController> Log);
