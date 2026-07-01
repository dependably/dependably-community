using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
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
public sealed partial class MavenController : OrgScopedControllerBase
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

        // ── Global-plane proxy cache-hit: check cache_artifact for newly-proxied artifacts ──
        // Proxy artifacts whose first-fetch happened after P3b are stored in cache_artifact
        // (not maven_version_files). Look up the primary filename for both primary and sidecar
        // requests so sidecars can be synthesised from the primary's content_hash.
        var globalCa = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "maven", coords.PackageName, coords.Version ?? "", primaryFilename, ct);
        if (globalCa is not null)
        {
            // Literal SNAPSHOT freshness re-check on the global-plane path: before serving
            // the cached alias, confirm that upstream hasn't published a newer timestamped
            // build. This mirrors the freshness logic for maven_version_files rows above.
            // Uploaded SNAPSHOTs never reach this branch (they are served from row ≠ null).
            if (isLiteralSnapshot && _svc.Upstream is not null)
            {
                var freshnessResult = await CheckSnapshotFreshnessAsync(
                    orgId, coords, conn, settings, token, ct);
                if (freshnessResult is not null)
                {
                    return freshnessResult;
                }
            }
            return await ServeGlobalPlaneArtifactAsync(orgId, coords, settings, token, globalCa, ct);
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

        // Check whether the resolved timestamped artifact is already in cache:
        // first in maven_version_files (legacy / uploaded rows), then in cache_artifact
        // (global-plane proxy rows written by the P3b path).
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

        if (!timestampedIsCached)
        {
            // Also check the global plane — the timestamped row may be in cache_artifact
            // rather than maven_version_files when it was fetched after the P3b migration.
            // The check uses the same tenant join as the serve-facts lookup.
            var caRow = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
                orgId, "maven", coords.PackageName, coords.Version ?? "",
                currentTimestampedFilename, ct);
            timestampedIsCached = caRow is not null;
        }

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
        // Per-version origin gate: when AnonymousPull is disabled, a token is required for
        // all origins. When a token is present and the artifact is uploaded-origin, ReadArtifact
        // is required. Proxy-cached artifacts are not capability-gated beyond the AnonymousPull check.
        if (row.Origin == "uploaded")
        {
            if (settings is not null && !settings.AnonymousPull && token is null)
            {
                Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return Unauthorized();
            }
            if (token is not null && !token.HasCapability(Capabilities.ReadArtifact))
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
                    MaxEpssTolerance: settings?.MaxEpssTolerance,
                    Origin: row.Origin), ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        Response.Headers["X-Cache"] = "HIT";

        return coords.IsChecksumSidecar
            ? await ServeChecksumSidecarAsync(coords, row, ct)
            : await ServePrimaryFromCacheAsync(orgId, coords, token?.UserId, row, ct);
    }

    // Serves a Maven proxy artifact that was cached in the global plane (cache_artifact) rather
    // than in maven_version_files. Auth and block-gate semantics match ServeCachedArtifactAsync.
    // For checksum sidecars the content_hash from the primary cache_artifact row is returned
    // directly (only SHA-256 available from cache_artifact; other algorithms compute on-the-fly).
    private async Task<IActionResult> ServeGlobalPlaneArtifactAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token,
        CacheArtifactServeFacts caFacts, CancellationToken ct)
    {
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        if (await _svc.BlockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "maven", caFacts.Purl ?? string.Empty, string.Empty,
                    caFacts.ManualBlockState, caFacts.VulnCheckedAt,
                    token?.UserId, settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScoreTolerance,
                    HttpContext.GetNormalizedRemoteIp(),
                    MinReleaseAgeHours: settings?.MinReleaseAgeHours,
                    PublishedAt: caFacts.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: caFacts.Deprecated,
                    BlockDeprecatedMode: settings?.BlockDeprecated,
                    BlockMaliciousMode: settings?.BlockMalicious,
                    BlockKevMode: settings?.BlockKev,
                    MaxEpssTolerance: settings?.MaxEpssTolerance,
                    Origin: "proxy",
                    HasInstallScript: caFacts.HasInstallScript,
                    InstallScriptKind: caFacts.InstallScriptKind,
                    BlockInstallScriptsMode: settings?.BlockInstallScripts,
                    ProvenanceStatus: caFacts.ProvenanceStatus,
                    CacheArtifactId: caFacts.Id), ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        Response.Headers["X-Cache"] = "HIT";

        // Checksum sidecar: synthesise from the primary's stored content_hash.
        if (coords.IsChecksumSidecar)
        {
            return await ServeGlobalPlaneChecksumSidecarAsync(coords, caFacts, ct);
        }

        // Primary artifact: stream from blob store.
        // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey maps to cache tier.
        var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        if (!string.IsNullOrEmpty(caFacts.ContentHash))
        {
            Response.Headers.ETag = $"\"sha256:{caFacts.ContentHash[..Math.Min(ETagHexPrefixLength, caFacts.ContentHash.Length)]}\"";
            Response.Headers.CacheControl = coords.IsSnapshot
                ? "private, max-age=60"
                : "private, max-age=31536000, immutable";
        }
        string purl = caFacts.Purl ?? PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version ?? "unknown");
        await _svc.Audit.LogActivityAsync(orgId, "maven", purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        // Increment per-tenant download count on the global plane.
        await _svc.TenantAccess.UpsertStateAsync(orgId, caFacts.Id, _svc.Time.GetUtcNow(), ct);
        return File(stream, ContentTypeFor(coords.Extension), coords.Filename);
    }

    // Synthesises a checksum sidecar for a global-plane (cache_artifact) primary: returns the
    // stored content_hash for sha256, otherwise opens the blob and computes the requested digest.
    private async Task<IActionResult> ServeGlobalPlaneChecksumSidecarAsync(
        MavenCoordinates coords, CacheArtifactServeFacts caFacts, CancellationToken ct)
    {
        if (coords.ChecksumAlgorithm == "sha256" && !string.IsNullOrEmpty(caFacts.ContentHash))
        {
            return new ContentResult
            {
                Content = caFacts.ContentHash,
                ContentType = "text/plain",
                StatusCode = StatusCodes.Status200OK,
            };
        }

        // Other algorithms require the blob bytes — open from store and compute on-the-fly.
        if (coords.ChecksumAlgorithm is { } algo)
        {
            // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey maps to cache tier.
            var blobForChecksum = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
            if (blobForChecksum is null)
            {
                return NotFound();
            }
            string? hex = await ComputeChecksumAsync(blobForChecksum, algo, ct);
            return hex is null
                ? NotFound()
                : (IActionResult)new ContentResult { Content = hex, ContentType = "text/plain", StatusCode = StatusCodes.Status200OK };
        }
        return NotFound();
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
        await _svc.Packages.IncrementDownloadCountByPurlAsync(orgId, purl, ct);

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
        foreach (var source in bases)
        {
            try
            {
                result = await _svc.Upstream.FetchArtifactAsync(
                    source.Url, upstreamPath, ct, orgId: orgId, purl: purlForLog,
                    authorizationHeader: source.AuthorizationHeader);
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

        // Capture the literal filename before resolving so the literal alias can be written
        // after a successful SNAPSHOT first-fetch. When the literal and resolved filenames
        // differ (i.e. the SNAPSHOT resolved to a timestamped build), RecordScanAndServeAsync
        // writes a cache_artifact alias row under the literal name so subsequent literal
        // requests serve from the global plane without another upstream round-trip.
        string? snapshotLiteralFilename = resolvedCoords.Filename != coords.Filename
            ? coords.Filename
            : null;

        if (result is null)
        {
            return NotFound();
        }

        // Verify detached OpenPGP signature when the tenant has Maven signature verification
        // enabled and this org has at least one Maven PGP trust anchor configured. The .asc
        // sidecar is fetched from the same upstream that produced the artifact; the trust root is
        // always the per-org operator-pinned anchor ring, never the upstream-served key.
        // NotApplicable (off or no anchor) leaves provenance_status NULL (no gate effect).
        string? mavenVerifyMode = settings?.VerifyMavenSignatures;
        (string? mavenProvenanceStatus, string? mavenProvenanceSigner) =
            await VerifyMavenSignatureAsync(orgId, mavenVerifyMode, bases, upstreamPath, result.Bytes, ct);

        return await RecordScanAndServeAsync(orgId, resolvedCoords, result, settings, token,
            snapshotLiteralFilename, mavenProvenanceStatus, mavenProvenanceSigner, mavenVerifyMode, ct);
    }

    // Verifies the detached OpenPGP (.asc) signature for a freshly-fetched Maven artifact when the
    // tenant has signature verification enabled and the org has at least one Maven PGP trust
    // anchor configured. The sidecar signature file is fetched from the same upstreams that
    // produced the artifact, and the trust root is always the per-org operator-pinned anchor
    // ring, never the upstream-served key. Returns (null, null) when verification is off or no
    // anchor is configured, leaving the provenance status column unset with no gate effect.
    private async Task<(string? Status, string? Signer)> VerifyMavenSignatureAsync(
        string orgId, string? verifyMode, IReadOnlyList<UpstreamSource> bases, string upstreamPath,
        byte[] artifactBytes, CancellationToken ct)
    {
        if (verifyMode == "off" || !await _svc.MavenProvenance.IsConfiguredForAsync(orgId, ct))
        {
            return (null, null);
        }

        byte[]? ascBytes = null;
        foreach (var source in bases)
        {
            ascBytes = await _svc.Upstream.TryFetchAscSidecarAsync(source.Url, upstreamPath, ct, source.AuthorizationHeader);
            if (ascBytes is not null)
            {
                break;
            }
        }

        var provResult = await _svc.MavenProvenance.VerifyArtifactAsync(orgId, artifactBytes, ascBytes, ct);
        return (ProvenanceStatuses.ToColumn(provResult.Status), provResult.Signer);
    }

    // Records the artifact via the global proxy pipeline (OSV scan, block gate, cache_artifact
    // write) and serves the artifact bytes. Returns 403 when the gate blocks, or a File result.
    // When snapshotLiteralFilename is set (literal -SNAPSHOT.jar requested, resolved to a
    // timestamped build), a cache_artifact alias row is written under the literal filename so
    // subsequent literal requests are served directly from the global plane.
    // provenanceStatus / provenanceSigner / verifyProvenanceMode carry the detached-signature
    // outcome computed in ProxyFetchAndCacheAsync; they are forwarded into ProxyFetchRequest
    // so the shared pipeline can persist and gate on them.
    // Each parameter is a distinct pipeline input (request context, fetch result, gate settings,
    // and the precomputed provenance trio forwarded verbatim into ProxyFetchRequest); grouping
    // them into an aggregate would hide the data flow without adding cohesion.
#pragma warning disable S107
    private async Task<IActionResult> RecordScanAndServeAsync(
        string orgId, MavenCoordinates resolvedCoords, MavenArtifactFetchResult result,
        OrgSettings? settings, TokenRecord? token,
        string? snapshotLiteralFilename,
        string? provenanceStatus, string? provenanceSigner, string? verifyProvenanceMode,
        CancellationToken ct)
#pragma warning restore S107
    {
        string purl = PurlNormalizer.Maven(resolvedCoords.GroupId, resolvedCoords.ArtifactId, resolvedCoords.Version!);
        string upstreamPath = $"{resolvedCoords.GroupId.Replace('.', '/')}/{resolvedCoords.ArtifactId}/{resolvedCoords.Version}/{resolvedCoords.Filename}";

        // Run the shared proxy pipeline: write cache_artifact (global plane), synchronously
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
            CacheAccess: new CacheAccess(orgId, "maven", resolvedCoords.PackageName,
                resolvedCoords.Version!, resolvedCoords.Filename,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: upstreamPath),
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            Sha1Hex: result.Sha1,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            MaxEpssTolerance: settings?.MaxEpssTolerance,
            ProvenanceStatus: provenanceStatus,
            ProvenanceSigner: provenanceSigner,
            VerifyProvenanceMode: verifyProvenanceMode), ct);

        if (fetch.Decision == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // RecordMavenFileAsync survives for legacy rows (VersionId non-null from pre-P3b rows
        // still in package_versions). New proxy artifacts take the global-plane path (VersionId
        // null) and skip the maven_version_files write — the cache_artifact row is authoritative.
        if (fetch.VersionId is not null)
        {
            await RecordMavenFileAsync(fetch.VersionId, resolvedCoords, result, ct);
        }

        // SNAPSHOT literal alias: when the caller requested a literal -SNAPSHOT.jar but the
        // artifact resolved to a timestamped build (e.g. lib-1.0-20240101.120000-3.jar), write
        // a cache_artifact alias row under the literal filename so a second literal request
        // finds the global plane and gets a HIT instead of another upstream round-trip. The
        // alias shares the same blob_key and content_hash as the primary timestamped row.
        if (snapshotLiteralFilename is not null && fetch.VersionId is null)
        {
            _ = await _svc.CacheRecorder.RecordAccessAsync(new CacheAccess(
                orgId, "maven", resolvedCoords.PackageName,
                resolvedCoords.Version!, snapshotLiteralFilename,
                Sha256: result.Sha256,
                SizeBytes: result.Bytes.LongLength,
                BlobKey: result.BlobKey,
                UpstreamUrl: null), ct);
        }

        Response.Headers["X-Cache"] = "MISS";
        return File(result.Bytes, ContentTypeFor(resolvedCoords.Extension), resolvedCoords.Filename);
    }

    // Sidecar-before-primary path: the primary artifact is fetched and cached first (via a
    // recursive ProxyFetchAndCacheAsync call), then the sidecar is served from the checksum
    // columns of the newly-cached primary row. The block gate and scan run exactly once,
    // on the primary, and are not re-run for the sidecar.
    // For global-plane artifacts (VersionId null after the primary fetch), the sidecar
    // is served from the cache_artifact row written by the primary fetch instead of
    // maven_version_files. This handles both non-SNAPSHOT and SNAPSHOT (literal or
    // timestamped) coordinates transparently because RecordScanAndServeAsync writes a
    // literal alias row when the SNAPSHOT was resolved to a timestamped build.
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

        if (row is not null)
        {
            return await ServeChecksumSidecarAsync(coords, row, ct);
        }

        // Global-plane path: primary was stored in cache_artifact (not maven_version_files).
        // RecordScanAndServeAsync writes both the timestamped row and a literal alias when a
        // SNAPSHOT literal was resolved, so a lookup by primaryFilename finds the row for
        // both non-SNAPSHOT and literal-SNAPSHOT sidecar requests.
        var caFacts = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "maven", coords.PackageName, coords.Version ?? "", primaryFilename, ct);
        return caFacts is null
            ? NotFound()
            : await ServeGlobalPlaneArtifactAsync(orgId, coords, settings, token, caFacts, ct);
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
                 checksum_sha256, checksum_sha1, checksum_md5, origin, owner_kind)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'proxy', 'package_version')
            ON CONFLICT(package_version_id, filename) WHERE owner_kind = 'package_version' DO NOTHING
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
                         checksum_sha256, checksum_sha1, checksum_md5, origin, owner_kind)
                    VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                            @sha256, @sha1, @md5, 'proxy', 'package_version')
                    ON CONFLICT(package_version_id, filename) WHERE owner_kind = 'package_version' DO UPDATE SET
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
        // WHERE owner_kind='package_version' overwrites so a republished file gets the new hash.
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin, owner_kind)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'uploaded', 'package_version')
            ON CONFLICT(package_version_id, filename) WHERE owner_kind = 'package_version' DO UPDATE SET
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
    ILogger<MavenController> Log,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    TimeProvider Time,
    CacheAccessRecorder CacheRecorder,
    Dependably.Protocol.Provenance.MavenProvenanceVerifier MavenProvenance);
