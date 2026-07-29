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
    // in-memory rendered-body cache and match the npm/PyPI/NuGet metadata-cache TTLs, and are
    // operator-tunable via METADATA_PROXY/LOCAL_CACHE_TTL_SECONDS (see RenderedMetadataCacheOptions).
    private TimeSpan MetadataProxyTtl => _svc.CacheOptions.ProxyTtl;
    private TimeSpan MetadataLocalTtl => _svc.CacheOptions.LocalTtl;

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

        // The path is composed into the upstream proxy URL (ServeArtifactAsync /
        // ServeMetadataAsync), so every segment must clear the %-banning gate before it is even
        // parsed or fetched.
        if (FirstUnsafePathSegmentMessage(path) is { } unsafeSegment)
        {
            return BadRequest(unsafeSegment);
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
        // Fail-closed on an edge node: Maven publishes write the registry tier directly (outside
        // the shared publish service), so the edge guard is applied here at the choke point.
        if (_svc.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

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
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Path-traversal / control-character defence: reject anything that couldn't safely
        // land in a blob key or a composed upstream URL. Shares the download path's gate.
        if (FirstUnsafePathSegmentMessage(path) is { } unsafeSegment)
        {
            return BadRequest(unsafeSegment);
        }

        // Per-tenant Maven cap → instance Maven cap → instance global cap. Resolve BEFORE
        // reading the body so the cap gates the stream itself; the route ceiling bounds it when
        // no tenant/instance cap is configured.
        long? sizeCap = await ResolveSizeCapAsync(orgId, ct);
        long effectiveCap = sizeCap ?? MavenUploadSizeLimitBytes;

        // Stream the request body to a staging temp file with SHA-256/SHA-1/MD5 computed inline,
        // instead of the old growing-MemoryStream + ToArray double buffer that peaked at ~2x the
        // body and only checked the cap afterward. The primary JAR is the large payload; sidecars
        // and metadata are tiny and share the same bounded path.
        RequestBodyStager.StagedBody staged;
        try
        {
            staged = await RequestBodyStager.StageAsync(
                Request.Body, _svc.Staging.Path, effectiveCap, withMavenDigests: true, ct);
        }
        catch (InvalidDataException)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge, $"Maven upload exceeds size limit ({effectiveCap} bytes).");
        }

        try
        {
            // Metadata uploads (maven-metadata.xml) are deploy-time bookkeeping the client
            // computes locally. We accept and discard — the metadata we serve is generated
            // server-side from package_versions / maven_version_files so trusting client
            // input here would let a misbehaving client poison the index for everyone.
            return coords.IsMetadata
                ? StatusCode(StatusCodes.Status201Created)
                : await StoreFileAsync(orgId, coords!, staged, settings, token, ct);
        }
        finally
        {
            RequestBodyStager.TryDelete(staged.Path);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    // Every '/'-separated segment of a Maven path becomes either a blob-key component (publish)
    // or a segment of the composed upstream proxy URL (download/metadata). Both demand the
    // %-banning ValidateUpstreamSegment: ASP.NET leaves %2F/%2E undecoded in the {**path}
    // catch-all, so a percent-encoded traversal would otherwise survive into the upstream request
    // and be decoded to '../' there — invisible to the host-only SSRF guard. Returns the first
    // failing segment's message, or null when every segment is safe.
    private static string? FirstUnsafePathSegmentMessage(string path)
    {
        foreach (string seg in path.Split('/'))
        {
            var r = PathSafeValidator.ValidateUpstreamSegment(seg, "path");
            if (!r.IsValid)
            {
                return r.Message;
            }
        }

        return null;
    }

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
            // plane-ok: maven_version_files hosted serve; global-plane proxy served via the sibling CacheArtifacts.GetServeFactsByCoordinateAsync in this method.
            """
            SELECT mvf.id AS Id, mvf.package_version_id AS PackageVersionId,
                   mvf.filename AS Filename,
                   mvf.extension AS Extension, mvf.blob_key AS BlobKey,
                   mvf.checksum_sha256 AS ChecksumSha256,
                   mvf.checksum_sha1 AS ChecksumSha1, mvf.checksum_md5 AS ChecksumMd5,
                   mvf.origin AS Origin,
                   pv.purl AS Purl, pv.manual_block_state AS ManualBlockState,
                   pv.vuln_checked_at AS VulnCheckedAt, pv.published_at AS PublishedAt,
                   pv.deprecated AS Deprecated,
                   pv.origin AS VersionOrigin,
                   pv.has_install_script AS HasInstallScript,
                   pv.install_script_kind AS InstallScriptKind,
                   pv.provenance_status AS ProvenanceStatus,
                   pv.revoked_at AS RevokedAt
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
            // plane-ok: maven_version_files freshness probe; global-plane checked via the sibling CacheArtifacts.GetServeFactsByCoordinateAsync in this method.
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

        // The block gate runs before we serve cached bytes — including the checksum sidecar, so a
        // blocked artifact's hashes don't leak either. The row's projection carries the owning
        // package_versions row's full gate-fact set (see MavenFileRow.ToPackageVersion), so this
        // plane goes through the same BlockGateRequest.For factory every other hosted serve path
        // uses and evaluates the same arms: manual block, vulnerability, deprecation, release age,
        // revocation, install script, provenance, and licence.
        if (await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.For(
                    orgId, "maven", row.ToPackageVersion(), token, settings,
                    HttpContext.GetNormalizedRemoteIp()), ct)
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
                BlockGateRequest.ForProxyCacheFacts(
                    orgId, "maven", caFacts, token, settings, HttpContext.GetNormalizedRemoteIp()), ct)
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

        // 304 short-circuit: check the client's cached copy before opening the blob stream.
        string? globalEtag = !string.IsNullOrEmpty(caFacts.ContentHash)
            ? $"\"sha256:{caFacts.ContentHash[..Math.Min(ETagHexPrefixLength, caFacts.ContentHash.Length)]}\""
            : null;
        string globalCacheControl = coords.IsSnapshot
            ? "private, max-age=60"
            : "private, max-age=31536000, immutable";
        if (globalEtag is not null && ConditionalRequestHelper.IfNoneMatchHits(Request.Headers, globalEtag))
        {
            Response.Headers.ETag = globalEtag;
            Response.Headers.CacheControl = globalCacheControl;
            return StatusCode(StatusCodes.Status304NotModified);
        }

        // Primary artifact: stream from blob store.
        // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey maps to cache tier.
        var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        if (globalEtag is not null)
        {
            Response.Headers.ETag = globalEtag;
            Response.Headers.CacheControl = globalCacheControl;
        }
        string purl = caFacts.Purl ?? PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version ?? "unknown");
        await _svc.Audit.LogActivityAsync(orgId, "maven", purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        // Increment per-tenant download count on the global plane. Enqueued off the request
        // path — the row already exists (seeded durably at first-fetch).
        await _svc.TenantAccess.RecordDownloadHitAsync(orgId, caFacts.Id, _svc.Time.GetUtcNow(), ct);
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
        // 304 short-circuit: check the client's cached copy before opening the blob stream.
        string? uploadedEtag = row.ChecksumSha256 is not null ? $"\"sha256:{row.ChecksumSha256}\"" : null;
        string uploadedCacheControl = coords.IsSnapshot
            ? "private, max-age=60"
            : "private, max-age=31536000, immutable";
        if (uploadedEtag is not null && ConditionalRequestHelper.IfNoneMatchHits(Request.Headers, uploadedEtag))
        {
            Response.Headers.ETag = uploadedEtag;
            Response.Headers.CacheControl = uploadedCacheControl;
            return StatusCode(StatusCodes.Status304NotModified);
        }

        var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version ?? "unknown");
        if (uploadedEtag is not null)
        {
            Response.Headers.ETag = uploadedEtag;
            Response.Headers.CacheControl = uploadedCacheControl;
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
            await VerifyMavenSignatureAsync(orgId, mavenVerifyMode, bases, upstreamPath, result, ct);

        try
        {
            return await RecordScanAndServeAsync(orgId, resolvedCoords, result, settings, token,
                snapshotLiteralFilename, mavenProvenanceStatus, mavenProvenanceSigner, mavenVerifyMode, ct);
        }
        catch (ProxyCatalogueUnavailableException)
        {
            // The artefact could not be recorded on the cache plane, so it could not be scanned or
            // gated — and an artefact the registry cannot vouch for is not served. 503, not 404: it
            // exists upstream, we could not admit it. The bytes are staged, so a retry is cheap.
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    // Verifies the detached OpenPGP (.asc) signature for a freshly-fetched Maven artifact when the
    // tenant has signature verification enabled and the org has at least one Maven PGP trust
    // anchor configured. The sidecar signature file is fetched from the same upstreams that
    // produced the artifact, and the trust root is always the per-org operator-pinned anchor
    // ring, never the upstream-served key. Returns (null, null) when verification is off or no
    // anchor is configured, leaving the provenance status column unset with no gate effect.
    private async Task<(string? Status, string? Signer)> VerifyMavenSignatureAsync(
        string orgId, string? verifyMode, IReadOnlyList<UpstreamSource> bases, string upstreamPath,
        MavenArtifactFetchResult result, CancellationToken ct)
    {
        if (verifyMode == "off" || !await _svc.MavenProvenance.IsConfiguredForAsync(orgId, ct))
        {
            return (null, null);
        }

        // Signature verification is active for this tenant — read the cached artifact (bounded by
        // the upstream fetch cap, already SHA-256-verified and content-addressed) to hand the
        // bytes to BouncyCastle. This is the only Maven serve path that materialises the artifact,
        // and only when the operator opted into PGP verification.
        byte[] artifactBytes;
        // blobkey-ok: result.BlobKey is BlobKeys.Proxy(sha256) from the fetch; StoreKey routes it.
        await using (var blob = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(result.BlobKey), ct)
            ?? throw new InvalidOperationException($"Blob {result.BlobKey} vanished before signature verification."))
        {
            using var ms = result.SizeBytes is > 0 and <= int.MaxValue
                ? new MemoryStream((int)result.SizeBytes)
                : new MemoryStream();
            await blob.CopyToAsync(ms, ct);
            artifactBytes = ms.ToArray();
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
        var blob = new BlobHandle(result.BlobKey, result.Sha256, result.SizeBytes,
            async openCt => await _svc.Blobs.GetAsync(BlobKeys.StoreKey(result.BlobKey), openCt)
                ?? throw new InvalidOperationException(
                    $"Blob {result.BlobKey} vanished between fetch and serve."));

        var fetch = await _svc.ProxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: orgId, Ecosystem: "maven",
            PackageName: resolvedCoords.PackageName, PurlName: resolvedCoords.PackageName,
            Version: resolvedCoords.Version!, Purl: purl, File: resolvedCoords.Filename, Blob: blob,
            // Licenses live only in the POM; the .jar/.aar carry none. Gate extraction on the
            // resolved coordinate extension so the callback runs against the .pom's own
            // cache_artifact row and stays null for every other artifact file.
            ExtractLicenses: string.Equals(resolvedCoords.Extension, "pom", StringComparison.OrdinalIgnoreCase)
                ? LicenseExtractor.FromPomXml
                : null,
            UserId: token?.UserId,
            ActorKind: token?.ActorKind,
            SourceIp: HttpContext.GetNormalizedRemoteIp(),
            MaxOsvScoreTolerance: settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScoreTolerance,
            // The ABSOLUTE fetch URL (resolved upstream base + repository path), not the
            // repository-relative path: cache_artifact.upstream_url is contracted to hold a full
            // URL — every other ecosystem stores one — and a relative path cannot identify the
            // upstream host, so consumers that gate on origin (e.g. the registry-page link) can
            // never resolve it. Falls back to the relative path only if the fetcher supplied none.
            CacheAccess: new CacheAccess(orgId, "maven", resolvedCoords.PackageName,
                resolvedCoords.Version!, resolvedCoords.Filename,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: result.UpstreamUrl ?? upstreamPath),
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            Sha1Hex: result.Sha1,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            BlockRevokedMode: settings?.BlockRevoked,
            MaxEpssTolerance: settings?.MaxEpssTolerance,
            ProvenanceStatus: provenanceStatus,
            ProvenanceSigner: provenanceSigner,
            VerifyProvenanceMode: verifyProvenanceMode,
            LicenseEnforcementMode: settings?.LicenseEnforcementMode), ct);

        if (fetch.Decision == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // A proxied artefact is catalogued on the cache plane (the cache_artifact row the fetch
        // wrote); the serve path resolves its file rows from there, so nothing is written to
        // maven_version_files, which holds only locally-published (origin='uploaded') files.

        // SNAPSHOT literal alias: when the caller requested a literal -SNAPSHOT.jar but the
        // artifact resolved to a timestamped build (e.g. lib-1.0-20240101.120000-3.jar), write
        // a cache_artifact alias row under the literal filename so a second literal request
        // finds the global plane and gets a HIT instead of another upstream round-trip. The
        // alias shares the same blob_key and content_hash as the primary timestamped row.
        if (snapshotLiteralFilename is not null)
        {
            _ = await _svc.CacheRecorder.RecordAccessAsync(new CacheAccess(
                orgId, "maven", resolvedCoords.PackageName,
                resolvedCoords.Version!, snapshotLiteralFilename,
                Sha256: result.Sha256,
                SizeBytes: result.SizeBytes,
                BlobKey: result.BlobKey,
                UpstreamUrl: null), ct);
        }

        // Serve by streaming the cached blob straight to the response — the artifact never
        // re-enters managed memory on the serve path.
        // blobkey-ok: result.BlobKey is BlobKeys.Proxy(sha256) from the fetch; StoreKey routes it.
        var serveStream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(result.BlobKey), ct)
            ?? throw new InvalidOperationException($"Blob {result.BlobKey} vanished between fetch and serve.");
        Response.Headers["X-Cache"] = "MISS";
        return File(serveStream, ContentTypeFor(resolvedCoords.Extension), resolvedCoords.Filename);
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
            // plane-ok: PV-plane sidecar re-query; global-plane primary served via the sibling CacheArtifacts.GetServeFactsByCoordinateAsync in this method.
            """
            SELECT mvf.id AS Id, mvf.package_version_id AS PackageVersionId,
                   mvf.filename AS Filename,
                   mvf.extension AS Extension, mvf.blob_key AS BlobKey,
                   mvf.checksum_sha256 AS ChecksumSha256,
                   mvf.checksum_sha1 AS ChecksumSha1, mvf.checksum_md5 AS ChecksumMd5,
                   mvf.origin AS Origin,
                   pv.purl AS Purl, pv.manual_block_state AS ManualBlockState,
                   pv.vuln_checked_at AS VulnCheckedAt, pv.published_at AS PublishedAt,
                   pv.deprecated AS Deprecated,
                   pv.origin AS VersionOrigin,
                   pv.has_install_script AS HasInstallScript,
                   pv.install_script_kind AS InstallScriptKind,
                   pv.provenance_status AS ProvenanceStatus,
                   pv.revoked_at AS RevokedAt
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



    // The staged file path is a server-generated GUID under the operator-configured staging root;
    // the request body reaches the file content, not the file name. SCS's taint from Request.Body
    // into staged.Path is a false positive.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0018",
        Justification = "Staging path is a server-generated GUID under the operator-configured root, not user input.")]
    private async Task<IActionResult> StoreFileAsync(
        string orgId, MavenCoordinates coords, RequestBodyStager.StagedBody staged,
        OrgSettings? settings, TokenRecord token, CancellationToken ct)
    {
        // Sidecar checksums: clients upload them next to the primary. We don't store the
        // sidecar bytes — we accept, validate that the hex matches what we'd compute,
        // and discard. Sidecars are tiny (a hex digest), so reading the staged file back is
        // cheap. This keeps sidecars consistent with the primary artifact in the happy case
        // and rejects a deliberately mismatched upload.
        if (coords.IsChecksumSidecar)
        {
            // staged.Path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            byte[] sidecarBytes = await System.IO.File.ReadAllBytesAsync(staged.Path, ct);
            return await ValidateAndAcknowledgeSidecarAsync(orgId, coords, sidecarBytes, ct);
        }

        // License hard-block. Maven licenses live only in the .pom, uploaded after the .jar, so
        // a version row may already exist by the time this fires — the "no version row on
        // block" invariant the shared publish pipeline gives every other hosted-push ecosystem
        // is not achievable here. Instead the .pom PUT itself is rejected before it is stored;
        // the serve-path license arm (BlockGateService) then covers the already-stored jar via
        // the shared package_versions row's license entries.
        if (string.Equals(coords.Extension, "pom", StringComparison.OrdinalIgnoreCase)
            && await EvaluateMavenPomLicenseGateAsync(orgId, settings, staged.Path, ct) is { } licenseReject)
        {
            return licenseReject;
        }

        // Name-level publish authorization. Keys on the authenticated token principal (never a
        // request field), so a token holding only publish:maven cannot seize a groupId:artifactId
        // a different principal already owns. No-op unless PUBLISH_NAME_BINDING=on.
        var namePrincipal = Dependably.Infrastructure.NamePrincipal.FromToken(token);
        if (_svc.NameBinding is { } nameGate
            && !await nameGate.IsPublishAuthorizedAsync(orgId, "maven", coords.PackageName, namePrincipal, ct))
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                $"Publishing to '{coords.PackageName}' is not permitted: the name is owned by a " +
                "different principal in this org and you hold no publish grant for it.");
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version!);
        // Digests were computed inline while streaming the body to disk — no re-hash of a
        // fully-buffered artifact.
        string sha256Hex = staged.Sha256;
        string sha1Hex = staged.Sha1!;
        string md5Hex = staged.Md5!;

        // Content-addressed hosted key: the artefact's SHA-256 (computed inline while the body
        // streamed to the staging file) is a key segment, so the bytes under a key always hash
        // to the digest the key names. Two concurrent publishes of one file coordinate carrying
        // different bytes therefore address disjoint keys and cannot overwrite one another —
        // the (blob_key, checksum_sha256) pair each of package_versions and maven_version_files
        // commits stays true of the stored bytes with no lock and no ordering constraint between
        // the blob write and the metadata write. A republish with different bytes repoints the
        // maven_version_files row at the new key and leaves the superseded blob unreferenced for
        // the orphan reconciler, rather than overwriting bytes a committed row still names.
        // Readers resolve hosted blobs from the stored blob_key (never by rebuilding the
        // coordinate), so rows written under the older coordinate-only key shape keep resolving.
        string blobKey = BlobKeys.HostedArtifact(
            orgId, "maven",
            coords.PackageName.Replace(':', '/'),  // groupId/artifactId in the blob path
            coords.Version!,
            sha256Hex,
            coords.Filename);

        // PackageRepository.GetOrCreateAsync + manual package_versions / maven_version_files
        // because Maven's multi-file shape doesn't fit IPackagePublishService's
        // one-blob-one-version contract. The package_versions row is shared across all
        // files of a version; maven_version_files carries the per-file mapping.
        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "maven", coords.PackageName, coords.PackageName, isProxy: false, ct);

        // Store the artifact by streaming the staged file into the blob store — the cap was
        // already enforced during staging, so no blob is ever written for an oversize upload.
        // staged.Path is under the operator-configured staging root — no user input reaches the path.
        await using (var artifactStream = new FileStream(
            staged.Path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true))
        {
            await _svc.Blobs.PutAsync(blobKey, artifactStream, ct);
        }

        await using var conn = await _svc.Db.OpenAsync(ct);

        string versionId = await GetOrCreateVersionRowAsync(
            conn, pkg.Id, coords, purl, blobKey, sha256Hex, sha1Hex, staged.Size);

        await UpsertMavenVersionFileAsync(conn, versionId, coords, blobKey, staged.Size, sha256Hex, sha1Hex, md5Hex);

        // Record first-publisher ownership now that the artefact and its rows are durably stored
        // (the remaining license-extraction step is best-effort and never fails the publish).
        if (_svc.NameBinding is { } ownerGate)
        {
            await ownerGate.RecordOwnershipAsync(orgId, "maven", coords.PackageName, namePrincipal, ct);
        }

        // Licenses live only in the POM. On a .pom publish, parse the staged bytes and attach
        // the resolved SPDX identifiers to the shared package_versions row so hosted Maven
        // artifacts feed license governance the same way proxied ones do. Extraction failures
        // never fail the publish — the artifact is already stored and the row already written.
        if (string.Equals(coords.Extension, "pom", StringComparison.OrdinalIgnoreCase))
        {
            await ExtractAndAttachPomLicensesAsync(staged.Path, pkg.Id, versionId, purl, ct);
        }

        await _svc.Audit.LogActivityAsync(orgId, "maven", purl, "push",
            actorId: token.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        EvictMavenMetadataCacheAfterPublish(orgId, coords);

        Response.Headers["X-Dependably-PURL"] = purl;
        return StatusCode(StatusCodes.Status201Created);
    }

    // Insert / replace the maven_version_files row. ON CONFLICT(package_version_id, filename)
    // WHERE owner_kind='package_version' overwrites so a republished file gets the new hash.
    private static async Task UpsertMavenVersionFileAsync(
        System.Data.Common.DbConnection conn, string versionId, MavenCoordinates coords, string blobKey,
        long sizeBytes, string sha256Hex, string sha1Hex, string md5Hex)
    {
        // xtenant: keyed by versionId from GetOrCreateVersionRowAsync(pkg.Id, …), and pkg came from
        // GetOrCreateAsync(orgId, …) — the FK chain package_versions → packages carries the org_id.
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
                sizeBytes,
                sha256 = sha256Hex,
                sha1 = sha1Hex,
                md5 = md5Hex,
            });
    }

    // staged.Path is under the operator-configured staging root — no user input reaches the path.
    // FromPomXml takes ownership of and disposes the stream (class stream-ownership contract).
    private async Task ExtractAndAttachPomLicensesAsync(
        string stagedPath, string packageId, string versionId, string purl, CancellationToken ct)
    {
        try
        {
            var pomStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true);
            var licenses = LicenseExtractor.FromPomXml(pomStream);
            if (licenses.Spdx.Count > 0)
            {
                await _svc.Licenses.SetLicensesAsync(versionId, licenses.Spdx, "upstream", ct);
            }

            // The POM's <url>/<scm><url>/<description> feed the per-tenant packages presentation row.
            await _svc.Packages.UpdateMetadataAsync(
                packageId, licenses.Homepage, licenses.Repository, licenses.Description, ct);
        }
        catch (Exception ex)
        {
            _svc.Log.LogWarning(ex, "Maven POM license extraction failed for {Purl}; publish unaffected.", purl);
        }
    }

    // A real-artifact publish changed this coordinate's version set; invalidate the rendered
    // maven-metadata.xml so a publish-then-resolve sees the new version immediately instead
    // of waiting out the TTL. (The metadata-acknowledge path changes no versions and is
    // handled before StoreFileAsync, so it never reaches here.) A SNAPSHOT publish also names
    // its version so the version-level document goes too — the new file changes the <snapshot>/
    // <snapshotVersions> build list that document reports.
    private void EvictMavenMetadataCacheAfterPublish(string orgId, MavenCoordinates coords)
    {
        _svc.Invalidation.Invalidate(MetadataInvalidation.ForMaven(
            orgId, coords.GroupId, coords.ArtifactId, coords.IsSnapshot ? coords.Version : null));
    }

    /// <summary>
    /// License hard-block for the .pom PUT, governed by the existing
    /// <c>org_settings.license_enforcement_mode</c> ('off'/'warn'/'block'). Parses the staged
    /// POM the same way the post-store license-mirroring step does; a parse failure or a POM
    /// with no license entries fails open (no rejection) — matching the persisted mirroring
    /// step's "extraction failures never fail the publish" contract. Only 'block' can reject.
    /// </summary>
    private async Task<IActionResult?> EvaluateMavenPomLicenseGateAsync(
        string orgId, OrgSettings? settings, string stagedPath, CancellationToken ct)
    {
        if (settings?.LicenseEnforcementMode != "block")
        {
            return null;
        }

        LicenseExtractor.ExtractedMetadata licenses;
        try
        {
            // stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            var pomStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true);
            // FromPomXml takes ownership of and disposes the stream (class stream-ownership contract).
            licenses = LicenseExtractor.FromPomXml(pomStream);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _svc.Log.LogWarning(ex, "Maven POM license gate parse failed; publish unaffected.");
            return null;
        }

        if (licenses.Spdx.Count == 0)
        {
            return null;
        }

        var (allowed, blocked) = await _svc.Licenses.CheckPolicyAsync(orgId, "block", licenses.Spdx, ct);
        return allowed
            ? null
            : new ObjectResult(new ProblemDetails
            {
                Detail = $"License '{blocked}' is not permitted by this org's license policy.",
                Status = StatusCodes.Status403Forbidden,
            })
            { StatusCode = StatusCodes.Status403Forbidden };
    }

    // Get-or-create the shared package_versions row for this coordinate/version: Maven's
    // multi-file shape means the row is shared across every file of a version (the per-file
    // mapping lives in maven_version_files), so a second file of an already-seen version reuses
    // the existing row rather than inserting a duplicate.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct coordinate/checksum input for the row upsert; bundling would add no cohesion.")]
    private static async Task<string> GetOrCreateVersionRowAsync(
        System.Data.Common.DbConnection conn, string packageId, MavenCoordinates coords, string purl,
        string blobKey, string sha256Hex, string sha1Hex, long sizeBytes)
    {
        // xtenant: packageId came from GetOrCreateAsync(orgId, ...), so this lookup is keyed
        // by a tenant-scoped FK target. package_versions joins through packages.org_id.
        var (id, _) = await conn.QuerySingleOrDefaultAsync<(string Id, string BlobKey)>(
            "SELECT id AS Id, blob_key AS BlobKey FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = packageId, version = coords.Version });

        if (id is not null)
        {
            return id;
        }

        string versionId = Guid.NewGuid().ToString("N");
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
                pkgId = packageId,
                version = coords.Version,
                purl,
                blobKey,
                filename = coords.Filename,
                sizeBytes,
                sha256 = sha256Hex,
                sha1 = sha1Hex,
            });
        return versionId;
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
            // plane-ok: sidecar checksum validation on the hosted PUT/publish path; sidecars exist only for hosted maven_version_files rows.
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
            // Maven sidecar spec — see class-level SuppressMessage.
            "sha1" => SHA1.Create(),
            // Maven sidecar spec — see class-level SuppressMessage.
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
            // Maven sidecar spec — see class-level SuppressMessage.
            "sha1" => SHA1.Create(),
            // Maven sidecar spec — see class-level SuppressMessage.
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

    /// <summary>
    /// One <c>maven_version_files</c> row joined to the gate facts of its owning
    /// <c>package_versions</c> row. <c>Origin</c> is the FILE's origin (drives the per-file auth
    /// branch); <c>VersionOrigin</c> is the VERSION's origin, which is what the block gate reads.
    ///
    /// <para>
    /// Property-mapped rather than a positional record on purpose: Dapper resolves a constructor
    /// only when every parameter's CLR type equals the reader's field type, and the two providers
    /// disagree on the boolean columns (SQLite reports INTEGER, PostgreSQL reports boolean). The
    /// per-property mapper converts, so one row type serves both — the same shape
    /// <see cref="PackageVersion"/> itself uses.
    /// </para>
    /// </summary>
    private sealed class MavenFileRow
    {
        public string Id { get; set; } = "";
        public string PackageVersionId { get; set; } = "";
        public string Filename { get; set; } = "";
        public string Extension { get; set; } = "";
        public string BlobKey { get; set; } = "";
        public string? ChecksumSha256 { get; set; }
        public string? ChecksumSha1 { get; set; }
        public string? ChecksumMd5 { get; set; }
        public string Origin { get; set; } = "";
        public string Purl { get; set; } = "";
        public string? ManualBlockState { get; set; }
        public DateTimeOffset? VulnCheckedAt { get; set; }
        public DateTimeOffset? PublishedAt { get; set; }
        public string? Deprecated { get; set; }
        public string VersionOrigin { get; set; } = "proxy";
        public bool HasInstallScript { get; set; }
        public string? InstallScriptKind { get; set; }
        public string? ProvenanceStatus { get; set; }
        public DateTimeOffset? RevokedAt { get; set; }

        /// <summary>
        /// Rehydrates the owning <c>package_versions</c> row in the shape
        /// <see cref="BlockGateRequest.For"/> reads, so this plane's serve gate is built by the
        /// same factory — and therefore fires the same arms — as every other hosted serve path.
        /// Only the gate-fact set is carried; fields no block arm reads keep their defaults.
        /// </summary>
        public PackageVersion ToPackageVersion() => new()
        {
            Id = PackageVersionId,
            Purl = Purl,
            BlobKey = BlobKey,
            ChecksumSha256 = ChecksumSha256,
            ChecksumSha1 = ChecksumSha1,
            ManualBlockState = ManualBlockState,
            VulnCheckedAt = VulnCheckedAt,
            PublishedAt = PublishedAt,
            Deprecated = Deprecated,
            Origin = VersionOrigin,
            HasInstallScript = HasInstallScript,
            InstallScriptKind = InstallScriptKind,
            ProvenanceStatus = ProvenanceStatus,
            RevokedAt = RevokedAt,
        };
    }
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
    MetadataInvalidationCoordinator Invalidation,
    RenderedMetadataCacheOptions CacheOptions,
    ILogger<MavenController> Log,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    TimeProvider Time,
    CacheAccessRecorder CacheRecorder,
    Dependably.Protocol.Provenance.MavenProvenanceVerifier MavenProvenance,
    Dependably.Infrastructure.Edge.EdgePublishGuard EdgeGuard,
    Dependably.Infrastructure.StagingOptions Staging,
    LicenseRepository Licenses,
    Dependably.Security.NameBindingGate? NameBinding = null);
