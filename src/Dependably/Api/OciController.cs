using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// OCI Distribution Spec v2 surface. Docker daemons configured against <c>/v2/</c> can both
/// <c>docker pull</c> (read side) and <c>docker push</c> (write side) images.
///
/// Write side: blob uploads (<c>POST</c> init, <c>PATCH</c> chunk, <c>PUT</c> finalize) and
/// manifest puts (<c>PUT .../manifests/...</c>) are delegated to <see cref="OciUploadService"/>,
/// which hashes-and-stages blob bytes, verifies the client digest, and writes to the Registry
/// tier with <c>origin='uploaded'</c> — the same rows the read side below serves back.
///
/// Cache-miss path: when a manifest, blob, or tag list is not found in the local DB /
/// blob store, <see cref="OciUpstreamResolver"/> is consulted. It probes the first matching
/// upstream registry (prefix-based routing), fetches with Bearer-token auth, verifies the blob
/// SHA-256 digest, writes to the Cache tier, and returns a stream the controller serves
/// directly. Subsequent requests for the same digest are served from cache without an upstream
/// round-trip.
///
/// Routing note: OCI repository names embed slashes (e.g. <c>library/ubuntu</c>), so all v2
/// paths route through a single <c>{**path}</c> handler that parses the suffix manually.
///
/// Errors use the OCI Distribution Spec error response shape.
/// </summary>
[ApiController]
public sealed class OciController : OrgScopedControllerBase
{
    private readonly OciControllerServices _svc;
    private readonly ILogger<OciController> _logger;

    public OciController(OciControllerServices svc, ILogger<OciController> logger)
    {
        _svc = svc;
        _logger = logger;
    }

    // Route-level hard ceiling for OCI upload requests (2048 MiB matches the OCI default).
    private const long OciUploadSizeLimitBytes = 2048L * 1024 * 1024;

    // Referrer scan cap: repositories with more manifests return an incomplete list (valid per OCI 1.1).
    private const int OciReferrersScanCap = 10000;

    /// <summary>
    /// GET dispatcher — parses the v2 path suffix and routes to manifest / blob / tags
    /// handlers. An empty or null <paramref name="path"/> is the Distribution Spec auth probe
    /// (Docker daemon hits it before any pull/push).
    /// </summary>
    [HttpGet("/v2/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Get(string? path, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(path))
        {
            return await PingAsync(ct);
        }

        var route = OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.Manifest => await ServeManifestAsync(route.Name, route.Reference!, headOnly: false, ct),
                OciRouteKind.Blob => await ServeBlobAsync(route.Name, route.Reference!, headOnly: false, ct),
                OciRouteKind.TagsList => await ListTagsAsync(route.Name, ct),
                OciRouteKind.Referrers => await ListReferrersAsync(route.Name, route.Reference!, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// HEAD dispatcher — same shape as GET but no body.
    /// </summary>
    [HttpHead("/v2/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Head(string? path, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(path))
        {
            return await PingAsync(ct);
        }

        var route = OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.Manifest => await ServeManifestAsync(route.Name, route.Reference!, headOnly: true, ct),
                OciRouteKind.Blob => await ServeBlobAsync(route.Name, route.Reference!, headOnly: true, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// POST dispatcher — begins a blob upload session (<c>/blobs/uploads</c>). A monolithic
    /// single-POST (<c>?digest=</c> with the full body) is finalized inline.
    /// </summary>
    [HttpPost("/v2/{**path}")]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(OciUploadSizeLimitBytes)] // hard ceiling matching the 2048 MB OCI default; UploadSizeLimitMiddleware + the cumulative check enforce tighter per-tenant caps
    public async Task<IActionResult> Post(string? path, CancellationToken ct)
    {
        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.BlobUploadInit => await HandleUploadInitAsync(route.Name, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>PATCH dispatcher — appends a chunk to an open blob upload session.</summary>
    [HttpPatch("/v2/{**path}")]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(OciUploadSizeLimitBytes)] // hard ceiling matching the 2048 MB OCI default; UploadSizeLimitMiddleware + the cumulative check enforce tighter per-tenant caps
    public async Task<IActionResult> Patch(string? path, CancellationToken ct)
    {
        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.BlobUploadSession => await HandleUploadChunkAsync(route.Name, route.Reference!, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// PUT dispatcher — finalizes a blob upload (<c>/blobs/uploads/{id}?digest=</c>) or stores
    /// a manifest (<c>/manifests/{reference}</c>).
    /// </summary>
    [HttpPut("/v2/{**path}")]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(OciUploadSizeLimitBytes)] // hard ceiling matching the 2048 MB OCI default; UploadSizeLimitMiddleware + the cumulative check enforce tighter per-tenant caps
    public async Task<IActionResult> Put(string? path, CancellationToken ct)
    {
        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.BlobUploadSession => await HandleBlobFinalizeAsync(route.Name, route.Reference!, ct),
                OciRouteKind.Manifest => await HandleManifestPutAsync(route.Name, route.Reference!, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// DELETE dispatcher — manifest delete by digest or tag, blob delete (405 per spec).
    /// Requires <c>yank:oci</c> capability (same gate as the management-API delete).
    /// </summary>
    [HttpDelete("/v2/{**path}")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> Delete(string? path, CancellationToken ct)
    {
        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.Manifest => await HandleManifestDeleteAsync(route.Name, route.Reference!, ct),
                OciRouteKind.Blob => HandleBlobDeleteNotAllowed(),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    // ── Action handlers ────────────────────────────────────────────────────────

    private async Task<IActionResult> ServeManifestAsync(
        string name, string reference, bool headOnly, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID,
                "Invalid repository or reference.");
        }

        string orgId = CurrentTenantId();

        // Local cache first; on a miss (unknown reference or evicted blob), fall through
        // to the upstream proxy.
        var local = await TryServeLocalManifestAsync(orgId, name, coords, headOnly, auth.Token, ct);
        return local ?? await ServeUpstreamManifestAsync(orgId, name, reference, coords.IsDigest, headOnly, auth.Token, ct);
    }

    /// <summary>
    /// Serves a manifest from the local DB / blob store. Returns <c>null</c> when the
    /// manifest is not available locally (unresolved tag, no blob record, or the blob has
    /// been evicted from the store), signalling the caller to fall through to upstream.
    /// </summary>
    private async Task<IActionResult?> TryServeLocalManifestAsync(
        string orgId, string name, OciCoordinates coords, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        // Resolve tag → digest first (returns the reference unchanged if it's already a digest).
        string? resolved = await ResolveDigestAsync(orgId, coords, ct);
        if (resolved is null)
        {
            return null;
        }

        // xtenant: (digest, org_id) PK is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        // deepcode ignore Sqli: Dapper binds @digest/@orgId as parameters; SQL string is a constant literal.
        var (MediaType, SizeBytes, BlobKey, Origin) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest = resolved, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        if (headOnly)
        {
            // HEAD: confirm the blob is still present without opening a stream.
            bool exists = await BlobTierFor(Origin).ExistsAsync(BlobKey, ct);
            if (!exists)
            {
                // Blob evicted — fall through to upstream.
                return null;
            }

            SetManifestHeaders(resolved, SizeBytes, MediaType, "HIT", coords.IsDigest);
            return Ok();
        }

        var stream = await BlobTierFor(Origin).GetAsync(BlobKey, ct);
        if (stream is null)
        {
            // Blob evicted from store — fall through to upstream.
            return null;
        }

        SetManifestHeaders(resolved, SizeBytes, MediaType, "HIT", coords.IsDigest);

        // "download" is the canonical fetch event across ecosystems (npm/PyPI/NuGet)
        // and the only one the Audit page filter knows; the PURL digest distinguishes
        // a manifest pull from a layer pull, so a dedicated event name isn't needed.
        //
        // OCI is deliberately omitted from the package_versions.download_count counter:
        // one `docker pull` fans out into a manifest GET plus N layer-blob GETs (which
        // would multi-count a single pull), and the bare digest PURL logged here doesn't
        // match the version row's canonical PURL (which carries ?repository_url=…&tag=…).
        // OCI download volume is still tracked org-wide via these activity rows.
        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{resolved}", "download",
            actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(stream, MediaType!);
    }

    /// <summary>
    /// Fetches a manifest through the upstream proxy on a local cache miss; the resolver
    /// caches it so subsequent requests are served locally. On HEAD, only the manifest
    /// metadata (digest, size, media type) is fetched — no body is downloaded.
    /// </summary>
    private async Task<IActionResult> ServeUpstreamManifestAsync(
        string orgId, string name, string reference, bool isDigest, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        if (headOnly)
        {
            // HEAD: fetch only response headers from upstream to avoid downloading the full
            // manifest body. The resolver issues a HEAD request; the response headers carry
            // Docker-Content-Digest and Content-Length which are sufficient to satisfy the
            // OCI spec HEAD contract.
            var meta = await _svc.Upstream.FetchManifestMetadataAsync(
                orgId, name, reference, isDigest, ct);
            if (meta is null)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                    $"Manifest unknown: {reference}");
            }

            SetManifestHeaders(meta.Digest, meta.SizeBytes, meta.MediaType, "MISS", isDigest);
            return Ok();
        }

        var upstreamResult = await _svc.Upstream.FetchManifestAsync(
            orgId, name, reference, isDigest, ct);
        if (upstreamResult is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                $"Manifest unknown: {reference}");
        }

        SetManifestHeaders(upstreamResult.Digest, upstreamResult.SizeBytes, upstreamResult.MediaType, "MISS", isDigest);
        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{upstreamResult.Digest}", "download",
            actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(upstreamResult.Content, upstreamResult.MediaType);
    }

    /// <summary>
    /// Sets the manifest response headers shared by the local-cache and upstream paths.
    /// Digest-addressed manifests are content-addressed and immutable; tag-addressed
    /// manifests may be updated, so they get a short TTL only.
    /// </summary>
    private void SetManifestHeaders(string digest, long sizeBytes, string? mediaType, string cacheStatus, bool isDigest)
    {
        Response.Headers["Docker-Content-Digest"] = digest;
        Response.Headers["Content-Length"] = sizeBytes.ToString();
        Response.Headers["X-Cache"] = cacheStatus;
        Response.ContentType = mediaType;
        if (isDigest)
        {
            Response.Headers.ETag = $"\"{digest}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        else
        {
            Response.Headers.CacheControl = "private, max-age=60";
        }
    }

    private async Task<IActionResult> ServeBlobAsync(
        string name, string digest, bool headOnly, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        if (!OciCoordinatesParser.IsValidRepositoryName(name))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        }

        if (!OciCoordinatesParser.IsValidDigest(digest))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID, "Invalid digest format.");
        }

        string orgId = CurrentTenantId();

        // Local cache first; on a miss (no blob record or evicted blob), fall through
        // to the upstream proxy.
        var local = await TryServeLocalBlobAsync(orgId, name, digest, headOnly, auth.Token, ct);
        return local ?? await ServeUpstreamBlobAsync(orgId, name, digest, headOnly, auth.Token, ct);
    }

    /// <summary>
    /// Serves a blob from the local DB / blob store, honouring an optional single-range
    /// Range header. Returns <c>null</c> when no blob record exists or the blob has been
    /// evicted from the store, signalling the caller to fall through to upstream.
    /// </summary>
    private async Task<IActionResult?> TryServeLocalBlobAsync(
        string orgId, string name, string digest, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        // xtenant: (digest, org_id) PK is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        // deepcode ignore Sqli: Dapper binds @digest/@orgId as parameters; SQL string is a constant literal.
        var (MediaType, SizeBytes, BlobKey, Origin) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        var blob = new ResolvedLocalBlob(BlobTierFor(Origin), BlobKey, SizeBytes, MediaType);

        // Advertise byte-range support on every blob response (GET and HEAD).
        Response.Headers.AcceptRanges = "bytes";
        Response.Headers["Docker-Content-Digest"] = digest;
        Response.Headers["Content-Length"] = SizeBytes.ToString();
        Response.Headers["X-Cache"] = "HIT";
        Response.ContentType = MediaType;

        if (headOnly)
        {
            return Ok();
        }

        // Parse an optional Range header and attempt a ranged read.
        var ranged = await TryServeRangedBlobAsync(blob, orgId, name, digest, token, ct);
        if (ranged is not null)
        {
            return ranged;
        }

        var stream = await blob.Tier.GetAsync(blob.BlobKey, ct);
        if (stream is null)
        {
            // Blob evicted — fall through to upstream.
            return null;
        }

        Response.Headers["Docker-Content-Digest"] = digest;
        Response.Headers["Content-Length"] = SizeBytes.ToString();
        Response.Headers["X-Cache"] = "HIT";
        Response.ContentType = MediaType;
        // OCI blobs are always digest-addressed and content-addressed — immutable by definition.
        Response.Headers.ETag = $"\"{digest}\"";
        Response.Headers.CacheControl = "private, max-age=31536000, immutable";

        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{digest}", "download",
            actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(stream, MediaType!);
    }

    /// <summary>
    /// Attempts a ranged (206) read of a locally stored blob. Returns <c>null</c> when the
    /// request carries no valid Range header, or when the blob has been evicted between
    /// the record lookup and the ranged read — the caller falls back to a full read.
    /// </summary>
    private async Task<IActionResult?> TryServeRangedBlobAsync(
        ResolvedLocalBlob blob, string orgId, string name, string digest,
        TokenRecord? token, CancellationToken ct)
    {
        if (!TryParseRangeHeader(out long rangeFrom, out long rangeTo))
        {
            return null;
        }

        var ranged = await blob.Tier.GetRangeAsync(blob.BlobKey, rangeFrom, rangeTo, ct);
        if (ranged is null)
        {
            return null;
        }

        await using (ranged)
        {
            // Sentinel From > To means the requested start is past the end of the
            // blob — clear the pre-set full-size Content-Length before returning 416
            // so Kestrel does not emit a body-size mismatch on the wire.
            if (ranged.From > ranged.To)
            {
                Response.Headers.Remove("Content-Length");
                Response.Headers.ContentRange = $"bytes */{blob.SizeBytes}";
                return StatusCode(StatusCodes.Status416RangeNotSatisfiable);
            }

            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{digest}", "download",
                actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

            Response.Headers.ContentRange = $"bytes {ranged.From}-{ranged.To}/{ranged.TotalLength}";
            Response.Headers["Content-Length"] = (ranged.To - ranged.From + 1).ToString();
            Response.StatusCode = StatusCodes.Status206PartialContent;
            Response.ContentType = blob.MediaType;
            await ranged.Content.CopyToAsync(Response.Body, ct);
            return new EmptyResult();
        }
    }

    /// <summary>
    /// Fetches a blob through the upstream proxy on a local cache miss. On HEAD, only
    /// upstream headers are fetched — no body is downloaded. Range requests against
    /// upstream blobs fall back to a full 200 — the upstream fetch stores the blob
    /// locally, so a retry after the cache-miss uses the ranged path.
    /// </summary>
    private async Task<IActionResult> ServeUpstreamBlobAsync(
        string orgId, string name, string digest, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        if (headOnly)
        {
            // HEAD: issue a HEAD request to upstream to confirm existence without
            // downloading the full blob body (which may be gigabytes for large layers).
            var meta = await _svc.Upstream.FetchBlobMetadataAsync(orgId, name, digest, ct);
            if (meta is null)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}");
            }

            Response.Headers.AcceptRanges = "bytes";
            Response.Headers["Docker-Content-Digest"] = digest;
            Response.Headers["X-Cache"] = "MISS";
            Response.ContentType = meta.MediaType;
            Response.Headers.ETag = $"\"{digest}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
            return Ok();
        }

        var upstreamResult = await _svc.Upstream.FetchBlobAsync(orgId, name, digest, ct);
        if (upstreamResult is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}");
        }

        Response.Headers.AcceptRanges = "bytes";
        Response.Headers["Docker-Content-Digest"] = digest;
        Response.Headers["X-Cache"] = "MISS";
        Response.ContentType = upstreamResult.MediaType;
        Response.Headers.ETag = $"\"{digest}\"";
        Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{digest}", "download",
            actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(upstreamResult.Content, upstreamResult.MediaType);
    }

    /// <summary>
    /// Parses the <c>Range: bytes=from-to</c> header on the current request. Supports the
    /// common single-range form only (multi-range is not required by the OCI Distribution
    /// Spec and is not used by Docker or containerd). Returns <c>false</c> when no Range
    /// header is present, when the header uses a non-bytes unit, or when the range is
    /// syntactically invalid (missing or non-numeric start/end). Suffix ranges
    /// (<c>bytes=-N</c>) are treated as invalid and return <c>false</c> — byte-range pulls
    /// from resumable downloads always use an explicit start byte.
    /// </summary>
    private bool TryParseRangeHeader(out long from, out long to)
    {
        from = 0;
        to = long.MaxValue;

        string? raw = Request.Headers.Range.FirstOrDefault();
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }

        // Expect exactly "bytes=from-to" or "bytes=from-".
        const string prefix = "bytes=";
        if (!raw.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string range = raw[prefix.Length..];
        int dash = range.IndexOf('-');
        if (dash < 0)
        {
            return false;
        }

        string startStr = range[..dash];
        string endStr = range[(dash + 1)..];

        if (!long.TryParse(startStr, out from) || from < 0)
        {
            return false;
        }

        // Open-ended range (bytes=from-) — serve from `from` to the end.
        if (string.IsNullOrEmpty(endStr))
        {
            to = long.MaxValue;
            return true;
        }

        if (!long.TryParse(endStr, out to) || to < 0)
        {
            return false;
        }

        // Inverted range (from > to) is syntactically invalid.
        return from <= to;
    }

    // Maximum page size for tags/list responses. OCI clients that request n= larger than
    // this receive exactly this many tags with a Link: rel="next" header when more exist.
    private const int TagsMaxPageSize = 1000;

    private async Task<IActionResult> ListTagsAsync(string name, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        if (!OciCoordinatesParser.IsValidRepositoryName(name))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        }

        string orgId = CurrentTenantId();

        var (n, nZero) = ParseTagsPageSize();
        // last=: lexical continuation token — return tags strictly after this value.
        string? last = Request.Query["last"].FirstOrDefault();

        // OCI spec: n=0 returns an empty tag list with no Link header.
        if (nZero)
        {
            return new JsonResult(new { name, tags = Array.Empty<string>() });
        }

        // ── Local tag list ─────────────────────────────────────────────────────
        // xtenant: (org_id, repository) index is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var localTags = (await conn.QueryAsync<string>(
            "SELECT tag FROM oci_tags WHERE org_id = @orgId AND repository = @repo ORDER BY tag ASC",
            new { orgId, repo = name })).ToList();

        var upstreamTags = await FetchUpstreamTagsOrDegradeAsync(name, ct);
        var allTags = MergeTags(localTags, upstreamTags);

        return allTags.Count == 0
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.NAME_UNKNOWN, "Repository unknown.")
            : BuildTagsPage(name, allTags, n, last);
    }

    /// <summary>
    /// Parses the <c>n=</c> page-size query parameter on the current request: the number of
    /// results per page (clamped to <see cref="TagsMaxPageSize"/>). <c>n=0</c> returns an
    /// empty list per the OCI Distribution Spec; omitted or negative values use the page maximum.
    /// </summary>
    private (int N, bool NZero) ParseTagsPageSize()
    {
        if (!Request.Query.TryGetValue("n", out var nVal) ||
            !int.TryParse(nVal.FirstOrDefault(), out int nParsed))
        {
            return (TagsMaxPageSize, false);
        }

        if (nParsed == 0)
        {
            return (TagsMaxPageSize, true);
        }

        return nParsed > 0
            ? (Math.Min(nParsed, TagsMaxPageSize), false)
            : (TagsMaxPageSize, false);
    }

    /// <summary>
    /// Fetches the upstream tag list (attempted when the proxy is enabled), degrading to
    /// <c>null</c> — a local-only listing — on failure. AirGappedException means upstream is
    /// intentionally unreachable; any other transport failure is also degraded so a network
    /// error never 503s a local listing.
    /// </summary>
    private async Task<List<string>?> FetchUpstreamTagsOrDegradeAsync(string name, CancellationToken ct)
    {
        try
        {
            return await _svc.Upstream.FetchTagsAsync(CurrentTenantId(), name, ct);
        }
        catch (AirGappedException)
        {
            // Air-gap mode: upstream unreachable by design; serve local tags only.
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Transport or parse failure: degrade to local tags; a warning is already
            // emitted inside FetchTagsAsync for the upstream-error case.
            _ = ex; // suppressed; logged upstream
            return null;
        }
    }

    /// <summary>
    /// Merged listing: local union upstream, deduplicated, sorted lexically.
    /// Local tags win on collision only in the sense that one name always maps to
    /// exactly one digest — the tag name list itself is just strings, no collision.
    /// </summary>
    private static List<string> MergeTags(List<string> localTags, List<string>? upstreamTags)
    {
        if (upstreamTags is not { Count: > 0 })
        {
            return localTags;
        }

        // Union: add upstream tags not already present locally.
        var merged = new SortedSet<string>(localTags, StringComparer.Ordinal);
        foreach (string t in upstreamTags)
        {
            merged.Add(t);
        }
        return new List<string>(merged);
    }

    /// <summary>
    /// Applies the <c>last=</c> continuation and the page size to the merged tag list,
    /// emitting a Link header when a further page exists.
    /// </summary>
    private JsonResult BuildTagsPage(string name, List<string> allTags, int n, string? last)
    {
        IEnumerable<string> filtered = allTags;
        if (!string.IsNullOrEmpty(last))
        {
            filtered = allTags.Where(t => string.Compare(t, last, StringComparison.Ordinal) > 0);
        }

        var page = filtered.Take(n + 1).ToList(); // fetch one extra to detect "has next page"
        bool hasMore = page.Count > n;
        if (hasMore)
        {
            page.RemoveAt(page.Count - 1);
        }

        if (hasMore && page.Count > 0)
        {
            string lastTag = page[^1];
            // RFC 5988 Link header for pagination continuation per the OCI Distribution Spec.
            Response.Headers.Link = $"</v2/{name}/tags/list?n={n}&last={lastTag}>; rel=\"next\"";
        }

        return new JsonResult(new { name, tags = page });
    }

    // OCI image index media type used for referrers API responses (OCI 1.1).
    private const string OciImageIndexMediaType = "application/vnd.oci.image.index.v1+json";

    /// <summary>
    /// GET /v2/{name}/referrers/{digest} — OCI 1.1 Referrers API.
    ///
    /// Returns an OCI image index listing all manifests in this org's repository whose
    /// subject.digest matches the requested digest. Supports optional artifactType filter
    /// via the ?artifactType= query parameter.
    ///
    /// Implementation scans stored manifest blobs for this repository and parses each for
    /// a subject field — acceptable at community scale where repository sizes are bounded.
    /// The scan is capped at 10,000 manifests to bound parse time on large repos.
    /// </summary>
    private async Task<IActionResult> ListReferrersAsync(string name, string digest, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        if (!OciCoordinatesParser.IsValidRepositoryName(name))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        }

        if (!OciCoordinatesParser.IsValidDigest(digest))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID, "Invalid digest format.");
        }

        string? artifactTypeFilter = Request.Query["artifactType"].FirstOrDefault();
        string orgId = CurrentTenantId();

        // Fetch all manifest digests for this repository from the org's oci_tags table to
        // identify candidates, then scan the manifest blobs for subject.digest matches.
        // xtenant: org_id filters ensure only this tenant's manifests are examined.
        await using var conn = await _svc.Db.OpenAsync(ct);
        // Collect distinct manifest digests associated with this repository (via tags).
        // Cap at OciReferrersScanCap to bound scan time; repositories with more manifests than
        // this cap return an incomplete referrers list, which is valid per the OCI 1.1 spec
        // (clients follow pagination, but here we return a single page with what we have).
        // rawsql: ORDER BY + LIMIT on a constant; not user input.
        var candidateDigests = (await conn.QueryAsync<string>(
            "SELECT DISTINCT digest FROM oci_tags WHERE org_id = @orgId AND repository = @repo LIMIT " + (OciReferrersScanCap + 1),
            new { orgId, repo = name })).ToList();
        if (candidateDigests.Count > OciReferrersScanCap)
        {
            candidateDigests.RemoveAt(candidateDigests.Count - 1);
            // deepcode ignore LogForging: name is a repository route segment; Serilog structured logging sanitises it.
            _logger.LogWarning(
                "OCI referrers scan for {Repository} hit the 10,000-manifest cap; response may be incomplete.",
                name);
        }

        var descriptors = await ScanManifestsForReferrersAsync(
            orgId, conn, candidateDigests, digest, artifactTypeFilter, ct);

        if (!string.IsNullOrEmpty(artifactTypeFilter))
        {
            Response.Headers["OCI-Filters-Applied"] = "artifactType";
        }

        Response.ContentType = OciImageIndexMediaType;
        var index = new
        {
            schemaVersion = 2,
            mediaType = OciImageIndexMediaType,
            manifests = descriptors.Select(d => new
            {
                mediaType = d.MediaType,
                digest = d.Digest,
                size = d.SizeBytes,
                artifactType = d.ArtifactType,
                annotations = d.Annotations,
            }).ToArray(),
        };
        return new JsonResult(index);
    }

    // Scans candidate manifest digests for entries whose subject.digest matches the target
    // digest, applying the optional artifactType filter. Returns the matching referrer descriptors.
    private async Task<List<OciReferrerDescriptor>> ScanManifestsForReferrersAsync(
        string orgId, System.Data.Common.DbConnection conn, List<string> candidateDigests,
        string targetDigest, string? artifactTypeFilter, CancellationToken ct)
    {
        var descriptors = new List<OciReferrerDescriptor>();
        foreach (string candidateDigest in candidateDigests)
        {
            // xtenant: (digest, org_id) PK is tenant-scoped.
            var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
                "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
                "FROM oci_blobs WHERE digest = @d AND org_id = @orgId",
                new { d = candidateDigest, orgId });

            if (BlobKey is null)
            {
                continue;
            }

            // Read and parse the manifest blob to check for a subject.digest match.
            var tier = BlobTierFor("uploaded"); // referrers only apply to locally pushed manifests
            var stream = await tier.GetAsync(BlobKey, ct);
            if (stream is null)
            {
                continue;
            }

            byte[] bytes;
            await using (stream)
            {
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms, ct);
                bytes = ms.ToArray();
            }

            var referrer = OciReferrerParser.TryParseReferrer(
                bytes, candidateDigest, MediaType ?? OciImageIndexMediaType, SizeBytes, targetDigest);
            if (referrer is null)
            {
                continue;
            }

            if (!string.IsNullOrEmpty(artifactTypeFilter) &&
                !string.Equals(referrer.ArtifactType, artifactTypeFilter, StringComparison.Ordinal))
            {
                continue;
            }

            descriptors.Add(referrer);
        }
        return descriptors;
    }

    /// <summary>
    /// DELETE /v2/{name}/manifests/{reference} — protocol-level manifest delete.
    ///
    /// Digest form: removes the manifest oci_blobs record and all oci_tags rows pointing
    /// to that digest within this org, then deletes the blob from the Registry tier only
    /// for uploaded manifests. The lookup matches the digest regardless of origin (a pushed
    /// manifest can carry origin='proxy' through content-addressed dedup), so digest-
    /// addressed delete works for any locally catalogued manifest. Shared cache blobs are
    /// never deleted (other tenants may reference the same content-addressed key; GC is the
    /// right mechanism for unreferenced cache blobs).
    ///
    /// Tag form: removes only the tag record (untag only — spec-compliant behaviour for
    /// tag deletion). The manifest blob and its digest-addressed record remain intact.
    ///
    /// Requires yank:oci capability — the same gate as the management-API delete.
    /// </summary>
    private async Task<IActionResult> HandleManifestDeleteAsync(string name, string reference, CancellationToken ct)
    {
        var (token, error) = await AuthorizeYankAsync(ct);
        if (error is not null)
        {
            return error;
        }

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository or reference.");
        }

        string orgId = CurrentTenantId();
        await using var conn = await _svc.Db.OpenAsync(ct);

        if (coords.IsDigest)
        {
            // Digest delete: find the blob record for this org regardless of origin, remove
            // all tags pointing to it, then remove the blob record. Origin is not filtered:
            // OCI blobs are content-addressed, so a pushed manifest whose digest was first
            // seen via the proxy keeps origin='proxy' (the upsert never rewrites origin) —
            // filtering on origin='uploaded' here made delete-by-digest 404 for those
            // round-trippable manifests. Physical deletion is still gated on origin below.
            // xtenant: (digest, org_id) PK ensures this is scoped to the caller's org.
            var (blobKey, origin) = await conn.QuerySingleOrDefaultAsync<(string? BlobKey, string? Origin)>(
                "SELECT blob_key AS BlobKey, origin AS Origin FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                new { digest = reference, orgId });

            if (blobKey is null)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                    $"Manifest unknown: {reference}");
            }

            // Remove all tags in this org's repository pointing to this digest.
            // xtenant: org_id filter ensures cross-org isolation.
            await conn.ExecuteAsync(
                "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND digest = @digest",
                new { orgId, repo = name, digest = reference });

            // Remove the manifest blob record for this org.
            // xtenant: (digest, org_id) PK.
            await conn.ExecuteAsync(
                "DELETE FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                new { digest = reference, orgId });

            // Physical delete applies only to Registry-tier (uploaded) blobs. Proxy blobs
            // live in the Cache tier and are content-addressed, shared across tenants — blob
            // GC reclaims unreferenced cache entries, so we never delete them here.
            if (origin == "uploaded")
            {
                // OCI blob keys are content-addressed with no org segment — two orgs pushing
                // the same digest share one physical blob. Count remaining rows for this
                // blob_key across all orgs before deleting the physical file.
                // xtenant: refcount guard before physical delete of shared content-addressed blob
                int remainingRefs = await conn.ExecuteScalarAsync<int>(
                    "SELECT COUNT(*) FROM oci_blobs WHERE blob_key = @key",
                    new { key = blobKey });

                if (remainingRefs == 0)
                {
                    await _svc.BlobStore.Registry.DeleteAsync(blobKey, ct);
                }
            }

            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{reference}", "delete",
                actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

            return NoContent();
        }
        else
        {
            // Tag delete: remove only the tag record. Manifest blob and its digest record
            // remain intact so digest-addressed pulls still work (spec: tag deletion
            // removes the name→digest mapping, not the manifest content).
            // xtenant: (org_id, repository, tag) PK.
            int deleted = await conn.ExecuteAsync(
                "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
                new { orgId, repo = name, tag = reference });

            if (deleted == 0)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                    $"Tag unknown: {reference}");
            }

            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}:{reference}", "delete",
                actorId: token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

            return NoContent();
        }
    }

    /// <summary>
    /// DELETE /v2/{name}/blobs/{digest} — blob deletion is not supported.
    /// Registries MAY disallow blob deletion per the OCI Distribution Spec; ours relies
    /// on org-scoped GC for unreferenced blob cleanup.
    /// </summary>
    private static ObjectResult HandleBlobDeleteNotAllowed()
        => OciError(StatusCodes.Status405MethodNotAllowed, OciErrorCode.UNSUPPORTED,
            "Blob deletion is not supported; use the manifest delete endpoint.");

    // ── Helpers ────────────────────────────────────────────────────────────────

    // Advertise Basic, not Bearer: a Bearer challenge's realm must be the absolute
    // URL of a token endpoint, which we do not run. ResolveTokenAsync accepts
    // base64(user:PAT) over Basic — the same scheme PyPI/NuGet/Maven advertise — so
    // docker/skopeo authenticate without a token-exchange flow.
    private const string BasicChallenge = "Basic realm=\"dependably\"";

    /// <summary>
    /// The Distribution-Spec <c>/v2/</c> ping is the auth-discovery endpoint: docker,
    /// skopeo and containerd hit it first and read <c>WWW-Authenticate</c> to decide
    /// whether — and how — to authenticate. Answering 200 with no challenge makes a
    /// client conclude the registry needs no auth and send every later request
    /// (including the manifest <c>PUT</c>) anonymously, so push fails at the first
    /// authed write. Challenge an unauthenticated ping so clients switch into
    /// Basic-auth mode; a credential-less client retries reads without auth, which the
    /// read endpoints still serve when anonymous pull is allowed.
    /// </summary>
    private async Task<IActionResult> PingAsync(CancellationToken ct)
    {
        Response.Headers["Docker-Distribution-API-Version"] = "registry/2.0";
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required.");
        }
        return Ok();
    }

    private async Task<(TokenRecord? Token, IActionResult? Unauthorized)> AuthorizePullAsync(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        return (token, null);
    }

    // ── Push handlers ────────────────────────────────────────────────────────────

    private async Task<IActionResult> HandleUploadInitAsync(string name, CancellationToken ct)
    {
        var (_, Error) = await AuthorizePushAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        if (!OciCoordinatesParser.IsValidRepositoryName(name))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        }

        string orgId = CurrentTenantId();
        OciUploadSession session;
        try
        {
            session = await _svc.Uploads.StartUploadAsync(orgId, name, ct);
        }
        catch (OciSessionCapExceededException ex)
        {
            _logger.LogWarning(
                "OCI upload session cap reached for org {OrgId}: {Active}/{Cap}",
                ex.OrgId, ex.ActiveCount, ex.Cap);
            return OciError(StatusCodes.Status429TooManyRequests, OciErrorCode.DENIED,
                $"Too many concurrent upload sessions for this tenant (cap: {ex.Cap}).");
        }

        // Monolithic single-POST: ?digest=sha256:... carries the full blob in this request.
        string? digest = Request.Query["digest"].FirstOrDefault();
        if (!string.IsNullOrEmpty(digest))
        {
            return await CompleteBlobAsync(orgId, session, name, digest, ct);
        }

        Response.Headers.Location = $"/v2/{name}/blobs/uploads/{session.UploadId}";
        Response.Headers["Docker-Upload-UUID"] = session.UploadId;
        Response.Headers.Range = "0-0";
        return StatusCode(StatusCodes.Status202Accepted);
    }

    private async Task<IActionResult> HandleUploadChunkAsync(string name, string uploadId, CancellationToken ct)
    {
        var (_, Error) = await AuthorizePushAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        string orgId = CurrentTenantId();
        var session = await _svc.Uploads.GetSessionAsync(orgId, uploadId, ct);
        if (session is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UPLOAD_UNKNOWN, "Upload session unknown.");
        }

        var (total, sizeError) = await AppendWithLimitAsync(orgId, session, ct);
        if (sizeError is not null)
        {
            return sizeError;
        }

        Response.Headers.Location = $"/v2/{name}/blobs/uploads/{uploadId}";
        Response.Headers["Docker-Upload-UUID"] = uploadId;
        Response.Headers.Range = $"0-{(total > 0 ? total - 1 : 0)}";
        return StatusCode(StatusCodes.Status202Accepted);
    }

    private async Task<IActionResult> HandleBlobFinalizeAsync(string name, string uploadId, CancellationToken ct)
    {
        var (_, Error) = await AuthorizePushAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        string orgId = CurrentTenantId();
        var session = await _svc.Uploads.GetSessionAsync(orgId, uploadId, ct);
        if (session is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UPLOAD_UNKNOWN, "Upload session unknown.");
        }

        string? digest = Request.Query["digest"].FirstOrDefault();
        return string.IsNullOrEmpty(digest)
            ? OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID, "Missing digest query parameter.")
            : await CompleteBlobAsync(orgId, session, name, digest, ct);
    }

    /// <summary>
    /// Appends any request body to the session (the PUT final chunk, or the full blob for a
    /// monolithic POST — an empty body is a no-op), enforces the cumulative size limit, then
    /// verifies + stores the blob. Shared by the monolithic-POST and PUT-finalize paths.
    /// </summary>
    private async Task<IActionResult> CompleteBlobAsync(
        string orgId, OciUploadSession session, string name, string digest, CancellationToken ct)
    {
        if (!OciCoordinatesParser.IsValidDigest(digest))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID, "Invalid digest format.");
        }

        var (_, sizeError) = await AppendWithLimitAsync(orgId, session, ct);
        if (sizeError is not null)
        {
            return sizeError;
        }

        var result = await _svc.Uploads.FinalizeBlobAsync(orgId, session, digest, ct);
        switch (result.Status)
        {
            case OciFinalizeStatus.Ok:
                Response.Headers.Location = $"/v2/{name}/blobs/{result.Digest}";
                Response.Headers["Docker-Content-Digest"] = result.Digest!;
                return StatusCode(StatusCodes.Status201Created);
            case OciFinalizeStatus.BadDigest:
                return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID,
                    "Unsupported digest algorithm (only sha256 is accepted on push).");
            case OciFinalizeStatus.DigestMismatch:
                return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID,
                    "Uploaded content does not match the provided digest.");
            case OciFinalizeStatus.QuotaExceeded:
                return OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                    "Tenant storage quota would be exceeded by this blob upload.");
            default:
                return OciError(StatusCodes.Status500InternalServerError, OciErrorCode.BLOB_UPLOAD_INVALID, "Upload failed.");
        }
    }

    private async Task<IActionResult> HandleManifestPutAsync(string name, string reference, CancellationToken ct)
    {
        var (Token, Error) = await AuthorizePushAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository or reference.");
        }

        string? mediaType = Request.ContentType;
        if (mediaType is not null)
        {
            int semi = mediaType.IndexOf(';');
            if (semi >= 0)
            {
                mediaType = mediaType[..semi].Trim();
            }
        }
        if (!OciManifestParser.IsAcceptedMediaType(mediaType))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.MANIFEST_INVALID,
                "Unsupported or missing manifest media type.");
        }

        string orgId = CurrentTenantId();

        byte[] bytes;
        await using (var ms = new MemoryStream())
        {
            await Request.Body.CopyToAsync(ms, ct);
            bytes = ms.ToArray();
        }

        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        long limit = await _svc.Orgs.GetUploadLimitAsync(settings, "oci", ct);
        if (bytes.Length > limit)
        {
            return OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                $"Manifest exceeds the oci upload limit of {limit} bytes.");
        }

        var result = await _svc.Uploads.StoreManifestAsync(orgId, name, reference, bytes, mediaType!, ct);
        switch (result.Status)
        {
            case OciManifestStatus.Ok:
                await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{result.Digest}", "push",
                    actorId: Token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
                Response.Headers.Location = $"/v2/{name}/manifests/{result.Digest}";
                Response.Headers["Docker-Content-Digest"] = result.Digest!;
                return StatusCode(StatusCodes.Status201Created);
            case OciManifestStatus.MissingBlob:
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_BLOB_UNKNOWN,
                    $"Referenced blob not present: {result.MissingDigest}");
            case OciManifestStatus.QuotaExceeded:
                return OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                    "Tenant storage quota would be exceeded by this manifest push.");
            default:
                return OciError(StatusCodes.Status400BadRequest, OciErrorCode.MANIFEST_INVALID,
                    "Manifest is not valid JSON or has no recognizable structure.");
        }
    }

    /// <summary>
    /// Streams the request body into the session and enforces the cumulative per-tenant OCI
    /// upload limit (chunked pushes can exceed it across requests even when each chunk's
    /// Content-Length is small). Aborts the session and returns a 413 on breach.
    /// </summary>
    private async Task<(long Total, IActionResult? Error)> AppendWithLimitAsync(
        string orgId, OciUploadSession session, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        long limit = await _svc.Orgs.GetUploadLimitAsync(settings, "oci", ct);
        long total = await _svc.Uploads.AppendChunkAsync(orgId, session, Request.Body, ct);
        if (total > limit)
        {
            await _svc.Uploads.AbortUploadAsync(orgId, session, ct);
            return (total, OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                $"Upload exceeds the oci upload limit of {limit} bytes."));
        }
        return (total, null);
    }

    private async Task<(TokenRecord? Token, IActionResult? Error)> AuthorizePushAsync(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        if (!token.HasCapability(Capabilities.PublishOci))
        {
            return (null, OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
                "Insufficient scope: publish:oci required."));
        }

        return (token, null);
    }

    private async Task<(TokenRecord? Token, IActionResult? Error)> AuthorizeYankAsync(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        if (!token.HasCapability(Capabilities.YankOci))
        {
            return (null, OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
                "Insufficient scope: yank:oci required."));
        }

        return (token, null);
    }

    private async Task<string?> ResolveDigestAsync(string orgId, OciCoordinates coords, CancellationToken ct)
    {
        if (coords.IsDigest)
        {
            return coords.Reference;
        }

        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT digest FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = coords.Repository, tag = coords.Reference });
    }

    /// <summary>
    /// Returns the blob-store tier to read from based on the <c>origin</c> column.
    /// Proxy blobs live in the Cache tier (eviction-friendly); hosted blobs in Registry.
    /// </summary>
    private IBlobStore BlobTierFor(string? origin)
        => origin == "proxy" ? _svc.BlobStore.Cache : _svc.BlobStore.Registry;

    /// <summary>
    /// A locally catalogued blob resolved for serving: the tier it lives in, its storage
    /// key, and the content metadata stamped on the response.
    /// </summary>
    private sealed record ResolvedLocalBlob(IBlobStore Tier, string BlobKey, long SizeBytes, string? MediaType);

    private static ObjectResult OciError(int statusCode, OciErrorCode code, string message)
    {
        var body = new OciErrorResponse(new[] { new OciError(code, message) });
        return new ObjectResult(body) { StatusCode = statusCode };
    }
}

/// <summary>Parses a v2 path suffix into one of three Distribution-Spec verbs.</summary>
internal sealed record OciRoute(OciRouteKind Kind, string Name, string? Reference)
{
    public static OciRoute? Parse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        path = path.Trim('/');

        // Tags list: trailing "/tags/list".
        const string tagsSuffix = "/tags/list";
        if (path.EndsWith(tagsSuffix, StringComparison.Ordinal))
        {
            string name = path[..^tagsSuffix.Length];
            return name.Length > 0 ? new OciRoute(OciRouteKind.TagsList, name, null) : null;
        }

        // Referrers: "/referrers/{digest}" somewhere after the repo name.
        const string referrersMarker = "/referrers/";
        int referrersIdx = path.IndexOf(referrersMarker, StringComparison.Ordinal);
        if (referrersIdx > 0)
        {
            string name = path[..referrersIdx];
            string reference = path[(referrersIdx + referrersMarker.Length)..];
            return reference.Length > 0 ? new OciRoute(OciRouteKind.Referrers, name, reference) : null;
        }

        // Manifests: "/manifests/{reference}" somewhere after the repo name.
        const string manifestsMarker = "/manifests/";
        int manifestsIdx = path.IndexOf(manifestsMarker, StringComparison.Ordinal);
        if (manifestsIdx > 0)
        {
            string name = path[..manifestsIdx];
            string reference = path[(manifestsIdx + manifestsMarker.Length)..];
            return reference.Length > 0 ? new OciRoute(OciRouteKind.Manifest, name, reference) : null;
        }

        // Blobs: "/blobs/{digest}" (pull) or the push upload sub-paths.
        const string blobsMarker = "/blobs/";
        int blobsIdx = path.IndexOf(blobsMarker, StringComparison.Ordinal);
        return blobsIdx > 0 ? ParseBlobs(path[..blobsIdx], path[(blobsIdx + blobsMarker.Length)..]) : null;
    }

    /// <summary>Resolves the "/blobs/…" tail into a pull, an upload-init, or an upload-session verb.</summary>
    private static OciRoute? ParseBlobs(string name, string rest)
    {
        // Push: "/blobs/uploads" begins a session; "/blobs/uploads/{id}" advances one.
        if (rest == "uploads")
        {
            return new OciRoute(OciRouteKind.BlobUploadInit, name, null);
        }

        const string uploadsPrefix = "uploads/";
        if (rest.StartsWith(uploadsPrefix, StringComparison.Ordinal))
        {
            string uploadId = rest[uploadsPrefix.Length..];
            return uploadId.Length > 0 ? new OciRoute(OciRouteKind.BlobUploadSession, name, uploadId) : null;
        }

        return rest.Length > 0 ? new OciRoute(OciRouteKind.Blob, name, rest) : null;
    }
}

internal enum OciRouteKind { Manifest, Blob, TagsList, BlobUploadInit, BlobUploadSession, Referrers }

/// <summary>Scoped DI bundle for the OCI controller.</summary>
public sealed record OciControllerServices(
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    TieredBlobStorage BlobStore,
    IMetadataStore Db,
    OciUpstreamResolver Upstream,
    OciUploadService Uploads);
