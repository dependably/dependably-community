using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

// Blob read (local cache, ranged reads, upstream proxy) and the full upload/push chain (session
// init, chunk append, finalize). Split out of OciController.cs (partial class) to keep any single
// file under the 1000-line cap; see that file for the dispatchers, shared auth helpers, and the
// OciControllerServices bundle.
public sealed partial class OciController
{
    private async Task<IActionResult> ServeBlobAsync(
        string name, string digest, bool headOnly, CancellationToken ct)
    {
        // allowPushProbe only on HEAD: docker/BuildKit HEAD a blob's digest before uploading it,
        // to skip re-uploading a layer the registry already holds — a normal existence probe a
        // publish-only token must still pass. A GET of the same route returns the actual layer
        // bytes, which is real pull content and stays gated behind pull:oci/read:artifact.
        var auth = await AuthorizePullAsync(ct, allowPushProbe: headOnly);
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
        // Dapper binds @digest/@orgId as parameters; SQL string is a constant literal.
        var (MediaType, SizeBytes, BlobKey, Origin, LicenseSpdx) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin, string? LicenseSpdx)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin, license_spdx AS LicenseSpdx " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        string purl = $"pkg:oci/{name}@{digest}";

        // Block gate before any bytes and before any URL. A manifest is reachable by its digest
        // through this route too, so the license arm runs here on exactly the same terms it runs
        // on the manifest route.
        if (await EvaluateLicenseBlockAsync(orgId, purl, LicenseSpdx, token, ct) is { } blocked)
        {
            return blocked;
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

        // Presigned redirect, when enabled and the tier can sign. Reached only after the pull
        // authorization, the digest validation, the tenant-scoped row lookup, and the block gate
        // above have all passed — there is no earlier return that mints a URL, and a refusal on
        // any of them leaves this code unreached.
        var redirect = await TryRedirectToPresignedBlobAsync(blob, orgId, purl, token, ct);
        if (redirect is not null)
        {
            return redirect;
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

        await RecordBlobDownloadAsync(orgId, purl, token, ct);
        return File(stream, MediaType!);
    }

    /// <summary>
    /// Answers a full (non-ranged) digest-addressed blob GET with a <c>307</c> to a short-lived
    /// presigned URL, so the layer bytes move from the object store straight to the client.
    /// Returns <c>null</c> whenever the read must be streamed instead — the feature is off, the
    /// tier cannot sign, or the blob is no longer in the store.
    ///
    /// <para>
    /// The Distribution Spec explicitly permits a registry to redirect a blob GET, and a blob is
    /// addressed by its own digest, so the content behind the URL cannot change under the client
    /// and the URL cannot go stale in the way a tag-addressed one would. Nothing mutable and
    /// nothing not digest-addressed is redirected: manifests (tags move), tag lists, and the
    /// upstream cache-miss path all keep streaming.
    /// </para>
    ///
    /// <para>
    /// <c>307</c> rather than <c>302</c> keeps the method and headers intact, which is what makes
    /// a client's HEAD stay a HEAD. The redirect itself carries <c>no-store</c>: the response body
    /// is a bearer credential with a minutes-or-less lifetime and must not be cached by a proxy or
    /// a CDN, even though the blob it points at is immutable.
    /// </para>
    ///
    /// <para>
    /// The download is recorded before the redirect is written, so the activity row lands on
    /// exactly the same terms as on the streaming path. What the redirect cannot observe is
    /// whether the client then completed the transfer — that is true of a streamed response the
    /// client abandons as well, but a redirect additionally means a replay of the URL inside its
    /// TTL is invisible here. The short TTL is what bounds that, and it is why the feature is
    /// opt-in.
    /// </para>
    /// </summary>
    private async Task<IActionResult?> TryRedirectToPresignedBlobAsync(
        ResolvedLocalBlob blob, string orgId, string purl, TokenRecord? token, CancellationToken ct)
    {
        if (_svc.Presign is not { Enabled: true } presign)
        {
            return null;
        }

        var url = await presign.TryCreateAsync(blob.Tier, blob.BlobKey, ct);
        if (url is null)
        {
            return null;
        }

        // Content-Length was pre-set to the blob size for the streamed response; a 307 carries no
        // body, so leaving it would put a body-size mismatch on the wire.
        Response.Headers.Remove("Content-Length");
        Response.ContentType = null;
        Response.Headers.CacheControl = "private, no-store";

        await RecordBlobDownloadAsync(orgId, purl, token, ct);
        return new RedirectResult(url.Value.Url.ToString(), permanent: false, preserveMethod: true);
    }

    /// <summary>
    /// The one download-telemetry call the local blob read path makes, so the streamed, ranged,
    /// and redirected answers cannot drift apart. OCI stays out of the
    /// <c>package_versions.download_count</c> counter for the reason spelled out on the manifest
    /// path — one <c>docker pull</c> is a manifest GET plus N layer GETs — so this activity row is
    /// the whole of it.
    /// </summary>
    private Task RecordBlobDownloadAsync(string orgId, string purl, TokenRecord? token, CancellationToken ct)
        => _svc.Audit.LogActivityAsync(orgId, "oci", purl, "download",
            actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

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

            await RecordBlobDownloadAsync(orgId, $"pkg:oci/{name}@{digest}", token, ct);

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
    /// <remarks>
    /// Air-gap is answered here rather than by the middleware, for the reason spelled out on
    /// <c>AirGappedManifestMiss</c>: a 503 tells the client to retry for content that will never
    /// arrive. A layer blob is pulled once per image, so the retry storm is per-layer.
    /// </remarks>
    private async Task<IActionResult> ServeUpstreamBlobAsync(
        string orgId, string name, string digest, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        if (headOnly)
        {
            // HEAD: issue a HEAD request to upstream to confirm existence without
            // downloading the full blob body (which may be gigabytes for large layers).
            OciBlobMetadata? meta;
            try
            {
                meta = await _svc.Upstream.FetchBlobMetadataAsync(orgId, name, digest, ct);
            }
            catch (AirGappedException)
            {
                return AirGappedBlobMiss(name, digest);
            }
            catch (Exception ex) when (IsUpstreamFailure(ex, ct))
            {
                return UpstreamUnreachable(ex, name, digest);
            }

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

        OciBlobResult? upstreamResult;
        try
        {
            upstreamResult = await _svc.Upstream.FetchBlobAsync(orgId, name, digest, ct);
        }
        catch (AirGappedException)
        {
            return AirGappedBlobMiss(name, digest);
        }
        catch (Exception ex) when (IsUpstreamFailure(ex, ct))
        {
            return UpstreamUnreachable(ex, name, digest);
        }

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
            actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(upstreamResult.Content, upstreamResult.MediaType);
    }

    /// <summary>The blob counterpart of <c>AirGappedManifestMiss</c> — see that method for why 404.</summary>
    private static ObjectResult AirGappedBlobMiss(string name, string digest) =>
        OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN,
            $"Blob unknown: {digest}. This instance is air-gapped, so {name} was not fetched from "
            + "an upstream registry; only locally held content is available.");

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

    /// <summary>
    /// DELETE /v2/{name}/blobs/{digest} — blob deletion is not supported.
    /// Registries MAY disallow blob deletion per the OCI Distribution Spec; ours relies
    /// on org-scoped GC for unreferenced blob cleanup.
    /// </summary>
    private static ObjectResult HandleBlobDeleteNotAllowed()
        => OciError(StatusCodes.Status405MethodNotAllowed, OciErrorCode.UNSUPPORTED,
            "Blob deletion is not supported; use the manifest delete endpoint.");


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

        // Cross-repository blob mount: ?mount=<digest>&from=<repo> asks the registry to reuse
        // a blob already known to this org instead of re-uploading it. oci_blobs is keyed by
        // (digest, org_id) rather than per-repository, so any blob previously pushed or cached
        // anywhere in the org satisfies a mount regardless of the "from" repo — no upload
        // session is created and no bytes are transferred. When the digest is missing,
        // malformed, or not found, this falls through to the normal upload-session flow: per
        // the Distribution Spec, a failed mount is not an error, the client just uploads normally.
        string? mountDigest = Request.Query["mount"].FirstOrDefault();
        string? mountFrom = Request.Query["from"].FirstOrDefault();
        if (!string.IsNullOrEmpty(mountDigest) && !string.IsNullOrEmpty(mountFrom)
            && OciCoordinatesParser.IsValidDigest(mountDigest)
            && await _svc.Uploads.BlobExistsAsync(orgId, mountDigest, ct))
        {
            Response.Headers.Location = $"/v2/{name}/blobs/{mountDigest}";
            Response.Headers["Docker-Content-Digest"] = mountDigest;
            return StatusCode(StatusCodes.Status201Created);
        }

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

        // The Distribution Spec makes Content-Range optional on PATCH but requires that, when it
        // is sent, an out-of-order chunk is refused with 416. Checking it before the append keeps
        // a client that resumes from the wrong offset from silently producing a blob that only
        // fails to hash at finalize.
        if (ValidateContentRange(session) is { } rangeError)
        {
            return rangeError;
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
    /// <summary>
    /// Streams the request body into the session and enforces the cumulative per-tenant OCI
    /// upload limit (chunked pushes can exceed it across requests even when each chunk's
    /// Content-Length is small). Aborts the session and returns a 413 on breach.
    ///
    /// A staging-continuity violation surfaces here as <see cref="OciUploadRangeException"/> and
    /// becomes a 416 rather than propagating: the append never happened, so the session is intact
    /// and resumable.
    /// </summary>
    private async Task<(long Total, IActionResult? Error)> AppendWithLimitAsync(
        string orgId, OciUploadSession session, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        long limit = await _svc.Orgs.GetUploadLimitAsync(settings, "oci", ct);

        long total;
        try
        {
            total = await _svc.Uploads.AppendChunkAsync(orgId, session, Request.Body, ct);
        }
        catch (OciUploadRangeException ex)
        {
            return (session.ReceivedBytes, RangeNotSatisfiable(ex));
        }

        if (total > limit)
        {
            await _svc.Uploads.AbortUploadAsync(orgId, session, ct);
            return (total, OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                $"Upload exceeds the oci upload limit of {limit} bytes."));
        }
        return (total, null);
    }

    /// <summary>
    /// Validates a chunked PATCH's <c>Content-Range</c> against the session's recorded progress,
    /// returning null when the chunk may proceed. That is the case when the header is absent — it
    /// is optional per the Distribution Spec, and docker/containerd omit it — or when the chunk
    /// starts exactly where the session left off.
    ///
    /// A header that cannot be parsed is passed rather than refused: the staging-continuity check
    /// in <see cref="OciUploadService.AppendChunkAsync"/> is the authoritative guard, and it reads
    /// the file the bytes actually land in rather than what the client claims about them.
    /// </summary>
    private ObjectResult? ValidateContentRange(OciUploadSession session)
    {
        string? header = Request.Headers.ContentRange.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        // OCI sends a bare "<start>-<end>", not RFC 7233's "bytes <start>-<end>/<total>"; accept
        // the RFC-shaped spelling too rather than refusing a client that is being more correct
        // than the spec requires.
        var value = header.AsSpan().Trim();
        if (value.StartsWith("bytes ", StringComparison.OrdinalIgnoreCase))
        {
            value = value["bytes ".Length..].Trim();
        }

        int slash = value.IndexOf('/');
        if (slash >= 0)
        {
            value = value[..slash];
        }

        int dash = value.IndexOf('-');
        return dash <= 0 || !long.TryParse(value[..dash], out long start) || start == session.ReceivedBytes
            ? null
            : RangeNotSatisfiable(new OciUploadRangeException(session.UploadId, session.ReceivedBytes, start));
    }

    /// <summary>
    /// Renders a chunk-discontinuity refusal as 416 with the <c>Range</c> the session is actually
    /// at, so a client (or an operator reading the log) can see where to resume instead of
    /// discovering at finalize that the staged bytes hash to the wrong digest.
    /// </summary>
    private ObjectResult RangeNotSatisfiable(OciUploadRangeException ex)
    {
        _logger.LogWarning(
            "OCI chunk rejected for upload {UploadId}: session is at {ExpectedOffset} bytes, chunk presented {ActualOffset}. " +
            "A missing staging file means the request reached a replica that does not own the session — check upload session affinity.",
            ex.UploadId, ex.ExpectedOffset, ex.ActualOffset);

        Response.Headers["Docker-Upload-UUID"] = ex.UploadId;
        Response.Headers.Range = $"0-{(ex.ExpectedOffset > 0 ? ex.ExpectedOffset - 1 : 0)}";
        return OciError(StatusCodes.Status416RangeNotSatisfiable, OciErrorCode.BLOB_UPLOAD_INVALID,
            ex.ActualOffset is null
                ? "Upload session has no staged content on this replica; chunked uploads require session affinity."
                : $"Chunk is not contiguous with the upload; expected it to start at byte {ex.ExpectedOffset}.");
    }
}
