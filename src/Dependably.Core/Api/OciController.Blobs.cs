using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http.Features;
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
        // to the upstream proxy. An edge whose master gates the org (or whose last 'off' is older
        // than the freshness bound) reads manifest bytes through the master even on this route;
        // layers stay served from the edge's own cache.
        bool throughMaster = await MustAskMasterAsync(orgId, ct) && await IsHeldManifestAsync(orgId, digest, ct);
        var local = throughMaster ? null : await TryServeLocalBlobAsync(orgId, name, digest, headOnly, auth.Token, ct);
        return local ?? await ServeUpstreamBlobAsync(orgId, name, digest, headOnly, auth.Token, ct, throughMaster);
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

        // Canonical purl-spec form via PurlNormalizer — the single source of package identity.
        // No tag: this route is digest-addressed by definition.
        string purl = PurlNormalizer.Oci(name, digest);

        // Block gate before any bytes and before any URL. A manifest is reachable by its digest
        // through this route too, so the license arm runs here on exactly the same terms it runs
        // on the manifest route. Under scan enforcement the stored media type is not trusted to
        // say what the bytes are: a manifest fetched through this route is often stored under a
        // generic type, so it is recognised by what the org knows of the digest or by its bytes.
        string? manifestType = OciManifestParser.IsAcceptedMediaType(MediaType) ? MediaType
            : await IsScanEnforcedAsync(orgId, ct)
                ? await IsManifestBlobAsync(
                    orgId, digest, MediaType, SizeBytes,
                    readCt => ProbeStoredBlobAsync(BlobTierFor(Origin), BlobKey, SizeBytes, readCt), ct)
                : null;
        if (OciManifestParser.IsAcceptedMediaType(manifestType))
        {
            // The bytes were recognised as a manifest stored under a generic label: answer with
            // the manifest's own type, so a caching edge stores what the bytes are.
            MediaType = manifestType;
        }

        if (await EvaluateOciPullGateAsync(
                orgId, name, digest, LicenseSpdx, token, ct, gatesManifest: manifestType is not null) is { } blocked)
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

        // Presigned redirect, when enabled for OCI and the tier can sign. Reached only after the
        // pull authorization, the digest validation, the tenant-scoped row lookup, and the block
        // gate above have all passed — there is no earlier return that mints a URL, and a refusal
        // on any of them leaves this code unreached. The Distribution Spec explicitly permits a
        // registry to redirect a blob GET, and a blob is addressed by its own digest, so the URL
        // cannot go stale the way a tag-addressed one would; manifests, tag lists, and the
        // upstream cache-miss path all keep streaming. The origin is the row's, never the key's:
        // an uploaded layer and a proxied one with the same digest share a blob key.
        if (_svc.Presign is { } presign
            && await presign.TryRedirectAsync(
                HttpContext, blob.Tier, blob.BlobKey, blob.SizeBytes, BlobOrigins.FromColumn(Origin), "oci", ct) is { } redirect)
        {
            await RecordBlobDownloadAsync(orgId, purl, token, ct);
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

            await RecordBlobDownloadAsync(orgId, PurlNormalizer.Oci(name, digest), token, ct);

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
        string orgId, string name, string digest, bool headOnly, TokenRecord? token, CancellationToken ct,
        bool throughMaster = false)
    {
        if (headOnly)
        {
            return await ServeUpstreamBlobHeadAsync(orgId, name, digest, token, throughMaster, ct);
        }

        // Stream-through: the resolver commits headers and starts the body as soon as upstream
        // answers, instead of after the whole layer has landed.
        bool gateManifests = await IsScanEnforcedAsync(orgId, ct);
        bool knownManifest = await IsHeldAsManifestAsync(orgId, digest, gateManifests, ct);
        var sink = CreateUpstreamBlobSink(digest, gateManifests, holdAll: knownManifest);

        var (upstreamResult, failure) = await FetchUpstreamBlobAsync(orgId, name, digest, token, sink, throughMaster, ct);
        if (failure is not null)
        {
            return failure;
        }

        if (upstreamResult is null)
        {
            return OrAbortIfStarted(
                OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}"));
        }

        await _svc.Audit.LogActivityAsync(orgId, "oci", PurlNormalizer.Oci(name, digest), "download",
            actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        if (upstreamResult.Streamed)
        {
            // The sink already carried every byte; the response is complete.
            return new EmptyResult();
        }

        var blob = upstreamResult.Blob!;

        // Not streamed, so the response should not have begun. If it somehow did — a sink that
        // committed the response and then failed — sending a second body would be worse than
        // sending none, so reset instead.
        if (Response.HasStarted)
        {
            await blob.Content.DisposeAsync();
            HttpContext.Abort();
            return new EmptyResult();
        }

        if (!gateManifests)
        {
            SetUpstreamBlobHeaders(digest, blob.MediaType);
            return File(blob.Content, blob.MediaType);
        }

        var (content, probe) = await BufferBlobCandidateAsync(digest, blob, ct);
        if (content is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}");
        }

        string? manifestType = await IsManifestBlobAsync(
            orgId, digest, await ReadBlobMediaTypeAsync(orgId, digest, blob.MediaType, ct), content.CanSeek ? content.Length : null,
            _ => Task.FromResult(probe), ct);
        if (await EvaluateOciPullGateAsync(
                orgId, name, digest, await ReadStampedLicenseAsync(orgId, digest, ct), token, ct,
                gatesManifest: manifestType is not null) is { } refused)
        {
            await content.DisposeAsync();
            return refused;
        }

        // A manifest recognised by its bytes is answered under its manifest type, so an edge
        // caching this answer stores what the bytes are rather than the upstream's generic label.
        string servedType = OciManifestParser.IsAcceptedMediaType(manifestType) ? manifestType! : blob.MediaType;
        SetUpstreamBlobHeaders(digest, servedType);
        return File(content, servedType);
    }

    // Whether a blob is held back from streaming because the org already knows its digest as a
    // manifest. Stream-through hands the resolver somewhere to mirror the layer into, so it
    // commits headers and starts the body as soon as upstream answers. The distinction is
    // invisible on a small blob and decisive on a large one: a store-and-forward pull of a
    // multi-gigabyte layer sends nothing for minutes, which no reverse proxy's read timeout
    // tolerates. Under scan enforcement only a blob that cannot be a manifest streams through:
    // one larger than any manifest, and not labelled as one. The upstream's label never proves a
    // smaller blob is not a manifest (Docker distribution labels a manifest read through this
    // route application/octet-stream, and nothing stops an upstream calling one a layer), so
    // every smaller blob is cached first and checked by its bytes before any byte is sent. A
    // digest the org already knows as a manifest is held whatever its size, so it reaches the
    // gate however the upstream labels it and however large it says it is.
    private async Task<bool> IsHeldAsManifestAsync(string orgId, string digest, bool gateManifests, CancellationToken ct) =>
        gateManifests && _svc.PullGate is { } pullGate && await pullGate.IsKnownManifestAsync(orgId, digest, ct);

    // An upstream blob fetch whose every failure is mapped to the response the client gets. A
    // failure may arrive after the sink already began the response, so each one aborts rather
    // than writing a second body.
    private async Task<(OciBlobServeResult? Result, IActionResult? Failure)> FetchUpstreamBlobAsync(
        string orgId, string name, string digest, TokenRecord? token, OciBlobStreamSink? sink, bool throughMaster,
        CancellationToken ct)
    {
        try
        {
            var result = await _svc.Upstream.FetchBlobAsync(orgId, name, digest, ct, sink, throughMaster);
            return (result, null);
        }
        catch (AirGappedException)
        {
            return (null, OrAbortIfStarted(AirGappedBlobMiss(name, digest)));
        }
        catch (OciPassthroughOffException)
        {
            return (null, OrAbortIfStarted(PassthroughOffBlobMiss(name, digest)));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return (null, OrAbortIfStarted(ClientWentAway(name, digest)));
        }
        catch (OciBlobRefusedException ex)
        {
            return (null, OrAbortIfStarted(BlobRefused(ex, name, digest, token)));
        }
        catch (OciUpstreamRefusedException ex)
        {
            return (null, OrAbortIfStarted(MasterRefusal(ex)));
        }
        catch (Exception ex) when (IsUpstreamFailure(ex, ct))
        {
            return (null, throughMaster && !Response.HasStarted
                ? await ServeThroughMasterOutageAsync(orgId, name, digest, HttpMethods.IsHead(Request.Method), token, ex, ct)
                : OrAbortIfStarted(UpstreamUnreachable(ex, name, digest)));
        }
    }

    /// <summary>
    /// The blob-route answer for a held manifest digest read through a master that cannot be
    /// reached: refused for an org whose last-known posture is <c>warn</c> or <c>block</c>,
    /// otherwise served from the edge's own cache as it would be with no gate, and 502 only when
    /// the edge does not hold it.
    /// </summary>
#pragma warning disable S107 // the request coordinates plus the failure being answered
    private async Task<IActionResult> ServeThroughMasterOutageAsync(
        string orgId, string name, string digest, bool headOnly, TokenRecord? token, Exception ex, CancellationToken ct)
#pragma warning restore S107
    {
        if (await MasterOutageGatedPostureAsync(orgId, ct) is { } gated)
        {
            return MasterOutageRefusal(gated, name, digest, ex);
        }

        if (await TryServeLocalBlobAsync(orgId, name, digest, headOnly, token, ct) is { } local)
        {
            _logger.LogWarning(
                "OCI master unreachable for {Repository}@{Digest} ({ExceptionType}); served from the edge cache, as "
                + "the org's last-known master posture does not gate it.",
                name, digest, ex.GetType().Name);
            return local;
        }

        return UpstreamUnreachable(ex, name, digest);
    }

    // A blob that could still be a manifest is buffered so its bytes can be checked and still
    // sent. One that is too large, or whose first byte shows it is not a JSON document, is not
    // buffered; it is reopened to send, since the check consumed part of the stream. Content is
    // null when the reopen finds nothing.
    private async Task<(Stream? Content, BlobProbe Probe)> BufferBlobCandidateAsync(
        string digest, OciBlobResult blob, CancellationToken ct)
    {
        if (await OciManifestParser.ReadManifestCandidateAsync(blob.Content, ct) is { } candidate)
        {
            return (candidate, BlobProbe.Candidate(candidate.TryGetBuffer(out var segment) ? segment : default));
        }

        await blob.Content.DisposeAsync();
        string[] parts = digest.Split(':', 2);
        var reopened = await _svc.BlobStore.Cache.GetAsync(BlobKeys.OciBlob(parts[0], parts[^1]), ct);
        return (reopened, BlobProbe.NotAManifest);
    }

    /// <summary>
    /// HEAD on a cache miss: asks upstream for the blob's headers to confirm it exists without
    /// downloading the body, which may be gigabytes for a large layer. Under scan enforcement a
    /// blob that could be a manifest is acquired first and answered as a cache hit is
    /// (<see cref="AnswerHeadMissAsHitAsync"/>), so the same digest gets the same status either way.
    /// </summary>
    private async Task<IActionResult> ServeUpstreamBlobHeadAsync(
        string orgId, string name, string digest, TokenRecord? token, bool throughMaster, CancellationToken ct)
    {
        OciBlobMetadata? meta;
        try
        {
            meta = await _svc.Upstream.FetchBlobMetadataAsync(orgId, name, digest, ct, throughMaster);
        }
        catch (AirGappedException)
        {
            return AirGappedBlobMiss(name, digest);
        }
        catch (OciPassthroughOffException)
        {
            return PassthroughOffBlobMiss(name, digest);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return ClientWentAway(name, digest);
        }
        catch (OciBlobRefusedException ex)
        {
            return BlobRefused(ex, name, digest, token);
        }
        catch (OciUpstreamRefusedException ex)
        {
            return MasterRefusal(ex);
        }
        catch (Exception ex) when (IsUpstreamFailure(ex, ct))
        {
            return throughMaster
                ? await ServeThroughMasterOutageAsync(orgId, name, digest, headOnly: true, token, ex, ct)
                : UpstreamUnreachable(ex, name, digest);
        }

        if (meta is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}");
        }

        if (!IsPushProbe(token) && await IsScanEnforcedAsync(orgId, ct)
            && await AnswerHeadMissAsHitAsync(orgId, name, digest, meta, token, throughMaster, ct) is { } answered)
        {
            return answered;
        }

        SetUpstreamBlobHeaders(digest, meta.MediaType);
        return Ok();
    }

    /// <summary>
    /// Under scan enforcement, the answer to a blob-route HEAD miss for a blob that could be a
    /// manifest: one labelled as a manifest, one the org already knows as a manifest, or one no
    /// larger than a manifest may be (the upstream's label never proves a smaller blob is not one).
    /// The blob is fetched and cached, as the GET would, and the HEAD is then answered by the
    /// cache-hit path, which recognises a manifest by its bytes and gates it. Null for a blob too
    /// large to be a manifest, which keeps the headers-only answer, as its GET streams ungated;
    /// the manifest route refuses a manifest that large under enforcement. A push probe never
    /// reaches here: it downloads nothing and is answered from the headers.
    /// </summary>
#pragma warning disable S107 // the request coordinates plus the upstream headers already read
    private async Task<IActionResult?> AnswerHeadMissAsHitAsync(
        string orgId, string name, string digest, OciBlobMetadata meta, TokenRecord? token, bool throughMaster,
        CancellationToken ct)
#pragma warning restore S107
    {
        bool labelled = OciManifestParser.IsAcceptedMediaType(meta.MediaType);
        bool known = await IsHeldAsManifestAsync(orgId, digest, gateManifests: true, ct);
        if (!labelled && !known && meta.SizeBytes > OciManifestParser.ManifestSniffMaxBytes)
        {
            return null;
        }

        var (fetched, failure) = await FetchUpstreamBlobAsync(orgId, name, digest, token, sink: null, throughMaster, ct);
        if (failure is not null)
        {
            return failure;
        }

        if (fetched?.Blob is not { } blob)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}");
        }

        await blob.Content.DisposeAsync();
        if (await TryServeLocalBlobAsync(orgId, name, digest, headOnly: true, token, ct) is { } local)
        {
            Response.Headers["X-Cache"] = "MISS";
            return local;
        }

        // Fetched but not held (evicted between the two reads): gated on what the headers say.
        return await EvaluateOciPullGateAsync(
            orgId, name, digest, await ReadStampedLicenseAsync(orgId, digest, ct), token, ct,
            gatesManifest: labelled || known);
    }

    /// <summary>
    /// The sink a cache-miss GET streams the upstream layer through: it commits the response
    /// headers and starts the body as soon as upstream answers, and resets the connection when
    /// the resolver refuses bytes already on the wire.
    /// </summary>
    private OciBlobStreamSink CreateUpstreamBlobSink(string digest, bool holdManifests = false, bool holdAll = false)
    {
        return new OciBlobStreamSink(
            BeginAsync: async (mediaType, contentLength, beginCt) =>
            {
                SetUpstreamBlobHeaders(digest, mediaType);
                if (contentLength is { } declared)
                {
                    // Declared up front so the client can size the transfer and, more to the
                    // point, can tell a reset mid-layer from an honest end.
                    Response.ContentLength = declared;
                }

                await Response.StartAsync(beginCt);
                return Response.Body;
            },
            AbortAsync: () =>
            {
                // Reset rather than complete: the bytes already sent are ones this registry has
                // just decided it will not vouch for.
                HttpContext.Abort();
                return Task.CompletedTask;
            },
            AllowSynchronousWrites: () =>
            {
                // Requested only if the blob store turns out to copy the upstream body
                // synchronously, which Kestrel otherwise refuses on a response body. Granting it
                // up front would permit synchronous writes on every streamed blob response; asked
                // for on demand, the common deployment — a store that copies with CopyToAsync —
                // never grants it at all. Where it is granted, the thread it blocks is the one
                // the store's own synchronous copy already owns, so no additional worker is
                // consumed; the alternative, awaiting an async write from inside a synchronous
                // read, waits on a pool thread while holding one, which is the starvation this
                // avoids rather than causes.
                if (HttpContext.Features.Get<IHttpBodyControlFeature>() is { } bodyControl)
                {
                    bodyControl.AllowSynchronousIO = true;
                }
            })
        {
            // Under scan enforcement mirrors only a blob that cannot be a manifest: one larger than
            // any manifest is allowed to be. A blob the upstream labels with a manifest type, or one
            // the org already knows as a manifest, is always held, whatever its size.
            Mirrors = holdAll ? (_, _) => false
                : holdManifests
                ? (mediaType, length) => !OciManifestParser.IsAcceptedMediaType(mediaType)
                    && length > OciManifestParser.ManifestSniffMaxBytes
                : null,
        };
    }

    private async Task<bool> IsScanEnforcedAsync(string orgId, CancellationToken ct) =>
        (await _svc.Orgs.GetSettingsAsync(orgId, ct))?.OciScanEnforcement is "warn" or "block";

    /// <summary>
    /// Whether a blob read through the blob route is a manifest, under scan enforcement, and
    /// under which manifest media type: null when it is not. A manifest media type; a digest the
    /// org already knows as a manifest (catalogued, or listed by an index it holds); or bytes that
    /// parse as one, whatever type they were stored or labelled under. A blob larger than any
    /// manifest is not read, and is a manifest only when the org already knows its digest as one;
    /// any other is read once, and a layer stops at its first byte. When the bytes reveal a
    /// manifest stored under the
    /// wrong type, the row is corrected, so the next read does not need the bytes; when they
    /// prove a blob is not a manifest, that is remembered so later reads skip the read.
    /// </summary>
#pragma warning disable S107 // the blob's identity and stored facts plus how to read its bytes
    private async Task<string?> IsManifestBlobAsync(
        string orgId, string digest, string? storedType, long? sizeBytes,
        Func<CancellationToken, Task<BlobProbe>> probeBlob, CancellationToken ct)
#pragma warning restore S107
    {
        if (OciManifestParser.IsAcceptedMediaType(storedType))
        {
            return storedType;
        }

        if (sizeBytes > OciManifestParser.ManifestSniffMaxBytes)
        {
            // Too large to read, but a digest the org already knows as a manifest (a row cached
            // when manifests were allowed to be larger) is still one.
            return _svc.PullGate is { } sizedGate && await sizedGate.IsKnownManifestAsync(orgId, digest, ct)
                ? storedType ?? string.Empty
                : null;
        }

        bool known = _svc.PullGate is { } gate && await gate.IsKnownManifestAsync(orgId, digest, ct);
        if (!known && NonManifestBlobs.Contains(orgId, digest))
        {
            return null;
        }

        var probe = await probeBlob(ct);
        string? sniffed = probe.Kind == BlobProbeKind.Candidate
            ? OciManifestParser.SniffManifestMediaType(probe.Bytes)
            : null;
        if (sniffed is null)
        {
            if (probe.Kind != BlobProbeKind.Unavailable && !known)
            {
                // Content-addressed: bytes that are not a manifest never become one.
                NonManifestBlobs.Add(orgId, digest);
            }

            return known ? storedType ?? string.Empty : null;
        }

        await using var conn = await _svc.Db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE oci_blobs SET media_type = @sniffed WHERE digest = @digest AND org_id = @orgId",
            new { sniffed, digest, orgId });
        return sniffed;
    }

    private enum BlobProbeKind { Unavailable, NotAManifest, Candidate }

    // What reading a blob's leading bytes established: it cannot be a manifest (too large, or not
    // a JSON document), its whole content is in hand, or its bytes could not be read at all.
    private readonly record struct BlobProbe(BlobProbeKind Kind, ReadOnlyMemory<byte> Bytes)
    {
        public static BlobProbe Unavailable => new(BlobProbeKind.Unavailable, default);

        public static BlobProbe NotAManifest => new(BlobProbeKind.NotAManifest, default);

        public static BlobProbe Candidate(ArraySegment<byte> bytes) => new(BlobProbeKind.Candidate, bytes);
    }

    // The probe of a stored blob: its bytes when it could be a manifest, NotAManifest when its
    // recorded size or leading byte rules that out, Unavailable when the store no longer has it.
    private static async Task<BlobProbe> ProbeStoredBlobAsync(IBlobStore tier, string blobKey, long sizeBytes, CancellationToken ct)
    {
        if (sizeBytes > OciManifestParser.ManifestSniffMaxBytes)
        {
            return BlobProbe.NotAManifest;
        }

        await using var stream = await tier.GetAsync(blobKey, ct);
        if (stream is null)
        {
            return BlobProbe.Unavailable;
        }

        using var candidate = await OciManifestParser.ReadManifestCandidateAsync(stream, ct);
        return candidate is null
            ? BlobProbe.NotAManifest
            : BlobProbe.Candidate(candidate.TryGetBuffer(out var segment) ? segment : default);
    }

    // Digests proven, by their bytes, not to be manifests: bounded, in-process, keyed by tenant.
    private static readonly NonManifestBlobMemo NonManifestBlobs = new();

    private sealed class NonManifestBlobMemo
    {
        private const int Capacity = 8192;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<(string OrgId, string Digest), byte> _entries = new();

        public bool Contains(string orgId, string digest) => _entries.ContainsKey((orgId, digest));

        public void Add(string orgId, string digest)
        {
            if (_entries.Count >= Capacity)
            {
                _entries.Clear();
            }

            _entries[(orgId, digest)] = 0;
        }
    }

    // True when the org holds this digest as a manifest: recorded as one, known to its catalogue,
    // or (under a generic label) bytes that parse as one. An edge asks this for every blob read
    // of an org whose master gates it, so a manifest primed under a generic label still goes to
    // the master.
    private async Task<bool> IsHeldManifestAsync(string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (MediaType, SizeBytes, BlobKey, Origin) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        return BlobKey is not null
            && await IsManifestBlobAsync(
                orgId, digest, MediaType, SizeBytes,
                readCt => ProbeStoredBlobAsync(BlobTierFor(Origin), BlobKey, SizeBytes, readCt), ct) is not null;
    }

    // The media type recorded for a blob this org now holds: the oci_blobs row the fetch wrote,
    // falling back to what the serve result carried. A cache-store hit reports a generic octet
    // stream, so the row is the reliable answer to "is this a manifest".
    private async Task<string?> ReadBlobMediaTypeAsync(string orgId, string digest, string fallback, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT media_type FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId }) ?? fallback;
    }

    /// <summary>Response headers common to every cache-miss blob answer, streamed or not.</summary>
    private void SetUpstreamBlobHeaders(string digest, string mediaType)
    {
        Response.Headers.AcceptRanges = "bytes";
        Response.Headers["Docker-Content-Digest"] = digest;
        Response.Headers["X-Cache"] = "MISS";
        Response.ContentType = mediaType;
        Response.Headers.ETag = $"\"{digest}\"";
        Response.Headers.CacheControl = "private, max-age=31536000, immutable";
    }

    /// <summary>
    /// Substitutes an abort for a status once the response is already on the wire. A status is a
    /// promise made at the start of a response; after the first byte there is no way to retract
    /// it, so the only honest signal left is to reset the connection.
    /// </summary>
    private IActionResult OrAbortIfStarted(IActionResult result)
    {
        if (!Response.HasStarted)
        {
            return result;
        }

        HttpContext.Abort();
        return new EmptyResult();
    }

    /// <summary>
    /// The answer when the caller's own request was cancelled — nearly always the client, or a
    /// proxy in front of it, hanging up before the pull finished.
    ///
    /// <para>
    /// This is not a server fault and must not be reported as one. Left unhandled it surfaced as
    /// <c>500</c> with a full stack trace at Error level, which is wrong twice over: it tells a
    /// puller that this registry broke, so the puller retries from byte zero into whatever
    /// deadline just cut it off, and it fills the log with stack traces for the most ordinary
    /// event a byte-range-free multi-gigabyte transfer has. 504 says what happened — the transfer
    /// did not finish in the time available — and the fetch it interrupted keeps running in the
    /// background, so the next attempt can be a cache hit.
    /// </para>
    /// </summary>
    private ObjectResult ClientWentAway(string name, string digest)
    {
        _logger.LogInformation(
            "OCI blob {Repository}/{Digest}: the caller went away before the pull completed; the upstream fetch continues.",
            name, digest);

        return OciError(
            StatusCodes.Status504GatewayTimeout, OciErrorCode.UNAVAILABLE,
            $"Blob {digest} did not transfer completely for repository '{name}'; the fetch is continuing and a retry may be served from cache.");
    }

    /// <summary>
    /// The answer for a blob this registry declines to proxy, as distinct from one it does not have.
    ///
    /// <para>
    /// The status is the substance of the fix. Both refusals — a layer over
    /// <c>Oci:MaxBlobProxyBytes</c>, and bytes that did not hash to the digest they were
    /// requested under — used to arrive as <c>404 BLOB_UNKNOWN</c>, which asserts the content
    /// does not exist. It does exist; upstream was handing it over. A client acts on that and
    /// stops, and an operator reads "blob unknown" and concludes the cache is corrupt, which is
    /// the wrong place to look for either fault. 5xx is the honest class: the content is real and
    /// this registry did not deliver it. <see cref="OciErrorCode.UNAVAILABLE"/> with 502 is the
    /// posture this controller already takes for an upstream it could not reach
    /// (<c>UpstreamUnreachable</c>), so a refusal reuses it rather than minting a second
    /// vocabulary for the same "not delivered, not absent" claim.
    /// </para>
    ///
    /// <para>
    /// The status is unconditional; the explanation is not. <c>/v2/</c> blob reads are reachable
    /// without a credential whenever the org enables anonymous pull, and the upstream host is
    /// supply-chain topology — the same reason <c>ManifestUnknownAsync</c> withholds it. So an
    /// anonymous caller gets the class of answer and nothing that names where this org fetches
    /// from, while a caller holding a token for the org gets the fault, the host, and the
    /// setting to change. Returning 502 to everyone discloses nothing new: the unreachable-upstream
    /// path on this same route already answers 502 anonymously, so the status was never the
    /// signal that a route exists.
    /// </para>
    /// </summary>
    private ObjectResult BlobRefused(
        OciBlobRefusedException ex, string name, string digest, TokenRecord? token, string kind = "Blob")
    {
        bool authenticated = token is not null;

        _logger.LogWarning(
            "OCI {Kind} refused for {Repository}/{Digest}: {Fault}. {Reason}",
            kind.ToLowerInvariant(), name, digest, ex.Fault, ex.Message);

        string message = $"{kind} {digest} could not be served for repository '{name}'.";
        if (authenticated)
        {
            message += " " + ex.OperatorMessage;
        }

        // Structured form for tooling, authenticated callers only — the shape itself would
        // otherwise separate the two faults that the anonymous prose deliberately does not.
        object? detail = authenticated
            ? new Dictionary<string, object?>
            {
                ["repository"] = name,
                ["digest"] = digest,
                ["upstream"] = ex.UpstreamHost,
                ["fault"] = ex.Fault,
            }
            : null;

        return OciError(StatusCodes.Status502BadGateway, OciErrorCode.UNAVAILABLE, message, detail);
    }

    /// <summary>The blob counterpart of <c>AirGappedManifestMiss</c> — see that method for why 404.</summary>
    private static ObjectResult AirGappedBlobMiss(string name, string digest) =>
        OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN,
            $"Blob unknown: {digest}. This instance is air-gapped, so {name} was not fetched from "
            + "an upstream registry; only locally held content is available.");

    /// <summary>The blob counterpart of <c>PassthroughOffManifestMiss</c>.</summary>
    private static ObjectResult PassthroughOffBlobMiss(string name, string digest) =>
        OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN,
            $"Blob unknown: {digest}. Proxy passthrough is off for this organization, so {name} was not "
            + "fetched from an upstream registry; only locally held content is available.");

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
