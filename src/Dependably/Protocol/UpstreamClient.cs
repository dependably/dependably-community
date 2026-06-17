using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Protocol;


/// <summary>
/// Fetches blobs from upstream registries with:
///   - Thundering herd prevention (ConcurrentDictionary + Lazy deduplication)
///   - Per-ecosystem checksum verification before caching
///   - OpenTelemetry counters and inflight gauge (see DependablyMeter)
///   - Graceful shutdown: host-stopping token is linked into the actual HTTP fetch so
///     a slow upstream pull (30-min client timeout) does not outlive the drain window.
///     Client disconnects do NOT cancel the shared single-flight fetch — only host
///     shutdown does.
/// </summary>
public sealed class UpstreamClient
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IBlobStore _blobs;   // resolved to TieredBlobStorage.Cache
    private readonly AuditRepository _audit;
    private readonly IUpstreamUrlValidator _urlValidator;
    private readonly IAirGapMode _airGap;
    private readonly IStagingDiskInfo _stagingDiskInfo;
    private readonly long _stagingDiskFloorBytes;
    private readonly ILogger<UpstreamClient> _logger;
    private readonly string _stagingPath;
    private readonly CancellationToken _hostStopping;

    // Dedup in-flight blob fetches: only one upstream request per blob key at a time.
    // Single shared work item produces (sha, size, key) — no shared byte[]. Concurrent
    // waiters each independently open the cached blob after the lazy resolves.
    private readonly ConcurrentDictionary<string, Lazy<Task<UpstreamFetchResult>>> _inflight = new();

    // Dedup in-flight metadata fetches: only one upstream request per URL at a time.
    // Separate from _inflight because the result shape (UpstreamMetadataResponse) and
    // the key (URL, not blob key) are different — same single-flight pattern though.
    private readonly ConcurrentDictionary<string, Lazy<Task<UpstreamMetadataResponse>>> _metadataInflight = new();

    // Dedup in-flight artifact fetches for the no-pre-known-SHA case (npm tarballs,
    // NuGet flatcontainer). Keyed by upstream URL so concurrent first-fetches of the same
    // coordinate share one streaming fetch rather than buffering N independent copies.
    private readonly ConcurrentDictionary<string, Lazy<Task<UpstreamFetchResult>>> _urlInflight = new();

#pragma warning disable S107 // Dependency-injection constructor: the parameter list is the declared dependency set; grouping it into an aggregate would hide dependencies without adding cohesion.
    public UpstreamClient(
        IHttpClientFactory httpClientFactory,
        TieredBlobStorage blobs,
        AuditRepository audit,
        IUpstreamUrlValidator urlValidator,
        IAirGapMode airGap,
        IStagingDiskInfo stagingDiskInfo,
        StagingOptions stagingOptions,
        ILogger<UpstreamClient> logger,
        IHostApplicationLifetime? lifetime = null)
#pragma warning restore S107
    {
        _httpClientFactory = httpClientFactory;
        // Proxy fetches always land on the cache tier — they're recoverable, eviction-friendly,
        // and (in split-tier deployments) sit on cheaper storage than the registry.
        _blobs = blobs.Cache;
        _audit = audit;
        _urlValidator = urlValidator;
        _airGap = airGap;
        _stagingDiskInfo = stagingDiskInfo;
        _logger = logger;
        _hostStopping = lifetime?.ApplicationStopping ?? CancellationToken.None;

        // Staging dir for hash-and-stage MISS path, plus the hard floor for available
        // staging disk space — both resolved by StagingOptions so the path probed by
        // IStagingDiskInfo and the floor enforced here can't diverge.
        _stagingPath = stagingOptions.Path;
        _stagingDiskFloorBytes = stagingOptions.FloorBytes;
        // deepcode ignore PT: PROXY_STAGING_PATH is set by the operator deploying the container
        // (env var, secret manager, or compose file). The process trust boundary already covers
        // anyone who can set this env var — no further tenant-side input reaches the path.
        try { Directory.CreateDirectory(_stagingPath); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to create PROXY_STAGING_PATH directory {StagingPath}: {ExceptionType}",
                _stagingPath, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Streaming proxy fetch. On cache HIT, returns the blob-store stream
    /// directly so the controller can <c>File(stream, ...)</c> straight through to the
    /// response without ever materialising the artifact in memory. On cache MISS, streams
    /// upstream → local temp file (hashing inline) → verifies → uploads to blob store →
    /// re-opens the cached blob and returns it. Memory usage is bounded by the staging
    /// buffer regardless of concurrency.
    /// </summary>
    public async Task<(Stream Body, bool IsHit)> GetOrFetchStreamAsync(
        string blobKey,
        string upstreamUrl,
        ChecksumSpec? checksumSpec,
        string ecosystem,
        string? orgId = null,
        string? purl = null,
        CancellationToken ct = default)
    {
        var cached = await _blobs.GetAsync(blobKey, ct);
        if (cached is not null)
        {
            DependablyMeter.CacheLookups.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", "hit"));
            SnapshotCounters.IncrementCacheHit();
            // The caller (typically ControllerBase.File) owns dispose of the stream.
            return (cached, true);
        }

        DependablyMeter.CacheLookups.Add(1,
            new KeyValuePair<string, object?>("ecosystem", ecosystem),
            new KeyValuePair<string, object?>("outcome", "miss"));
        SnapshotCounters.IncrementCacheMiss();
        SnapshotCounters.IncrementProxyFetch();

        // Air-gapped deployments must never reach upstream on a cache miss. Cached
        // artefacts above still serve normally; only the fetch path is blocked. The
        // exception bubbles up to the AirGappedExceptionMiddleware which translates it
        // to a 503 with a clear body — better than a 504 timeout when egress is firewalled.
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(blobKey);
        }

        // Thundering herd dedup — only one fetch per blobKey in flight. The shared work
        // item produces (sha, size, blobKey) only; each waiter independently opens the
        // cached blob after the lazy resolves so no byte[] is shared. Use
        // CancellationToken.None so a disconnect by the first caller doesn't fault the
        // shared Lazy and cancel all other waiters. The cache write is idempotent.
        var lazy = _inflight.GetOrAdd(blobKey, _ => new Lazy<Task<UpstreamFetchResult>>(
            () => FetchAndStageAsync(upstreamUrl, checksumSpec, blobKey, ecosystem, orgId, purl, CancellationToken.None)));

        return await FetchWithTelemetryAsync(lazy, blobKey, ecosystem, upstreamUrl, checksumSpec, purl, ct);
    }

    // Awaits the deduped lazy fetch, emits OTel activity + metrics, and opens the cached blob
    // for the caller. All exception handling lives here to keep GetOrFetchStreamAsync linear.
    private async Task<(Stream Body, bool IsHit)> FetchWithTelemetryAsync(
        Lazy<Task<UpstreamFetchResult>> lazy,
        string blobKey, string ecosystem, string upstreamUrl,
        ChecksumSpec? checksumSpec, string? purl, CancellationToken ct)
    {
        using var activity = DependablyActivitySource.Source.StartActivity(
            "proxy.fetch", ActivityKind.Client);
        activity?.SetTag("dependably.ecosystem", ecosystem);
        activity?.SetTag("dependably.operation", "proxy.fetch");
        activity?.SetTag("dependably.tier", "cache");
        if (purl is not null)
        {
            activity?.SetTag("dependably.purl", purl);
        }

        if (checksumSpec is { Algorithm: ChecksumAlgorithm.Sha256, ExpectedValue: { } sha })
        {
            activity?.SetTag("dependably.sha256", sha);
        }

        var stopwatch = Stopwatch.StartNew();
        string outcome = "success";

        DependablyMeter.UpstreamInflightFetches.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            var result = await lazy.Value;
            var stream = await _blobs.GetAsync(result.BlobKey, ct)
                ?? throw new InvalidOperationException(
                    $"Blob {result.BlobKey} vanished between PutAsync and GetAsync.");
            return (stream, false);
        }
        catch (ChecksumException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "checksum mismatch");
            throw;
        }
        catch (UpstreamResponseTooLargeException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream response too large");
            throw;
        }
        catch (AirGappedException)
        {
            outcome = "blocked";
            activity?.SetStatus(ActivityStatusCode.Error, "air-gapped");
            throw;
        }
        catch (StagingDiskFullException)
        {
            outcome = "staging_disk_full";
            activity?.SetStatus(ActivityStatusCode.Error, "staging disk full");
            throw;
        }
        catch (UpstreamFetchFailedException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream fetch failed");
            throw;
        }
        catch (Exception ex)
        {
            outcome = "server_error";
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            _logger.LogWarning(
                ex,
                "Upstream fetch failed: {ExceptionType} for {Ecosystem} {BlobKey} from {UpstreamUrl} after {Duration:F0}ms trace={TraceId}",
                ex.GetType().Name,
                ecosystem,
                blobKey,
                upstreamUrl,
                stopwatch.Elapsed.TotalMilliseconds,
                Activity.Current?.TraceId.ToString());
            throw;
        }
        finally
        {
            DependablyMeter.UpstreamInflightFetches.Add(-1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
            _inflight.TryRemove(blobKey, out _);

            DependablyMeter.UpstreamFetchDuration.Record(
                stopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", outcome));

            activity?.SetTag("dependably.outcome", outcome);
        }
    }

    /// <summary>
    /// Hard cap for upstream artifact bodies (streamed or buffered). Applied by the
    /// hash-and-stage path and passed explicitly by callers that buffer artifact bytes
    /// through <see cref="GetOrFetchMetadataAsync(string, long, CancellationToken)"/>.
    /// </summary>
    public const long MaxUpstreamResponseBytes = 600L * 1024 * 1024; // 600 MB

    /// <summary>
    /// Hard cap for buffered upstream metadata documents (packuments, simple-index HTML,
    /// registration JSON, repodata indexes, OCI manifests). Deliberately far below the
    /// artifact cap: the shared upstream client auto-decompresses, so an attacker-controlled
    /// upstream could otherwise inflate a tiny gzip body into gigabytes of managed memory.
    /// Real-world metadata documents are comfortably under this limit.
    /// </summary>
    public const long MaxMetadataResponseBytes = 32L * 1024 * 1024; // 32 MB

    /// <summary>
    /// Hash-and-stage MISS path: streams upstream → temp file (with SHA-256
    /// computed inline via <see cref="IncrementalHash"/> and a running byte counter
    /// that throws on the 600 MB cap) → verifies checksum → uploads verified bytes to
    /// the blob store via <see cref="IBlobStore.PutAsync"/>. Cleans up the temp file
    /// unconditionally. Caller (the lazy in <see cref="GetOrFetchStreamAsync"/>) only
    /// receives (sha, size, blobKey); concurrent waiters each independently re-open
    /// the cached blob.
    /// </summary>
    // Initial backoff before first retry; doubled each subsequent attempt (capped at 400ms
    // for MaxUpstreamFetchAttempts=3, i.e. 200ms then 400ms between the two retries).
    private const int RetryBackoffBaseMs = 200;
    private const double RetryBackoffExponent = 2.0;
    private const int MaxUpstreamFetchAttempts = 3;

    private async Task<UpstreamFetchResult> FetchAndStageAsync(
        string url,
        ChecksumSpec? spec,
        string blobKey,
        string ecosystem,
        string? orgId,
        string? purl,
        CancellationToken ct)
    {
        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
        {
            throw new SsrfBlockedException(url);
        }

        // Hard floor check: reject the fetch before touching the network when the
        // staging volume is critically low. The effective floor is the larger of the
        // configured absolute minimum and 2× Content-Length (determined after the
        // response headers arrive), so the check runs in two phases:
        // Phase 1 — absolute floor before the HTTP GET. STAGING_DISK_FLOOR_BYTES=0 is the
        // operator opt-out: the whole check (including the fail-closed read-failure path) is
        // skipped so disk-full protection is fully off.
        if (_stagingDiskFloorBytes > 0)
        {
            try
            {
                long availableBeforeGet = _stagingDiskInfo.GetAvailableBytes();
                if (availableBeforeGet < _stagingDiskFloorBytes)
                {
                    throw new StagingDiskFullException(availableBeforeGet, _stagingDiskFloorBytes);
                }
            }
            catch (StagingDiskFullException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Could not read staging disk space before fetch: {ExceptionType}",
                    ex.GetType().Name);
                throw new StagingDiskFullException(0, _stagingDiskFloorBytes); // fail closed
            }
        }

        // Link the host-stopping token into the fetch so a slow upstream pull does not
        // outlive the graceful-shutdown drain window. The caller passes CancellationToken.None
        // rather than the client request token, so client disconnects never cancel the shared
        // fetch — only host shutdown does. The linked source is disposed once the fetch completes.
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _hostStopping);
        var fetchCt = linked.Token;

        var client = _httpClientFactory.CreateClient("upstream");
        // Retry loop for transient upstream failures; exits on first success or throws.
        using var successResponse = await FetchWithRetryAsync(client, url, orgId, fetchCt);

        // Phase 2 — dynamic floor based on Content-Length, checked after response headers arrive.
        EnsureStagingDiskFloorForContentLength(successResponse.Content.Headers.ContentLength);

        // Abort early if Content-Length already exceeds 600MB limit (cheap fail-fast).
        // The HashingFileStream below still enforces the cap for chunked transfers.
        if (successResponse.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
        {
            await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem, purl: purl,
                detail: $"{{\"url\":\"{url}\",\"content_length\":{successResponse.Content.Headers.ContentLength}}}", ct: fetchCt);
            throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
        }

        return await StreamVerifyAndStoreAsync(
            new UpstreamStagingContext(successResponse, blobKey, spec, url, ecosystem, orgId, purl), fetchCt);
    }

    // Sends a GET request to url with transient-failure retries (429, 403, 5xx).
    // A fresh HttpRequestMessage is created per attempt — HttpClient rejects a reused one.
    // Exits on first 2xx response or throws: UpstreamFetchFailedException on exhausted
    // transient retries, HttpRequestException on non-transient failures (404/410/…) so the
    // caller's multi-base loop can try the next upstream registry.
    private async Task<HttpResponseMessage> FetchWithRetryAsync(
        HttpClient client, string url, string? orgId, CancellationToken ct)
    {
        for (int attempt = 0; attempt < MaxUpstreamFetchAttempts; attempt++)
        {
            // Pass org context via request options so SsrfAwareRedirectHandler can attribute
            // blocked-redirect audit events to the correct tenant.
            using var fetchRequest = new HttpRequestMessage(HttpMethod.Get, url);
            if (orgId is not null)
            {
                fetchRequest.Options.Set(SsrfAwareRedirectHandler.OrgIdOption, orgId);
            }

            var response = await UnwrapSsrfAsync(
                () => client.SendAsync(fetchRequest, HttpCompletionOption.ResponseHeadersRead, ct));

            if (response.IsSuccessStatusCode)
            {
                return response;
            }

            int statusInt = (int)response.StatusCode;
            bool transient = statusInt is 429 or 403 or >= 500;

            var (diagRetryAfter, diagCfRay, diagXServedBy, diagVia, diagUserAgent) = GetResponseDiagHeaders(response, fetchRequest);
            // Structured boundary log on every non-success response for diagnosability.
            // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes all structured fields.
            _logger.LogWarning(
                "Upstream fetch non-success: Status={StatusCode} Url={Url} Transient={Transient} Attempt={Attempt}/{MaxAttempts} " +
                "RetryAfter={RetryAfterHeader} CfRay={CfRay} XServedBy={XServedBy} Via={Via} UserAgent={UserAgent} SingleFlighted=true",
                (int)response.StatusCode, url, transient, attempt + 1, MaxUpstreamFetchAttempts,
                diagRetryAfter, diagCfRay, diagXServedBy, diagVia, diagUserAgent);

            if (transient && attempt < MaxUpstreamFetchAttempts - 1)
            {
                response.Dispose();
                // Capped exponential back-off: 200ms, 400ms.
                await Task.Delay(TimeSpan.FromMilliseconds(RetryBackoffBaseMs * Math.Pow(RetryBackoffExponent, attempt)), ct);
                continue;
            }

            if (transient)
            {
                // Exhausted retries on a transient status — parse Retry-After (delta-seconds
                // form) and throw so the middleware maps it to 503/502 instead of 404.
                var retryAfter = ParseRetryAfter(response);
                int exhaustedStatus = (int)response.StatusCode;
                response.Dispose();
                throw new UpstreamFetchFailedException { Url = url, StatusCode = exhaustedStatus, RetryAfter = retryAfter, Transient = true };
            }

            // Non-transient (e.g. 404, 410): surface as HttpRequestException so the
            // controller's multi-base loop can try the next upstream registry.
            response.EnsureSuccessStatusCode();
        }

        // Unreachable: the loop always returns, continues, or throws.
        throw new InvalidOperationException("Retry loop exited without returning a response.");
    }

    // Extracts the diagnostic response headers used in the non-success boundary log.
    private static (string? RetryAfter, string? CfRay, string? XServedBy, string? Via, string UserAgent)
        GetResponseDiagHeaders(HttpResponseMessage response, HttpRequestMessage fetchRequest)
    {
        string? retryAfter = response.Headers.TryGetValues("Retry-After", out var raVals)
            ? string.Join(",", raVals) : null;
        string? cfRay = response.Headers.TryGetValues("CF-Ray", out var cfVals)
            ? string.Join(",", cfVals) : null;
        string? xServedBy = response.Headers.TryGetValues("X-Served-By", out var xsVals)
            ? string.Join(",", xsVals) : null;
        string? via = response.Headers.TryGetValues("Via", out var viaVals)
            ? string.Join(",", viaVals) : null;
        return (retryAfter, cfRay, xServedBy, via, fetchRequest.Headers.UserAgent.ToString());
    }

    // Parses the Retry-After header (delta-seconds form) from an exhausted-retry response.
    // Returns null when the header is absent or non-numeric.
    private static TimeSpan? ParseRetryAfter(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Retry-After", out var raHeaders)
            && int.TryParse(raHeaders.FirstOrDefault(), out int raSecs) && raSecs >= 0
            ? TimeSpan.FromSeconds(raSecs)
            : null;

    // Resolved upstream fetch context passed to the staging/verify tail, bundled to keep
    // StreamVerifyAndStoreAsync within the parameter-count threshold (S107).
    private sealed record UpstreamStagingContext(
        HttpResponseMessage Response, string BlobKey,
        ChecksumSpec? Spec, string Url, string Ecosystem, string? OrgId, string? Purl);

    // Streams the upstream response body to a temp file while computing SHA-256 inline,
    // verifies the checksum, uploads to the blob store, and cleans up the temp file.
    // Separated from FetchAndStageAsync to keep each method under the S138 line ceiling.
    private async Task<UpstreamFetchResult> StreamVerifyAndStoreAsync(
        UpstreamStagingContext ctx, CancellationToken fetchCt)
    {
        string tempPath = Path.Combine(_stagingPath, $"dependably-stage-{Guid.NewGuid():N}.tmp");
        string sha256Hex = string.Empty;
        long sizeBytes = 0;

        try
        {
            // Stream upstream → temp file, hashing inline. HashingFileStream wraps the
            // FileStream and forwards writes to disk AND to IncrementalHash, throwing on
            // the 600 MB cap.
            await using (var responseStream = await ctx.Response.Content.ReadAsStreamAsync(fetchCt))
            {
                var fileStream = new FileStream(
                    tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    bufferSize: 81920, useAsync: true);
                await using var staging = new HashingFileStream(fileStream, MaxUpstreamResponseBytes);
                try
                {
                    await responseStream.CopyToAsync(staging, fetchCt);
                }
                catch (UpstreamResponseTooLargeException)
                {
                    await _audit.LogAsync(
                        "upstream_response_too_large", orgId: ctx.OrgId, ecosystem: ctx.Ecosystem, purl: ctx.Purl,
                        detail: $"{{\"url\":\"{ctx.Url}\",\"bytes_read\":{staging.BytesWritten}}}", ct: fetchCt);
                    throw new UpstreamResponseTooLargeException(ctx.Url, MaxUpstreamResponseBytes);
                }
                sha256Hex = staging.GetSha256Hex();
                sizeBytes = staging.BytesWritten;
            }

            // For SHA-256 specs we already computed the hash inline; for SHA-1/SHA-512
            // (npm shasum, NuGet packageHash) we re-read the staged file. Same temp file,
            // single disk write.
            if (ctx.Spec is not null && !await VerifyChecksumAsync(
                    new VerifyChecksumRequest(tempPath, sha256Hex, ctx.Spec, ctx.Url, ctx.Ecosystem, ctx.OrgId, ctx.Purl), fetchCt))
            {
                throw new ChecksumException($"Upstream checksum mismatch for {ctx.Url}");
            }

            // Upload the verified bytes to the blob store.
            await using (var verified = new FileStream(
                tempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: true))
            {
                // LocalBlobStore.PutAsync writes directly to the final blob path without
                // a write-then-rename; cancelling mid-write leaves a truncated file that
                // is served as a cache HIT on subsequent requests (no integrity re-check
                // at serve time). Use CancellationToken.None so the commit is atomic with
                // respect to host shutdown; only the preceding fetch/stage steps use fetchCt.
                await _blobs.PutAsync(ctx.BlobKey, verified, CancellationToken.None);
            }

            return new UpstreamFetchResult(sha256Hex, sizeBytes, ctx.BlobKey);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to delete staging temp file {TempPath}: {ExceptionType}",
                    tempPath, ex.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Phase 2 of the staging-disk floor check — runs after response headers arrive, when
    /// the declared Content-Length is known. Requires the larger of the configured absolute
    /// floor and 2× the declared body size, taking a fresh disk reading so transient writes
    /// between the pre-GET check and the upstream GET are accounted for. Throws
    /// <see cref="StagingDiskFullException"/> below the floor, and fails closed (reports
    /// zero available bytes) when the disk reading itself fails. A missing or non-positive
    /// Content-Length (chunked transfer) skips the check; the streaming cap still bounds it.
    /// </summary>
    private void EnsureStagingDiskFloorForContentLength(long? declaredContentLength)
    {
        // STAGING_DISK_FLOOR_BYTES=0 is the operator opt-out: skip the dynamic floor too, so
        // disk-full protection is fully off rather than only the absolute floor.
        if (_stagingDiskFloorBytes <= 0)
        {
            return;
        }

        if (declaredContentLength is not { } contentLength || contentLength <= 0)
        {
            return;
        }

        long availableAfterGet;
        try
        {
            availableAfterGet = _stagingDiskInfo.GetAvailableBytes();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not read staging disk space after response headers: {ExceptionType}",
                ex.GetType().Name);
            throw new StagingDiskFullException(0, _stagingDiskFloorBytes); // fail closed
        }
        long dynamicFloor = Math.Max(_stagingDiskFloorBytes, contentLength * 2);
        if (availableAfterGet < dynamicFloor)
        {
            throw new StagingDiskFullException(availableAfterGet, dynamicFloor);
        }
    }

    /// <summary>
    /// Checks the staged temp file against the upstream-supplied checksum spec.
    /// SHA-256 reuses the inline-computed hex (avoiding a re-read); other algorithms
    /// re-read the file. On mismatch audits <c>checksum_failure</c> and returns false
    /// so the caller throws.
    /// </summary>
    // SocketsHttpHandler surfaces a SsrfBlockedException thrown by the connect-time guard
    // (SsrfConnectCallback) wrapped inside an HttpRequestException. Unwrap it so a block
    // at the TCP level (DNS-rebinding caught at socket-open time) reports with the same
    // exception type and SSRF metric as a URL-level pre-check block or redirect-hop block.
    private static async Task<T> UnwrapSsrfAsync<T>(Func<Task<T>> send)
    {
        try
        {
            return await send();
        }
        catch (HttpRequestException ex) when (ex.InnerException is SsrfBlockedException ssrf)
        {
            DependablyMeter.UpstreamUrlBlocks.Add(1);
            throw ssrf;
        }
    }

    private async Task<bool> VerifyChecksumAsync(VerifyChecksumRequest req, CancellationToken ct)
    {
        bool ok;
        string actualForAudit;
        if (req.Spec.Algorithm == ChecksumAlgorithm.Sha256)
        {
            ok = string.Equals(req.Sha256Hex, req.Spec.ExpectedValue.ToLowerInvariant(), StringComparison.Ordinal);
            actualForAudit = req.Sha256Hex;
        }
        else
        {
            await using var fs = new FileStream(
                req.TempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: true);
            ok = await ChecksumVerifier.VerifyAsync(fs, req.Spec, ct);
            actualForAudit = req.Sha256Hex; // SHA-256 of the bytes — still useful in the audit row
        }
        if (ok)
        {
            return true;
        }

        _logger.LogWarning("Checksum mismatch for {Url}: expected {Expected}, sha256={Actual}",
            req.Url, req.Spec.ExpectedValue, actualForAudit);

        DependablyMeter.UpstreamChecksumFailures.Add(1, new KeyValuePair<string, object?>("ecosystem", req.Ecosystem));
        await _audit.LogAsync(
            "checksum_failure",
            orgId: req.OrgId,
            ecosystem: req.Ecosystem,
            purl: req.Purl,
            detail: $"{{\"url\":\"{req.Url}\",\"expected\":\"{req.Spec.ExpectedValue}\",\"actual\":\"{actualForAudit}\"}}",
            ct: ct);

        return false;
    }

    private sealed record VerifyChecksumRequest(
        string TempPath,
        string Sha256Hex,
        ChecksumSpec Spec,
        string Url,
        string Ecosystem,
        string? OrgId,
        string? Purl);

    /// <summary>
    /// Streaming proxy fetch for artifacts whose SHA-256 is not known before the download
    /// (npm tarballs, NuGet flatcontainer). Streams upstream → local temp file (hashing
    /// inline) → stores under <see cref="BlobKeys.Proxy(string)"/> using the computed
    /// SHA-256 → returns the <see cref="UpstreamFetchResult"/> with the content-addressed
    /// key, SHA-256 hex, and byte count. Memory usage is bounded by the staging buffer
    /// regardless of artifact size. Skips the upload when the blob already exists in the
    /// store (idempotent). Uses the same thundering-herd dedup as
    /// <see cref="GetOrFetchStreamAsync"/> — concurrent first-fetches of the same URL
    /// share one upstream call.
    /// </summary>
    public async Task<UpstreamFetchResult> FetchAndCacheByUrlAsync(
        string upstreamUrl,
        ChecksumSpec? checksumSpec,
        string ecosystem,
        string? orgId = null,
        CancellationToken ct = default)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(upstreamUrl);
        }

        // Dedup concurrent fetches by URL. The shared work item writes the blob and returns
        // the content-addressed key; each caller receives the same UpstreamFetchResult and
        // can independently open the cached blob. CancellationToken.None prevents a single
        // caller disconnect from faulting the shared Lazy and cancelling all other waiters.
        var lazy = _urlInflight.GetOrAdd(upstreamUrl, _ => new Lazy<Task<UpstreamFetchResult>>(
            () => FetchAndStageToContentKeyAsync(upstreamUrl, checksumSpec, ecosystem, orgId, CancellationToken.None)));

        using var activity = DependablyActivitySource.Source.StartActivity(
            "proxy.fetch", ActivityKind.Client);
        activity?.SetTag("dependably.ecosystem", ecosystem);
        activity?.SetTag("dependably.operation", "proxy.fetch");
        activity?.SetTag("dependably.tier", "cache");

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        string outcome = "success";

        DependablyMeter.UpstreamInflightFetches.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            return await lazy.Value.WaitAsync(ct);
        }
        catch (ChecksumException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "checksum mismatch");
            throw;
        }
        catch (UpstreamResponseTooLargeException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream response too large");
            throw;
        }
        catch (AirGappedException)
        {
            outcome = "blocked";
            activity?.SetStatus(ActivityStatusCode.Error, "air-gapped");
            throw;
        }
        catch (UpstreamFetchFailedException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream fetch failed");
            throw;
        }
        catch (Exception ex)
        {
            outcome = "server_error";
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            _logger.LogWarning(
                ex,
                "Upstream fetch failed: {ExceptionType} for {Ecosystem} from {UpstreamUrl} after {Duration:F0}ms trace={TraceId}",
                ex.GetType().Name,
                ecosystem,
                upstreamUrl,
                stopwatch.Elapsed.TotalMilliseconds,
                Activity.Current?.TraceId.ToString());
            throw;
        }
        finally
        {
            DependablyMeter.UpstreamInflightFetches.Add(-1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
            _urlInflight.TryRemove(upstreamUrl, out _);

            DependablyMeter.UpstreamFetchDuration.Record(
                stopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", outcome));

            activity?.SetTag("dependably.outcome", outcome);
        }
    }

    /// <summary>
    /// Hash-and-stage MISS path for the no-pre-known-SHA case (npm, NuGet). Streams
    /// upstream → temp file → verifies optional checksum → writes the blob under
    /// <see cref="BlobKeys.Proxy(string)"/> (the content-addressed key derived from the
    /// inline-computed SHA-256) → returns the result. Skips the blob-store write when
    /// the content-addressed key already exists (concurrent callers that lost the race
    /// to the same artifact content).
    /// </summary>
    private async Task<UpstreamFetchResult> FetchAndStageToContentKeyAsync(
        string url, ChecksumSpec? spec, string ecosystem, string? orgId, CancellationToken ct)
    {
        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
        {
            throw new SsrfBlockedException(url);
        }

        var client = _httpClientFactory.CreateClient("upstream");
        // Retry loop for transient upstream failures; same contract as FetchAndStageAsync.
        // Non-transient failures (e.g. 404) propagate as HttpRequestException so the
        // controller's multi-base loop can try the next upstream registry.
        using var response = await FetchWithRetryAsync(client, url, orgId, ct);

        if (response.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
        {
            await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem,
                detail: $"{{\"url\":\"{url}\",\"content_length\":{response.Content.Headers.ContentLength}}}", ct: ct);
            throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
        }

        return await StreamHashAndStoreByContentKeyAsync(response, spec, url, ecosystem, orgId, ct);
    }

    // Streams the upstream response body to a temp file, computes SHA-256 inline, verifies
    // any supplied checksum, stores under the content-addressed BlobKeys.Proxy key, and
    // returns the result. Cleans up the temp file unconditionally. Separated from
    // FetchAndStageToContentKeyAsync to keep each method under the S138 line ceiling.
    private async Task<UpstreamFetchResult> StreamHashAndStoreByContentKeyAsync(
        HttpResponseMessage response, ChecksumSpec? spec,
        string url, string ecosystem, string? orgId, CancellationToken ct)
    {
        string tempPath = Path.Combine(_stagingPath, $"dependably-stage-{Guid.NewGuid():N}.tmp");
        string sha256Hex = string.Empty;
        long sizeBytes = 0;

        try
        {
            await using (var responseStream = await response.Content.ReadAsStreamAsync(ct))
            {
                var fileStream = new FileStream(
                    tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    bufferSize: 81920, useAsync: true);
                await using var staging = new HashingFileStream(fileStream, MaxUpstreamResponseBytes);
                try
                {
                    await responseStream.CopyToAsync(staging, ct);
                }
                catch (UpstreamResponseTooLargeException)
                {
                    await _audit.LogAsync(
                        "upstream_response_too_large", orgId: orgId, ecosystem: ecosystem,
                        detail: $"{{\"url\":\"{url}\",\"bytes_read\":{staging.BytesWritten}}}", ct: ct);
                    throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
                }
                sha256Hex = staging.GetSha256Hex();
                sizeBytes = staging.BytesWritten;
            }

            if (spec is not null && !await VerifyChecksumAsync(
                    new VerifyChecksumRequest(tempPath, sha256Hex, spec, url, ecosystem, orgId, null), ct))
            {
                throw new ChecksumException($"Upstream checksum mismatch for {url}");
            }

            // Store under the content-addressed key derived from the computed SHA-256.
            // Idempotent: concurrent callers that hashed the same content skip the write.
            string blobKey = BlobKeys.Proxy(sha256Hex);
            if (!await _blobs.ExistsAsync(blobKey, ct))
            {
                await using var verified = new FileStream(
                    tempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    bufferSize: 81920, useAsync: true);
                await _blobs.PutAsync(blobKey, verified, ct);
            }

            DependablyMeter.CacheLookups.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", "miss"));
            SnapshotCounters.IncrementCacheMiss();
            SnapshotCounters.IncrementProxyFetch();

            return new UpstreamFetchResult(sha256Hex, sizeBytes, blobKey);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to delete staging temp file {TempPath}: {ExceptionType}",
                    tempPath, ex.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Fetches metadata without caching (simple index, registration JSON, etc.).
    /// </summary>
    public async Task<HttpResponseMessage> GetMetadataAsync(string url, CancellationToken ct = default)
    {
        // Air-gapped: also block uncached metadata fetches. Simple-index pages and npm
        // packuments are derived locally from the registry's own state in air-gap mode.
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(url);
        }

        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
        {
            throw new SsrfBlockedException(url);
        }

        var client = _httpClientFactory.CreateClient("upstream");
        return await UnwrapSsrfAsync(() => client.GetAsync(url, ct));
    }

    /// <summary>
    /// Single-flighted metadata fetch. Returns a buffered response shareable across
    /// concurrent callers — only one upstream HTTP request runs per URL at a time, even
    /// when N CI runners hit a cold-start coordinate simultaneously. Returned value is
    /// immutable; callers inspect <see cref="UpstreamMetadataResponse.StatusCode"/> and
    /// read the buffered body directly (the old <see cref="GetMetadataAsync"/> path
    /// returned an <see cref="HttpResponseMessage"/> whose stream could only be consumed
    /// once, which is why the controllers couldn't share fetches).
    /// </summary>
    public Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(string url, CancellationToken ct = default)
        => GetOrFetchMetadataAsync(url, MaxMetadataResponseBytes, ct);

    /// <summary>
    /// Variant of <see cref="GetOrFetchMetadataAsync(string, CancellationToken)"/> with an
    /// explicit body cap. Callers that buffer artifact bytes through this path (npm tarballs,
    /// NuGet flatcontainer, Maven fetch-then-hash, PyPI unknown-sha cold start) pass
    /// <see cref="MaxUpstreamResponseBytes"/>; metadata callers use the default overload.
    /// Throws <see cref="UpstreamResponseTooLargeException"/> when the body exceeds the cap.
    /// </summary>
    public async Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(
        string url, long maxBytes, CancellationToken ct = default)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(url);
        }

        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
        {
            throw new SsrfBlockedException(url);
        }

        // CancellationToken.None: a disconnect from the first caller must not fault the
        // shared Lazy and cancel every other waiter (mirrors the blob-fetch convention).
        var lazy = _metadataInflight.GetOrAdd(url, _ => new Lazy<Task<UpstreamMetadataResponse>>(
            () => FetchMetadataBufferedAsync(url, maxBytes, CancellationToken.None)));

        try
        {
            return await lazy.Value.WaitAsync(ct);
        }
        finally
        {
            _metadataInflight.TryRemove(url, out _);
        }
    }

    private async Task<UpstreamMetadataResponse> FetchMetadataBufferedAsync(string url, long maxBytes, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("upstream");
        // ResponseHeadersRead is load-bearing: the default (ResponseContentRead) would have
        // HttpClient buffer the whole body before the cap check, defeating it.
        using var response = await UnwrapSsrfAsync(
            () => client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct));
        byte[] body = await ReadBodyCappedAsync(response, maxBytes, url, ct);
        string? contentType = response.Content.Headers.ContentType?.ToString();
        return new UpstreamMetadataResponse(
            (int)response.StatusCode,
            response.IsSuccessStatusCode,
            contentType,
            body);
    }

    /// <summary>
    /// Buffers an upstream response body with a hard byte cap. The single place buffered
    /// upstream reads are allowed to materialise bytes: fails fast when the declared
    /// Content-Length already exceeds the cap (mirroring the streaming path), then copies
    /// the body through a counted loop so chunked or auto-decompressed transfers — where
    /// Content-Length is absent or describes the compressed size — cannot inflate past the
    /// cap into managed memory. Throws <see cref="UpstreamResponseTooLargeException"/> when
    /// the cap is crossed.
    /// </summary>
    public static async Task<byte[]> ReadBodyCappedAsync(
        HttpResponseMessage response, long maxBytes, string url, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new UpstreamResponseTooLargeException(url, maxBytes);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var buffered = new MemoryStream();
        byte[] buffer = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (buffered.Length + read > maxBytes)
            {
                throw new UpstreamResponseTooLargeException(url, maxBytes);
            }

            buffered.Write(buffer, 0, read);
        }

        return buffered.ToArray();
    }
}

/// <summary>
/// Result of the hash-and-stage MISS path. No byte[] — concurrent waiters share
/// the (sha, size, blobKey) triple and each independently re-open the cached blob via
/// <see cref="IBlobStore.GetAsync"/>.
/// </summary>
public sealed record UpstreamFetchResult(string Sha256Hex, long SizeBytes, string BlobKey);

/// <summary>
/// Write-only Stream that forwards every write to an inner <see cref="Stream"/> (the
/// staging temp file) AND updates an <see cref="IncrementalHash"/> (SHA-256) AND
/// increments a byte counter. Throws <see cref="UpstreamResponseTooLargeException"/>
/// when the counter crosses the configured cap — catches chunked transfers without a
/// Content-Length header that try to exceed the 600 MB limit. The URL is left blank
/// in the exception because the staging stream doesn't know about it; the caller
/// rewraps with the actual URL before throwing to the outer pipeline.
/// </summary>
internal sealed class HashingFileStream : Stream
{
    private readonly Stream _inner;
    private readonly IncrementalHash _hash;
    private readonly long _maxBytes;
    private byte[]? _finalHash;
    private bool _disposed;

    public HashingFileStream(Stream inner, long maxBytes)
    {
        _inner = inner;
        _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        _maxBytes = maxBytes;
    }

    public long BytesWritten { get; private set; }

    public string GetSha256Hex()
    {
        _finalHash ??= _hash.GetHashAndReset();
        return Convert.ToHexString(_finalHash).ToLowerInvariant();
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => BytesWritten; set => throw new NotSupportedException(); }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        CheckCap(count);
        _hash.AppendData(buffer, offset, count);
        _inner.Write(buffer, offset, count);
        BytesWritten += count;
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        CheckCap(buffer.Length);
        // IncrementalHash accepts ReadOnlySpan<byte>; project the memory before consuming
        // it so we hash the same bytes the file write consumes.
        _hash.AppendData(buffer.Span);
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        BytesWritten += buffer.Length;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken).AsTask();

    private void CheckCap(int incoming)
    {
        if (BytesWritten + incoming > _maxBytes)
        {
            throw new UpstreamResponseTooLargeException("(staging)", _maxBytes);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (disposing)
        {
            _hash.Dispose();
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed) { await base.DisposeAsync().ConfigureAwait(false); return; }
        _disposed = true;
        _hash.Dispose();
        await _inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// Buffered upstream metadata response shareable across concurrent callers. See
/// <see cref="UpstreamClient.GetOrFetchMetadataAsync"/> for why the body is buffered up
/// front (the stream form is single-consumer, which defeats single-flight dedup).
/// </summary>
public sealed record UpstreamMetadataResponse(
    int StatusCode,
    bool IsSuccessStatusCode,
    string? ContentType,
    byte[] Body)
{
    public string BodyAsString() => System.Text.Encoding.UTF8.GetString(Body);
}

// S3925 (legacy ISerializable pattern) is suppressed on each exception below:
// .NET 10 obsoletes the binary-serialization ctor on Exception (SYSLIB0051), so
// adding (SerializationInfo, StreamingContext) would trade a Sonar warning for a
// build-time obsolete warning. These exceptions never cross an AppDomain or binary
// serialization boundary.

/// <summary>
/// Thrown when an upstream blob fetch fails with a transient/retryable status after retries
/// are exhausted; mapped by <c>UpstreamFetchFailedExceptionMiddleware</c> to 503/502 so
/// clients retry rather than treat it as fatal policy (403) or absence (404).
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class UpstreamFetchFailedException : Exception
{
    public string Url { get; init; } = string.Empty;
    public int StatusCode { get; init; }
    public TimeSpan? RetryAfter { get; init; }
    public bool Transient { get; init; }

    public UpstreamFetchFailedException()
        : base("Upstream blob fetch failed after retries were exhausted.") { }
}

[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class ChecksumException : Exception
{
    public ChecksumException(string message) : base(message) { }
}

[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class UpstreamResponseTooLargeException : Exception
{
    public UpstreamResponseTooLargeException(string url, long maxBytes)
        : base($"Upstream response exceeded the {maxBytes}-byte limit: {url}") { }
}

[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class SsrfBlockedException : Exception
{
    public SsrfBlockedException(string url)
        : base($"Upstream URL blocked by SSRF policy: {url}") { }
}

/// <summary>
/// Thrown by <see cref="UpstreamClient"/> when AIR_GAPPED=true and a request needs to
/// reach an upstream registry. Caught by <c>AirGappedExceptionMiddleware</c> and
/// translated to <c>503 Service Unavailable</c>. Cache hits never raise this exception
/// — only the fetch path is blocked.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class AirGappedException : Exception
{
    public string Resource { get; }

    public AirGappedException(string resource)
        : base($"Upstream fetch refused: this deployment is air-gapped (resource: {resource}).")
    {
        Resource = resource;
    }
}

/// <summary>
/// Thrown by <see cref="UpstreamClient"/> when the staging volume does not have
/// enough free space to safely accommodate the incoming proxy fetch. Caught by
/// <c>StagingDiskFullExceptionMiddleware</c> and translated to
/// <c>507 Insufficient Storage</c> so callers receive a standard HTTP response
/// rather than a generic 500.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class StagingDiskFullException : Exception
{
    public long AvailableBytes { get; }
    public long FloorBytes { get; }

    public StagingDiskFullException(long availableBytes, long floorBytes)
        : base($"Staging disk too full to accept a new proxy fetch: {availableBytes} bytes available, floor is {floorBytes} bytes.")
    {
        AvailableBytes = availableBytes;
        FloorBytes = floorBytes;
    }
}
