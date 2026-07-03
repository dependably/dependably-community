using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
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
    private readonly MetadataResponseCache? _metadataCache;
    private readonly EdgeStatusTracker? _edgeStatus;
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
    // NuGet flatcontainer). Keyed by upstream URL + a hash of the Authorization header so
    // concurrent first-fetches of the same coordinate under the SAME credentials share one
    // streaming fetch rather than buffering N independent copies, while differing credentials
    // never ride a fetch made with someone else's Authorization header.
    private readonly ConcurrentDictionary<string, Lazy<Task<UpstreamFetchResult>>> _urlInflight = new();

    // Process-wide reservation ledger for in-flight staging writes. Phase 1
    // (EnsureStagingDiskFloorBeforeFetch) and Phase 2 (EnsureStagingDiskFloorForContentLength) of
    // the staging-disk floor check evaluate available disk space against
    // `available - reservedInFlight` rather than a bare disk reading, so a burst of concurrent
    // large fetches that have not yet written a byte is accounted for — not just bytes already on
    // disk. Declared Content-Length is reserved when known; chunked transfers (no declared length)
    // reserve MaxUpstreamResponseBytes — the enforced streaming cap — as a conservative worst case.
    // Reserved via ReserveStagingBytes once a fetch's own floor check passes, released via
    // ReleaseStagingBytes in the caller's finally once the fetch completes.
    private long _reservedInFlightBytes;

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
        IHostApplicationLifetime? lifetime = null,
        MetadataResponseCache? metadataCache = null,
        EdgeStatusTracker? edgeStatus = null)
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
        // A null cache means metadata caching is off — the single-flight-only pass-through path,
        // which is the standard (non-edge) default. The cache decides internally whether it is
        // enabled (positive TTL configured), so callers never branch on the mode here.
        _metadataCache = metadataCache;
        // The master-reachability tracker is registered as a singleton in every deployment mode
        // and injected here unconditionally; the derived status is only ever exposed through the
        // edge-only /edge/status endpoint, so off-edge the recorded outcomes are simply never
        // read. The parameter is nullable so tests and callers can omit it, in which case each
        // fetch outcome is a cheap null-check. Injected (not read from a mode flag) so the single
        // seam works identically in every mode without branching here.
        _edgeStatus = edgeStatus;
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

    private long ReservedInFlightBytes => Interlocked.Read(ref _reservedInFlightBytes);

    // Reserves declaredContentLength (or MaxUpstreamResponseBytes as a conservative default when
    // the transfer is chunked / declares no length) against the process-wide in-flight total, so
    // OTHER concurrent fetches' floor checks see bytes this fetch is about to write. No-op
    // (returns 0) when the floor check is disabled (STAGING_DISK_FLOOR_BYTES=0). The caller
    // reserves only after its OWN floor check has passed, and releases the same amount in a
    // finally once the fetch completes — see ReleaseStagingBytes.
    private long ReserveStagingBytes(long? declaredContentLength)
    {
        if (_stagingDiskFloorBytes <= 0)
        {
            return 0;
        }

        long amount = declaredContentLength is { } len && len > 0 ? len : MaxUpstreamResponseBytes;
        Interlocked.Add(ref _reservedInFlightBytes, amount);
        return amount;
    }

    // Releases a reservation made by ReserveStagingBytes. Always called from a finally so a
    // faulted or cancelled fetch still frees its reservation.
    private void ReleaseStagingBytes(long reservedAmount)
    {
        if (reservedAmount == 0)
        {
            return;
        }

        Interlocked.Add(ref _reservedInFlightBytes, -reservedAmount);
    }

    // Attaches a continuation that removes exactly this (key, lazy) pair from dict once the
    // shared work item genuinely completes — success or failure — never when an individual
    // caller's WaitAsync(ct) merely detaches early. A caller cancelling mid-fetch must not evict a
    // live in-flight entry (the shared upstream call keeps running for the remaining waiters), and
    // the pair-targeted removal never touches a newer generation that replaced this entry. Every
    // concurrent caller attaches its own continuation to the same Task; TryRemove is idempotent —
    // only the first continuation to run has any effect.
    private static void ScheduleInflightRemoval<TResult>(
        ConcurrentDictionary<string, Lazy<Task<TResult>>> dict, string key, Lazy<Task<TResult>> lazy)
    {
        lazy.Value.ContinueWith(
            _ => dict.TryRemove(new KeyValuePair<string, Lazy<Task<TResult>>>(key, lazy)),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    // Hex-encoded SHA-256 of the per-upstream Authorization header, used as a single-flight key
    // component so joiners never share a fetch across differing credentials. Anonymous (no-header)
    // requests all hash to the same fixed value, which still dedups correctly among themselves.
    private static string AuthHeaderHash(string? authorizationHeader) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(authorizationHeader ?? string.Empty)))
            .ToLowerInvariant();

    /// <summary>
    /// Streaming proxy fetch. On cache HIT, returns the blob-store stream
    /// directly so the controller can <c>File(stream, ...)</c> straight through to the
    /// response without ever materialising the artifact in memory. On cache MISS, streams
    /// upstream → local temp file (hashing inline) → verifies → uploads to blob store →
    /// re-opens the cached blob and returns it. Memory usage is bounded by the staging
    /// buffer regardless of concurrency.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct proxy-fetch input; the trailing optional context params add no cohesion when bundled.")]
    public async Task<(Stream Body, bool IsHit)> GetOrFetchStreamAsync(
        string blobKey,
        string upstreamUrl,
        ChecksumSpec? checksumSpec,
        string ecosystem,
        string? orgId = null,
        string? purl = null,
        string? authorizationHeader = null,
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
            () => FetchAndStageAsync(
                new UpstreamFetchRequest(upstreamUrl, checksumSpec, blobKey, ecosystem, orgId, purl, authorizationHeader),
                CancellationToken.None)));
        ScheduleInflightRemoval(_inflight, blobKey, lazy);

        return await FetchWithTelemetryAsync(lazy, blobKey, ecosystem, upstreamUrl, checksumSpec, purl, ct);
    }

    /// <summary>
    /// Like <see cref="GetOrFetchStreamAsync"/>, but stores under the caller-supplied
    /// <paramref name="blobKey"/> and returns the fetch facts (SHA-256, size, key) instead of
    /// an open stream. Callers that serve the artifact straight from the blob store use this to
    /// avoid buffering the whole artifact in managed memory and recomputing the SHA-256 the
    /// streamed stage already produced. On a cache HIT the digest is recovered by stream-hashing
    /// the stored blob (bounded memory, no full buffer). Shares the same single-flight dedup and
    /// telemetry as the streaming variant.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct proxy-fetch input; the trailing optional context params add no cohesion when bundled.")]
    public async Task<UpstreamFetchResult> GetOrFetchToBlobKeyAsync(
        string blobKey,
        string upstreamUrl,
        ChecksumSpec? checksumSpec,
        string ecosystem,
        string? orgId = null,
        string? purl = null,
        string? authorizationHeader = null,
        CancellationToken ct = default)
    {
        var cached = await _blobs.GetAsync(blobKey, ct);
        if (cached is not null)
        {
            DependablyMeter.CacheLookups.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", "hit"));
            SnapshotCounters.IncrementCacheHit();
            await using (cached)
            {
                var (sha256Hex, sizeBytes) = await HashStreamAsync(cached, ct);
                return new UpstreamFetchResult(sha256Hex, sizeBytes, blobKey);
            }
        }

        DependablyMeter.CacheLookups.Add(1,
            new KeyValuePair<string, object?>("ecosystem", ecosystem),
            new KeyValuePair<string, object?>("outcome", "miss"));
        SnapshotCounters.IncrementCacheMiss();
        SnapshotCounters.IncrementProxyFetch();

        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(blobKey);
        }

        var lazy = _inflight.GetOrAdd(blobKey, _ => new Lazy<Task<UpstreamFetchResult>>(
            () => FetchAndStageAsync(
                new UpstreamFetchRequest(upstreamUrl, checksumSpec, blobKey, ecosystem, orgId, purl, authorizationHeader),
                CancellationToken.None)));
        ScheduleInflightRemoval(_inflight, blobKey, lazy);

        return await FetchResultWithTelemetryAsync(lazy, blobKey, ecosystem, upstreamUrl, checksumSpec, purl, ct);
    }

    // Stream-hashes a blob to recover its SHA-256 and byte count without materialising it in
    // memory — used on the cache-hit path of GetOrFetchToBlobKeyAsync where the digest was not
    // carried by the (already-stored) blob.
    private static async Task<(string Sha256Hex, long SizeBytes)> HashStreamAsync(
        Stream stream, CancellationToken ct)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            hasher.AppendData(buffer, 0, read);
            total += read;
        }
        return (Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant(), total);
    }

    // Awaits the deduped lazy fetch, emits OTel activity + metrics, and opens the cached blob
    // for the caller. All exception handling lives here to keep GetOrFetchStreamAsync linear.
    private async Task<(Stream Body, bool IsHit)> FetchWithTelemetryAsync(
        Lazy<Task<UpstreamFetchResult>> lazy,
        string blobKey, string ecosystem, string upstreamUrl,
        ChecksumSpec? checksumSpec, string? purl, CancellationToken ct)
    {
        var result = await FetchResultWithTelemetryAsync(
            lazy, blobKey, ecosystem, upstreamUrl, checksumSpec, purl, ct);
        var stream = await _blobs.GetAsync(result.BlobKey, ct)
            ?? throw new InvalidOperationException(
                $"Blob {result.BlobKey} vanished between PutAsync and GetAsync.");
        return (stream, false);
    }

    // Awaits the deduped lazy fetch under the same OTel activity + metrics wrapper as
    // FetchWithTelemetryAsync, returning the fetch facts (sha256, size, key) without opening
    // the blob. Callers that serve straight from the blob store (e.g. the Cargo proxy path)
    // use this to avoid buffering the artifact and recomputing a digest the streamed stage
    // already produced.
    private async Task<UpstreamFetchResult> FetchResultWithTelemetryAsync(
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

        DependablyMeter.UpstreamSingleFlightJoins.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            // WaitAsync(ct) lets this caller's request token abort ITS OWN wait without
            // cancelling the shared upstream fetch that other waiters depend on (mirrors the
            // URL-keyed and metadata single-flight paths).
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
            activity?.SetTag("dependably.outcome", outcome);
            RecordEdgeOutcome(outcome);
        }
    }

    // Feeds an artifact-fetch outcome into the edge master-reachability tracker. Maps the
    // already-computed OTel outcome string to a coarse success/failure signal; a policy block
    // (air-gap) is a local decision, not a statement about whether the master is reachable, so
    // it is not recorded. No-op off-edge (the tracker is null) — a single null-check per fetch.
    private void RecordEdgeOutcome(string outcome)
    {
        if (_edgeStatus is null)
        {
            return;
        }

        switch (outcome)
        {
            case "success":
                _edgeStatus.RecordSuccess();
                break;
            case "blocked":
                // Air-gap block: not an upstream-reachability signal.
                break;
            default:
                _edgeStatus.RecordFailure();
                break;
        }
    }

    /// <summary>
    /// Hard cap for upstream artifact bodies (streamed or buffered). Applied by the
    /// hash-and-stage path and passed explicitly by callers that buffer artifact bytes
    /// through <see cref="GetOrFetchMetadataAsync(string, long, string, CancellationToken)"/>.
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

    // Bundles the fetch coordinate + tenant/PURL context passed to FetchAndStageAsync, keeping
    // it within the parameter-count threshold (S107).
    private sealed record UpstreamFetchRequest(
        string Url, ChecksumSpec? Spec, string BlobKey, string Ecosystem,
        string? OrgId, string? Purl, string? AuthorizationHeader);

    // The shared single-flight work item behind _inflight — runs exactly once per blobKey
    // regardless of caller fan-in. Owns the UpstreamInflightFetches gauge and
    // UpstreamFetchDuration histogram so both instruments count real upstream operations, not
    // per-caller waits (waiters only observe the shared Task in FetchWithTelemetryAsync).
    private async Task<UpstreamFetchResult> FetchAndStageAsync(UpstreamFetchRequest req, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        string outcome = "success";
        DependablyMeter.UpstreamInflightFetches.Add(1, new KeyValuePair<string, object?>("ecosystem", req.Ecosystem));
        try
        {
            return await FetchAndStageCoreAsync(req, ct);
        }
        catch (ChecksumException) { outcome = "upstream_error"; throw; }
        catch (UpstreamResponseTooLargeException) { outcome = "upstream_error"; throw; }
        catch (StagingDiskFullException) { outcome = "staging_disk_full"; throw; }
        catch (UpstreamFetchFailedException) { outcome = "upstream_error"; throw; }
        catch (Exception) { outcome = "server_error"; throw; }
        finally
        {
            DependablyMeter.UpstreamInflightFetches.Add(-1, new KeyValuePair<string, object?>("ecosystem", req.Ecosystem));
            DependablyMeter.UpstreamFetchDuration.Record(
                stopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("ecosystem", req.Ecosystem),
                new KeyValuePair<string, object?>("outcome", outcome));
        }
    }

    private async Task<UpstreamFetchResult> FetchAndStageCoreAsync(UpstreamFetchRequest req, CancellationToken ct)
    {
        string url = req.Url;
        string? orgId = req.OrgId;
        string? authorizationHeader = req.AuthorizationHeader;

        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
        {
            throw new SsrfBlockedException(url);
        }

        // Phase 1 — absolute floor before the HTTP GET.
        EnsureStagingDiskFloorBeforeFetch();

        // Link the host-stopping token into the fetch so a slow upstream pull does not
        // outlive the graceful-shutdown drain window. The caller passes CancellationToken.None
        // rather than the client request token, so client disconnects never cancel the shared
        // fetch — only host shutdown does. The linked source is disposed once the fetch completes.
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _hostStopping);
        var fetchCt = linked.Token;

        var client = _httpClientFactory.CreateClient("upstream");
        // Retry loop for transient upstream failures; exits on first success or throws.
        using var successResponse = await FetchWithRetryAsync(client, url, orgId, authorizationHeader, fetchCt);

        // Phase 2 — dynamic floor based on Content-Length, checked after response headers arrive.
        EnsureStagingDiskFloorForContentLength(successResponse.Content.Headers.ContentLength);

        // Reserve this fetch's declared size against the in-flight ledger now that its own floor
        // check has passed, so other concurrent fetches' floor checks see these bytes as spoken
        // for. Released once staging + verification + upload complete (or fault).
        long reservedBytes = ReserveStagingBytes(successResponse.Content.Headers.ContentLength);
        try
        {
            // Abort early if Content-Length already exceeds 600MB limit (cheap fail-fast).
            // The HashingFileStream below still enforces the cap for chunked transfers.
            if (successResponse.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
            {
                await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: req.Ecosystem, purl: req.Purl,
                    detail: JsonSerializer.Serialize(
                        new { url, content_length = successResponse.Content.Headers.ContentLength }, EventJsonOptions.Detail),
                    ct: fetchCt);
                throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
            }

            return await StreamVerifyAndStoreAsync(
                new UpstreamStagingContext(successResponse, req.BlobKey, req.Spec, url, req.Ecosystem, orgId, req.Purl), fetchCt);
        }
        finally
        {
            ReleaseStagingBytes(reservedBytes);
        }
    }

    // Phase 1 of the staging-disk floor check — the absolute floor, evaluated before the HTTP GET
    // so a fetch is rejected before touching the network when the staging volume is already
    // critically low. Evaluated against available bytes minus bytes already reserved by other
    // in-flight fetches (see ReserveStagingBytes), so a burst of concurrent large fetches cannot
    // each pass against the same free-space snapshot. STAGING_DISK_FLOOR_BYTES=0 is the operator
    // opt-out: the whole check (including the fail-closed read-failure path) is skipped so
    // disk-full protection is fully off.
    private void EnsureStagingDiskFloorBeforeFetch()
    {
        if (_stagingDiskFloorBytes <= 0)
        {
            return;
        }

        try
        {
            long availableBeforeGet = _stagingDiskInfo.GetAvailableBytes() - ReservedInFlightBytes;
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

    // Sends a GET request to url with transient-failure retries (429, 403, 5xx).
    // A fresh HttpRequestMessage is created per attempt — HttpClient rejects a reused one.
    // Exits on first 2xx response or throws: UpstreamFetchFailedException on exhausted
    // transient retries, HttpRequestException on non-transient failures (404/410/…) so the
    // caller's multi-base loop can try the next upstream registry.
    private async Task<HttpResponseMessage> FetchWithRetryAsync(
        HttpClient client, string url, string? orgId, string? authorizationHeader, CancellationToken ct)
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

            // Attach the per-upstream Authorization header (Bearer/Basic) when configured. Built
            // once at resolve time; null for anonymous upstreams. TryAddWithoutValidation mirrors
            // the OCI attach path and avoids HttpClient's header-format validation.
            if (authorizationHeader is not null)
            {
                fetchRequest.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
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
            // controller's multi-base loop can try the next upstream registry. Dispose the
            // undrained ResponseHeadersRead response first so its pooled connection is returned
            // to the (max-10-per-host) pool instead of being stranded until GC finalization —
            // upstream 404s are the high-frequency case on proxy/multi-base paths.
            try
            {
                response.EnsureSuccessStatusCode();
            }
            finally
            {
                response.Dispose();
            }
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
                        detail: JsonSerializer.Serialize(
                            new { url = ctx.Url, bytes_read = staging.BytesWritten }, EventJsonOptions.Detail),
                        ct: fetchCt);
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

            // Upload the verified bytes to the blob store. PutAsync stages to a
            // same-directory temp file and renames atomically into place, so a
            // cancellation here leaves at most a sweepable temp file — never a truncated
            // file visible at the content-addressed key — and the fetch cancellation
            // token can be used throughout.
            await using (var verified = new FileStream(
                tempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: true))
            {
                await _blobs.PutAsync(ctx.BlobKey, verified, fetchCt);
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
    /// floor and 2× the declared body size, taking a fresh disk reading (minus bytes already
    /// reserved by other in-flight fetches — see <see cref="ReserveStagingBytes"/>) so both
    /// transient writes between the pre-GET check and the upstream GET, and concurrent
    /// not-yet-written fetches, are accounted for. Throws <see cref="StagingDiskFullException"/>
    /// below the floor, and fails closed (reports zero available bytes) when the disk reading
    /// itself fails. A missing or non-positive Content-Length (chunked transfer) skips the check;
    /// the streaming cap still bounds it.
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
            availableAfterGet = _stagingDiskInfo.GetAvailableBytes() - ReservedInFlightBytes;
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
    // exception type as a URL-level pre-check block or redirect-hop block. Emits the
    // dns_rebind reason on the upstream_url_blocks counter.
    internal static async Task<T> UnwrapSsrfAsync<T>(Func<Task<T>> send)
    {
        try
        {
            return await send();
        }
        catch (HttpRequestException ex) when (ex.InnerException is SsrfBlockedException ssrf)
        {
            DependablyMeter.UpstreamUrlBlocks.Add(1,
                new KeyValuePair<string, object?>("reason", "dns_rebind"));
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
            detail: JsonSerializer.Serialize(
                new { url = req.Url, expected = req.Spec.ExpectedValue, actual = actualForAudit }, EventJsonOptions.Detail),
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
        string? authorizationHeader = null,
        CancellationToken ct = default)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(upstreamUrl);
        }

        // Dedup concurrent fetches by URL + a hash of the Authorization header. Keying on the
        // header (not just the URL) means two callers presenting different credentials — or
        // different per-tenant upstream tokens for the same URL — never ride the same fetch;
        // genuinely identical requests (same URL, same credentials) still collapse to one. The
        // shared work item writes the blob and returns the content-addressed key; each caller
        // receives the same UpstreamFetchResult and can independently open the cached blob.
        // CancellationToken.None prevents a single caller disconnect from faulting the shared
        // Lazy and cancelling all other waiters.
        string inflightKey = upstreamUrl + "\n" + AuthHeaderHash(authorizationHeader);
        var lazy = _urlInflight.GetOrAdd(inflightKey, _ => new Lazy<Task<UpstreamFetchResult>>(
            () => FetchAndStageToContentKeyAsync(upstreamUrl, checksumSpec, ecosystem, orgId, authorizationHeader, CancellationToken.None)));
        ScheduleInflightRemoval(_urlInflight, inflightKey, lazy);

        using var activity = DependablyActivitySource.Source.StartActivity(
            "proxy.fetch", ActivityKind.Client);
        activity?.SetTag("dependably.ecosystem", ecosystem);
        activity?.SetTag("dependably.operation", "proxy.fetch");
        activity?.SetTag("dependably.tier", "cache");

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        string outcome = "success";

        DependablyMeter.UpstreamSingleFlightJoins.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
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
            activity?.SetTag("dependably.outcome", outcome);
            RecordEdgeOutcome(outcome);
        }
    }

    /// <summary>
    /// Hash-and-stage MISS path for the no-pre-known-SHA case (npm, NuGet). Streams
    /// upstream → temp file → verifies optional checksum → writes the blob under
    /// <see cref="BlobKeys.Proxy(string)"/> (the content-addressed key derived from the
    /// inline-computed SHA-256) → returns the result. Skips the blob-store write when
    /// the content-addressed key already exists (concurrent callers that lost the race
    /// to the same artifact content). The shared single-flight work item behind _urlInflight —
    /// owns the UpstreamInflightFetches gauge and UpstreamFetchDuration histogram so both
    /// instruments count real upstream operations, not per-caller waits.
    /// </summary>
    private async Task<UpstreamFetchResult> FetchAndStageToContentKeyAsync(
        string url, ChecksumSpec? spec, string ecosystem, string? orgId, string? authorizationHeader, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        string outcome = "success";
        DependablyMeter.UpstreamInflightFetches.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            return await FetchAndStageToContentKeyCoreAsync(url, spec, ecosystem, orgId, authorizationHeader, ct);
        }
        catch (ChecksumException) { outcome = "upstream_error"; throw; }
        catch (UpstreamResponseTooLargeException) { outcome = "upstream_error"; throw; }
        catch (StagingDiskFullException) { outcome = "staging_disk_full"; throw; }
        catch (UpstreamFetchFailedException) { outcome = "upstream_error"; throw; }
        catch (Exception) { outcome = "server_error"; throw; }
        finally
        {
            DependablyMeter.UpstreamInflightFetches.Add(-1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
            DependablyMeter.UpstreamFetchDuration.Record(
                stopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", outcome));
        }
    }

    private async Task<UpstreamFetchResult> FetchAndStageToContentKeyCoreAsync(
        string url, ChecksumSpec? spec, string ecosystem, string? orgId, string? authorizationHeader, CancellationToken ct)
    {
        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
        {
            throw new SsrfBlockedException(url);
        }

        // Phase 1 — absolute floor before the HTTP GET (mirrors FetchAndStageCoreAsync).
        EnsureStagingDiskFloorBeforeFetch();

        var client = _httpClientFactory.CreateClient("upstream");
        // Retry loop for transient upstream failures; same contract as FetchAndStageAsync.
        // Non-transient failures (e.g. 404) propagate as HttpRequestException so the
        // controller's multi-base loop can try the next upstream registry.
        using var response = await FetchWithRetryAsync(client, url, orgId, authorizationHeader, ct);

        // Phase 2 — dynamic floor based on Content-Length, checked after response headers arrive.
        EnsureStagingDiskFloorForContentLength(response.Content.Headers.ContentLength);

        long reservedBytes = ReserveStagingBytes(response.Content.Headers.ContentLength);
        try
        {
            if (response.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
            {
                await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem,
                    detail: JsonSerializer.Serialize(
                        new { url, content_length = response.Content.Headers.ContentLength }, EventJsonOptions.Detail),
                    ct: ct);
                throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
            }

            return await StreamHashAndStoreByContentKeyAsync(response, spec, url, ecosystem, orgId, ct);
        }
        finally
        {
            ReleaseStagingBytes(reservedBytes);
        }
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
                        detail: JsonSerializer.Serialize(
                            new { url, bytes_read = staging.BytesWritten }, EventJsonOptions.Detail),
                        ct: ct);
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
    public async Task<HttpResponseMessage> GetMetadataAsync(
        string url, string? authorizationHeader = null, CancellationToken ct = default)
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
        return await UnwrapSsrfAsync(() => SendMetadataRequestAsync(client, url, authorizationHeader, ct, HttpCompletionOption.ResponseContentRead));
    }

    // Builds and sends a GET for a metadata document, attaching the per-upstream Authorization
    // header (Bearer/Basic) when configured. A fresh HttpRequestMessage is required because a
    // header on the shared "upstream" HttpClient would leak across tenants.
    private static async Task<HttpResponseMessage> SendMetadataRequestAsync(
        HttpClient client, string url, string? authorizationHeader, CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseHeadersRead)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (authorizationHeader is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        return await client.SendAsync(request, completionOption, ct);
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
    public Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(
        string url, string? authorizationHeader = null, CancellationToken ct = default)
        => GetOrFetchMetadataAsync(url, MaxMetadataResponseBytes, authorizationHeader, ct);

    /// <summary>
    /// Variant of <see cref="GetOrFetchMetadataAsync(string, string, CancellationToken)"/> with an
    /// explicit body cap. Callers that buffer artifact bytes through this path (npm tarballs,
    /// NuGet flatcontainer, Maven fetch-then-hash, PyPI unknown-sha cold start) pass
    /// <see cref="MaxUpstreamResponseBytes"/>; metadata callers use the default overload.
    /// Throws <see cref="UpstreamResponseTooLargeException"/> when the body exceeds the cap.
    /// </summary>
    public async Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(
        string url, long maxBytes, string? authorizationHeader = null, CancellationToken ct = default)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(url);
        }

        // A fresh cached entry short-circuits before any SSRF pre-check or upstream call — the
        // whole point of the cache. Stale entries fall through to a single-flight refresh below
        // and are only served if that refresh fails transiently.
        bool cacheEnabled = _metadataCache is { Enabled: true };
        if (cacheEnabled && _metadataCache!.TryGet(url) is { Fresh: true } hit)
        {
            return hit.Response;
        }

        bool allowed = await _urlValidator.IsAllowedAsync(url, orgId: null, ct);
        if (!allowed)
        {
            throw new SsrfBlockedException(url);
        }

        try
        {
            if (cacheEnabled)
            {
                // The cached path records its own edge outcome at the source of truth: only it
                // can tell a genuine upstream 2xx apart from a stale entry served because the
                // master was unreachable — both surface here as an identical 2xx response.
                return await GetOrFetchMetadataCachedAsync(url, maxBytes, authorizationHeader, ct);
            }

            var result = await SingleFlightMetadataAsync(url, maxBytes, authorizationHeader, ct);

            // The master answered — a 2xx or a 404 both prove reachability. A returned 5xx
            // (surfaced without throwing) is an upstream failure, not a reachable response.
            RecordEdgeMetadataOutcome(reachable: !IsTransientStatus(result.StatusCode));
            return result;
        }
        catch (OperationCanceledException)
        {
            // Caller cancellation is not a master-reachability signal.
            throw;
        }
        catch (Exception ex) when (IsTransientMetadataFailure(ex))
        {
            RecordEdgeMetadataOutcome(reachable: false);
            throw;
        }
    }

    // Feeds a metadata-fetch outcome into the edge master-reachability tracker; a null tracker
    // (omitted in tests or callers that don't wire it) makes this a cheap no-op.
    private void RecordEdgeMetadataOutcome(bool reachable)
    {
        if (_edgeStatus is null)
        {
            return;
        }

        if (reachable)
        {
            _edgeStatus.RecordSuccess();
        }
        else
        {
            _edgeStatus.RecordFailure();
        }
    }

    // Runs the single-flight refresh through the cache: stores a 2xx positively, a 404
    // negatively, and — on a transient upstream failure (network/timeout/5xx) — serves a stale
    // positive entry within the max-stale window rather than propagating the failure.
    //
    // Records the edge master-reachability outcome for every path that RETURNS a response,
    // because it is the only place that knows the true outcome: a stale-served 2xx (or the
    // LogServedStale-logged 5xx fallback) means the master was UNREACHABLE even though the caller
    // sees a 2xx, so it must record a failure — otherwise a steady outage while stale metadata is
    // served looks like a healthy link. Exactly one outcome is recorded per fetch: a genuine
    // 2xx/404 = success, a stale-serve = failure. A transient failure with no stale entry to
    // serve rethrows and is recorded once by the caller's catch, not here.
    private async Task<UpstreamMetadataResponse> GetOrFetchMetadataCachedAsync(
        string url, long maxBytes, string? authorizationHeader, CancellationToken ct)
    {
        var cache = _metadataCache!;
        UpstreamMetadataResponse response;
        try
        {
            response = await SingleFlightMetadataAsync(url, maxBytes, authorizationHeader, ct);
        }
        catch (Exception ex) when (IsTransientMetadataFailure(ex))
        {
            var stale = cache.ShouldServeStale(url);
            if (stale is not null)
            {
                // Serving stale means the master could not be reached — record the failure even
                // though the caller receives a usable 2xx from the cache.
                RecordEdgeMetadataOutcome(reachable: false);
                MetadataResponseCache.LogServedStale(_logger, url, ex, upstreamStatus: null);
                return stale;
            }

            // No stale entry to fall back on: let the transient failure propagate. The caller's
            // catch records the failure outcome, so this path must not record it here.
            throw;
        }

        if (response.IsSuccessStatusCode)
        {
            cache.StorePositive(url, response);
        }
        else if (response.StatusCode == (int)System.Net.HttpStatusCode.NotFound)
        {
            cache.StoreNegative(url, response);
        }
        else if (IsTransientStatus(response.StatusCode) && cache.ShouldServeStale(url) is UpstreamMetadataResponse stale)
        {
            // A 5xx that isn't itself an exception: prefer a stale-but-good answer over relaying
            // the upstream's transient failure. Never cache the 5xx itself. The master was
            // unreachable, so record a failure even though a stale 2xx is returned.
            RecordEdgeMetadataOutcome(reachable: false);
            MetadataResponseCache.LogServedStale(_logger, url, cause: null, upstreamStatus: response.StatusCode);
            return stale;
        }

        // A genuine upstream answer reached us: 2xx/404 proves reachability, a non-stale-served
        // 5xx is still an upstream failure.
        RecordEdgeMetadataOutcome(reachable: !IsTransientStatus(response.StatusCode));
        return response;
    }

    // Coalesces concurrent callers for the same URL into one upstream fetch (the existing
    // single-flight machinery), independent of whether a TTL cache wraps it.
    private async Task<UpstreamMetadataResponse> SingleFlightMetadataAsync(
        string url, long maxBytes, string? authorizationHeader, CancellationToken ct)
    {
        // Key on URL + maxBytes + a hash of the Authorization header so joiners never inherit a
        // different caller's body cap or credentials: two callers with different caps (e.g. a
        // 32 MB metadata cap vs the 600 MB artifact cap) or different per-org upstream tokens for
        // the same URL never share a fetch; genuinely identical requests still collapse to one.
        string inflightKey = url + "\n" + maxBytes + "\n" + AuthHeaderHash(authorizationHeader);

        // CancellationToken.None: a disconnect from the first caller must not fault the
        // shared Lazy and cancel every other waiter (mirrors the blob-fetch convention).
        var lazy = _metadataInflight.GetOrAdd(inflightKey, _ => new Lazy<Task<UpstreamMetadataResponse>>(
            () => FetchMetadataBufferedAsync(url, maxBytes, authorizationHeader, CancellationToken.None)));
        ScheduleInflightRemoval(_metadataInflight, inflightKey, lazy);

        return await lazy.Value.WaitAsync(ct);
    }

    // A thrown failure is transient (serve-stale-eligible) when it is a network/timeout/
    // too-large condition — not a pre-flight policy block (SSRF, air-gap) and not a caller
    // cancellation. SsrfBlockedException and AirGappedException surface as themselves; a caller
    // cancellation (ct) is the caller's own concern, not an upstream failure.
    private static bool IsTransientMetadataFailure(Exception ex) => ex switch
    {
        SsrfBlockedException => false,
        AirGappedException => false,
        OperationCanceledException => false,
        UpstreamResponseTooLargeException => true,
        HttpRequestException => true,
        IOException => true,
        _ => false,
    };

    // The full 5xx range (not just the named HttpStatusCode members) counts as a transient
    // upstream failure eligible for stale-serve.
    private const int ServerErrorRangeStart = (int)System.Net.HttpStatusCode.InternalServerError;
    private const int ServerErrorRangeEnd = 599;

    private static bool IsTransientStatus(int status) =>
        status is >= ServerErrorRangeStart and <= ServerErrorRangeEnd;

    private async Task<UpstreamMetadataResponse> FetchMetadataBufferedAsync(
        string url, long maxBytes, string? authorizationHeader, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("upstream");
        // ResponseHeadersRead is load-bearing: the default (ResponseContentRead) would have
        // HttpClient buffer the whole body before the cap check, defeating it.
        using var response = await UnwrapSsrfAsync(
            () => SendMetadataRequestAsync(client, url, authorizationHeader, ct));
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

        // Pre-size the buffer from a trustworthy Content-Length so a body near the cap does not
        // drive the MemoryStream through ~13 doubling reallocations (each copying the whole
        // buffer). A missing, zero, or over-cap Content-Length (chunked / auto-decompressed
        // transfers) falls back to the default growth strategy — the counted loop below still
        // enforces the hard cap regardless of the declared length.
        long? declared = response.Content.Headers.ContentLength;
        int initialCapacity = declared is > 0 && declared <= maxBytes ? (int)declared.Value : 0;
        using var buffered = initialCapacity > 0 ? new MemoryStream(initialCapacity) : new MemoryStream();
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

        // When the pre-sized buffer filled exactly (Content-Length matched the actual body),
        // GetBuffer() already holds a right-sized array — return it directly instead of paying
        // for a second full-size copy via ToArray(), which would double the transient peak at
        // the 600 MB artifact cap. Any mismatch (chunked, truncated, or grown past capacity)
        // falls back to ToArray() so the returned array is never over-allocated.
        byte[] exact = buffered.GetBuffer();
        return exact.Length == buffered.Length ? exact : buffered.ToArray();
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
// MD5/SHA-1 are computed only when a caller opts into the Maven sidecar digests; mvn/gradle
// require the .sha1/.md5 sidecar files for client compatibility — these are never used for a
// security decision (the content-addressed key and integrity gate are SHA-256).
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0006",
    Justification = "MD5/SHA-1 used only for Maven sidecar compatibility, not authentication.")]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350",
    Justification = "SHA-1 used only for Maven sidecar compatibility, not a security decision.")]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5351",
    Justification = "MD5 used only for Maven sidecar compatibility, not a security decision.")]
internal sealed class HashingFileStream : Stream
{
    private readonly Stream _inner;
    private readonly IncrementalHash _hash;
    private readonly IncrementalHash? _sha1;
    private readonly IncrementalHash? _md5;
    private readonly long _maxBytes;
    private byte[]? _finalHash;
    private byte[]? _finalSha1;
    private byte[]? _finalMd5;
    private bool _disposed;

    public HashingFileStream(Stream inner, long maxBytes, bool alsoMavenDigests = false)
    {
        _inner = inner;
        _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (alsoMavenDigests)
        {
            _sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            _md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        }
        _maxBytes = maxBytes;
    }

    public long BytesWritten { get; private set; }

    public string GetSha256Hex()
    {
        _finalHash ??= _hash.GetHashAndReset();
        return Convert.ToHexString(_finalHash).ToLowerInvariant();
    }

    /// <summary>Maven .sha1 sidecar digest. Only valid when the stream was created with the
    /// Maven digests enabled; throws otherwise.</summary>
    public string GetSha1Hex()
    {
        _finalSha1 ??= (_sha1 ?? throw new InvalidOperationException("SHA-1 not enabled")).GetHashAndReset();
        return Convert.ToHexString(_finalSha1).ToLowerInvariant();
    }

    /// <summary>Maven .md5 sidecar digest. Only valid when the stream was created with the
    /// Maven digests enabled; throws otherwise.</summary>
    public string GetMd5Hex()
    {
        _finalMd5 ??= (_md5 ?? throw new InvalidOperationException("MD5 not enabled")).GetHashAndReset();
        return Convert.ToHexString(_finalMd5).ToLowerInvariant();
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
        _sha1?.AppendData(buffer, offset, count);
        _md5?.AppendData(buffer, offset, count);
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
        _sha1?.AppendData(buffer.Span);
        _md5?.AppendData(buffer.Span);
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
            _sha1?.Dispose();
            _md5?.Dispose();
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed) { await base.DisposeAsync().ConfigureAwait(false); return; }
        _disposed = true;
        _hash.Dispose();
        _sha1?.Dispose();
        _md5?.Dispose();
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
