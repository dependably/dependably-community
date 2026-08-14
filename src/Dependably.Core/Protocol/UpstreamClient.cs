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
public sealed partial class UpstreamClient
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
    private readonly OrgRepository? _orgs;
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
        EdgeStatusTracker? edgeStatus = null,
        OrgRepository? orgs = null)
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
        // Gates the proxy cache-fill write against the tenant's storage quota — the same
        // per-org ceiling PackagePublishService and OciUploadService enforce. Nullable so tests
        // that don't exercise quota enforcement can omit it; EnsureTenantCacheQuotaAsync treats a
        // null dependency the same as "no quota configured" (unlimited).
        _orgs = orgs;
        _hostStopping = lifetime?.ApplicationStopping ?? CancellationToken.None;

        // Staging dir for hash-and-stage MISS path, plus the hard floor for available
        // staging disk space — both resolved by StagingOptions so the path probed by
        // IStagingDiskInfo and the floor enforced here can't diverge.
        _stagingPath = stagingOptions.Path;
        _stagingDiskFloorBytes = stagingOptions.FloorBytes;
        // PROXY_STAGING_PATH is set by the operator deploying the container
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
        string? containmentBase = null,
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
                new UpstreamFetchRequest(
                    upstreamUrl, checksumSpec, blobKey, ecosystem, orgId, purl, authorizationHeader,
                    containmentBase),
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

        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
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
        catch (UpstreamFetchFailedException ex) when (ex.Refused)
        {
            outcome = "upstream_refused";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream refused (auth/policy)");
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
    // (air-gap) or a deterministic upstream refusal (401/403) is a verdict about this request,
    // not a statement about whether the master is reachable, so neither is recorded as a
    // reachability failure. No-op off-edge (the tracker is null) — a single null-check per fetch.
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
            case "upstream_refused":
                // Deterministic auth/policy refusal (401/403): a statement about this
                // credential's authorization on the master, not master unreachability.
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
        string? OrgId, string? Purl, string? AuthorizationHeader, string? ContainmentBase = null);

    // The shared single-flight work item behind _inflight — runs exactly once per blobKey
    // regardless of caller fan-in. Owns the UpstreamInflightFetches gauge and
    // UpstreamFetchDuration histogram so both instruments count real upstream operations, not
    // per-caller waits (waiters only observe the shared Task in FetchWithTelemetryAsync).
    private async Task<UpstreamFetchResult> FetchAndStageAsync(UpstreamFetchRequest req, CancellationToken ct)
    {
        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
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
        using var successResponse = await FetchWithRetryAsync(
            client, url, orgId, authorizationHeader, req.ContainmentBase, fetchCt);

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
                // audit-attribution-ok: single-flight dedup — this fetch may be shared by several
                // concurrent inbound requests for the same URL (see the class docs), so there is
                // no one caller's IP to attribute the shared upstream outcome to.
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

    // Sends a GET request to url with transient-failure retries (429, 5xx, and anonymous
    // 403 — public CDN bot mitigation emits genuinely transient 403s). A fresh
    // HttpRequestMessage is created per attempt — HttpClient rejects a reused one. Exits on
    // first 2xx response or throws: UpstreamFetchFailedException on exhausted transient
    // retries OR on a deterministic authenticated 401/403 refusal (never retried — a
    // credential that is unauthorized on attempt 1 is unauthorized on attempt 3),
    // HttpRequestException on other non-transient failures (404/410/…) so the caller's
    // multi-base loop can try the next upstream registry.
    private async Task<HttpResponseMessage> FetchWithRetryAsync(
        HttpClient client, string url, string? orgId, string? authorizationHeader,
        string? containmentBase, CancellationToken ct)
    {
        for (int attempt = 0; attempt < MaxUpstreamFetchAttempts; attempt++)
        {
            using var fetchRequest = BuildFetchRequest(url, orgId, authorizationHeader, containmentBase);

            var response = await UnwrapSsrfAsync(
                () => client.SendAsync(fetchRequest, HttpCompletionOption.ResponseHeadersRead, ct));

            if (response.IsSuccessStatusCode)
            {
                return response;
            }

            var (refused, transient) = ClassifyAndLogNonSuccess(
                response, fetchRequest, url, authorizationHeader, attempt);

            if (refused)
            {
                // Deterministic refusal — fail after this single attempt rather than continuing
                // the loop, so the caller sees the verdict immediately instead of after
                // MaxUpstreamFetchAttempts of retries against the same answer.
                int refusedStatus = (int)response.StatusCode;
                response.Dispose();
                throw new UpstreamFetchFailedException { Url = url, StatusCode = refusedStatus, Transient = false, Refused = true };
            }

            if (transient && attempt < MaxUpstreamFetchAttempts - 1)
            {
                response.Dispose();
                // Capped exponential back-off: 200ms, 400ms.
                // now-ok: back-off between live HTTP attempts against a transiently failing
                // upstream — the pause has to be real elapsed time to be worth anything, and
                // no caller observes it as a deadline.
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

    // Builds the per-attempt GET request. Pass org context via request options so
    // SsrfAwareRedirectHandler can attribute blocked-redirect audit events to the correct
    // tenant, and attach the per-upstream Authorization header (Bearer/Basic) when configured —
    // built once at resolve time, null for anonymous upstreams. TryAddWithoutValidation mirrors
    // the OCI attach path and avoids HttpClient's header-format validation.
    private static HttpRequestMessage BuildFetchRequest(
        string url, string? orgId, string? authorizationHeader, string? containmentBase)
    {
        var fetchRequest = new HttpRequestMessage(HttpMethod.Get, url);
        if (orgId is not null)
        {
            fetchRequest.Options.Set(SsrfAwareRedirectHandler.OrgIdOption, orgId);
        }

        if (containmentBase is not null)
        {
            fetchRequest.Options.Set(SsrfAwareRedirectHandler.ContainmentBaseOption, containmentBase);
        }

        if (authorizationHeader is not null)
        {
            fetchRequest.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        return fetchRequest;
    }

    // Classifies a non-success response as a deterministic refusal vs. a transient failure and
    // logs the boundary event. A 401/403 from an upstream this request AUTHENTICATED to
    // (edge→master, an authenticated upstream registry) is a deterministic auth/policy verdict
    // about the presented credential — retrying burns upstream capacity and delays surfacing the
    // refusal, so it fails after a single attempt. An ANONYMOUS 403 is a different animal: public
    // registry CDNs (bot mitigation, edge throttling) emit genuinely transient 403s, so with no
    // credential to be refused it stays in the transient bucket and is retried with backoff
    // (mapping to a retryable 503 when exhausted).
    private (bool Refused, bool Transient) ClassifyAndLogNonSuccess(
        HttpResponseMessage response, HttpRequestMessage fetchRequest, string url,
        string? authorizationHeader, int attempt)
    {
        int statusInt = (int)response.StatusCode;
        bool refused = authorizationHeader is not null && statusInt is 401 or 403;
        bool transient = !refused && statusInt is 429 or 403 or >= 500;

        var (diagRetryAfter, diagCfRay, diagXServedBy, diagVia, diagUserAgent) = GetResponseDiagHeaders(response, fetchRequest);
        // Structured boundary log on every non-success response for diagnosability.
        // RenderedCompactJsonFormatter JSON-encodes all structured fields.
        _logger.LogWarning(
            "Upstream fetch non-success: Status={StatusCode} Url={Url} Transient={Transient} Refused={Refused} " +
            "Attempt={Attempt}/{MaxAttempts} RetryAfter={RetryAfterHeader} CfRay={CfRay} XServedBy={XServedBy} " +
            "Via={Via} UserAgent={UserAgent} SingleFlighted=true",
            statusInt, url, transient, refused, attempt + 1, MaxUpstreamFetchAttempts,
            diagRetryAfter, diagCfRay, diagXServedBy, diagVia, diagUserAgent);

        return (refused, transient);
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
                    // audit-attribution-ok: single-flight dedup — this fetch may be shared by
                    // several concurrent inbound requests for the same URL (see the class docs),
                    // so there is no one caller's IP to attribute the shared upstream outcome to.
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

            // Enforce the tenant's storage ceiling on the verified bytes before they land in the
            // blob store — the same per-org quota hosted publish and OCI push enforce. Throws
            // when the fill would exceed it, so the artefact is never cached. The reservation is
            // held until the write completes, so a concurrent fill weighs these bytes even though
            // nothing has recorded them on the cache plane yet.
            using var quota = await ReserveTenantCacheQuotaAsync(ctx.OrgId, sizeBytes, fetchCt);

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

    // Refuses a proxy cache-fill that would carry orgId past its storage ceiling, so an
    // authenticated tenant cannot grow the shared cache plane without bound.
    //
    // The reservation itself is OrgRepository's — the same gate hosted publish and OCI push call,
    // reading the same derived org_storage_bytes sum and charging the same in-flight ledger. A
    // proxy fill and a hosted publish racing each other therefore weigh each other's bytes instead
    // of each enforcing the ceiling from its own private reading. All this adds is the proxy
    // path's refusal shape: an exception, mapped by TenantStorageQuotaExceededExceptionMiddleware
    // to 413, rather than a result the publish caller inspects.
    //
    // No-op when there is no org context or no OrgRepository dependency (test doubles that omit
    // it). The returned reservation must be disposed once the fill completes — the caller does so
    // in a using, so a failed or cancelled fill releases too.
    private async Task<StorageReservation> ReserveTenantCacheQuotaAsync(
        string? orgId, long sizeBytes, CancellationToken ct)
    {
        if (_orgs is null || orgId is null)
        {
            return StorageReservation.None;
        }

        long? quota = await _orgs.GetEffectiveStorageQuotaAsync(orgId, ct);
        return await _orgs.TryReserveStorageAsync(orgId, sizeBytes, quota, ct)
            ?? throw new TenantStorageQuotaExceededException(orgId, quota!.Value);
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
        // audit-attribution-ok: single-flight dedup — this fetch may be shared by several
        // concurrent inbound requests for the same URL (see the class docs), so there is no one
        // caller's IP to attribute the shared upstream outcome to.
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
}
