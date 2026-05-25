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
/// </summary>
public sealed class UpstreamClient
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IBlobStore _blobs;   // resolved to TieredBlobStorage.Cache (#57)
    private readonly AuditRepository _audit;
    private readonly IUpstreamUrlValidator _urlValidator;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<UpstreamClient> _logger;

    // Dedup in-flight fetches: only one upstream request per blob key at a time
    private readonly ConcurrentDictionary<string, Lazy<Task<byte[]>>> _inflight = new();

    public UpstreamClient(
        IHttpClientFactory httpClientFactory,
        TieredBlobStorage blobs,
        AuditRepository audit,
        IUpstreamUrlValidator urlValidator,
        IAirGapMode airGap,
        ILogger<UpstreamClient> logger)
    {
        _httpClientFactory = httpClientFactory;
        // Proxy fetches always land on the cache tier — they're recoverable, eviction-friendly,
        // and (in split-tier deployments) sit on cheaper storage than the registry.
        _blobs = blobs.Cache;
        _audit = audit;
        _urlValidator = urlValidator;
        _airGap = airGap;
        _logger = logger;
    }

    /// <summary>
    /// Fetches a blob from upstream if not already cached.
    /// Verifies checksum before writing to blob store.
    /// Returns (bytes, isHit). Throws <see cref="ChecksumException"/> on mismatch.
    /// Multiple concurrent callers for the same key share a single upstream fetch.
    /// </summary>
    public async Task<(byte[] Bytes, bool IsHit)> GetOrFetchAsync(
        string blobKey,
        string upstreamUrl,
        ChecksumSpec? checksumSpec,
        string ecosystem,
        string? orgId = null,
        string? purl = null,
        CancellationToken ct = default)
    {
        // Check cache first (before entering the dedup map)
        var cached = await _blobs.GetAsync(blobKey, ct);
        if (cached is not null)
        {
            DependablyMeter.CacheLookups.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", "hit"));
            SnapshotCounters.IncrementCacheHit();
            using var ms = new MemoryStream();
            await cached.CopyToAsync(ms, ct);
            return (ms.ToArray(), true);
        }

        DependablyMeter.CacheLookups.Add(1,
            new KeyValuePair<string, object?>("ecosystem", ecosystem),
            new KeyValuePair<string, object?>("outcome", "miss"));
        SnapshotCounters.IncrementCacheMiss();
        SnapshotCounters.IncrementProxyFetch();

        // Air-gapped deployments must never reach upstream on a cache miss (#48). Cached
        // artefacts above still serve normally; only the fetch path is blocked. The
        // exception bubbles up to the AirGappedExceptionMiddleware which translates it
        // to a 503 with a clear body — better than a 504 timeout when egress is firewalled.
        if (_airGap.IsEnabled)
            throw new AirGappedException(blobKey);

        // Thundering herd dedup — only one fetch per blobKey in flight.
        // Use CancellationToken.None so a disconnect by the first caller doesn't fault
        // the shared Lazy and cancel all other waiters. The cache write is idempotent.
        var lazy = _inflight.GetOrAdd(blobKey, _ => new Lazy<Task<byte[]>>(
            () => FetchAndVerifyAsync(upstreamUrl, checksumSpec, blobKey, ecosystem, orgId, purl, CancellationToken.None)));

        using var activity = DependablyActivitySource.Source.StartActivity(
            "proxy.fetch", ActivityKind.Client);
        activity?.SetTag("dependably.ecosystem", ecosystem);
        activity?.SetTag("dependably.operation", "proxy.fetch");
        activity?.SetTag("dependably.tier", "cache");
        if (purl is not null) activity?.SetTag("dependably.purl", purl);
        if (checksumSpec is { Algorithm: ChecksumAlgorithm.Sha256, ExpectedValue: { } sha })
            activity?.SetTag("dependably.sha256", sha);

        var stopwatch = Stopwatch.StartNew();
        var outcome = "success";

        DependablyMeter.UpstreamInflightFetches.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            var bytes = await lazy.Value;
            return (bytes, false);
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
        catch (Exception ex)
        {
            outcome = "server_error";
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
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

    private const long MaxUpstreamResponseBytes = 600L * 1024 * 1024; // 600 MB

    private async Task<byte[]> FetchAndVerifyAsync(
        string url,
        ChecksumSpec? spec,
        string blobKey,
        string ecosystem,
        string? orgId,
        string? purl,
        CancellationToken ct)
    {
        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
            throw new SsrfBlockedException(url);

        var client = _httpClientFactory.CreateClient("upstream");
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        // Abort early if Content-Length already exceeds 600MB limit
        if (response.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
        {
            await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem, purl: purl,
                detail: $"{{\"url\":\"{url}\",\"content_length\":{response.Content.Headers.ContentLength}}}", ct: ct);
            throw new UpstreamResponseTooLargeException(url);
        }

        // Stream with hard cap
        using var responseStream = await response.Content.ReadAsStreamAsync(ct);
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = await responseStream.ReadAsync(buffer, ct)) > 0)
        {
            ms.Write(buffer, 0, read);
            if (ms.Length > MaxUpstreamResponseBytes)
            {
                await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem, purl: purl,
                    detail: $"{{\"url\":\"{url}\",\"bytes_read\":{ms.Length}}}", ct: ct);
                throw new UpstreamResponseTooLargeException(url);
            }
        }
        var bytes = ms.ToArray();

        if (spec is not null && !ChecksumVerifier.Verify(bytes, spec))
        {
            var actual = ChecksumVerifier.ComputeSha256Hex(bytes);
            _logger.LogWarning("Checksum mismatch for {Url}: expected {Expected}, got {Actual}",
                url, spec.ExpectedValue, actual);

            DependablyMeter.UpstreamChecksumFailures.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
            await _audit.LogAsync(
                "checksum_failure",
                orgId: orgId,
                ecosystem: ecosystem,
                purl: purl,
                detail: $"{{\"url\":\"{url}\",\"expected\":\"{spec.ExpectedValue}\",\"actual\":\"{actual}\"}}",
                ct: ct);

            throw new ChecksumException($"Upstream checksum mismatch for {url}");
        }

        // Cache the verified blob
        await _blobs.PutAsync(blobKey, new MemoryStream(bytes), ct);
        return bytes;
    }

    /// <summary>
    /// Fetches metadata without caching (simple index, registration JSON, etc.).
    /// </summary>
    public async Task<HttpResponseMessage> GetMetadataAsync(string url, CancellationToken ct = default)
    {
        // Air-gapped: also block uncached metadata fetches. Simple-index pages and npm
        // packuments are derived locally from the registry's own state in air-gap mode.
        if (_airGap.IsEnabled)
            throw new AirGappedException(url);

        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
            throw new SsrfBlockedException(url);

        var client = _httpClientFactory.CreateClient("upstream");
        return await client.GetAsync(url, ct);
    }
}

// S3925 (legacy ISerializable pattern) is suppressed on each exception below:
// .NET 10 obsoletes the binary-serialization ctor on Exception (SYSLIB0051), so
// adding (SerializationInfo, StreamingContext) would trade a Sonar warning for a
// build-time obsolete warning. These exceptions never cross an AppDomain or binary
// serialization boundary.

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
    public UpstreamResponseTooLargeException(string url)
        : base($"Upstream response exceeded 600 MB limit: {url}") { }
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
