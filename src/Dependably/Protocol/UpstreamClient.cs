using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;

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
    private readonly IBlobStore _blobs;   // resolved to TieredBlobStorage.Cache
    private readonly AuditRepository _audit;
    private readonly IUpstreamUrlValidator _urlValidator;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<UpstreamClient> _logger;
    private readonly string _stagingPath;

    // Dedup in-flight blob fetches: only one upstream request per blob key at a time.
    // Single shared work item produces (sha, size, key) — no shared byte[]. Concurrent
    // waiters each independently open the cached blob after the lazy resolves.
    private readonly ConcurrentDictionary<string, Lazy<Task<UpstreamFetchResult>>> _inflight = new();

    // Dedup in-flight metadata fetches: only one upstream request per URL at a time.
    // Separate from _inflight because the result shape (UpstreamMetadataResponse) and
    // the key (URL, not blob key) are different — same single-flight pattern though.
    private readonly ConcurrentDictionary<string, Lazy<Task<UpstreamMetadataResponse>>> _metadataInflight = new();

    public UpstreamClient(
        IHttpClientFactory httpClientFactory,
        TieredBlobStorage blobs,
        AuditRepository audit,
        IUpstreamUrlValidator urlValidator,
        IAirGapMode airGap,
        IConfiguration configuration,
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

        // Staging dir for hash-and-stage MISS path. Defaults to the OS temp
        // directory — operators expecting large artefacts on containerised deployments
        // should point this at a disk-backed volume (e.g. /data/staging), because /tmp
        // is often tmpfs (RAM-backed), which defeats the memory-bounding goal of streaming.
        var configured = configuration["PROXY_STAGING_PATH"];
        _stagingPath = string.IsNullOrWhiteSpace(configured) ? Path.GetTempPath() : configured;
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
            throw new AirGappedException(blobKey);

        // Thundering herd dedup — only one fetch per blobKey in flight. The shared work
        // item produces (sha, size, blobKey) only; each waiter independently opens the
        // cached blob after the lazy resolves so no byte[] is shared. Use
        // CancellationToken.None so a disconnect by the first caller doesn't fault the
        // shared Lazy and cancel all other waiters. The cache write is idempotent.
        var lazy = _inflight.GetOrAdd(blobKey, _ => new Lazy<Task<UpstreamFetchResult>>(
            () => FetchAndStageAsync(upstreamUrl, checksumSpec, blobKey, ecosystem, orgId, purl, CancellationToken.None)));

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

    private const long MaxUpstreamResponseBytes = 600L * 1024 * 1024; // 600 MB

    /// <summary>
    /// Hash-and-stage MISS path: streams upstream → temp file (with SHA-256
    /// computed inline via <see cref="IncrementalHash"/> and a running byte counter
    /// that throws on the 600 MB cap) → verifies checksum → uploads verified bytes to
    /// the blob store via <see cref="IBlobStore.PutAsync"/>. Cleans up the temp file
    /// unconditionally. Caller (the lazy in <see cref="GetOrFetchStreamAsync"/>) only
    /// receives (sha, size, blobKey); concurrent waiters each independently re-open
    /// the cached blob.
    /// </summary>
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
            throw new SsrfBlockedException(url);

        var client = _httpClientFactory.CreateClient("upstream");
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        // Abort early if Content-Length already exceeds 600MB limit (cheap fail-fast).
        // The HashingFileStream below still enforces the cap for chunked transfers.
        if (response.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
        {
            await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem, purl: purl,
                detail: $"{{\"url\":\"{url}\",\"content_length\":{response.Content.Headers.ContentLength}}}", ct: ct);
            throw new UpstreamResponseTooLargeException(url);
        }

        var tempPath = Path.Combine(_stagingPath, $"dependably-stage-{Guid.NewGuid():N}.tmp");
        var sha256Hex = string.Empty;
        long sizeBytes = 0;

        try
        {
            // Stream upstream → temp file, hashing inline. HashingFileStream wraps the
            // FileStream and forwards writes to disk AND to IncrementalHash, throwing on
            // the 600 MB cap.
            await using (var responseStream = await response.Content.ReadAsStreamAsync(ct))
            {
                var fileStream = new FileStream(
                    tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    bufferSize: 81920, useAsync: true);
                await using (var staging = new HashingFileStream(fileStream, MaxUpstreamResponseBytes))
                {
                    try
                    {
                        await responseStream.CopyToAsync(staging, ct);
                    }
                    catch (UpstreamResponseTooLargeException)
                    {
                        await _audit.LogAsync(
                            "upstream_response_too_large", orgId: orgId, ecosystem: ecosystem, purl: purl,
                            detail: $"{{\"url\":\"{url}\",\"bytes_read\":{staging.BytesWritten}}}", ct: ct);
                        throw new UpstreamResponseTooLargeException(url);
                    }
                    sha256Hex = staging.GetSha256Hex();
                    sizeBytes = staging.BytesWritten;
                }
            }

            // For SHA-256 specs we already computed the hash inline; for SHA-1/SHA-512
            // (npm shasum, NuGet packageHash) we re-read the staged file. Same temp file,
            // single disk write.
            if (spec is not null && !await VerifyChecksumAsync(
                    new VerifyChecksumRequest(tempPath, sha256Hex, spec, url, ecosystem, orgId, purl), ct))
                throw new ChecksumException($"Upstream checksum mismatch for {url}");

            // Upload the verified bytes to the blob store.
            await using (var verified = new FileStream(
                tempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: true))
            {
                await _blobs.PutAsync(blobKey, verified, ct);
            }

            return new UpstreamFetchResult(sha256Hex, sizeBytes, blobKey);
        }
        finally
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to delete staging temp file {TempPath}: {ExceptionType}",
                    tempPath, ex.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Checks the staged temp file against the upstream-supplied checksum spec.
    /// SHA-256 reuses the inline-computed hex (avoiding a re-read); other algorithms
    /// re-read the file. On mismatch audits <c>checksum_failure</c> and returns false
    /// so the caller throws.
    /// </summary>
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
        if (ok) return true;

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

    /// <summary>
    /// Single-flighted metadata fetch. Returns a buffered response shareable across
    /// concurrent callers — only one upstream HTTP request runs per URL at a time, even
    /// when N CI runners hit a cold-start coordinate simultaneously. Returned value is
    /// immutable; callers inspect <see cref="UpstreamMetadataResponse.StatusCode"/> and
    /// read the buffered body directly (the old <see cref="GetMetadataAsync"/> path
    /// returned an <see cref="HttpResponseMessage"/> whose stream could only be consumed
    /// once, which is why the controllers couldn't share fetches).
    /// </summary>
    public async Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(string url, CancellationToken ct = default)
    {
        if (_airGap.IsEnabled)
            throw new AirGappedException(url);

        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
            throw new SsrfBlockedException(url);

        // CancellationToken.None: a disconnect from the first caller must not fault the
        // shared Lazy and cancel every other waiter (mirrors the blob-fetch convention).
        var lazy = _metadataInflight.GetOrAdd(url, _ => new Lazy<Task<UpstreamMetadataResponse>>(
            () => FetchMetadataBufferedAsync(url, CancellationToken.None)));

        try
        {
            return await lazy.Value.WaitAsync(ct);
        }
        finally
        {
            _metadataInflight.TryRemove(url, out _);
        }
    }

    private async Task<UpstreamMetadataResponse> FetchMetadataBufferedAsync(string url, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("upstream");
        using var response = await client.GetAsync(url, ct);
        var body = await response.Content.ReadAsByteArrayAsync(ct);
        var contentType = response.Content.Headers.ContentType?.ToString();
        return new UpstreamMetadataResponse(
            (int)response.StatusCode,
            response.IsSuccessStatusCode,
            contentType,
            body);
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
    private long _bytesWritten;
    private byte[]? _finalHash;
    private bool _disposed;

    public HashingFileStream(Stream inner, long maxBytes)
    {
        _inner = inner;
        _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        _maxBytes = maxBytes;
    }

    public long BytesWritten => _bytesWritten;

    public string GetSha256Hex()
    {
        _finalHash ??= _hash.GetHashAndReset();
        return Convert.ToHexString(_finalHash).ToLowerInvariant();
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => _bytesWritten; set => throw new NotSupportedException(); }

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
        _bytesWritten += count;
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        CheckCap(buffer.Length);
        // IncrementalHash accepts ReadOnlySpan<byte>; project the memory before consuming
        // it so we hash the same bytes the file write consumes.
        _hash.AppendData(buffer.Span);
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        _bytesWritten += buffer.Length;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken).AsTask();

    private void CheckCap(int incoming)
    {
        if (_bytesWritten + incoming > _maxBytes)
            throw new UpstreamResponseTooLargeException("(staging)");
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
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
