using System.Security.Cryptography;
using Dependably.Storage;

namespace Dependably.Protocol;

/// <summary>
/// Result of the hash-and-stage MISS path. No byte[] — concurrent waiters share
/// the (sha, size, blobKey) triple and each independently re-open the cached blob via
/// <see cref="IBlobStore.GetAsync"/>.
/// </summary>
/// <param name="LastModified">
/// The upstream response's <c>Last-Modified</c> header, captured on the content-addressed fetch
/// path (<see cref="UpstreamClient.FetchAndCacheByUrlAsync"/>). Null for callers that don't read
/// it. Maven reads this as an artifact's upstream publish timestamp: the flat repository layout
/// it proxies carries no per-version metadata document with one, so the HTTP header on the
/// artifact's own response is the only upstream-agnostic signal available.
/// </param>
public sealed record UpstreamFetchResult(
    string Sha256Hex, long SizeBytes, string BlobKey, DateTimeOffset? LastModified = null);

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
/// Thrown when an upstream blob fetch fails after the retry policy gives up — either a
/// transient/retryable status (429, 5xx, anonymous 403) exhausted all attempts, or a
/// deterministic authenticated 401/403 refusal short-circuited after the first attempt. Mapped by
/// <c>UpstreamFetchFailedExceptionMiddleware</c> to a 503 (transient — clients should retry)
/// or a 502 (non-transient) so callers never treat it as absence (404). <see cref="Refused"/>
/// distinguishes a deterministic auth/policy refusal from generic upstream unreachability
/// within the 502 case, both in the response body and in the edge master-reachability signal.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class UpstreamFetchFailedException : Exception
{
    public string Url { get; init; } = string.Empty;
    public int StatusCode { get; init; }
    public TimeSpan? RetryAfter { get; init; }
    public bool Transient { get; init; }

    /// <summary>
    /// True when an upstream the fetch authenticated to responded 401/403 — a deterministic
    /// auth/policy refusal of the presented credential rather than a transient or unreachable
    /// failure. Refused fetches are never retried (see <c>UpstreamClient.FetchWithRetryAsync</c>)
    /// and are excluded from the edge master-reachability signal (see
    /// <c>UpstreamClient.RecordEdgeOutcome</c>) — a refusal is a statement about this
    /// credential's authorization, not about whether the master is up. An anonymous 403 never
    /// sets this: with no credential to refuse, public-CDN 403s are treated as transient.
    /// </summary>
    public bool Refused { get; init; }

    public UpstreamFetchFailedException()
        : base("Upstream blob fetch failed after retries were exhausted.") { }
}

/// <summary>
/// The proxy fetch could not record the artefact on the cache plane, so the fetch is refused.
///
/// That row is not bookkeeping. It is what the fetch scans and gates against — the OSV lookup and
/// the malicious-package, KEV, EPSS, CVSS-tolerance, release-age, install-script and licence gates
/// all run against it — and it is what later makes the artefact vulnerability-scannable and
/// evictable. An artefact with no cache-plane row is one the registry cannot vouch for, so it is not
/// served: a registry whose job is to gate its supply chain does not serve what it could not gate.
///
/// The bytes are already staged in the blob store, so a client retry is cheap and the recording gets
/// a fresh attempt. Callers map this to 503 — a retryable failure, never a 404, which would assert
/// the artefact does not exist upstream.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class ProxyCatalogueUnavailableException : Exception
{
    public ProxyCatalogueUnavailableException(string ecosystem, string purlName, string version)
        : base($"Could not record {ecosystem}/{purlName}@{version} on the cache plane; the fetch is refused rather than served ungated.")
    {
    }
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

/// <summary>
/// Thrown by <see cref="UpstreamClient"/> when storing a freshly-fetched proxy artifact would
/// exceed the tenant's storage quota. The fill is weighed against the tenant's live
/// <c>org_storage_bytes</c> total, so it is bounded by the same per-org ceiling hosted publish
/// (<c>PackagePublishService</c>) and OCI push (<c>OciUploadService</c>) enforce rather than
/// growing the cache plane without limit. Caught by
/// <c>TenantStorageQuotaExceededExceptionMiddleware</c> and translated to
/// <c>413 Payload Too Large</c>, matching the status hosted publish already returns for
/// <c>tenant_quota_exceeded</c>.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class TenantStorageQuotaExceededException : Exception
{
    public string OrgId { get; }
    public long QuotaBytes { get; }

    public TenantStorageQuotaExceededException(string orgId, long quotaBytes)
        : base($"Tenant storage quota ({quotaBytes} bytes) would be exceeded by this proxy cache fill.")
    {
        OrgId = orgId;
        QuotaBytes = quotaBytes;
    }
}
