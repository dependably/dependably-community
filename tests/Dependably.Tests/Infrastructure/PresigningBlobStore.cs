using System.Collections.Concurrent;
using Dependably.Storage;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// An S3-shaped test store: every byte operation forwards to an inner store, and the optional
/// presign capability signs a fake URL for any key it is asked about — like the real store
/// signers it only mints, and leaves the existence check to the presign seam. Every key it is
/// asked to sign is recorded, which is what gives an adversarial "no redirect" test its teeth — a
/// refusal that still minted a URL would pass on status code alone.
/// </summary>
public sealed class PresigningBlobStore(IBlobStore inner) : IBlobStore, IPresignedReadBlobStore
{
    public const string UrlBase = "https://signed.test/";

    private readonly ConcurrentQueue<string> _signed = new();

    /// <summary>The store the bytes actually live in.</summary>
    public IBlobStore Inner { get; } = inner;

    /// <summary>Whether the store can sign right now; false models a store with no signing credential.</summary>
    public bool CanSign { get; set; } = true;

    /// <summary>Every key signed since the last <see cref="ClearSigned"/>, in order.</summary>
    public IReadOnlyList<string> Signed => [.. _signed];

    public void ClearSigned() => _signed.Clear();

    public bool SupportsPresignedReads => CanSign;

    public Task<Uri?> TryCreatePresignedReadUrlAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        _signed.Enqueue(key);
        return Task.FromResult<Uri?>(new Uri($"{UrlBase}{Uri.EscapeDataString(key)}?expires={expiresAt.ToUnixTimeSeconds()}"));
    }

    public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Inner.PutAsync(key, data, ct);
    public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => Inner.GetAsync(key, ct);
    public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => Inner.ExistsAsync(key, ct);
    public Task DeleteAsync(string key, CancellationToken ct = default) => Inner.DeleteAsync(key, ct);
    public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Inner.GetTotalSizeAsync(ct);
    public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
        => Inner.GetRangeAsync(key, from, to, ct);
    public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => Inner.ListAsync(prefix, ct);
}
