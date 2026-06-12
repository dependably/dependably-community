using System.Threading.Channels;
using Dependably.Infrastructure.Observability;

namespace Dependably.Infrastructure;

/// <summary>
/// Bounded channel-backed download-count writer. Every
/// <see cref="PackageRepository.IncrementDownloadCountAsync"/> and
/// <see cref="PackageRepository.IncrementDownloadCountByPurlAsync"/> call on the download
/// hot path previously awaited a fresh SQLite connection open and a synchronous UPDATE before
/// the response could continue. SQLite WAL serialises writers, so at sustained download
/// throughput the writer queue grows and busy_timeout trips spike across every ecosystem.
///
/// This writer accepts a record via <see cref="TryEnqueue"/> (lock-free, microseconds) and
/// the companion <see cref="DownloadCountWriterHostedService"/> drains the channel in batched
/// UPDATEs (one UPDATE per unique versionId or purl per batch, with an aggregated count).
///
/// Overflow policy: drop on full. A lost increment means the durable counter is slightly
/// understated — acceptable under extreme load; a blocked download is not.
/// The <see cref="DependablyMeter.DownloadCountWriterDropped"/> counter surfaces drop volume
/// so operators see when the writer falls behind.
/// </summary>
public sealed class DownloadCountWriter
{
    // Capacity chosen to match ActivityWriter. At one record per download, this gives
    // the drainer ~50 s of runway at 200 RPS before the channel saturates.
    public const int ChannelCapacity = 10_000;

    // FullMode.Wait makes TryWrite return false synchronously when the channel is full,
    // which is exactly what we want: enqueue is lock-free and never blocks the request
    // thread, and we can detect drops + increment the metric.
    private readonly Channel<DownloadCountRecord> _channel = Channel.CreateBounded<DownloadCountRecord>(
        new BoundedChannelOptions(ChannelCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

    /// <summary>Drainer-side reader. Used by <see cref="DownloadCountWriterHostedService"/>.</summary>
    public ChannelReader<DownloadCountRecord> Reader => _channel.Reader;

    private long _enqueued;
    /// <summary>
    /// Monotonic count of records successfully written to the channel. Used by
    /// <see cref="DownloadCountWriterHostedService.WaitForIdleAsync"/> as the high-water mark
    /// the drainer must catch up to. Dropped records do not increment.
    /// </summary>
    public long EnqueuedCount => Interlocked.Read(ref _enqueued);

    /// <summary>
    /// Returns true if the record was queued; false if the channel was full and the record
    /// was dropped (drop counter incremented). Never throws.
    /// </summary>
    public bool TryEnqueue(DownloadCountRecord record)
    {
        // Increment before TryWrite so WaitForIdleAsync never sees EnqueuedCount lag a
        // record that is already readable by the drainer.
        Interlocked.Increment(ref _enqueued);
        if (_channel.Writer.TryWrite(record))
        {
            return true;
        }
        // Channel full — undo the optimistic increment and count the drop.
        Interlocked.Decrement(ref _enqueued);
        DependablyMeter.DownloadCountWriterDropped.Add(1);
        return false;
    }

    /// <summary>Signals no further writes — drains and exits the hosted service.</summary>
    public void Complete() => _channel.Writer.TryComplete();
}

/// <summary>
/// One download-count increment queued for async aggregation and write.
/// Exactly one of <see cref="VersionId"/> or <see cref="Purl"/> is non-null,
/// matching the two keying strategies used by the download-serve paths.
/// </summary>
public sealed record DownloadCountRecord(string? VersionId, string? Purl);
