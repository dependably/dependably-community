using System.Threading.Channels;
using Dapper;
using Dependably.Infrastructure.Observability;

namespace Dependably.Infrastructure;

/// <summary>
/// Bounded channel-backed activity writer. Every <see cref="AuditRepository.LogActivityAsync"/>
/// call on the download / push hot paths previously awaited a fresh SQLite connection open
/// and a synchronous INSERT before the response could continue. SQLite WAL serialises
/// writers, so at sustained 200+ downloads/sec the writer queue grew, <c>busy_timeout</c>
/// trips spiked, and download latency degraded across every ecosystem at once.
///
/// This writer accepts a record via <see cref="TryEnqueue"/> (lock-free, microseconds) and
/// the companion <see cref="ActivityWriterHostedService"/> drains the channel in batched
/// inserts (one transaction per ~200 rows or 100 ms — whichever first).
///
/// Overflow policy: drop on full. Activity rows are observability data, not audit (audit
/// stays synchronous via <see cref="AuditRepository.LogAsync"/>). The
/// <see cref="DependablyMeter.ActivityWriterDropped"/> counter surfaces drop volume so
/// operators see when the writer falls behind.
/// </summary>
public sealed class ActivityWriter
{
    // 10k capacity matches the issue spec. At a typical p99 row size (~600 bytes), that's
    // ~6 MB of buffered records — well within process headroom — and gives the drainer
    // ~50s of runway at 200 RPS before the channel saturates.
    public const int ChannelCapacity = 10_000;

    // FullMode.Wait makes TryWrite return false synchronously when the channel is full,
    // which is exactly what we want: enqueue is lock-free and never blocks the request
    // thread, and we can detect drops + increment the metric. The .DropWrite mode would
    // silently make TryWrite always return true and drop the row anyway, so we'd lose
    // observability of the drops.
    private readonly Channel<ActivityRecord> _channel = Channel.CreateBounded<ActivityRecord>(
        new BoundedChannelOptions(ChannelCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

    /// <summary>Drainer-side reader. Used by <see cref="ActivityWriterHostedService"/>.</summary>
    public ChannelReader<ActivityRecord> Reader => _channel.Reader;

    private long _enqueued;
    /// <summary>
    /// Monotonic count of records successfully written to the channel. Used by
    /// <see cref="ActivityWriterHostedService.WaitForIdleAsync"/> as the high-water mark the
    /// drainer must catch up to. Dropped rows do not increment.
    /// </summary>
    public long EnqueuedCount => Interlocked.Read(ref _enqueued);

    /// <summary>
    /// Returns true if the record was queued; false if the channel was full and the row
    /// was dropped (drop counter incremented). Never throws.
    /// </summary>
    public bool TryEnqueue(ActivityRecord record)
    {
        if (_channel.Writer.TryWrite(record))
        {
            Interlocked.Increment(ref _enqueued);
            return true;
        }
        DependablyMeter.ActivityWriterDropped.Add(1);
        return false;
    }

    /// <summary>Signals no further writes — drains and exits the hosted service.</summary>
    public void Complete() => _channel.Writer.TryComplete();
}

/// <summary>
/// One activity row queued for async insertion. Field set mirrors the columns inserted
/// by <see cref="AuditRepository.LogActivityAsync"/>'s synchronous fallback so the wire
/// shape matches the original contract exactly.
/// </summary>
public sealed record ActivityRecord(
    string Id,
    string OrgId,
    string Ecosystem,
    string? Purl,
    string EventType,
    string? ActorId,
    string? ActorKind,
    string? Detail,
    string? SourceIp,
    string CreatedAt);
