using System.Threading.Channels;
using Dependably.Infrastructure.Observability;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// The bounded channel between metered responses and <see cref="UsageEventWriterHostedService"/>,
/// which drains it into <c>usage_events</c>.
///
/// Unlike the download-count and activity writers, this one is not best-effort: a metering event
/// is billing data. <see cref="EnqueueAsync"/> writes without blocking while there is room and,
/// when the channel is full, waits up to a bounded time for room before giving up. The wait
/// happens after the response body has been written, so it delays a request's completion, never
/// its bytes. An event is shed only when the drainer has fallen so far behind that the wait
/// expires — a sustained database outage — and every shed event is counted on
/// <see cref="DependablyMeter.UsageEventsDropped"/>. Shedding undercounts, which is the
/// customer-favourable direction; nothing here can ever count an event twice.
/// </summary>
public sealed class UsageEventWriter
{
    /// <summary>Default channel capacity when no configuration override is supplied.</summary>
    public const int DefaultChannelCapacity = 100_000;

    /// <summary>How long a producer waits for room in a full channel before shedding.</summary>
    public static readonly TimeSpan DefaultMaxEnqueueWait = TimeSpan.FromSeconds(5);

    private readonly Channel<UsageEvent> _channel;
    private readonly TimeProvider _time;
    private readonly TimeSpan _maxEnqueueWait;
    private long _enqueued;

    public UsageEventWriter(TimeProvider time, int? capacity = null, TimeSpan? maxEnqueueWait = null)
    {
        _time = time;
        ChannelCapacity = capacity is > 0 ? capacity.Value : DefaultChannelCapacity;
        _maxEnqueueWait = maxEnqueueWait ?? DefaultMaxEnqueueWait;
        _channel = Channel.CreateBounded<UsageEvent>(
            new BoundedChannelOptions(ChannelCapacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
            });
    }

    public int ChannelCapacity { get; }

    /// <summary>Drainer-side reader.</summary>
    public ChannelReader<UsageEvent> Reader => _channel.Reader;

    /// <summary>Monotonic count of events accepted into the channel. Shed events do not count.</summary>
    public long EnqueuedCount => Interlocked.Read(ref _enqueued);

    /// <summary>
    /// Queues an event, waiting a bounded time for room when the channel is full. Returns false
    /// when the event was shed. Never throws.
    /// </summary>
    public async ValueTask<bool> EnqueueAsync(UsageEvent usageEvent)
    {
        if (_channel.Writer.TryWrite(usageEvent))
        {
            Interlocked.Increment(ref _enqueued);
            return true;
        }

        using var timeout = new CancellationTokenSource(_maxEnqueueWait, _time);
        try
        {
            await _channel.Writer.WriteAsync(usageEvent, timeout.Token);
            Interlocked.Increment(ref _enqueued);
            return true;
        }
        catch (OperationCanceledException)
        {
            DependablyMeter.UsageEventsDropped.Add(1);
            return false;
        }
        catch (ChannelClosedException)
        {
            DependablyMeter.UsageEventsDropped.Add(1);
            return false;
        }
    }

    /// <summary>Stops accepting events. The drainer empties what is already queued.</summary>
    public void Complete() => _channel.Writer.TryComplete();
}
