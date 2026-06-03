using System.Threading.Channels;

namespace Dependably.Infrastructure.Siem;

/// <summary>
/// Bounded in-memory queue + worker for outbound SIEM events. Producers (audit emit
/// sites) call <see cref="TryEnqueue"/> — non-blocking, drops on overflow with a metric so
/// the originating request never blocks waiting for the collector. The hosted background
/// service consumes the channel, dispatches to the configured forwarder, and retries
/// transient failures with bounded backoff.
///
/// If no <see cref="ISiemForwarder"/> is registered, this service is not started; producers
/// see <see cref="TryEnqueue"/> as a no-op (returns true; queue absent).
/// </summary>
public sealed class SiemForwarderQueue : BackgroundService
{
    private const int DefaultCapacity = 1024;
    private static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(30)
    ];

    private readonly Channel<SiemEvent> _channel;
    private readonly ISiemForwarder _forwarder;
    private readonly ILogger<SiemForwarderQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public SiemForwarderQueue(ISiemForwarder forwarder, IConfiguration config, ILogger<SiemForwarderQueue> logger)
    {
        _forwarder = forwarder;
        _logger = logger;
        var capacity = int.TryParse(config["SIEM_QUEUE_CAPACITY"], out var c) && c > 0 ? c : DefaultCapacity;
        // Default FullMode (Wait) lets TryWrite return false when the channel is at capacity,
        // so producers can record the drop. TryWrite never actually blocks; we just don't use
        // WriteAsync at all on the producer side.
        _channel = Channel.CreateBounded<SiemEvent>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false
        });
    }

    /// <summary>
    /// Non-blocking enqueue. Returns false if the queue was full and the event was dropped.
    /// Producers do not handle the failure — the metric is incremented and operations continue.
    /// </summary>
    public bool TryEnqueue(SiemEvent ev)
    {
        if (_channel.Writer.TryWrite(ev)) return true;
        Interlocked.Increment(ref _droppedCount);
        return false;
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "SIEM forwarder queue starting (transport={Transport}).", _forwarder.Name);

        await foreach (var ev in _channel.Reader.ReadAllAsync(stoppingToken))
        {
            await DeliverWithRetryAsync(ev, stoppingToken);
        }
    }

    private async Task DeliverWithRetryAsync(SiemEvent ev, CancellationToken ct)
    {
        for (var attempt = 0; attempt <= BackoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                await _forwarder.SendAsync(ev, ct);
                Interlocked.Increment(ref _deliveredCount);
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                if (attempt == BackoffSchedule.Length)
                {
                    Interlocked.Increment(ref _failedCount);
                    _logger.LogWarning(ex,
                        "SIEM forward failed after {Attempts} attempts; dropping event {EventId}.",
                        attempt + 1, ev.Id);
                    return;
                }
                _logger.LogDebug(ex,
                    "SIEM forward attempt {Attempt} failed; retrying in {Backoff}.",
                    attempt + 1, BackoffSchedule[attempt]);
                try { await Task.Delay(BackoffSchedule[attempt], ct); }
                catch (OperationCanceledException) { return; }
            }
        }
    }
}
