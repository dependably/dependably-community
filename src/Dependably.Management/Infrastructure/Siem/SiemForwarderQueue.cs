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

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// forwarding events still buffered in the channel once the host's stopping token has
    /// already fired. Bounded independently of the host's own shutdown timeout so one slow,
    /// retrying event cannot consume the entire grace period at the expense of every other
    /// compliance-relevant event waiting behind it in the channel.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

    private static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(30)
    ];

    private readonly Channel<SiemEvent> _channel;
    private readonly ISiemForwarder _forwarder;
    private readonly TimeProvider _time;
    private readonly ILogger<SiemForwarderQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public SiemForwarderQueue(
        ISiemForwarder forwarder, TimeProvider time, IConfiguration config, ILogger<SiemForwarderQueue> logger)
    {
        _forwarder = forwarder;
        _time = time;
        _logger = logger;
        int capacity = int.TryParse(config["SIEM_QUEUE_CAPACITY"], out int c) && c > 0 ? c : DefaultCapacity;
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
        if (_channel.Writer.TryWrite(ev))
        {
            return true;
        }

        Interlocked.Increment(ref _droppedCount);
        return false;
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>. <see cref="BackgroundService.StartAsync"/>
    /// short-circuits and never invokes <c>ExecuteAsync</c> at all when handed an already-cancelled
    /// token, so it cannot exercise the shutdown-drain race this method covers (a stopping token
    /// cancelled while the read loop is genuinely running, with events still buffered).
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "SIEM forwarder queue starting (transport={Transport}).", _forwarder.Name);

        try
        {
            await foreach (var ev in _channel.Reader.ReadAllAsync(stoppingToken))
            {
                await DeliverWithRetryAsync(ev, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // ReadAllAsync's WaitToReadAsync checks the stopping token before it checks whether
            // the channel has buffered items, so cancellation can fire here with events still
            // sitting in the channel — fall through to drain them instead of dropping them. SIEM
            // is a compliance sink, so events accepted into the queue before shutdown must still
            // reach the forwarder.
        }

        await DrainOnShutdownAsync();
    }

    /// <summary>
    /// Runs whatever is still buffered in the channel through the normal delivery path when
    /// shutdown cancels the main read loop above. The host's own stopping token is already
    /// cancelled by this point, so drained deliveries run on a fresh, time-bounded token
    /// (<see cref="DrainTimeout"/>) instead — otherwise every delivery attempt would see
    /// cancellation immediately and skip straight to "failed" without ever trying.
    /// </summary>
    private async Task DrainOnShutdownAsync()
    {
        using var drainCts = new CancellationTokenSource(DrainTimeout);
        int drained = 0;
        int abandoned = 0;

        while (_channel.Reader.TryRead(out var ev))
        {
            if (drainCts.IsCancellationRequested)
            {
                // Drain window exhausted — stop attempting deliveries but keep draining the
                // channel itself so the abandoned count is accurate.
                abandoned++;
                continue;
            }

            await DeliverWithRetryAsync(ev, drainCts.Token);
            drained++;
        }

        if (abandoned > 0)
        {
            _logger.LogWarning(
                "SIEM forwarder queue shutdown drain timed out after {Timeout}s; " +
                "{Count} event(s) still buffered were not attempted.",
                DrainTimeout.TotalSeconds, abandoned);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "SIEM forwarder queue drained {Count} event(s) still buffered at shutdown.", drained);
        }
    }

    private async Task DeliverWithRetryAsync(SiemEvent ev, CancellationToken ct)
    {
        for (int attempt = 0; attempt <= BackoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

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
                try { await Task.Delay(BackoffSchedule[attempt], _time, ct); }
                catch (OperationCanceledException) { return; }
            }
        }
    }
}
