using System.Threading.Channels;
using Dependably.Infrastructure.Observability;

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

    private static readonly TimeSpan[] DefaultBackoffSchedule =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(30)
    ];

    private readonly Channel<SiemEvent> _channel;
    private readonly ISiemForwarder _forwarder;
    private readonly TimeProvider _time;
    private readonly ILogger<SiemForwarderQueue> _logger;
    private readonly TimeSpan[] _backoffSchedule;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public SiemForwarderQueue(
        ISiemForwarder forwarder, TimeProvider time, IConfiguration config, ILogger<SiemForwarderQueue> logger)
        : this(forwarder, time, config, logger, backoffSchedule: null)
    {
    }

    /// <summary>
    /// Test seam over the retry backoff. <paramref name="backoffSchedule"/> replaces
    /// <see cref="DefaultBackoffSchedule"/>; null keeps it, which is what every production caller gets. It is not
    /// configuration — an operator has no way to reach it, so no deployment can shorten the
    /// interval a failing SIEM event is retried on.
    ///
    /// It exists because the alternative is worse. A test that only needs the retry chain to
    /// reach its terminal outcome, and asserts nothing about the intervals, otherwise has to
    /// hand-drive a <c>FakeTimeProvider</c> from outside while the loop registers its next
    /// timer from inside — and the two race. Every advance the pump spends before that timer
    /// exists is wasted, so the wait passes or fails on how heavily loaded the machine is.
    /// Injecting a zero schedule removes the clock from those tests entirely: a zero delay
    /// completes without any time, real or virtual, having to pass. Tests that assert on the
    /// intervals, or on the per-item budget that runs on the same injected clock, keep the real
    /// schedule and drive the clock.
    /// </summary>
    internal SiemForwarderQueue(
        ISiemForwarder forwarder, TimeProvider time, IConfiguration config, ILogger<SiemForwarderQueue> logger,
        TimeSpan[]? backoffSchedule)
    {
        _backoffSchedule = backoffSchedule ?? DefaultBackoffSchedule;
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
        DependablyMeter.SiemForwarderDropped.Add(1);
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
        for (int attempt = 0; attempt <= _backoffSchedule.Length; attempt++)
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
                if (attempt == _backoffSchedule.Length)
                {
                    Interlocked.Increment(ref _failedCount);
                    DependablyMeter.SiemForwarderFailed.Add(1);
                    _logger.LogWarning(ex,
                        "SIEM forward failed after {Attempts} attempts; dropping event {EventId}.",
                        attempt + 1, ev.Id);
                    return;
                }
                _logger.LogDebug(ex,
                    "SIEM forward attempt {Attempt} failed; retrying in {Backoff}.",
                    attempt + 1, _backoffSchedule[attempt]);
                try { await Task.Delay(_backoffSchedule[attempt], _time, ct); }
                catch (OperationCanceledException) { return; }
            }
        }
    }
}
