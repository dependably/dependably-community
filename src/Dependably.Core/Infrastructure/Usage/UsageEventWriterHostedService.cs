using System.Threading.Channels;
using Dependably.Infrastructure.Observability;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Drains <see cref="UsageEventWriter"/> into <c>usage_events</c> in batches.
///
/// A batch leaves memory only once it has committed. A failed insert is retried with capped
/// exponential back-off, holding the same batch, while the channel keeps absorbing new events;
/// because inserts are idempotent on <c>event_id</c>, retrying a batch whose commit actually
/// succeeded before the error surfaced stores nothing twice. On shutdown the writer stops
/// accepting events and the drainer empties the channel before returning; only an insert that
/// still fails at that point loses events, and those are counted on
/// <see cref="DependablyMeter.UsageEventsDropped"/> and logged.
///
/// suspension-ok: not a scheduled tenant sweep — a write-behind flush of usage that was already
/// served. A suspended org cannot generate new metered responses (the protocol plane is behind
/// TenantStatusEnforcementMiddleware), and usage served before a suspension is exactly what the
/// final invoice must still record, so persisting it is required rather than merely harmless.
/// </summary>
public sealed class UsageEventWriterHostedService : BackgroundService
{
    public const int MaxBatch = 1000;
    public static readonly TimeSpan MaxFlushInterval = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan InitialRetryDelay = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(30);

    private readonly UsageEventWriter _writer;
    private readonly UsageEventRepository _repository;
    private readonly ILogger<UsageEventWriterHostedService> _logger;
    private readonly TimeProvider _time;
    private long _flushed;

    public UsageEventWriterHostedService(
        UsageEventWriter writer,
        UsageEventRepository repository,
        ILogger<UsageEventWriterHostedService> logger,
        TimeProvider time)
    {
        _writer = writer;
        _repository = repository;
        _logger = logger;
        _time = time;
    }

    /// <summary>Monotonic count of events committed to <c>usage_events</c>.</summary>
    public long FlushedCount => Interlocked.Read(ref _flushed);

    /// <summary>
    /// Drains everything currently queued, on the caller's thread. Only for a writer whose
    /// background loop is not running (unit tests); against a running host, use
    /// <see cref="WaitForIdleAsync"/> instead, since the channel has a single reader.
    /// </summary>
    public async Task DrainPendingAsync(CancellationToken ct = default)
    {
        var buffer = new List<UsageEvent>(MaxBatch);
        while (_writer.Reader.TryRead(out var usageEvent))
        {
            buffer.Add(usageEvent);
            if (buffer.Count >= MaxBatch)
            {
                await FlushOnceAsync(buffer, ct);
                buffer.Clear();
            }
        }

        if (buffer.Count > 0)
        {
            await FlushOnceAsync(buffer, ct);
        }
    }

    /// <summary>
    /// Waits until every accepted event has been committed. For tests against a running host.
    /// </summary>
    public async Task WaitForIdleAsync(TimeSpan timeout = default, CancellationToken ct = default)
    {
        if (timeout == default)
        {
            timeout = TimeSpan.FromSeconds(5);
        }

        // now-ok: a polling deadline awaiting genuine async completion of the drain on another
        // thread; both the deadline and the poll interval run on the real clock.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (FlushedCount >= _writer.EnqueuedCount)
            {
                return;
            }

            // now-ok: poll interval of the real-time drain wait above.
            await Task.Delay(5, ct);
        }

        throw new TimeoutException(
            $"UsageEventWriter did not become idle within {timeout.TotalMilliseconds} ms " +
            $"(enqueued={_writer.EnqueuedCount}, flushed={FlushedCount}).");
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _writer.Complete();
        await base.StopAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var reader = _writer.Reader;
        var buffer = new List<UsageEvent>(MaxBatch);

        try
        {
            while (await reader.WaitToReadAsync(stoppingToken))
            {
                await CollectAsync(reader, buffer, stoppingToken);
                await FlushWithRetryAsync(buffer, stoppingToken);
                buffer.Clear();
            }
        }
        catch (Exception) when (stoppingToken.IsCancellationRequested)
        {
            // Shutdown, including a flush interrupted mid-retry: whatever is still in the buffer
            // or the channel goes through the final drain.
        }

        await FinalDrainAsync(buffer);
    }

    private async Task CollectAsync(ChannelReader<UsageEvent> reader, List<UsageEvent> buffer, CancellationToken ct)
    {
        long start = _time.GetTimestamp();
        while (buffer.Count < MaxBatch)
        {
            if (reader.TryRead(out var usageEvent))
            {
                buffer.Add(usageEvent);
                continue;
            }

            var remaining = MaxFlushInterval - _time.GetElapsedTime(start);
            if (remaining <= TimeSpan.Zero)
            {
                return;
            }

            using var window = CancellationTokenSource.CreateLinkedTokenSource(ct);
            window.CancelAfter(remaining);
            try
            {
                if (!await reader.WaitToReadAsync(window.Token))
                {
                    return;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return;
            }
        }
    }

    private async Task FlushWithRetryAsync(List<UsageEvent> buffer, CancellationToken stoppingToken)
    {
        if (buffer.Count == 0)
        {
            return;
        }

        var delay = InitialRetryDelay;
        while (true)
        {
            try
            {
                await FlushOnceAsync(buffer, stoppingToken);
                return;
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogWarning(
                    ex,
                    "Usage event batch insert failed; retrying in {RetryDelayMs} ms. Pending={Count}",
                    (long)delay.TotalMilliseconds,
                    buffer.Count);
                await Task.Delay(delay, _time, stoppingToken);
                delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, MaxRetryDelay.Ticks));
            }
        }
    }

    private async Task FlushOnceAsync(List<UsageEvent> buffer, CancellationToken ct)
    {
        await _repository.InsertBatchAsync(buffer, ct);
        Interlocked.Add(ref _flushed, buffer.Count);
        DependablyMeter.UsageEventsWritten.Add(buffer.Count);
    }

    private async Task FinalDrainAsync(List<UsageEvent> buffer)
    {
        while (_writer.Reader.TryRead(out var usageEvent))
        {
            buffer.Add(usageEvent);
        }

        for (int offset = 0; offset < buffer.Count; offset += MaxBatch)
        {
            var batch = buffer.GetRange(offset, Math.Min(MaxBatch, buffer.Count - offset));
            try
            {
                await FlushOnceAsync(batch, CancellationToken.None);
            }
            catch (Exception ex)
            {
                DependablyMeter.UsageEventsDropped.Add(batch.Count);
                _logger.LogError(
                    ex,
                    "Usage events lost at shutdown: the final insert failed. Lost={Count}",
                    batch.Count);
            }
        }

        buffer.Clear();
    }
}
