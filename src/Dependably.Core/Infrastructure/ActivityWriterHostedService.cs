using System.Data.Common;
using System.Diagnostics;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Drains <see cref="ActivityWriter"/> into the <c>activity</c> table in batches.
/// Flush trigger is whichever of these comes first:
///   - <see cref="MaxBatch"/> records accumulated, or
///   - <see cref="MaxFlushInterval"/> since the first row in the buffer.
/// Both are tuned per the issue spec ("flush every ~100 ms or ~200 rows").
///
/// Shutdown: when the host signals cancellation we drain the channel one last time so
/// any rows queued just before SIGTERM still make it to disk. The 30 s SIGTERM drain
/// configured in Program.cs gives this plenty of headroom even at queue capacity.
/// </summary>
public sealed class ActivityWriterHostedService : BackgroundService
{
    public const int MaxBatch = 200;
    public static readonly TimeSpan MaxFlushInterval = TimeSpan.FromMilliseconds(100);

    // Polling interval used by WaitForIdleAsync when waiting for the writer to drain.
    private const int IdleCheckIntervalMs = 5;

    private readonly ActivityWriter _writer;
    private readonly IMetadataStore _db;
    private readonly ILogger<ActivityWriterHostedService> _logger;
    private long _flushed;
    /// <summary>
    /// Monotonic count of records successfully flushed to the DB. Paired with
    /// <see cref="ActivityWriter.EnqueuedCount"/> by <see cref="WaitForIdleAsync"/>.
    /// </summary>
    public long FlushedCount => Interlocked.Read(ref _flushed);

    public ActivityWriterHostedService(
        ActivityWriter writer,
        IMetadataStore db,
        ILogger<ActivityWriterHostedService> logger)
    {
        _writer = writer;
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Public entry-point for tests: drains the channel and writes any pending rows
    /// in batched INSERTs, then returns. <see cref="ExecuteAsync"/> wraps this in the
    /// long-running loop the host owns. Exposed because <see cref="BackgroundService.StartAsync"/>
    /// / <see cref="BackgroundService.StopAsync"/> drive ExecuteAsync as fire-and-forget,
    /// which is awkward to synchronise in a unit test.
    /// </summary>
    public async Task DrainPendingAsync(CancellationToken ct = default)
    {
        var reader = _writer.Reader;
        var buffer = new List<ActivityRecord>(MaxBatch);
        while (reader.TryRead(out var record))
        {
            buffer.Add(record);
            if (buffer.Count >= MaxBatch)
            {
                await FlushAsync(buffer, ct);
                buffer.Clear();
            }
        }
        if (buffer.Count > 0)
        {
            await FlushAsync(buffer, ct);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var reader = _writer.Reader;
        var buffer = new List<ActivityRecord>(MaxBatch);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Block until at least one record is available — when the channel completes
                // (graceful shutdown) WaitToReadAsync returns false and the loop exits.
                if (!await reader.WaitToReadAsync(stoppingToken))
                {
                    break;
                }

                await CollectAndFlushBatchAsync(reader, buffer, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A failing batch must not kill the drainer — log and drop. The rows are
                // gone (mirroring the channel-full overflow semantics: activity is best-effort).
                _logger.LogWarning(
                    ex,
                    "ActivityWriter batch flush failed: {ExceptionType} dropped={Count} trace={TraceId}",
                    ex.GetType().Name,
                    buffer.Count,
                    Activity.Current?.TraceId.ToString());
                Observability.DependablyMeter.ActivityWriterDropped.Add(buffer.Count);
                buffer.Clear();
            }
        }

        await FinalDrainAsync(reader, buffer);
    }

    private async Task CollectAndFlushBatchAsync(
        System.Threading.Channels.ChannelReader<ActivityRecord> reader,
        List<ActivityRecord> buffer,
        CancellationToken stoppingToken)
    {
        buffer.Clear();
        var flushDeadline = Stopwatch.StartNew();

        // Greedy fill within the flush window. Alternates between draining whatever's
        // already buffered (TryRead) and a short timed wait for more. Keeps p99 latency on
        // the row's eventual write bounded by MaxFlushInterval.
        while (buffer.Count < MaxBatch && flushDeadline.Elapsed < MaxFlushInterval)
        {
            if (reader.TryRead(out var record))
            {
                buffer.Add(record);
                continue;
            }

            if (!await WaitForMoreOrTimeoutAsync(reader, flushDeadline, stoppingToken))
            {
                break;
            }
        }

        if (buffer.Count > 0)
        {
            await FlushAsync(buffer, stoppingToken);
        }
    }

    /// <summary>
    /// Waits the residual flush window for one more arrival. Returns false when the
    /// window closed or the channel completed — caller emits the partial batch.
    /// Cancellation from <paramref name="stoppingToken"/> propagates out.
    /// </summary>
    private static async Task<bool> WaitForMoreOrTimeoutAsync(
        System.Threading.Channels.ChannelReader<ActivityRecord> reader,
        Stopwatch flushDeadline,
        CancellationToken stoppingToken)
    {
        var remaining = MaxFlushInterval - flushDeadline.Elapsed;
        if (remaining <= TimeSpan.Zero)
        {
            return false;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        cts.CancelAfter(remaining);
        try
        {
            return await reader.WaitToReadAsync(cts.Token);
        }
        catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
        {
            // Flush-window timeout — we're done collecting; emit what we have.
            return false;
        }
    }

    /// <summary>
    /// Last batched flush of anything in the channel before the host stops. Beyond this
    /// point the channel is completed, so no new writers can land.
    /// </summary>
    private async Task FinalDrainAsync(
        System.Threading.Channels.ChannelReader<ActivityRecord> reader,
        List<ActivityRecord> buffer)
    {
        try
        {
            buffer.Clear();
            while (reader.TryRead(out var r))
            {
                buffer.Add(r);
                if (buffer.Count >= MaxBatch)
                {
                    await FlushAsync(buffer, CancellationToken.None);
                    buffer.Clear();
                }
            }
            if (buffer.Count > 0)
            {
                await FlushAsync(buffer, CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ActivityWriter shutdown drain failed: {ExceptionType}", ex.GetType().Name);
        }
    }

    internal async Task FlushAsync(IReadOnlyList<ActivityRecord> rows, CancellationToken ct)
    {
        if (rows.Count == 0)
        {
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        // Wrap the batch in a single transaction so the writer takes the write lock and
        // commits to disk once per batch instead of once per row.
        await using var tx = await conn.BeginTransactionAsync(ct);

        if (_db.Provider == DbProvider.Postgres)
        {
            // Npgsql supports DbBatch and pipelines the whole batch into a single network
            // round-trip. One DbBatchCommand per row; the command text is a constant
            // parameterized INSERT — no SQL is built from row data.
            await using var batch = conn.CreateBatch();
            batch.Transaction = tx;
            foreach (var row in rows)
            {
                var cmd = batch.CreateBatchCommand();
                cmd.CommandText = InsertActivitySql;
                AddParameter(cmd, "@Id", row.Id);
                AddParameter(cmd, "@OrgId", row.OrgId);
                AddParameter(cmd, "@Ecosystem", row.Ecosystem);
                AddParameter(cmd, "@Purl", row.Purl);
                AddParameter(cmd, "@EventType", row.EventType);
                AddParameter(cmd, "@ActorId", row.ActorId);
                AddParameter(cmd, "@ActorKind", row.ActorKind);
                AddParameter(cmd, "@Detail", row.Detail);
                AddParameter(cmd, "@SourceIp", row.SourceIp);
                AddParameter(cmd, "@CreatedAt", row.CreatedAt);
                batch.BatchCommands.Add(cmd);
            }

            await batch.ExecuteNonQueryAsync(ct);
        }
        else
        {
            // Microsoft.Data.Sqlite does not implement DbBatch. Dapper's IEnumerable
            // overload executes the command once per row; because all rows share the
            // same transaction the fsync is still amortised to a single commit.
            await conn.ExecuteAsync(InsertActivitySql, rows, transaction: tx);
        }

        await tx.CommitAsync(ct);
        Interlocked.Add(ref _flushed, rows.Count);
    }

    private const string InsertActivitySql =
        """
        INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id, actor_kind, detail, source_ip, created_at)
        VALUES (@Id, @OrgId, @Ecosystem, @Purl, @EventType, @ActorId, @ActorKind, @Detail, @SourceIp, @CreatedAt)
        """;

    private static void AddParameter(DbBatchCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    /// <summary>
    /// Waits until <see cref="FlushedCount"/> catches up with
    /// <see cref="ActivityWriter.EnqueuedCount"/>. Test hook: integration tests that read the
    /// <c>activity</c> table after a request use this to synchronise with the running batch
    /// loop (it owns the channel reader, so callers cannot just call
    /// <see cref="DrainPendingAsync"/>). Polls every 5 ms; throws on timeout.
    /// </summary>
    public async Task WaitForIdleAsync(TimeSpan timeout = default, CancellationToken ct = default)
    {
        if (timeout == default)
        {
            timeout = TimeSpan.FromSeconds(5);
        }

        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (FlushedCount >= _writer.EnqueuedCount)
            {
                return;
            }

            await Task.Delay(IdleCheckIntervalMs, ct);
        }
        throw new TimeoutException(
            $"ActivityWriter did not become idle within {timeout.TotalMilliseconds} ms " +
            $"(enqueued={_writer.EnqueuedCount}, flushed={FlushedCount}).");
    }
}
