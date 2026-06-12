using System.Diagnostics;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Drains <see cref="DownloadCountWriter"/> and flushes aggregated download-count
/// increments to the <c>package_versions</c> table in batches.
/// Flush trigger is whichever of these comes first:
///   - <see cref="MaxBatch"/> records accumulated, or
///   - <see cref="MaxFlushInterval"/> since the first record in the buffer.
///
/// Aggregation: records in a batch are grouped by key (versionId or purl). Each unique
/// key emits a single UPDATE with the total accumulated delta, keeping the write lock held
/// for the minimum time per batch.
///
/// Shutdown: when the host signals cancellation the channel is drained one last time so
/// any increments queued just before SIGTERM still reach disk. The 30 s SIGTERM drain
/// configured in Program.cs gives this plenty of headroom even at queue capacity.
/// </summary>
public sealed class DownloadCountWriterHostedService : BackgroundService
{
    public const int MaxBatch = 200;
    public static readonly TimeSpan MaxFlushInterval = TimeSpan.FromMilliseconds(100);

    private readonly DownloadCountWriter _writer;
    private readonly IMetadataStore _db;
    private readonly ILogger<DownloadCountWriterHostedService> _logger;
    private long _flushed;

    /// <summary>
    /// Monotonic count of records successfully flushed to the DB. Paired with
    /// <see cref="DownloadCountWriter.EnqueuedCount"/> by <see cref="WaitForIdleAsync"/>.
    /// </summary>
    public long FlushedCount => Interlocked.Read(ref _flushed);

    public DownloadCountWriterHostedService(
        DownloadCountWriter writer,
        IMetadataStore db,
        ILogger<DownloadCountWriterHostedService> logger)
    {
        _writer = writer;
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Public entry-point for tests: drains the channel and writes any pending records
    /// in batched UPDATEs, then returns. <see cref="ExecuteAsync"/> wraps this in the
    /// long-running loop the host owns. Exposed because <see cref="BackgroundService.StartAsync"/>
    /// / <see cref="BackgroundService.StopAsync"/> drive ExecuteAsync as fire-and-forget,
    /// which is awkward to synchronise in a unit test.
    /// </summary>
    public async Task DrainPendingAsync(CancellationToken ct = default)
    {
        var reader = _writer.Reader;
        var buffer = new List<DownloadCountRecord>(MaxBatch);
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
        var buffer = new List<DownloadCountRecord>(MaxBatch);

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
                // A failing batch must not kill the drainer — log and drop. The increments
                // are gone (mirroring the channel-full overflow semantics: download counts
                // are best-effort observability, not financial data).
                _logger.LogWarning(
                    ex,
                    "DownloadCountWriter batch flush failed: {ExceptionType} dropped={Count} trace={TraceId}",
                    ex.GetType().Name,
                    buffer.Count,
                    Activity.Current?.TraceId.ToString());
                Observability.DependablyMeter.DownloadCountWriterDropped.Add(buffer.Count);
                // Advance flushed so WaitForIdleAsync stays consistent — these records are
                // gone (best-effort semantics), not pending.
                Interlocked.Add(ref _flushed, buffer.Count);
                buffer.Clear();
            }
        }

        await FinalDrainAsync(reader, buffer);
    }

    private async Task CollectAndFlushBatchAsync(
        System.Threading.Channels.ChannelReader<DownloadCountRecord> reader,
        List<DownloadCountRecord> buffer,
        CancellationToken stoppingToken)
    {
        buffer.Clear();
        var flushDeadline = Stopwatch.StartNew();

        // Greedy fill within the flush window. Alternates between draining whatever's
        // already buffered (TryRead) and a short timed wait for more. Keeps p99 latency
        // on the flush bounded by MaxFlushInterval.
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
        System.Threading.Channels.ChannelReader<DownloadCountRecord> reader,
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
            // Flush-window timeout — done collecting; emit what we have.
            return false;
        }
    }

    /// <summary>
    /// Last batched flush of anything in the channel before the host stops. Beyond this
    /// point the channel is completed, so no new records can land.
    /// </summary>
    private async Task FinalDrainAsync(
        System.Threading.Channels.ChannelReader<DownloadCountRecord> reader,
        List<DownloadCountRecord> buffer)
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
            _logger.LogWarning(ex, "DownloadCountWriter shutdown drain failed: {ExceptionType}", ex.GetType().Name);
        }
    }

    /// <summary>
    /// Aggregates records in <paramref name="records"/> by key and issues one UPDATE per
    /// unique versionId and one per unique purl. Aggregation reduces write-lock hold time:
    /// N downloads of the same version in a batch become a single UPDATE with delta=N.
    /// </summary>
    internal async Task FlushAsync(IReadOnlyList<DownloadCountRecord> records, CancellationToken ct)
    {
        if (records.Count == 0)
        {
            return;
        }

        // Aggregate: sum increments per unique key within this batch.
        var byVersionId = new Dictionary<string, int>(StringComparer.Ordinal);
        var byPurl = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var rec in records)
        {
            if (rec.VersionId is not null)
            {
                byVersionId.TryGetValue(rec.VersionId, out int current);
                byVersionId[rec.VersionId] = current + 1;
            }
            else if (rec.Purl is not null)
            {
                byPurl.TryGetValue(rec.Purl, out int current);
                byPurl[rec.Purl] = current + 1;
            }
        }

        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        // Wrap all UPDATEs in a single transaction so the writer holds the WAL writer
        // lock once per batch instead of once per key.
        await using var tx = await conn.BeginTransactionAsync(ct);

        foreach (var kv in byVersionId)
        {
            // xtenant: keyed by version PK (id), which is a globally unique surrogate —
            // no org_id filter needed; the caller cannot manufacture a foreign id.
            await conn.ExecuteAsync(
                "UPDATE package_versions SET download_count = download_count + @n, last_used = @now WHERE id = @id",
                new { n = kv.Value, now, id = kv.Key },
                transaction: tx);
        }

        foreach (var kv in byPurl)
        {
            // xtenant: purl is the canonical globally-unique package identity built by
            // PurlNormalizer — it encodes ecosystem, name, and version, so it is unique
            // across orgs and no org_id filter is needed.
            await conn.ExecuteAsync(
                "UPDATE package_versions SET download_count = download_count + @n, last_used = @now WHERE purl = @purl",
                new { n = kv.Value, now, purl = kv.Key },
                transaction: tx);
        }

        await tx.CommitAsync(ct);
        Interlocked.Add(ref _flushed, records.Count);
    }

    /// <summary>
    /// Waits until <see cref="FlushedCount"/> catches up with
    /// <see cref="DownloadCountWriter.EnqueuedCount"/>. Test hook: integration tests that read
    /// download_count after a request use this to synchronise with the running batch loop.
    /// Polls every 5 ms; throws on timeout.
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

            await Task.Delay(5, ct);
        }
        throw new TimeoutException(
            $"DownloadCountWriter did not become idle within {timeout.TotalMilliseconds} ms " +
            $"(enqueued={_writer.EnqueuedCount}, flushed={FlushedCount}).");
    }
}
