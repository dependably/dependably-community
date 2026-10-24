using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The npm empty-licence requeue clears <c>license_checked_at</c> in batches sized from how long
/// the previous batch held the write lock. The clock here moves a fixed cost per row written, so a
/// slow per-row cost must shrink later batches and a fast one must grow them. A requeue that used a
/// fixed batch size fails both halves.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmLicenceRequeueBatchSizingTests : IAsyncLifetime
{
    private const int Rows = 2_000;
    private const int Start = CacheArtifactRepository.RequeueStartRows;
    private const int Floor = CacheArtifactRepository.RequeueMinRows;
    private const int Ceiling = CacheArtifactRepository.RequeueMaxRows;

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @rows)
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, license_checked_at)
            SELECT 'ca-' || i, 'npm', 'p' || i, '1.0.0', 'p.tgz', 'k' || i, 'h', '2026-01-01T00:00:00Z' FROM n
            """,
            new { rows = Rows });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task<List<int>> BatchesAsync(double msPerRow)
    {
        await using var counting = new CountingStore(_db);
        var clock = new RowCostClock(counting, msPerRow);
        int requeued = await new CacheArtifactRepository(counting).RequeueEmptyNpmLicenceChecksOnceAsync(clock);
        Assert.Equal(Rows, requeued);

        var batches = new List<int>();
        foreach (var c in counting.Connections)
        {
            for (int i = 0; i < c.Statements.Count; i++)
            {
                if (c.Statements[i].TrimStart().StartsWith("UPDATE cache_artifact", StringComparison.Ordinal) && c.AffectedRows[i] > 0)
                {
                    batches.Add(c.AffectedRows[i]);
                }
            }
        }

        return batches;
    }

    [Fact]
    public async Task SlowRows_ShrinkEveryLaterBatch_WithinTheFloor()
    {
        var batches = await BatchesAsync(msPerRow: 4.0);

        Assert.Equal(Rows, batches.Sum());
        Assert.True(batches.Count > 3, $"only {batches.Count} batches");
        Assert.Equal(Start, batches[0]);
        Assert.All(batches.Skip(1).Take(batches.Count - 2), b => Assert.InRange(b, Floor, Start - 1));
    }

    [Fact]
    public async Task FastRows_GrowLaterBatches_WithinTheCeiling()
    {
        var batches = await BatchesAsync(msPerRow: 0.001);

        Assert.Equal(Rows, batches.Sum());
        Assert.Equal(Start, batches[0]);
        Assert.True(batches[1] > Start, $"the second batch stayed at {batches[1]}: {string.Join(",", batches)}");
        Assert.Equal(Ceiling, batches.Max());
    }

    [Fact]
    public async Task ReadsIdsOnePagePerBatch_NeverTheWholeBacklog()
    {
        await using var counting = new CountingStore(_db);
        int requeued = await new CacheArtifactRepository(counting)
            .RequeueEmptyNpmLicenceChecksOnceAsync(TimeProvider.System, batchRows: 300);
        Assert.Equal(Rows, requeued);

        var statements = counting.Connections.SelectMany(c => c.Statements).ToList();
        int pages = statements.Count(s => s.TrimStart().StartsWith("SELECT ca.id", StringComparison.Ordinal));
        int updates = statements.Count(s => s.TrimStart().StartsWith("UPDATE cache_artifact", StringComparison.Ordinal));

        // 2000 rows at 300 per page: seven non-empty pages, then the empty page that ends the run.
        Assert.Equal(7, updates);
        Assert.Equal(updates + 1, pages);
    }

    [Fact]
    public async Task MarkerIsWrittenLast_AndSecondRunRequeuesNothing()
    {
        await using var counting = new CountingStore(_db);
        var repo = new CacheArtifactRepository(counting);
        await repo.RequeueEmptyNpmLicenceChecksOnceAsync(TimeProvider.System);

        var statements = counting.Connections.SelectMany(c => c.Statements).ToList();
        Assert.StartsWith("INSERT INTO instance_settings", statements[^1].TrimStart());

        Assert.Equal(-1, await repo.RequeueEmptyNpmLicenceChecksOnceAsync(TimeProvider.System));
    }

    private sealed class RowCostClock(CountingStore store, double msPerRow) : TimeProvider
    {
        private const long Frequency = TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow() => System.GetUtcNow();
        public override long TimestampFrequency => Frequency;

        public override long GetTimestamp()
        {
            long rows = store.Connections.SelectMany(c => c.AffectedRows).Where(r => r > 0).Sum(r => (long)r);
            return (long)(rows * msPerRow * (Frequency / 1000.0));
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            System.CreateTimer(callback, state, TimeSpan.Zero, period);
    }
}
