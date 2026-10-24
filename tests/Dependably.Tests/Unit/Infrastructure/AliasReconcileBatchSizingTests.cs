using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The alias-index reconcile commits in batches sized from how long the previous one held the write
/// lock, and pauses between full batches. The clock here moves a fixed cost per row written, so a
/// slow per-row cost must shrink later batches and a fast one must grow them. A reconcile that wrote
/// fixed 500-row transactions back to back fails every one of these.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AliasReconcileBatchSizingTests : IAsyncLifetime
{
    private const int Advisories = 2_000;
    private const int Start = VulnerabilityAliasIndex.ReconcileStartRows;
    private const int Floor = VulnerabilityAliasIndex.ReconcileMinRows;
    private const int Ceiling = VulnerabilityAliasIndex.ReconcileMaxRows;
    private const string BatchStatement = "UPDATE vulnerabilities SET aliases_indexed = aliases";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @rows)
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, aliases)
            SELECT 'a-' || i, 'GHSA-rec-' || i, 'npm', 'p', '["CVE-2026-' || i || '"]' FROM n
            """,
            new { rows = Advisories });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task<(List<int> Batches, int Pauses, int Reconciled)> RunAsync(double msPerRow)
    {
        await using var counting = new CountingStore(_db);
        await using var conn = await counting.OpenAsync();
        var clock = new RowCostClock(counting, msPerRow);
        int reconciled = await VulnerabilityAliasIndex.ReconcileAsync(conn, clock);

        var counted = Assert.Single(counting.Connections);
        var batches = new List<int>();
        for (int i = 0; i < counted.Statements.Count; i++)
        {
            if (counted.Statements[i].TrimStart().StartsWith(BatchStatement, StringComparison.Ordinal) && counted.AffectedRows[i] > 0)
            {
                batches.Add(counted.AffectedRows[i]);
            }
        }

        return (batches, clock.Pauses, reconciled);
    }

    [Fact]
    public async Task SlowRows_ShrinkEveryLaterBatch_WithinTheFloor()
    {
        var (batches, _, reconciled) = await RunAsync(msPerRow: 4.0);

        Assert.Equal(Advisories, reconciled);
        Assert.Equal(Advisories, batches.Sum());
        Assert.True(batches.Count > 3, $"only {batches.Count} batches");
        Assert.Equal(Start, batches[0]);
        Assert.All(batches.Skip(1).Take(batches.Count - 2), b => Assert.InRange(b, Floor, Start - 1));
    }

    [Fact]
    public async Task FastRows_GrowLaterBatches_WithinTheCeiling()
    {
        var (batches, _, reconciled) = await RunAsync(msPerRow: 0.001);

        Assert.Equal(Advisories, reconciled);
        Assert.Equal(Start, batches[0]);
        Assert.True(batches[1] > Start, $"the second batch stayed at {batches[1]}: {string.Join(",", batches)}");
        Assert.Equal(Ceiling, batches.Max());
        Assert.All(batches, b => Assert.InRange(b, 1, Ceiling));
    }

    [Fact]
    public async Task PausesBetweenBatches_NotAfterTheLast()
    {
        var (batches, pauses, _) = await RunAsync(msPerRow: 0.001);

        Assert.True(batches.Count > 1);
        Assert.Equal(batches.Count - 1, pauses);
    }

    [Fact]
    public async Task ExactMultipleBacklog_HasNoTrailingPause()
    {
        await using var counting = new CountingStore(_db);
        await using var conn = await counting.OpenAsync();
        var clock = new RowCostClock(counting, 0.001);
        Assert.Equal(Advisories, await VulnerabilityAliasIndex.ReconcileAsync(conn, clock, batchRows: 500));

        // 2000 rows at 500 per batch: four batches, three pauses between them.
        Assert.Equal(3, clock.Pauses);
    }

    [Fact]
    public async Task EndState_EveryAdvisoryIsIndexed_AndASecondRunMatchesNothing()
    {
        await using var conn = await _db.OpenAsync();
        Assert.Equal(Advisories, await VulnerabilityAliasIndex.ReconcileAsync(conn, TimeProvider.System, batchRows: 300));

        Assert.Equal(Advisories, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM vulnerability_aliases"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE COALESCE(aliases, '') <> COALESCE(aliases_indexed, '')"));
        Assert.Equal(0, await VulnerabilityAliasIndex.ReconcileAsync(conn, TimeProvider.System));
    }

    private sealed class RowCostClock(CountingStore store, double msPerRow) : TimeProvider
    {
        private const long Frequency = TimeSpan.TicksPerSecond;
        private int _pauses;

        public int Pauses => Volatile.Read(ref _pauses);

        public override DateTimeOffset GetUtcNow() => System.GetUtcNow();
        public override long TimestampFrequency => Frequency;

        public override long GetTimestamp()
        {
            long rows = store.Connections.Sum(c => c.Statements
                .Select((s, i) => s.TrimStart().StartsWith(BatchStatement, StringComparison.Ordinal) ? (long)c.AffectedRows[i] : 0).Sum());
            return (long)(rows * msPerRow * (Frequency / 1000.0));
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Interlocked.Increment(ref _pauses);
            return System.CreateTimer(callback, state, TimeSpan.Zero, period);
        }
    }
}
