using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The alias-donor sweeps size each write from how long the previous one held the write lock.
/// Real lock-held time depends on the runner, so this drives the sizing with a clock that moves a
/// fixed cost per row written: a slow per-row cost must shrink the next batch, a fast one must grow
/// it, and both stay inside the floor and ceiling. A sweep that used a fixed batch size fails both
/// halves.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AliasDonorSweepBatchSizingTests : IAsyncLifetime
{
    private const int Owners = 2_000;
    private const int Start = VulnerabilityRepository.SweepStartOwners;
    private const int Floor = VulnerabilityRepository.SweepMinOwners;
    private const int Ceiling = VulnerabilityRepository.SweepBatchOwners;

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // One advisory with a recorded basis, and a link per owner that was never resolved.
    private async Task SeedStaleLinksAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity) VALUES ('adv-1', 'GHSA-size-1', 'PyPI', 'pkg', 'HIGH')");
        await VulnerabilityRepository.ResolveStaleAliasDonorsAsync(conn, TimeProvider.System);
        // The owners are ids only; no package rows back them.
        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @owners)
            INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind)
            SELECT 'l-' || i, 'v-' || i, 'adv-1', 'package_version' FROM n
            """,
            new { owners = Owners });
    }

    private async Task SeedUnrecordedBasesAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @owners)
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity)
            SELECT 'a-' || i, 'GHSA-size-' || i, 'PyPI', 'pkg', 'HIGH' FROM n
            """,
            new { owners = Owners });
    }

    private async Task<List<int>> SweepBatchesAsync(double msPerRow, string statementPrefix)
    {
        await using var counting = new CountingStore(_db);
        await using var conn = await counting.OpenAsync();
        var clock = new RowCostClock(counting, msPerRow);
        await VulnerabilityRepository.ResolveStaleAliasDonorsAsync(conn, clock);

        var counted = Assert.Single(counting.Connections);
        var batches = new List<int>();
        for (int i = 0; i < counted.Statements.Count; i++)
        {
            if (counted.Statements[i].TrimStart().StartsWith(statementPrefix, StringComparison.Ordinal) && counted.AffectedRows[i] > 0)
            {
                batches.Add(counted.AffectedRows[i]);
            }
        }

        return batches;
    }

    private static void AssertShrinks(List<int> batches, int total)
    {
        Assert.Equal(total, batches.Sum());
        Assert.True(batches.Count > 3, $"only {batches.Count} batches");
        Assert.Equal(Start, batches[0]);

        // Every batch after the first ran with evidence the rows were slow, and the last is a remainder.
        Assert.All(batches.Skip(1).Take(batches.Count - 2), b => Assert.InRange(b, Floor, Start - 1));
    }

    private static void AssertGrows(List<int> batches, int total)
    {
        Assert.Equal(total, batches.Sum());
        Assert.Equal(Start, batches[0]);
        Assert.True(batches[1] > Start, $"the second batch stayed at {batches[1]}: {string.Join(",", batches)}");
        Assert.Equal(Ceiling, batches.Max());
        Assert.All(batches, b => Assert.InRange(b, 1, Ceiling));
    }

    [Fact]
    public async Task ResolveSweep_SlowRows_ShrinkEveryLaterBatch_WithinTheFloor()
    {
        await SeedStaleLinksAsync();
        AssertShrinks(await SweepBatchesAsync(msPerRow: 4.0, "UPDATE package_version_vulns"), Owners);
    }

    [Fact]
    public async Task ResolveSweep_FastRows_GrowLaterBatches_WithinTheCeiling()
    {
        await SeedStaleLinksAsync();
        AssertGrows(await SweepBatchesAsync(msPerRow: 0.001, "UPDATE package_version_vulns"), Owners);
    }

    [Fact]
    public async Task BasisSweep_SlowRows_ShrinkEveryLaterBatch_WithinTheFloor()
    {
        await SeedUnrecordedBasesAsync();
        AssertShrinks(await SweepBatchesAsync(msPerRow: 4.0, "UPDATE vulnerabilities"), Owners);
    }

    [Fact]
    public async Task BasisSweep_FastRows_GrowLaterBatches_WithinTheCeiling()
    {
        await SeedUnrecordedBasesAsync();
        AssertGrows(await SweepBatchesAsync(msPerRow: 0.001, "UPDATE vulnerabilities"), Owners);
    }

    // A clock whose timestamp is the rows the counted connections have written so far times a fixed
    // cost per row, so a batch's measured lock-held time is its row count times that cost. Waits
    // finish at once.
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
