using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The EPSS refresh sizes each locked batch from how long the previous one held the write lock.
/// Real lock-held time depends on the runner, so this drives the sizing with a clock that moves a
/// fixed cost per row written: a slow per-row cost must shrink the next batch, a fast one must grow
/// it, and both stay inside the floor and ceiling. A repository that ignored its budget (a fixed
/// batch size) fails both halves.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EpssBatchSizingTests : IAsyncLifetime
{
    private const int Rows = 3_000;
    private const int Advisories = 1_500;

    // Starting size, floor and ceiling of each phase's batch.
    private const int StagingStart = 500;
    private const int StagingFloor = 100;
    private const int StagingCeiling = 2_000;
    private const int ApplyStart = 500;
    private const int ApplyFloor = 100;
    private const int ApplyCeiling = 10_000;
    private const int FillStart = 100;
    private const int FillFloor = 25;
    private const int FillCeiling = 2_000;

    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_epss_sizing_{Guid.NewGuid():N}.db");
    private SqliteMetadataStore _store = null!;

    public async Task InitializeAsync()
    {
        _store = new SqliteMetadataStore(StorageStartupExtensions.BuildSqliteConnectionString(_dbFile));
        await new SchemaInitializer(_store).InitializeAsync();
    }

    public Task DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            File.Delete(_dbFile + suffix);
        }

        return Task.CompletedTask;
    }

    private static Dictionary<string, EpssScore> Scores(double probability)
    {
        var scores = new Dictionary<string, EpssScore>(Rows, StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < Rows; i++)
        {
            scores[$"CVE-2050-{i}"] = new EpssScore(probability, 0.5);
        }

        return scores;
    }

    private async Task<(List<int> Staging, List<int> Apply, List<int> Fill)> RunAsync(double msPerRow)
    {
        await new VulnerabilityRepository(_store, TimeProvider.System).ReplaceEpssScoresAsync(Scores(0.1), "2026-10-05");
        await using (var conn = await _store.OpenAsync())
        await using (var tx = await conn.BeginTransactionAsync())
        {
            for (int i = 0; i < Advisories; i++)
            {
                await conn.ExecuteAsync(
                    "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) VALUES (@id, @id, 'npm', 'pkg')",
                    new { id = $"CVE-2050-{i}" }, tx);
            }

            await tx.CommitAsync();
        }

        await using var counting = new CountingStore(_store);
        var clock = new RowCostClock(counting, msPerRow);
        var repo = new VulnerabilityRepository(counting, clock);

        await repo.ReplaceEpssScoresAsync(Scores(0.9), "2026-10-06");
        Assert.Equal(Advisories, await repo.FillMissingEpssFromStoredScoresAsync());

        var staging = new List<int>();
        var apply = new List<int>();
        var fill = new List<int>();
        foreach (var conn in counting.Connections)
        {
            var statements = conn.Statements;
            var starts = conn.TransactionStarts;
            for (int t = 0; t < starts.Count; t++)
            {
                int end = t + 1 < starts.Count ? starts[t + 1] : statements.Count;
                var range = Enumerable.Range(starts[t], end - starts[t]).ToList();
                int stagedRows = range.Sum(i => statements[i].StartsWith("INSERT INTO epss_scores_staging", StringComparison.Ordinal)
                    ? statements[i].Split("(@cve").Length - 1
                    : 0);
                if (stagedRows > 0)
                {
                    staging.Add(stagedRows);
                }

                foreach (int i in range)
                {
                    if (Regex.IsMatch(statements[i], @"^\s*INSERT INTO epss_scores\s*\(", RegexOptions.None, TimeSpan.FromSeconds(1)))
                    {
                        apply.Add(conn.AffectedRows[i]);
                    }
                    else if (statements[i].TrimStart().StartsWith("UPDATE vulnerabilities SET epss_score", StringComparison.Ordinal))
                    {
                        fill.Add(conn.AffectedRows[i]);
                    }
                }
            }
        }

        return (staging, apply, fill);
    }

    private static void AssertShrinks(List<int> batches, int start, int floor)
    {
        Assert.True(batches.Count > 3, $"only {batches.Count} batches");
        Assert.Equal(start, batches[0]);

        // Every batch after the first ran with evidence the rows were slow, and the last is a remainder.
        Assert.All(batches.Skip(1).Take(batches.Count - 2), b => Assert.InRange(b, floor, start - 1));
    }

    private static void AssertGrows(List<int> batches, int start, int ceiling)
    {
        Assert.True(batches.Count > 2, $"only {batches.Count} batches");
        Assert.Equal(start, batches[0]);
        Assert.True(batches[1] > start, $"the second batch stayed at {batches[1]}: {string.Join(",", batches)}");
        Assert.All(batches, b => Assert.InRange(b, 1, ceiling));
    }

    [Fact]
    public async Task SlowRows_ShrinkEveryLaterBatch_WithinTheFloor()
    {
        var (staging, apply, fill) = await RunAsync(msPerRow: 4.0);

        AssertShrinks(staging, StagingStart, StagingFloor);
        AssertShrinks(apply, ApplyStart, ApplyFloor);
        AssertShrinks(fill, FillStart, FillFloor);
    }

    [Fact]
    public async Task FastRows_GrowLaterBatches_WithinTheCeiling()
    {
        var (staging, apply, fill) = await RunAsync(msPerRow: 0.001);

        AssertGrows(staging, StagingStart, StagingCeiling);
        AssertGrows(apply, ApplyStart, ApplyCeiling);
        AssertGrows(fill, FillStart, FillCeiling);
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
