using System.Data.Common;
using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Xunit.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Replaces the EPSS file and then sweeps the fill on a host whose CPU is starved, with another
/// writer committing throughout. Starvation is emulated deterministically rather than with a load
/// generator, whose effect depends on the runner's scheduler: a trigger on each written table burns
/// a fixed amount of CPU per row written, so the same statements take many times longer, which is
/// exactly what a starved host does to a batch that was sized for an idle one. Slow by design, so it
/// is excluded from the default run.
///
/// <para>The gate is structural, read off the statements the replace issues, because how long any
/// one concurrent write waited depends on the runner (and Microsoft.Data.Sqlite retries a locked
/// write until its 30 s command timeout, so a long wait is not a failure by itself). Under the
/// emulated starvation every staging transaction holds a bounded number of rows, every apply
/// transaction is one key-range statement over a bounded number of rows. That batches shrink when
/// rows are slow and grow when they are fast is pinned by <c>EpssBatchSizingTests</c> with a clock
/// that charges a fixed cost per row; here the real per-row cost is the runner's, so the batch
/// sizes are only logged. The concurrent writer must also
/// not fail: a write that waited out the command timeout would surface as a failure. The slowest
/// wait is logged, not asserted.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class EpssScoresReplaceUnderCpuStarvationTests(ITestOutputHelper output) : IAsyncLifetime
{
    private const int Rows = 6_000;

    // The most rows one staging transaction may write, and one apply statement may touch.
    private const int MaxStagingRowsPerTransaction = 2_000;
    private const int MaxApplyRowsPerTransaction = 10_000;

    private const int Advisories = 1_000;

    // The per-row cost the burn is calibrated to, so a batch of the starting size holds the lock
    // for about twice the sizing target whatever the runner's speed.
    private const double TargetRowCostMs = 1.0;
    private const int CalibrationRows = 200;
    private const int ProbeIterations = 10_000;
    private const int MinBurnIterations = 1_000;
    private const int MaxBurnIterations = 200_000;

    // Iterations of a recursive-CTE count the per-row trigger burns; set by calibration.
    private int _burnIterations = ProbeIterations;

    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_epss_starved_{Guid.NewGuid():N}.db");
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

    [Fact]
    public async Task ReplaceAndFill_UnderCpuStarvation_KeepsEveryLockHoldBounded()
    {
        var repo = new VulnerabilityRepository(_store, TimeProvider.System);
        await repo.ReplaceEpssScoresAsync(Scores(0.1), "2026-10-05");
        await SeedUnscoredAdvisoriesAsync(Advisories);
        await CalibrateBurnAsync();
        await StarveWritesAsync();

        await using var counting = new CountingStore(_store);
        var measured = new VulnerabilityRepository(counting, TimeProvider.System);

        using var stop = new CancellationTokenSource();
        var failures = new List<Exception>();
        double maxWriteMs = 0;
        int writes = 0;
        var writer = Task.Run(async () =>
        {
            for (int i = 0; !stop.IsCancellationRequested; i++)
            {
                long t0 = TimeProvider.System.GetTimestamp();
                try
                {
                    await using var conn = await _store.OpenAsync();
                    await conn.ExecuteAsync(
                        "INSERT INTO kev_catalog (cve_id, known_ransomware, date_added, refreshed_at) VALUES (@cve, NULL, NULL, '2026-10-06T00:00:00Z')",
                        new { cve = $"CVE-2049-{i}" });
                    writes++;
                }
                catch (Exception ex)
                {
                    failures.Add(ex);
                }

                maxWriteMs = Math.Max(maxWriteMs, TimeProvider.System.GetElapsedTime(t0).TotalMilliseconds);
                await Task.Delay(5);
            }
        });

        long start = TimeProvider.System.GetTimestamp();
        await measured.ReplaceEpssScoresAsync(Scores(0.9), "2026-10-06");
        int filled = await measured.FillMissingEpssFromStoredScoresAsync();
        double elapsedMs = TimeProvider.System.GetElapsedTime(start).TotalMilliseconds;
        await stop.CancelAsync();
        await writer;

        output.WriteLine($"replace+fill {elapsedMs:F0} ms  with {_burnIterations} burn iterations per row write; {writes} concurrent writes; slowest write {maxWriteMs:F0} ms; {failures.Count} failures");
        Assert.Empty(failures);
        AssertBoundedTransactions(counting.Connections[0], writes);
        Assert.Equal(Rows, await repo.CountEpssScoresAsync());
        Assert.Equal(Advisories, filled);
    }

    private void AssertBoundedTransactions(CountingConnection conn, int concurrentWrites)
    {
        var statements = conn.Statements;
        var starts = conn.TransactionStarts;
        var transactions = starts
            .Select((begin, i) => Enumerable.Range(begin, (i + 1 < starts.Count ? starts[i + 1] : statements.Count) - begin).ToList())
            .ToList();

        var staging = transactions.Where(t => t.Any(i => IsStagingInsert(statements[i]))).ToList();
        var applies = transactions.Where(t => t.Any(i => IsApply(statements[i]))).ToList();

        // Every staging transaction holds a bounded number of rows.
        var stagingRows = staging.Select(t => t.Sum(i => RowsIn(statements[i]))).ToList();
        Assert.Equal(Rows, stagingRows.Sum());
        Assert.All(stagingRows, r => Assert.InRange(r, 1, MaxStagingRowsPerTransaction));

        // Every apply transaction is a single range statement touching a bounded number of rows.
        Assert.True(applies.Count > 1, "the apply was a single transaction");
        Assert.All(applies, t =>
        {
            int apply = Assert.Single(t, i => IsApply(statements[i]));
            Assert.Contains("cve_id > @after AND cve_id <= @lastKey", statements[apply]);
            Assert.InRange(conn.AffectedRows[apply], 0, MaxApplyRowsPerTransaction);
        });

        var upsertRows = applies
            .Select(t => t.Single(i => IsApply(statements[i])))
            .Where(i => IsUpsert(statements[i]))
            .Select(i => conn.AffectedRows[i])
            .ToList();

        // The writer was not shut out: it committed regularly through the replace.
        output.WriteLine(
            $"{staging.Count} staging and {applies.Count} apply transactions; staging batches {string.Join(",", stagingRows)}; "
            + $"apply batches {string.Join(",", upsertRows)}; {concurrentWrites} concurrent writes");
        Assert.True(concurrentWrites >= (staging.Count + applies.Count) / 5, "the concurrent writer was starved");
    }

    private static bool IsStagingInsert(string statement) =>
        statement.StartsWith("INSERT INTO epss_scores_staging", StringComparison.Ordinal);

    private static bool IsUpsert(string statement) =>
        Regex.IsMatch(statement, @"^\s*INSERT INTO epss_scores\s*\(", RegexOptions.None, TimeSpan.FromSeconds(1));

    private static bool IsApply(string statement) =>
        IsUpsert(statement)
        || Regex.IsMatch(statement, @"^\s*DELETE FROM epss_scores\s", RegexOptions.None, TimeSpan.FromSeconds(1));

    // Each staged row binds one @cveN placeholder.
    private static int RowsIn(string statement) =>
        IsStagingInsert(statement) ? statement.Split("(@cve").Length - 1 : 0;

    // The probe is one short sample on whatever the runner is doing at that moment, and it measures
    // an INSERT trigger firing once per single-row statement; the scenario's cost per row is that of
    // set-based statements (multi-row inserts, range upserts) whose trigger work is amortised
    // differently, and it is measured later under different contention. The two have been seen to
    // differ by several times, so the calibration only sets the order of magnitude of the burn and
    // nothing asserts that the run's rows cost what the probe said.
    // Times inserts into a scratch table carrying the burn trigger, then scales the iteration count
    // so one burned row costs about TargetRowCostMs on this machine.
    private async Task CalibrateBurnAsync()
    {
        await using var conn = await _store.OpenAsync();
        await conn.ExecuteAsync("CREATE TABLE burn_probe (n INTEGER)");
        await conn.ExecuteAsync(
            "CREATE TRIGGER burn_probe_insert AFTER INSERT ON burn_probe BEGIN "
            + $"SELECT COUNT(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < {ProbeIterations}) SELECT x FROM c); END");
        await using var tx = await conn.BeginTransactionAsync();
        long start = TimeProvider.System.GetTimestamp();
        for (int i = 0; i < CalibrationRows; i++)
        {
            await conn.ExecuteAsync("INSERT INTO burn_probe (n) VALUES (@i)", new { i }, tx);
        }

        double perRowMs = TimeProvider.System.GetElapsedTime(start).TotalMilliseconds / CalibrationRows;
        await tx.RollbackAsync();
        await conn.ExecuteAsync("DROP TABLE burn_probe");

        _burnIterations = (int)Math.Clamp(ProbeIterations * TargetRowCostMs / Math.Max(perRowMs, 0.001), MinBurnIterations, MaxBurnIterations);
        output.WriteLine($"calibration: {perRowMs:F3} ms per row at {ProbeIterations} iterations; using {_burnIterations} iterations (target {TargetRowCostMs} ms per row)");
    }

    private async Task StarveWritesAsync()
    {
        await using var conn = await _store.OpenAsync();
        foreach (var (table, op) in new[]
        {
            ("epss_scores_staging", "INSERT"), ("epss_scores", "INSERT"), ("epss_scores", "UPDATE"),
            ("epss_scores", "DELETE"), ("vulnerabilities", "UPDATE"),
        })
        {
            // rawsql: constant table and operation names from the literal list above; no input is spliced.
            await conn.ExecuteAsync(
                $"CREATE TRIGGER burn_{table}_{op} AFTER {op} ON {table} BEGIN "
                + $"SELECT COUNT(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < {_burnIterations}) SELECT x FROM c); END");
        }
    }

    private async Task SeedUnscoredAdvisoriesAsync(int count)
    {
        await using var conn = await _store.OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();
        for (int i = 0; i < count; i++)
        {
            await conn.ExecuteAsync(
                "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) VALUES (@id, @id, 'npm', 'pkg')",
                new { id = $"CVE-2050-{i}" }, tx);
        }

        await tx.CommitAsync();
    }
}
