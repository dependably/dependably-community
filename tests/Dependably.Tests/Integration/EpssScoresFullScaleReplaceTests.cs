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
/// Full-size (~383k rows) replace of the EPSS file on a file-backed WAL SQLite database while
/// another writer keeps committing. Slow by design, so it is excluded from the default run.
///
/// <para>The property is that the replace never holds the database write lock long enough for a
/// concurrent writer waiting out its lock retries and failing. How long any one
/// write waited depends on how loaded the host is, so the test does not time it. It asserts the
/// outcome (no concurrent write failed) and the structure that guarantees it on any host, read
/// off the statements the replace issues: the file is loaded in short committed transactions with
/// a pause between them, and the live table is rewritten by many short committed transactions, each
/// one set-based statement over a bounded key range, rather than one transaction over the whole
/// file. Every score stays present throughout (rows are upserted first, CVEs the file dropped are
/// removed last), so a reader sees a complete previous or new score for each CVE.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class EpssScoresFullScaleReplaceTests(ITestOutputHelper output) : IAsyncLifetime
{
    private const int Rows = 383_000;

    // The most rows one load transaction may write. A few thousand rows commit in tens of
    // milliseconds even on a slow disk; the whole file in one transaction takes tens of seconds.
    private const int MaxRowsPerLoadTransaction = 2_000;

    private const string StagingInsert = "INSERT INTO epss_scores_staging";

    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_epss_full_{Guid.NewGuid():N}.db");
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

    // Each staged row binds one @cveN placeholder.
    private static int RowsIn(string statement) =>
        statement.StartsWith(StagingInsert, StringComparison.Ordinal)
            ? statement.Split("(@cve").Length - 1
            : 0;

    private static bool IsUpsert(string statement) =>
        Regex.IsMatch(statement, @"^\s*INSERT INTO epss_scores\s*\(", RegexOptions.None, TimeSpan.FromSeconds(1));

    private static bool IsStaleDelete(string statement) =>
        Regex.IsMatch(statement, @"^\s*DELETE FROM epss_scores\s", RegexOptions.None, TimeSpan.FromSeconds(1));

    [Fact]
    public async Task ReplaceEpssScores_FullFile_KeepsEveryConcurrentWriteWithinBusyTimeout()
    {
        await new VulnerabilityRepository(_store, TimeProvider.System)
            .ReplaceEpssScoresAsync(Scores(0.1), "2026-10-05");

        await using var counting = new CountingStore(_store);
        var clock = new PauseCountingTimeProvider();
        var repo = new VulnerabilityRepository(counting, clock);

        using var stop = new CancellationTokenSource();
        var firstWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failures = new List<Exception>();
        int writes = 0;
        var writer = Task.Run(async () =>
        {
            for (int i = 0; !stop.IsCancellationRequested; i++)
            {
                try
                {
                    await using var conn = await _store.OpenAsync();
                    await conn.ExecuteAsync(
                        "INSERT INTO kev_catalog (cve_id, known_ransomware, date_added, refreshed_at) VALUES (@cve, NULL, NULL, '2026-10-06T00:00:00Z')",
                        new { cve = $"CVE-2049-{i}" });
                    writes++;
                    firstWrite.TrySetResult();
                }
                catch (Exception ex)
                {
                    failures.Add(ex);
                    firstWrite.TrySetResult();
                }

                await Task.Delay(5);
            }
        });

        // The writer is running before the replace starts, so its writes overlap the load.
        await firstWrite.Task;
        await repo.ReplaceEpssScoresAsync(Scores(0.9), "2026-10-06");
        await stop.CancelAsync();
        await writer;

        var conn = Assert.Single(counting.Connections);
        var statements = conn.Statements;
        var starts = conn.TransactionStarts;
        var transactions = starts
            .Select((begin, i) => statements
                .Skip(begin)
                .Take((i + 1 < starts.Count ? starts[i + 1] : statements.Count) - begin)
                .ToList())
            .ToList();
        var loads = transactions.Where(t => t.Any(s => s.StartsWith(StagingInsert, StringComparison.Ordinal))).ToList();
        var loadRows = loads.Select(t => t.Sum(RowsIn)).ToList();

        output.WriteLine(
            $"{writes} concurrent writes, {failures.Count} failures; {statements.Count} statements in "
            + $"{transactions.Count} transactions; largest load transaction {loadRows.Max()} rows; {clock.Pauses} pauses");

        // Outcome: no concurrent writer failed waiting for the lock.
        Assert.Empty(failures);

        // Every staged row is written inside a transaction, and every row of the file is staged.
        Assert.Equal(0, statements.Take(starts[0]).Sum(RowsIn));
        Assert.Equal(Rows, loadRows.Sum());

        // No load transaction holds the write lock for more than a short batch.
        Assert.All(loadRows, rows => Assert.InRange(rows, 1, MaxRowsPerLoadTransaction));

        // The loader yields the write lock between batches rather than retaking it at once.
        // The same holds for the apply step's batches below.
        var upserts = transactions.Where(t => t.Any(IsUpsert)).ToList();
        var deletes = transactions.Where(t => t.Any(IsStaleDelete)).ToList();
        Assert.Equal((loads.Count - 1) + (upserts.Count - 1) + (deletes.Count - 1), clock.Pauses);

        // The live table is rewritten incrementally: several transactions, each holding a single
        // set-based statement, never the load's inserts, and never more than one write statement.
        Assert.True(upserts.Count > 1, "the apply step was one transaction over the whole file");
        Assert.All(upserts.Concat(deletes), t =>
        {
            Assert.Single(t, s => IsUpsert(s) || IsStaleDelete(s));
            Assert.DoesNotContain(t, s => s.StartsWith(StagingInsert, StringComparison.Ordinal));
        });

        // Rows are applied before stale CVEs are removed, so none is absent mid-refresh; both come
        // after the whole file is staged.
        int lastLoad = transactions.IndexOf(loads[^1]);
        Assert.True(transactions.IndexOf(upserts[0]) > lastLoad);
        Assert.True(transactions.IndexOf(deletes[0]) > transactions.IndexOf(upserts[^1]));

        Assert.Equal(Rows, await repo.CountEpssScoresAsync());
    }
}
