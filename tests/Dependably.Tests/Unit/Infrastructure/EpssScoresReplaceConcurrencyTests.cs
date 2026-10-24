using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The EPSS bulk file is ~380k rows. Replacing it must not hold the SQLite write lock for the
/// whole load: every other writer (first-fetch recording, audit, publish, scans) waits at most
/// <c>busy_timeout</c> before failing with SQLITE_BUSY, and a single transaction over the whole
/// file outlasts it. Runs against a file-backed WAL database, because an in-memory shared-cache
/// database serialises on table locks and cannot show the behaviour.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EpssScoresReplaceConcurrencyTests : IAsyncLifetime
{
    private const int OldRows = 60_000;
    private const int NewRows = 150_000;

    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_epss_replace_{Guid.NewGuid():N}.db");
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

    private static Dictionary<string, EpssScore> Scores(int rows, double probability)
    {
        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < rows; i++)
        {
            scores[$"CVE-2050-{i}"] = new EpssScore(probability, 0.5);
        }

        return scores;
    }

    // Spread across the key range, so the probe reads rows the swap reaches early and late.
    private static readonly string[] Probe = Enumerable.Range(0, 20)
        .Select(i => $"CVE-2050-{i * (OldRows / 20)}")
        .ToArray();

    [Fact]
    public async Task ReplaceEpssScores_LargeSet_DoesNotBlockAConcurrentWriter_AndNeverHidesASharedCve()
    {
        var repo = new VulnerabilityRepository(_store, TimeProvider.System);
        await repo.ReplaceEpssScoresAsync(Scores(OldRows, 0.1), "2026-10-05");
        Assert.Equal(OldRows, await repo.CountEpssScoresAsync());

        using var stop = new CancellationTokenSource();
        var failures = new List<Exception>();
        int writes = 0;
        var misreads = new List<string>();

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
                    Interlocked.Increment(ref writes);
                }
                catch (Exception ex)
                {
                    lock (failures)
                    {
                        failures.Add(ex);
                    }
                }

                await Task.Delay(5);
            }
        });

        var reader = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                // Every CVE in both the old and the new file must read as one of its two complete
                // scores for the whole refresh: never absent, never a value from neither file.
                var seen = await repo.GetStoredEpssScoresAsync(Probe);
                if (seen.Count != Probe.Length)
                {
                    misreads.Add($"{Probe.Length - seen.Count} of {Probe.Length} shared CVEs were absent");
                }

                foreach (var (cve, score) in seen)
                {
                    if (score.Probability is not (0.1 or 0.9))
                    {
                        misreads.Add($"{cve} read {score.Probability}");
                    }
                }

                await Task.Delay(5);
            }
        });

        // Let the writer start cycling before the replace begins.
        while (Volatile.Read(ref writes) < 3)
        {
            await Task.Delay(5);
        }

        int writesBefore = Volatile.Read(ref writes);
        await repo.ReplaceEpssScoresAsync(Scores(NewRows, 0.9), "2026-10-06");
        int writesDuring = Volatile.Read(ref writes) - writesBefore;
        await stop.CancelAsync();
        await Task.WhenAll(writer, reader);

        Assert.Empty(failures);
        // A writer parked behind one long transaction completes nothing until it commits; one that
        // can interleave completes a write every few milliseconds throughout the load.
        Assert.True(writesDuring >= 10, $"the concurrent writer completed only {writesDuring} writes during the replace");
        Assert.Equal(NewRows, await repo.CountEpssScoresAsync());
        Assert.Empty(misreads);
        var stored = await repo.GetStoredEpssScoresAsync(["CVE-2050-0", "CVE-2050-149999"]);
        Assert.Equal(0.9, stored["CVE-2050-0"].Probability);
        Assert.Equal(2, stored.Count);
    }

    [Fact]
    public async Task ReplaceEpssScores_ShrinksTheStoredSet_AndLeavesNoStagingRows()
    {
        var repo = new VulnerabilityRepository(_store, TimeProvider.System);
        await repo.ReplaceEpssScoresAsync(Scores(1_000, 0.1), "2026-10-05");
        await repo.ReplaceEpssScoresAsync(Scores(400, 0.2), "2026-10-06");

        Assert.Equal(400, await repo.CountEpssScoresAsync());
        Assert.Empty(await repo.GetStoredEpssScoresAsync(["CVE-2050-400", "CVE-2050-999"]));
        await using var conn = await _store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM epss_scores_staging"));
    }
}
