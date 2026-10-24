using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Filling the EPSS columns of every unscored advisory after the bulk file lands must not hold the
/// SQLite write lock for the whole sweep: a concurrent writer waits at most <c>busy_timeout</c>
/// before failing with SQLITE_BUSY. Runs against a file-backed WAL database, because an in-memory
/// shared-cache database serialises on table locks and cannot show the behaviour.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EpssFillConcurrencyTests : IAsyncLifetime
{
    private const int Advisories = 60_000;

    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_epss_fill_{Guid.NewGuid():N}.db");
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

    private async Task SeedAdvisoriesAsync(int count)
    {
        await using var conn = await _store.OpenAsync();
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < @last)
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, modified_at, fetched_at)
            SELECT 'v' || i, 'CVE-2056-' || i, 'npm', 'pkg', '2026-10-06T00:00:00Z', '2026-10-06T00:00:00Z' FROM n
            """,
            new { last = count - 1 });
    }

    [Fact]
    public async Task Fill_LargeBacklog_DoesNotBlockAConcurrentWriter_AndScoresEveryMatchingAdvisory()
    {
        var repo = new VulnerabilityRepository(_store, TimeProvider.System);
        await SeedAdvisoriesAsync(Advisories);

        // Scores for every even-numbered advisory; the odd ones have no entry and must stay NULL.
        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < Advisories; i += 2)
        {
            scores[$"CVE-2056-{i}"] = new EpssScore(0.4, 0.5);
        }

        await repo.ReplaceEpssScoresAsync(scores, "2026-10-06");

        using var stop = new CancellationTokenSource();
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

        while (Volatile.Read(ref writes) < 3)
        {
            await Task.Delay(5);
        }

        int writesBefore = Volatile.Read(ref writes);
        int filled = await repo.FillMissingEpssFromStoredScoresAsync();
        int writesDuring = Volatile.Read(ref writes) - writesBefore;
        await stop.CancelAsync();
        await writer;

        Assert.Empty(failures);
        Assert.True(writesDuring >= 10, $"the concurrent writer completed only {writesDuring} writes during the fill");
        Assert.Equal(Advisories / 2, filled);
        await using var check = await _store.OpenAsync();
        Assert.Equal(Advisories / 2, await check.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NOT NULL"));
        Assert.Equal(0.5, await check.ExecuteScalarAsync<double>("SELECT epss_percentile FROM vulnerabilities WHERE osv_id = 'CVE-2056-0'"));
        Assert.Equal(0, await check.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NOT NULL AND osv_id = 'CVE-2056-1'"));

        // A second sweep finds the same unscorable advisories and writes nothing.
        Assert.Equal(0, await repo.FillMissingEpssFromStoredScoresAsync());
    }
}
