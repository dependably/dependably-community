using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres coverage of the threat-feed copies (<c>epss_scores</c>, <c>kev_catalog</c>): the
/// multi-row inserts are built from generated placeholder lists, a construct whose per-provider
/// parameter binding has failed on Npgsql where SQLite accepted it.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresThreatFeedStoreTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task EpssScores_replaceAndRead_roundTripAcrossInsertChunks_againstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var repo = new VulnerabilityRepository(store, TimeProvider.System);

        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 600; i++)
        {
            scores[$"CVE-2040-{1000 + i}"] = new EpssScore(0.25, i % 2 == 0 ? 0.5 : null);
        }

        await repo.ReplaceEpssScoresAsync(scores, "2026-10-05");
        await repo.ReplaceEpssScoresAsync(scores, "2026-10-06");

        Assert.Equal(600, await repo.CountEpssScoresAsync());
        var stored = await repo.GetStoredEpssScoresAsync(["cve-2040-1000", "CVE-2040-1001", "CVE-2040-9999"]);
        Assert.Equal(2, stored.Count);
        Assert.Equal(new EpssScore(0.25, 0.5), stored["CVE-2040-1000"]);
        Assert.Null(stored["CVE-2040-1001"].Percentile);
        await using var conn = await store.OpenAsync();
        // The second file repeats every score, so no row is rewritten and the date stays at the run that wrote it.
        Assert.Equal("2026-10-05", await conn.ExecuteScalarAsync<string>(
            "SELECT score_date FROM epss_scores WHERE cve_id = 'CVE-2040-1000'"));
    }

    [Fact]
    public async Task KevFlaggedCveCount_AndEpssStampOnUpsert_runAgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var repo = new VulnerabilityRepository(store, TimeProvider.System);

        await Dependably.Tests.Infrastructure.Seeding.VulnerabilitySeeder.InsertVulnAsync(
            store, "CVE-2060-0001", isKev: true);
        await Dependably.Tests.Infrastructure.Seeding.VulnerabilitySeeder.InsertVulnAsync(
            store, "GHSA-pg-0001", aliases: """["CVE-2060-0001","cve-2060-0002"]""", isKev: true);
        await Dependably.Tests.Infrastructure.Seeding.VulnerabilitySeeder.InsertVulnAsync(
            store, "GHSA-pg-0002", aliases: """["CVE-2060-0003"]""", isKev: false);
        Assert.Equal(2, await repo.CountKevFlaggedCvesAsync());

        await repo.ReplaceEpssScoresAsync(
            new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2060-0003"] = new EpssScore(0.8, 0.97),
                ["CVE-2060-0004"] = new EpssScore(0.1, 0.2),
            },
            "2026-10-06");
        await repo.UpsertVulnerabilityAsync(
            new OsvAdvisory(
                Id: "GHSA-pg-0003",
                Aliases: ["CVE-2060-0003"],
                Summary: "advisory",
                Severity: "LOW",
                CvssScore: 2.0,
                AffectedPackages: [new OsvAffectedPackage("pkg:npm/acme", "npm", "acme", ["1.0.0"])],
                Published: "2026-01-01T00:00:00Z",
                Modified: "2026-01-02T00:00:00Z",
                IsHydrated: true),
            "npm", "acme");

        await using var conn = await store.OpenAsync();
        var stamped = await conn.QuerySingleAsync<(double?, double?)>(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE osv_id = 'GHSA-pg-0003'");
        Assert.Equal((0.8, 0.97), stamped);
    }

    [Fact]
    public async Task EpssFill_scoresUnscoredAdvisories_acrossBatches_againstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var repo = new VulnerabilityRepository(store, TimeProvider.System);

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, aliases, modified_at, fetched_at)
                SELECT 'v' || i, 'GHSA-pgfill-' || LPAD(i::text, 5, '0'), 'npm', 'pkg',
                       '["CVE-2082-' || i || '"]', '2026-10-06T00:00:00Z', '2026-10-06T00:00:00Z'
                FROM generate_series(0, 1199) AS i
                """);
            await VulnerabilityAliasIndex.ReconcileAsync(conn, TimeProvider.System);
        }

        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 1200; i += 3)
        {
            scores[$"CVE-2082-{i}"] = new EpssScore(0.5, 0.9);
        }

        await repo.ReplaceEpssScoresAsync(scores, "2026-10-06");

        Assert.Equal(400, await repo.FillMissingEpssFromStoredScoresAsync());
        await using var check = await store.OpenAsync();
        Assert.Equal(400, await check.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM vulnerabilities WHERE epss_score = 0.5 AND epss_percentile = 0.9"));
        Assert.Equal(0, await repo.FillMissingEpssFromStoredScoresAsync());
    }

    [Fact]
    public async Task EpssScores_replace_rewritesOnlyChangedRows__againstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var repo = new VulnerabilityRepository(store, TimeProvider.System);

        var day1 = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 500; i++)
        {
            day1[$"CVE-2070-{i}"] = new EpssScore(0.1, 0.2);
        }

        await repo.ReplaceEpssScoresAsync(day1, "2026-10-05");
        await using var conn = await store.OpenAsync();
        var xminBefore = (await conn.QueryAsync<(string Cve, string Xmin)>(
            "SELECT cve_id, xmin::text FROM epss_scores")).ToDictionary(r => r.Cve, r => r.Xmin);

        // 50 rows change score, the other 450 come back identical (new file date only).
        var day2 = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 500; i++)
        {
            day2[$"CVE-2070-{i}"] = i < 50 ? new EpssScore(0.9, 0.95) : new EpssScore(0.1, 0.2);
        }

        await repo.ReplaceEpssScoresAsync(day2, "2026-10-06");
        var after = (await conn.QueryAsync<(string Cve, string Xmin, double Epss)>(
            "SELECT cve_id, xmin::text, epss FROM epss_scores")).ToList();

        Assert.Equal(500, after.Count);
        Assert.Equal(50, after.Count(r => r.Xmin != xminBefore[r.Cve]));
        Assert.All(after.Where(r => r.Xmin != xminBefore[r.Cve]), r => Assert.Equal(0.9, r.Epss));

        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM epss_scores_staging"));
    }
}
