using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// The tracker enrichment-overlay columns on <c>vulnerabilities</c>: the NVD band/score, the three
/// SSVC decision points, and two stamps per signal class. Covers what the static schema-parity and
/// temporal-CHECK gates cannot — that the vocabularies actually reject a bad value on a fresh
/// install, that <c>NONE</c> is admitted where the OSV-derived <c>severity</c> column refuses it,
/// and that an existing database gains all nine columns through the additive ALTER path.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerOverlayColumnsMigrationTests : IAsyncLifetime
{
    private static readonly string[] OverlayColumns =
    [
        "nvd_severity", "nvd_score", "nvd_checked_at", "nvd_asserted_at",
        "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
        "ssvc_checked_at", "ssvc_asserted_at",
    ];

    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static async Task SeedAdvisoryAsync(System.Data.Common.DbConnection conn, string id) =>
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) "
            + "VALUES (@id, @id, 'npm', 'left-pad')",
            new { id });

    [Fact]
    public async Task FreshSchema_DeclaresEveryOverlayColumn()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        var columns = (await conn.QueryAsync<string>(
            "SELECT name FROM pragma_table_info('vulnerabilities')")).ToHashSet();

        foreach (string column in OverlayColumns)
        {
            Assert.Contains(column, columns);
        }
    }

    [Fact]
    public async Task FreshSchema_AcceptsACompleteEnrichmentRow()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-ok");

        await conn.ExecuteAsync(
            """
            UPDATE vulnerabilities SET
                nvd_severity = 'HIGH', nvd_score = 8.1,
                nvd_checked_at = '2026-08-23T00:00:00Z', nvd_asserted_at = '2026-08-22T00:00:00Z',
                ssvc_exploitation = 'active', ssvc_automatable = 'yes',
                ssvc_technical_impact = 'total',
                ssvc_checked_at = '2026-08-23T00:00:00Z', ssvc_asserted_at = '2026-08-22T00:00:00Z'
            WHERE id = 'v-ok'
            """);

        string? band = await conn.ExecuteScalarAsync<string>(
            "SELECT nvd_severity FROM vulnerabilities WHERE id = 'v-ok'");
        Assert.Equal("HIGH", band);
    }

    [Fact]
    public async Task FreshSchema_AdmitsTheNoneBand_WhichTheOsvSeverityColumnRefuses()
    {
        // The deliberate divergence: NVD assigns NONE to a 0.0 base score, so refusing it would
        // fail the enrichment write rather than record the band the source publishes. The second
        // half is the twin — it proves the value set genuinely differs from the neighbouring
        // column's rather than both having been widened by accident.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-none");

        await conn.ExecuteAsync(
            "UPDATE vulnerabilities SET nvd_severity = 'NONE' WHERE id = 'v-none'");
        Assert.Equal("NONE", await conn.ExecuteScalarAsync<string>(
            "SELECT nvd_severity FROM vulnerabilities WHERE id = 'v-none'"));

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "UPDATE vulnerabilities SET severity = 'NONE' WHERE id = 'v-none'"));
        Assert.Contains("CHECK", ex.Message);
    }

    [Theory]
    [InlineData("nvd_severity", "BOGUS")]
    [InlineData("nvd_severity", "high")]                 // vocabulary is upper-case
    [InlineData("ssvc_exploitation", "Active")]          // vocabulary is lower-case
    [InlineData("ssvc_exploitation", "exploited")]
    [InlineData("ssvc_automatable", "true")]
    [InlineData("ssvc_technical_impact", "complete")]
    public async Task FreshSchema_RejectsAValueOutsideTheVocabulary(string column, string value)
    {
        // Case matters in both directions here, and the two vocabularies disagree on it: NVD
        // bands are upper-case, SSVC decision points lower-case. A CHECK that quietly accepted
        // either casing would let two spellings of one fact into the same column.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-bad");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = @value WHERE id = 'v-bad'", new { value }));
        Assert.Contains("CHECK", ex.Message);
    }

    [Theory]
    [InlineData("nvd_checked_at")]
    [InlineData("nvd_asserted_at")]
    [InlineData("ssvc_checked_at")]
    [InlineData("ssvc_asserted_at")]
    public async Task FreshSchema_RejectsANonCanonicalTimestamp(string column)
    {
        // Both stamps per signal class carry the canonical-UTC CHECK, not just the local one.
        // The producer-asserted stamp arrives from outside this system, which is precisely why
        // it needs the constraint rather than being trusted to be well-shaped.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-ts");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = '2026-08-23 00:00:00+00' WHERE id = 'v-ts'"));
        Assert.Contains("CHECK", ex.Message);

        // Twin: the canonical shape is accepted, so the rejection above is the format check
        // doing its job rather than the column being unwritable.
        await conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = '2026-08-23T00:00:00Z' WHERE id = 'v-ts'");
        Assert.Equal("2026-08-23T00:00:00Z", await conn.ExecuteScalarAsync<string>(
            $"SELECT {column} FROM vulnerabilities WHERE id = 'v-ts'"));
    }

    [Fact]
    public async Task ExistingDatabaseWithoutTheColumns_GainsThemAllOnReInit()
    {
        // A database that predates the overlay: drop the table and recreate it without any of the
        // nine columns, then re-run the initializer. The additive ALTER path must add every one —
        // a partial application would leave the enrichment write failing on whichever column was
        // missed, which nothing else here would catch.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS vulnerabilities");
            await setup.ExecuteAsync(
                """
                CREATE TABLE vulnerabilities (
                    id           TEXT PRIMARY KEY,
                    osv_id       TEXT NOT NULL UNIQUE,
                    ecosystem    TEXT NOT NULL,
                    package_name TEXT NOT NULL
                )
                """);
            await SeedAdvisoryAsync(setup, "v-legacy");

            var columns = (await setup.QueryAsync<string>(
                "SELECT name FROM pragma_table_info('vulnerabilities')")).ToHashSet();
            Assert.DoesNotContain("nvd_severity", columns);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var after = (await conn.QueryAsync<string>(
            "SELECT name FROM pragma_table_info('vulnerabilities')")).ToHashSet();
        foreach (string column in OverlayColumns)
        {
            Assert.Contains(column, after);
        }

        // The pre-existing row survives with the overlay unset, which is the correct unenriched
        // state — no backfill, and nothing for a gate arm to read differently.
        string? band = await conn.ExecuteScalarAsync<string>(
            "SELECT nvd_severity FROM vulnerabilities WHERE id = 'v-legacy'");
        Assert.Null(band);
    }
}
