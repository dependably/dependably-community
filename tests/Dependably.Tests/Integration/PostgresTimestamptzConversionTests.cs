using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Exercises the <c>convert_legacy_timestamptz_columns</c> migration against a database that
/// actually has the legacy shape. The fresh-schema tests cannot cover this: they create the
/// columns as TEXT from the current <c>Schema.pg.sql</c>, so the migration no-ops and a broken
/// conversion would still pass. Here the columns are put back to TIMESTAMPTZ and the ledger row
/// removed, reproducing an upgraded deployment.
///
/// What the conversion has to get right is the instant, not just the type: Postgres renders a
/// TIMESTAMPTZ in the session TimeZone, so a conversion that forgets <c>AT TIME ZONE 'UTC'</c>
/// bakes the server's local offset into the stored text and every row silently shifts.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresTimestamptzConversionTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

    [Fact]
    public async Task ConvertsLegacyTimestamptzColumnsToCanonicalUtcText()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            // Put the column back to the legacy type and clear the ledger row, so the next
            // InitializeAsync sees exactly what an upgrading deployment has. The genuinely legacy
            // deployment this simulates predates the canonical-timestamp CHECK too — and Postgres
            // re-validates every constraint on a column against its new type on ALTER COLUMN TYPE,
            // so the CHECK's `~` (text-only) operator has to be dropped first or the TIMESTAMPTZ
            // conversion itself fails to typecheck.
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "upstream_negative_cache", "fetched_at");
            await conn.ExecuteAsync(
                """
                ALTER TABLE upstream_negative_cache
                    ALTER COLUMN fetched_at DROP DEFAULT,
                    ALTER COLUMN fetched_at TYPE TIMESTAMPTZ USING fetched_at::timestamptz,
                    ALTER COLUMN fetched_at SET DEFAULT now()
                """);
            await conn.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'convert_legacy_timestamptz_columns'");

            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_negative_cache (url_key, ecosystem, fetched_at)
                VALUES ('probe-key', 'maven', TIMESTAMPTZ '2026-07-25 12:00:00+00')
                """);
        }

        // Move the *database's* default TimeZone far from UTC, so the connection the migration
        // runs on inherits it. Setting it per-session would not reach that connection, and the
        // conversion would look correct on a UTC server while shifting every row on a server
        // configured to anything else. Pools are cleared so new physical sessions pick it up.
        await SetDatabaseTimeZoneAsync(store, "'America/New_York'");
        try
        {
            await new SchemaInitializer(store).InitializeAsync();
        }
        finally
        {
            await SetDatabaseTimeZoneAsync(store, "DEFAULT");
        }

        await using (var conn = await store.OpenAsync())
        {
            string? dataType = await conn.ExecuteScalarAsync<string?>(
                """
                SELECT data_type FROM information_schema.columns
                WHERE table_name = 'upstream_negative_cache' AND column_name = 'fetched_at'
                """);
            Assert.Equal("text", dataType);

            string? stored = await conn.ExecuteScalarAsync<string?>(
                "SELECT fetched_at FROM upstream_negative_cache WHERE url_key = 'probe-key'");
            Assert.Equal("2026-07-25T12:00:00Z", stored);

            // The restored DEFAULT must also produce the canonical form, not a Postgres
            // timestamp rendering — rows inserted without an explicit fetched_at have to
            // collate with the rows that supply one.
            await conn.ExecuteAsync(
                "INSERT INTO upstream_negative_cache (url_key, ecosystem) VALUES ('default-key', 'maven')");
            string? defaulted = await conn.ExecuteScalarAsync<string?>(
                "SELECT fetched_at FROM upstream_negative_cache WHERE url_key = 'default-key'");

            Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", defaulted);
        }
    }

    // ALTER DATABASE … SET TimeZone applies to sessions opened afterwards, so the pools are
    // cleared to force new physical connections.
    private static async Task SetDatabaseTimeZoneAsync(IMetadataStore store, string value)
    {
        await using (var conn = await store.OpenAsync())
        {
            string db = (await conn.ExecuteScalarAsync<string>("SELECT current_database()"))!;
            // rawsql: `db` is the connected database's own name read from the server, and `value`
            // is a literal supplied by this test; ALTER DATABASE takes no parameters.
            await conn.ExecuteAsync($"ALTER DATABASE \"{db}\" SET TimeZone TO {value}");
        }

        Npgsql.NpgsqlConnection.ClearAllPools();
    }
}
