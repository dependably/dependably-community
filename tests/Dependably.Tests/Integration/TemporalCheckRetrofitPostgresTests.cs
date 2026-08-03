using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the existing-database retrofit of the canonical-timestamp CHECK
/// (<c>SchemaInitializer.TemporalCheckRetrofit.cs</c>) against a LIVE Postgres server. The unit of
/// simulation throughout is <see cref="TemporalCheckTestHelper.DropPostgresCheckAsync"/>: a fresh
/// reset gets every constraint from <c>Schema.pg.sql</c>'s <c>CREATE TABLE</c> blocks, so dropping
/// one (or all of them) is what reproduces a database created before the constraint shipped.
///
/// Tagged <c>Category=SchemaPostgres</c> — see <see cref="PostgresSchemaApplyTests"/> for why this
/// only runs where a live Postgres is attached.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class TemporalCheckRetrofitPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    // A temporal column the every-boot repair sweep does NOT touch — it is not one of the columns a
    // raw DateTimeOffset bind could have poisoned, so nothing normalizes a bad value in it. This is
    // what makes it the right stand-in for the genuinely-unfixable case below.
    private const string UnsweptTable = "orgs";
    private const string UnsweptColumn = "deleted_at";

    [Fact]
    public async Task Retrofit_RestoresADroppedConstraint_AndIsANoOpOnReRun()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, UnsweptTable, UnsweptColumn);
            Assert.Null(await ConstraintValidatedAsync(conn, UnsweptTable, UnsweptColumn));
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            Assert.True(await ConstraintValidatedAsync(conn, UnsweptTable, UnsweptColumn));
        }

        // Re-running against a database the retrofit already brought up to date must not throw and
        // must not disturb the constraint: the pg_constraint probe sees convalidated = true and
        // returns before touching the table.
        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);

        await using (var conn = await pg.Store.OpenAsync())
        {
            Assert.True(await ConstraintValidatedAsync(conn, UnsweptTable, UnsweptColumn));
        }
    }

    [Fact]
    public async Task RetrofittedConstraint_IsIdenticalToTheFreshInstallOne()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        Dictionary<string, string> fresh;
        await using (var conn = await pg.Store.OpenAsync())
        {
            fresh = await TemporalConstraintDefinitionsAsync(conn);
            Assert.NotEmpty(fresh);

            foreach (var (table, column) in await DeclaredColumnsAsync())
            {
                await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, table, column);
            }

            Assert.Empty(await TemporalConstraintDefinitionsAsync(conn));
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            // Same names (the retrofit reuses Postgres's own <table>_<column>_check) and the same
            // catalogue definitions, so a retrofitted database and a fresh install are one shape,
            // not two that happen to enforce the same rule.
            Assert.Equal(fresh, await TemporalConstraintDefinitionsAsync(conn));
        }
    }

    [Fact]
    public async Task LegacyRowInASweptColumn_IsHealedFirst_SoTheConstraintStillValidates()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "first_cached_at");
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, first_cached_at)
                VALUES ('ca1', 'npm', 'lodash', '1.0.0', 'lodash-1.0.0.tgz', 'proxy/abc', 'h',
                        '2026-03-04 05:06:07.5+02')
                """);
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            // The repair sweep runs immediately before the retrofit, so by the time VALIDATE
            // CONSTRAINT scans the table the legacy row is already canonical.
            Assert.Equal(
                "2026-03-04T03:06:07Z",
                await conn.QuerySingleAsync<string>(
                    "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca1'"));
            Assert.True(await ConstraintValidatedAsync(conn, "cache_artifact", "first_cached_at"));
        }
    }

    [Fact]
    public async Task UnhealableRowInOneColumn_LeavesOnlyThatConstraintNotValid_AndBootsAnyway()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var logger = new CapturingLogger<SchemaInitializer>();
        var initializer = new SchemaInitializer(pg.Store, logger);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            // Two constraints removed: one whose column then receives a value nothing can repair,
            // and a second (swept, left clean) that proves the loop kept going past the failure
            // rather than aborting at it.
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, UnsweptTable, UnsweptColumn);
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "first_cached_at");
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug, deleted_at) VALUES ('o1', 'acme', '2026-03-04 05:06:07+02:00')");
        }

        // A single unfixable row must not be fatal: the boot completes.
        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);

        await using (var conn = await pg.Store.OpenAsync())
        {
            // The offending column's constraint exists but is NOT VALID — it still rejects new
            // non-canonical writes while making no claim about the rows already there.
            Assert.False(await ConstraintValidatedAsync(conn, UnsweptTable, UnsweptColumn));
            Assert.Equal(
                "2026-03-04 05:06:07+02:00",
                await conn.QuerySingleAsync<string>("SELECT deleted_at FROM orgs WHERE id = 'o1'"));

            // NOT VALID still enforces writes.
            var rejected = await Record.ExceptionAsync(() => conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug, deleted_at) VALUES ('o2', 'beta', '2026-03-04 05:06:07+02:00')"));
            Assert.NotNull(rejected);

            // Every other column in the same run validated normally — the failure was contained to
            // the one column, not to everything after it in the loop.
            Assert.True(await ConstraintValidatedAsync(conn, "cache_artifact", "first_cached_at"));

            var unvalidated = (await conn.QueryAsync<string>(
                """
                SELECT c.conname
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE c.contype = 'c' AND NOT c.convalidated AND n.nspname = current_schema()
                """)).ToList();
            Assert.Equal([$"{UnsweptTable}_{UnsweptColumn}_check"], unvalidated);
        }

        var warnings = logger.Records
            .Where(r => r.Level == LogLevel.Warning && r.Message.Contains($"{UnsweptTable}_{UnsweptColumn}_check", StringComparison.Ordinal))
            .ToList();
        Assert.Single(warnings);
        Assert.Contains("NOT VALID", warnings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RetrofittedDatabase_ReachesTheSameShapeAsAFreshInstall()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        Dictionary<string, string> fresh;
        await using (var conn = await pg.Store.OpenAsync())
        {
            fresh = await AllCheckConstraintsAsync(conn);
        }

        // Strip every temporal CHECK, then let a boot put the database back together.
        await using (var conn = await pg.Store.OpenAsync())
        {
            foreach (var (table, column) in await DeclaredColumnsAsync())
            {
                await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, table, column);
            }
        }

        await new SchemaInitializer(pg.Store).InitializeAsync();

        // Whole-catalogue comparison, not just the temporal subset: an upgraded database must not
        // have lost or gained any CHECK constraint relative to a fresh install, and every one of
        // them must be validated.
        await using var upgraded = await pg.Store.OpenAsync();
        Assert.Equal(fresh, await AllCheckConstraintsAsync(upgraded));
    }

    [Fact]
    public async Task Retrofit_NeedsNoViewDropDance()
    {
        // ADD CONSTRAINT ... NOT VALID and VALIDATE CONSTRAINT do not rewrite the table, so unlike a
        // column retype or a drop they never conflict with a dependent view. Proven by leaving the
        // read-model views in place across a full strip-and-retrofit and checking their identity
        // (pg_class OID) survives untouched.
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        Dictionary<string, long> viewsBefore;
        await using (var conn = await pg.Store.OpenAsync())
        {
            viewsBefore = await ViewOidsAsync(conn);
            Assert.NotEmpty(viewsBefore);

            foreach (var (table, column) in await DeclaredColumnsAsync())
            {
                await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, table, column);
            }
        }

        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var after = await pg.Store.OpenAsync();

        // The retrofit really did run — without this the OID equality below would hold vacuously on
        // a build where nothing touches the constraints at all.
        Assert.Equal((await DeclaredColumnsAsync()).Count, (await TemporalConstraintDefinitionsAsync(after)).Count);
        Assert.Equal(viewsBefore, await ViewOidsAsync(after));
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────

    // The retrofit's own derivation, run against the on-disk Schema.pg.sql — the same text the
    // embedded resource holds — so a test that strips "every" constraint strips exactly the set the
    // retrofit will put back, with no second hand-maintained list to drift.
    private static async Task<IReadOnlyList<(string Table, string Column)>> DeclaredColumnsAsync()
    {
        string sql = await File.ReadAllTextAsync(
            Compliance.SchemaTestPaths.PostgresSchema(Compliance.SchemaTestPaths.SourceRoot()));
        return SchemaInitializer.DeclaredTemporalCheckColumns(sql);
    }

    private static async Task<bool?> ConstraintValidatedAsync(
        System.Data.Common.DbConnection conn, string table, string column) =>
        await conn.ExecuteScalarAsync<bool?>(
            """
            SELECT c.convalidated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'c' AND c.conname = @name AND n.nspname = current_schema()
            """,
            new { name = $"{table}_{column}_check" });

    // Constraint name → "<definition>|<validated>" for the temporal CHECKs only.
    private static async Task<Dictionary<string, string>> TemporalConstraintDefinitionsAsync(
        System.Data.Common.DbConnection conn)
    {
        var names = (await DeclaredColumnsAsync())
            .Select(c => $"{c.Table}_{c.Column}_check")
            .ToHashSet(StringComparer.Ordinal);
        return (await AllCheckConstraintsAsync(conn))
            .Where(kv => names.Contains(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
    }

    private static async Task<Dictionary<string, string>> AllCheckConstraintsAsync(
        System.Data.Common.DbConnection conn)
    {
        var rows = await conn.QueryAsync<(string Name, string Definition, bool Validated)>(
            """
            SELECT c.conname AS Name, pg_get_constraintdef(c.oid) AS Definition,
                   c.convalidated AS Validated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'c' AND n.nspname = current_schema()
            """);
        return rows.ToDictionary(
            r => r.Name, r => $"{r.Definition}|{r.Validated}", StringComparer.Ordinal);
    }

    private static async Task<Dictionary<string, long>> ViewOidsAsync(System.Data.Common.DbConnection conn)
    {
        var rows = await conn.QueryAsync<(string Name, long Oid)>(
            """
            SELECT c.relname AS Name, c.oid::bigint AS Oid
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'v' AND n.nspname = current_schema()
            """);
        return rows.ToDictionary(r => r.Name, r => r.Oid, StringComparer.Ordinal);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Records { get; } = [];

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter) =>
            Records.Add((logLevel, formatter(state, exception)));
    }
}
