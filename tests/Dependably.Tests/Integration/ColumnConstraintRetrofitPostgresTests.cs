using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the existing-database retrofit of column-level CHECK and foreign-key constraints
/// (<c>SchemaInitializer.ColumnConstraintRetrofit.cs</c>) against a LIVE Postgres server. A fresh
/// reset gets every constraint from <c>Schema.pg.sql</c>'s <c>CREATE TABLE</c> blocks, so dropping
/// some is what reproduces a database whose columns arrived through the additive ALTER list.
///
/// Tagged <c>Category=SchemaPostgres</c> — see <see cref="PostgresSchemaApplyTests"/> for why this
/// only runs where a live Postgres is attached.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class ColumnConstraintRetrofitPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Retrofit_RestoresDroppedChecksAndForeignKeys_AndIsANoOpOnReRun()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        string[] dropped =
        [
            "org_settings_verify_sbom_signatures_check",
            "license_allowlist_disposition_check",
            "license_allowlist_created_by_fkey",
        ];
        await using (var conn = await pg.Store.OpenAsync())
        {
            await DropAsync(conn, "org_settings", dropped[0]);
            await DropAsync(conn, "license_allowlist", dropped[1]);
            await DropAsync(conn, "license_allowlist", dropped[2]);
            foreach (string name in dropped)
            {
                Assert.Null(await ValidatedAsync(conn, name));
            }
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            foreach (string name in dropped)
            {
                Assert.True(await ValidatedAsync(conn, name), name);
            }
        }

        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);
    }

    [Fact]
    public async Task RetrofittedDatabase_HasExactlyTheFreshInstallConstraints()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        Dictionary<string, string> fresh;
        await using (var conn = await pg.Store.OpenAsync())
        {
            fresh = await CheckAndForeignKeyConstraintsAsync(conn);

            // Strip every constraint the retrofit derives — the whole set an additive-only upgrade
            // path could have left missing.
            foreach (var constraint in await DeclaredAsync())
            {
                await DropAsync(conn, constraint.Table, constraint.Name);
            }
        }

        await new SchemaInitializer(pg.Store).InitializeAsync();

        // Same names, same catalogue definitions, all validated: one shape, not two that happen to
        // enforce the same rules.
        await using var upgraded = await pg.Store.OpenAsync();
        Assert.Equal(fresh, await CheckAndForeignKeyConstraintsAsync(upgraded));
    }

    [Fact]
    public async Task ViolatingRow_LeavesOnlyThatConstraintNotValid_AndBootsAnyway()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var logger = new CapturingLogger<SchemaInitializer>();
        var initializer = new SchemaInitializer(pg.Store, logger);
        await initializer.InitializeAsync();

        const string broken = "license_allowlist_disposition_check";
        const string clean = "org_settings_verify_sbom_signatures_check";
        await using (var conn = await pg.Store.OpenAsync())
        {
            await DropAsync(conn, "license_allowlist", broken);
            await DropAsync(conn, "org_settings", clean);
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
            await conn.ExecuteAsync(
                """
                INSERT INTO license_allowlist (id, org_id, license_spdx, disposition)
                VALUES ('l1', 'o1', 'MIT', 'legacy-value')
                """);
        }

        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);

        await using (var conn = await pg.Store.OpenAsync())
        {
            Assert.False(await ValidatedAsync(conn, broken));
            Assert.True(await ValidatedAsync(conn, clean));

            // NOT VALID still rejects new violating writes.
            var rejected = await Record.ExceptionAsync(() => conn.ExecuteAsync(
                """
                INSERT INTO license_allowlist (id, org_id, license_spdx, disposition)
                VALUES ('l2', 'o1', 'Apache-2.0', 'legacy-value')
                """));
            Assert.NotNull(rejected);
        }

        var (_, message) = Assert.Single(
            logger.Records,
            r => r.Level == LogLevel.Warning && r.Message.Contains(broken, StringComparison.Ordinal));
        Assert.Contains("NOT VALID", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LegacySymbolIndexUniqueKey_IsDropped()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        const string legacy = "nuget_symbol_index_org_id_ssqp_key_pdb_filename_package_ver_key";
        await using (var conn = await pg.Store.OpenAsync())
        {
            // The key a pre-owner-shape database carried; Postgres truncates the requested name the
            // same way it truncated the auto-generated one.
            await conn.ExecuteAsync(
                $"ALTER TABLE nuget_symbol_index ADD CONSTRAINT {legacy} " +
                "UNIQUE (org_id, ssqp_key, pdb_filename, package_version_id)");
            Assert.Equal(1, await UniqueConstraintCountAsync(conn, legacy));
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            Assert.Equal(0, await UniqueConstraintCountAsync(conn, legacy));
        }
    }

    [Fact]
    public async Task RenamedTablesForeignKey_IsKeptNotDuplicated_WhileAMissingOneIsStillAdded()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            // What `ALTER TABLE tokens RENAME TO user_tokens` leaves behind: the org_id foreign key
            // under the old table's name. user_id's foreign key is genuinely missing.
            await DropAsync(conn, "user_tokens", "user_tokens_org_id_fkey");
            await DropAsync(conn, "user_tokens", "user_tokens_user_id_fkey");
            await conn.ExecuteAsync(
                "ALTER TABLE user_tokens ADD CONSTRAINT tokens_org_id_fkey " +
                "FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE");
            Assert.Empty(await ForeignKeysOnAsync(conn, "user_tokens", "user_id"));
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            var orgFk = Assert.Single(await ForeignKeysOnAsync(conn, "user_tokens", "org_id"));
            Assert.Equal(("tokens_org_id_fkey", true), orgFk);

            var userFk = Assert.Single(await ForeignKeysOnAsync(conn, "user_tokens", "user_id"));
            Assert.Equal(("user_tokens_user_id_fkey", true), userFk);
        }

        await initializer.InitializeAsync();
        await using (var conn = await pg.Store.OpenAsync())
        {
            Assert.Single(await ForeignKeysOnAsync(conn, "user_tokens", "org_id"));
        }
    }

    [Fact]
    public async Task FreshInstall_CarriesNoDuplicateForeignKeys()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        // The allowlist/blocklist recreate migration runs on every install and renames *_new tables,
        // so their foreign keys carry the *_new name; the retrofit must not add a second one.
        await using var conn = await pg.Store.OpenAsync();
        var duplicates = (await conn.QueryAsync<string>(
            """
            SELECT t.relname || '(' || array_to_string(c.conkey, ',') || ') -> ' || rt.relname
                   || ': ' || string_agg(c.conname, ', ' ORDER BY c.conname)
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_class rt ON rt.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'f' AND n.nspname = current_schema()
            GROUP BY t.relname, c.conkey, rt.relname, c.confkey
            HAVING COUNT(*) > 1
            """)).ToList();
        Assert.Empty(duplicates);
        Assert.Equal(
            [("allowlist_new_org_id_fkey", true)], await ForeignKeysOnAsync(conn, "allowlist", "org_id"));
    }

    [Fact]
    public async Task NotValidLegacyNamedForeignKey_IsValidatedInPlace()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            // The allowlist recreate migration leaves its foreign key named for allowlist_new.
            await DropAsync(conn, "allowlist", "allowlist_new_org_id_fkey");
            await DropAsync(conn, "allowlist", "allowlist_org_id_fkey");
            await conn.ExecuteAsync(
                "ALTER TABLE allowlist ADD CONSTRAINT allowlist_new_org_id_fkey " +
                "FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE NOT VALID");
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            var fk = Assert.Single(await ForeignKeysOnAsync(conn, "allowlist", "org_id"));
            Assert.Equal(("allowlist_new_org_id_fkey", true), fk);
        }
    }

    [Fact]
    public async Task LegacyForeignKeyWithADifferentDeleteAction_DoesNotStandInForTheDeclaredOne()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await DropAsync(conn, "service_tokens", "service_tokens_org_id_fkey");
            await conn.ExecuteAsync(
                "ALTER TABLE service_tokens ADD CONSTRAINT cicd_tokens_org_id_fkey " +
                "FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE RESTRICT");
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            var names = (await ForeignKeysOnAsync(conn, "service_tokens", "org_id")).Select(f => f.Name);
            Assert.Equal(["cicd_tokens_org_id_fkey", "service_tokens_org_id_fkey"], names.Order(StringComparer.Ordinal));
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────

    // (name, validated) of every foreign key whose referencing columns are exactly {column}.
    private static async Task<List<(string Name, bool Validated)>> ForeignKeysOnAsync(
        DbConnection conn, string table, string column) =>
        (await conn.QueryAsync<(string Name, bool Validated)>(
            """
            SELECT c.conname AS Name, c.convalidated AS Validated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
            WHERE c.contype = 'f' AND t.relname = @table AND a.attname = @column
              AND cardinality(c.conkey) = 1 AND n.nspname = current_schema()
            ORDER BY c.conname
            """,
            new { table, column })).ToList();

    private static async Task<List<SchemaInitializer.DeclaredColumnConstraint>> DeclaredAsync()
    {
        string sql = await File.ReadAllTextAsync(
            Compliance.SchemaTestPaths.PostgresSchema(Compliance.SchemaTestPaths.SourceRoot()));
        return SchemaInitializer.DeclaredColumnConstraints(sql);
    }

    private static Task DropAsync(DbConnection conn, string table, string name) =>
        conn.ExecuteAsync($"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}");

    private static Task<bool?> ValidatedAsync(DbConnection conn, string name) =>
        conn.ExecuteScalarAsync<bool?>(
            """
            SELECT c.convalidated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.conname = @name AND n.nspname = current_schema()
            """,
            new { name });

    private static Task<int> UniqueConstraintCountAsync(DbConnection conn, string name) =>
        conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)::int
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE c.contype = 'u' AND c.conname = @name AND n.nspname = current_schema()
            """,
            new { name });

    // "<table>.<name>" → "<definition>|<validated>" for every CHECK and foreign key.
    private static async Task<Dictionary<string, string>> CheckAndForeignKeyConstraintsAsync(DbConnection conn)
    {
        var rows = await conn.QueryAsync<(string Table, string Name, string Definition, bool Validated)>(
            """
            SELECT t.relname AS Table, c.conname AS Name,
                   pg_get_constraintdef(c.oid) AS Definition, c.convalidated AS Validated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype IN ('c', 'f') AND n.nspname = current_schema()
            """);
        return rows.ToDictionary(
            r => $"{r.Table}.{r.Name}", r => $"{r.Definition}|{r.Validated}", StringComparer.Ordinal);
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
