using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Applies the real embedded schema (Schema.sql + every additive ALTER + the one-time migrations)
/// to a fresh in-memory SQLite database via <see cref="SchemaInitializer"/>, then asserts the
/// resulting schema is structurally sound and that re-running the initializer is a stable no-op.
///
/// All introspection goes through the parameterized <c>pragma_*</c> table-valued functions
/// (e.g. <c>pragma_table_info(@table)</c>) — the same form SchemaInitializer itself uses
/// (SchemaInitializer.cs) — so no SQL is string-built and the Dapper-interpolation analyzer stays
/// satisfied. The only bare PRAGMA statements are the argument-less whole-database checks.
/// </summary>
[Trait("Category", "Schema")]
public sealed class SchemaIntegrityTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // User tables only: drop SQLite internals and the migration ledger (its PK is asserted elsewhere).
    private const string UserTablesSql =
        "SELECT name FROM sqlite_master WHERE type='table' " +
        "AND name NOT LIKE 'sqlite_%' AND name <> '_applied_migrations' ORDER BY name";

    // Microsoft.Data.Sqlite returns the (untyped) pragma_foreign_key_list columns as BLOB (byte[]),
    // so decode each field explicitly rather than relying on Dapper's type inference.
    private static string? AsText(object? value) => value switch
    {
        null or DBNull => null,
        byte[] bytes => Encoding.UTF8.GetString(bytes),
        _ => value.ToString(),
    };

    [Fact]
    public async Task EveryTable_HasUniqueColumnNames()
    {
        await using var conn = await _db.OpenAsync();
        var tables = (await conn.QueryAsync<string>(UserTablesSql)).ToList();
        Assert.NotEmpty(tables);

        var dupes = new List<string>();
        foreach (string? table in tables)
        {
            var names = (await conn.QueryAsync<string>(
                "SELECT name FROM pragma_table_info(@table)", new { table })).ToList();
            foreach (var g in names.GroupBy(n => n, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
            {
                dupes.Add($"{table}.{g.Key} declared {g.Count()} times");
            }
        }
        Assert.True(dupes.Count == 0, "Duplicate columns:\n" + string.Join("\n", dupes));
    }

    [Fact]
    public async Task EveryTable_HasAPrimaryKey()
    {
        await using var conn = await _db.OpenAsync();
        var tables = (await conn.QueryAsync<string>(UserTablesSql)).ToList();

        var missing = new List<string>();
        foreach (string? table in tables)
        {
            long pkCols = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM pragma_table_info(@table) WHERE pk > 0", new { table });
            if (pkCols == 0)
            {
                missing.Add(table);
            }
        }
        Assert.True(missing.Count == 0, "Tables without a primary key: " + string.Join(", ", missing));
    }

    [Fact]
    public async Task ForeignKeys_ReferenceExistingTablesAndColumns()
    {
        await using var conn = await _db.OpenAsync();
        var tables = (await conn.QueryAsync<string>(UserTablesSql)).ToList();

        var violations = new List<string>();
        foreach (string? table in tables)
        {
            var fks = await conn.QueryAsync(
                "SELECT \"table\" AS TargetTable, \"from\" AS FromCol, \"to\" AS ToCol " +
                "FROM pragma_foreign_key_list(@table)", new { table });
            foreach (IDictionary<string, object> fk in fks)
            {
                string targetTable = AsText(fk["TargetTable"])!;
                string fromCol = AsText(fk["FromCol"])!;
                string? toCol = AsText(fk["ToCol"]);

                var targetCols = (await conn.QueryAsync<string>(
                    "SELECT name FROM pragma_table_info(@t)", new { t = targetTable })).ToList();
                if (targetCols.Count == 0)
                {
                    violations.Add($"{table}.{fromCol} -> {targetTable} (target table does not exist)");
                    continue;
                }
                // A NULL 'to' means the FK targets the parent's PRIMARY KEY implicitly — nothing to check.
                if (toCol is not null && !targetCols.Contains(toCol, StringComparer.OrdinalIgnoreCase))
                {
                    violations.Add($"{table}.{fromCol} -> {targetTable}.{toCol} (target column does not exist)");
                }
            }
        }
        Assert.True(violations.Count == 0, "FK target violations:\n" + string.Join("\n", violations));
    }

    [Fact]
    public async Task ForeignKeyCheck_ReportsNoViolations()
    {
        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync("PRAGMA foreign_key_check")).ToList();
        Assert.Empty(rows);
    }

    [Fact]
    public async Task IntegrityCheck_ReturnsOk()
    {
        await using var conn = await _db.OpenAsync();
        string? result = await conn.ExecuteScalarAsync<string>("PRAGMA integrity_check");
        Assert.Equal("ok", result);
    }

    [Fact]
    public async Task Indexes_ReferenceRealColumns()
    {
        await using var conn = await _db.OpenAsync();
        var tables = (await conn.QueryAsync<string>(UserTablesSql)).ToList();

        var violations = new List<string>();
        foreach (string? table in tables)
        {
            var tableCols = (await conn.QueryAsync<string>(
                "SELECT name FROM pragma_table_info(@t)", new { t = table })).ToList();
            var indexes = (await conn.QueryAsync<string>(
                "SELECT name FROM pragma_index_list(@t)", new { t = table })).ToList();
            foreach (string? index in indexes)
            {
                // pragma_index_info.name is NULL for expression columns — those reference no table column.
                var indexCols = await conn.QueryAsync<string?>(
                    "SELECT name FROM pragma_index_info(@i)", new { i = index });
                foreach (string? col in indexCols)
                {
                    if (col is not null && !tableCols.Contains(col, StringComparer.OrdinalIgnoreCase))
                    {
                        violations.Add($"index {index} on {table} references missing column {col}");
                    }
                }
            }
        }
        Assert.True(violations.Count == 0, "Index column violations:\n" + string.Join("\n", violations));
    }

    [Fact]
    public async Task ReInitialize_IsStable_NoThrow_AndIdenticalSchema()
    {
        // _db is already initialized once by IAsyncLifetime. Snapshot, replay twice, snapshot again.
        string before = await SnapshotAsync();

        var ex = await Record.ExceptionAsync(async () =>
        {
            await new SchemaInitializer(_db).InitializeAsync();
            await new SchemaInitializer(_db).InitializeAsync();
        });
        Assert.Null(ex);

        Assert.Equal(before, await SnapshotAsync());
    }

    [Fact]
    public async Task EveryOneTimeMigration_IsReRunnable_FromClearedLedger()
    {
        // Each one-time migration, replayed from a state where only its ledger row is cleared, must
        // re-apply without error and re-record itself — catching a non-idempotent one-time migration.
        List<string> names;
        await using (var conn = await _db.OpenAsync())
        {
            names = (await conn.QueryAsync<string>("SELECT name FROM _applied_migrations ORDER BY name")).ToList();
        }

        Assert.NotEmpty(names);

        foreach (string name in names)
        {
            await using (var conn = await _db.OpenAsync())
            {
                await conn.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @name", new { name });
            }

            var ex = await Record.ExceptionAsync(() => new SchemaInitializer(_db).InitializeAsync());
            Assert.True(ex is null, $"Replaying one-time migration '{name}' threw: {ex?.Message}");

            await using (var conn = await _db.OpenAsync())
            {
                long present = await conn.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name });
                Assert.True(present == 1, $"Migration '{name}' did not re-record itself after replay");
            }
        }
    }

    // Stable textual snapshot of tables, their columns (name:type, in cid order), and index names.
    private async Task<string> SnapshotAsync()
    {
        await using var conn = await _db.OpenAsync();
        var tables = (await conn.QueryAsync<string>(UserTablesSql)).ToList();
        var sb = new StringBuilder();
        foreach (string? table in tables)
        {
            var cols = (await conn.QueryAsync<string>(
                "SELECT name || ':' || type FROM pragma_table_info(@t) ORDER BY cid", new { t = table })).ToList();
            sb.Append(table).Append('(').AppendJoin(',', cols).Append(')').Append('\n');
        }
        var indexes = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='index' AND name IS NOT NULL ORDER BY name")).ToList();
        sb.Append("indexes:").AppendJoin(',', indexes);
        return sb.ToString();
    }
}
