using Dapper;
using Dependably.Infrastructure;
using static Dependably.Tests.Integration.ConstraintRetrofitLockBoundPostgresTests;

namespace Dependably.Tests.Integration;

/// <summary>
/// The constraint retrofits share one pass per boot: a single deadline and one set of locked tables.
/// These tests pin that a locked table (or a locked referenced table) is charged one retry budget no
/// matter how many constraints depend on it, that the deadline defers the remainder with a single
/// summary, and that a VALIDATE scan is cut off by the statement timeout. Every one holds a real
/// conflicting lock from a second connection or runs a genuinely slow scan.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class ConstraintRetrofitPassPostgresTests
{
    private static readonly SchemaInitializer.LockRetryPolicy TinyBudget =
        new(TimeSpan.FromMilliseconds(200), [TimeSpan.Zero, TimeSpan.Zero]);

    // One exhausted budget under TinyBudget logs two retry warnings and one give-up warning.
    private const int WarningsPerLockBudget = 3;

    private static int LockWarnings(CapturingLogger log) =>
        log.Warnings.Count(m => m.Contains("could not lock table", StringComparison.Ordinal));

    private static List<string> Summaries(CapturingLogger log) =>
        log.Warnings.Where(m => m.Contains("deferred to the next boot", StringComparison.Ordinal)).ToList();

    [Fact]
    public async Task TwoMissingChecksOnOneLockedTable_CostOneBudget_AndOneSummary()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };

        var checks = SchemaInitializer.DeclaredColumnConstraints(schema)
            .Where(c => c.Table == "org_settings" && c.Kind == SchemaInitializer.ColumnConstraintKind.Check)
            .Take(2).ToList();
        Assert.Equal(2, checks.Count);

        await using var conn = await pg.Store.OpenAsync();
        foreach (var c in checks)
        {
            await conn.ExecuteAsync($"ALTER TABLE org_settings DROP CONSTRAINT {c.Name}");
        }

        using (var blocker = new LockHolder(ConnectionString, "SELECT 1 FROM org_settings LIMIT 1"))
        {
            await CompleteWithinAsync(init.RetrofitColumnConstraintsAsync(conn, schema), blocker, TimeSpan.FromSeconds(30));
        }

        Assert.Equal(WarningsPerLockBudget, LockWarnings(log));
        string summary = Assert.Single(Summaries(log));
        Assert.StartsWith("2 constraint", summary, StringComparison.Ordinal);
        foreach (var c in checks)
        {
            Assert.Null(await ValidatedAsync(conn, c.Name));
        }
    }

    [Fact]
    public async Task TwoTemporalColumnsOnOneLockedTable_CostOneBudget()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };

        var table = SchemaInitializer.DeclaredTemporalCheckColumns(schema)
            .GroupBy(c => c.Table).First(g => g.Count() >= 2);
        var names = table.Take(2).Select(c => c.Table + "_" + c.Column + "_check").ToList();

        await using var conn = await pg.Store.OpenAsync();
        foreach (string name in names)
        {
            await conn.ExecuteAsync($"ALTER TABLE {table.Key} DROP CONSTRAINT {name}");
        }

        using (var blocker = new LockHolder(ConnectionString, $"SELECT 1 FROM {table.Key} LIMIT 1"))
        {
            await CompleteWithinAsync(init.RetrofitTemporalChecksAsync(conn, schema), blocker, TimeSpan.FromSeconds(30));
        }

        Assert.Equal(WarningsPerLockBudget, LockWarnings(log));
        Assert.StartsWith("2 constraint", Assert.Single(Summaries(log)), StringComparison.Ordinal);
        foreach (string name in names)
        {
            Assert.Null(await ValidatedAsync(conn, name));
        }
    }

    [Fact]
    public async Task LockedReferencedTable_BlocksOneForeignKeyAdd_AndTheNextReferencingItIsSkipped()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };

        var all = SchemaInitializer.DeclaredColumnConstraints(schema);
        var foreignKeys = all
            .Where(c => c.Kind == SchemaInitializer.ColumnConstraintKind.ForeignKey
                && c.Definition.Contains("REFERENCES orgs", StringComparison.Ordinal)
                && c.Table != "license_allowlist")
            .GroupBy(c => c.Table).Select(g => g.First()).Take(2).ToList();
        var bystander = all.Single(c => c.Name == "license_allowlist_disposition_check");
        Assert.Equal(2, foreignKeys.Count);

        await using var conn = await pg.Store.OpenAsync();
        foreach (var c in foreignKeys.Append(bystander))
        {
            await conn.ExecuteAsync($"ALTER TABLE {c.Table} DROP CONSTRAINT {c.Name}");
        }

        // ADD of a foreign key takes SHARE ROW EXCLUSIVE on orgs, which ROW EXCLUSIVE conflicts with.
        using (var blocker = new LockHolder(ConnectionString, "LOCK TABLE orgs IN ROW EXCLUSIVE MODE"))
        {
            await CompleteWithinAsync(init.RetrofitColumnConstraintsAsync(conn, schema), blocker, TimeSpan.FromSeconds(30));
        }

        Assert.Equal(WarningsPerLockBudget, LockWarnings(log));
        foreach (var c in foreignKeys)
        {
            Assert.Null(await ValidatedAsync(conn, c.Name));
        }

        // A constraint that does not touch orgs is not collateral damage.
        Assert.True(await ValidatedAsync(conn, bystander.Name));
    }

    [Fact]
    public async Task SpentPassDeadline_DefersTheRemainder_WithOneSummary()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { RetrofitPassBudget = TimeSpan.Zero };

        string[] dropped =
        [
            "org_settings_verify_sbom_signatures_check",
            "license_allowlist_disposition_check",
            "license_allowlist_created_by_fkey",
        ];
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync($"ALTER TABLE org_settings DROP CONSTRAINT {dropped[0]}");
        await conn.ExecuteAsync($"ALTER TABLE license_allowlist DROP CONSTRAINT {dropped[1]}");
        await conn.ExecuteAsync($"ALTER TABLE license_allowlist DROP CONSTRAINT {dropped[2]}");

        await init.RetrofitColumnConstraintsAsync(conn, schema);

        Assert.StartsWith("3 constraint", Assert.Single(Summaries(log)), StringComparison.Ordinal);
        foreach (string name in dropped)
        {
            Assert.Null(await ValidatedAsync(conn, name));
        }

        await new SchemaInitializer(pg.Store, log).RetrofitColumnConstraintsAsync(conn, schema);
        foreach (string name in dropped)
        {
            Assert.True(await ValidatedAsync(conn, name), name);
        }
    }

    [Fact]
    public async Task DeadlineCapsLockWaits_SoABlockedTableCannotOutlastThePass()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        // Un-capped, this policy would wait 5 s + 1 s + 5 s + 2 s + 5 s + 4 s + 5 s on the one table.
        var init = new SchemaInitializer(pg.Store, log)
        {
            RetrofitPassBudget = TimeSpan.FromSeconds(1),
            ConstraintLockRetry = new SchemaInitializer.LockRetryPolicy(
                TimeSpan.FromSeconds(5),
                [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)]),
        };

        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync("ALTER TABLE org_settings DROP CONSTRAINT org_settings_verify_sbom_signatures_check");

        long started = TimeProvider.System.GetTimestamp();
        using (var blocker = new LockHolder(ConnectionString, "SELECT 1 FROM org_settings LIMIT 1"))
        {
            await CompleteWithinAsync(init.RetrofitColumnConstraintsAsync(conn, schema), blocker, TimeSpan.FromSeconds(60));
        }

        var elapsed = TimeProvider.System.GetElapsedTime(started);
        Assert.True(elapsed < TimeSpan.FromSeconds(8), $"The pass outlasted its 1 s budget: {elapsed}.");
        Assert.Single(Summaries(log));
        Assert.Null(await ValidatedAsync(conn, "org_settings_verify_sbom_signatures_check"));
    }

    [Fact]
    public async Task ValidateExceedingStatementTimeout_LeavesNotValid_WarnsAndBootsOn()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ValidateStatementTimeout = TimeSpan.FromMilliseconds(300) };

        const string name = "org_settings_verify_sbom_signatures_check";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('o1')");
        await conn.ExecuteAsync(
            """
            CREATE FUNCTION slow_ok() RETURNS boolean LANGUAGE plpgsql AS 'BEGIN PERFORM pg_sleep(3); RETURN true; END';
            ALTER TABLE org_settings DROP CONSTRAINT org_settings_verify_sbom_signatures_check;
            ALTER TABLE org_settings ADD CONSTRAINT org_settings_verify_sbom_signatures_check CHECK (slow_ok()) NOT VALID;
            """);
        Assert.False(await ValidatedAsync(conn, name));

        var ex = await Record.ExceptionAsync(() => init.RetrofitColumnConstraintsAsync(conn, schema));

        Assert.Null(ex);
        Assert.False(await ValidatedAsync(conn, name));
        Assert.Contains(log.Warnings, m => m.Contains(name, StringComparison.Ordinal)
            && m.Contains("NOT VALID", StringComparison.Ordinal)
            && m.Contains("scan time limit", StringComparison.Ordinal));

        // The cancelled scan is counted in the pass's one summary without a second warning of its own.
        Assert.StartsWith("1 constraint", Assert.Single(Summaries(log)), StringComparison.Ordinal);

        // The session's timeouts were restored: the same connection runs a longer statement.
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT 1 FROM pg_sleep(0.6)"));
    }

    // A table with a canonical-timestamp CHECK and a plain column CHECK, and no additive-column
    // ALTERs, so a lock held across the whole boot is contended only by the constraint retrofits.
    private const string BootTable = "banners";

    private static async Task<(string Temporal, string Column)> DropOneOfEachAsync(
        System.Data.Common.DbConnection conn, string schema)
    {
        var (_, temporalColumn) = SchemaInitializer.DeclaredTemporalCheckColumns(schema).First(c => c.Table == BootTable);
        string temporal = BootTable + "_" + temporalColumn + "_check";
        string column = SchemaInitializer.DeclaredColumnConstraints(schema)
            .First(c => c.Table == BootTable && c.Kind == SchemaInitializer.ColumnConstraintKind.Check).Name;
        await conn.ExecuteAsync($"ALTER TABLE {BootTable} DROP CONSTRAINT {temporal}");
        await conn.ExecuteAsync($"ALTER TABLE {BootTable} DROP CONSTRAINT {column}");
        return (temporal, column);
    }

    [Fact]
    public async Task Boot_SpentBudget_DefersBothRetrofits_WithOneSummary()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        await using var conn = await pg.Store.OpenAsync();
        var (temporal, column) = await DropOneOfEachAsync(conn, schema);

        await new SchemaInitializer(pg.Store, log) { RetrofitPassBudget = TimeSpan.Zero }.InitializeAsync();

        Assert.StartsWith("2 constraint", Assert.Single(Summaries(log)), StringComparison.Ordinal);
        Assert.Null(await ValidatedAsync(conn, temporal));
        Assert.Null(await ValidatedAsync(conn, column));

        await new SchemaInitializer(pg.Store, log).InitializeAsync();
        Assert.True(await ValidatedAsync(conn, temporal));
        Assert.True(await ValidatedAsync(conn, column));
    }

    [Fact]
    public async Task Boot_LockedTable_CostsOneBudgetAcrossBothRetrofits_AndOneSummary()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        await using var conn = await pg.Store.OpenAsync();
        var (temporal, column) = await DropOneOfEachAsync(conn, schema);

        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };
        using (var blocker = new LockHolder(ConnectionString, $"SELECT 1 FROM {BootTable} LIMIT 1"))
        {
            await CompleteWithinAsync(init.InitializeAsync(), blocker, TimeSpan.FromSeconds(60));
        }

        // The temporal retrofit pays the one budget; the column retrofit skips the table outright.
        Assert.Equal(WarningsPerLockBudget, LockWarnings(log));
        Assert.StartsWith("2 constraint", Assert.Single(Summaries(log)), StringComparison.Ordinal);
        Assert.Null(await ValidatedAsync(conn, temporal));
        Assert.Null(await ValidatedAsync(conn, column));
    }
}
