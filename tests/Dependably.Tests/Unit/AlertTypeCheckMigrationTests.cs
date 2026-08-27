using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// Widening <c>alert.type</c>'s closed CHECK for <c>sbom_policy_violation</c>. Fresh installs pick
/// the wider set up from the <c>CREATE TABLE</c> block; a database created before it needs the
/// stored constraint rewritten, or the first SBOM policy alert an upgraded instance raises fails
/// its INSERT. Mirrors <see cref="BlockDeprecatedMigrationTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertTypeCheckMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task LegacySchemaWithNarrowCheck_IsWidenedInPlace_AndStillRefusesUnknownTypes()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
            await setup.ExecuteAsync("DROP TABLE IF EXISTS alert");
            // Stand-in carrying the exact narrow CHECK text the SQLite rewrite targets; the
            // additive ALTERs re-add the remaining columns on re-init.
            await setup.ExecuteAsync(
                "CREATE TABLE alert (\n" +
                "    id           TEXT PRIMARY KEY,\n" +
                "    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,\n" +
                "    type         TEXT NOT NULL CHECK (type IN ('quarantine_new', 'vuln_severity')),\n" +
                "    source_ref   TEXT NOT NULL,\n" +
                "    title        TEXT NOT NULL,\n" +
                "    state        TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'dismissed'))\n" +
                ")");
            await setup.ExecuteAsync(
                "INSERT INTO alert (id, org_id, type, source_ref, title) " +
                "VALUES ('a-old', 'o1', 'vuln_severity', 'pkg:npm/left-pad', 'Existing alert')");
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_alert_type_check_sbom_policy'");

            // Sanity: without the widen, the new type is refused — so this test would fail on a
            // build that ships the schema change without the migration.
            var ex = await Assert.ThrowsAsync<SqliteException>(() => setup.ExecuteAsync(
                "INSERT INTO alert (id, org_id, type, source_ref, title) " +
                "VALUES ('a-x', 'o1', 'sbom_policy_violation', 'x', 'Nope')"));
            Assert.Contains("CHECK", ex.Message);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        await verify.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title) " +
            "VALUES ('a-new', 'o1', 'sbom_policy_violation', 'pkg:npm/left-pad', 'Policy violation')");
        Assert.Equal(1, await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM alert WHERE type = 'sbom_policy_violation'"));

        // The reshape changes the accepted set, never the rows: the pre-existing alert survives.
        Assert.Equal(1, await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM alert WHERE id = 'a-old'"));

        // Widening is not the same as removing: an unregistered type is still refused.
        await Assert.ThrowsAsync<SqliteException>(() => verify.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title) " +
            "VALUES ('a-bad', 'o1', 'made_up_type', 'x', 'Nope')"));
    }

    /// <summary>
    /// The one-shot is idempotent, so a second boot after a crash that lost the ledger entry
    /// repeats it harmlessly rather than corrupting the stored CREATE text.
    /// </summary>
    [Fact]
    public async Task ReRunningTheWiden_IsANoOp()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var reset = await _db.OpenAsync())
        {
            await reset.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_alert_type_check_sbom_policy'");
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await verify.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title) " +
            "VALUES ('a1', 'o1', 'sbom_policy_violation', 'x', 'Policy violation')");
        await Assert.ThrowsAsync<SqliteException>(() => verify.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title) " +
            "VALUES ('a2', 'o1', 'made_up_type', 'x', 'Nope')"));
        Assert.Equal("ok", await verify.ExecuteScalarAsync<string>("PRAGMA integrity_check"));
    }
}
