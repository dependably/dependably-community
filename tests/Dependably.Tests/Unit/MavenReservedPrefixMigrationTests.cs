using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// One-shot data migration <c>migrate_maven_reserved_prefixes_to_table</c>: legacy
/// <c>org_settings.maven_reserved_prefixes</c> JSON entries become <c>reserved_namespace</c>
/// rows (ecosystem 'maven'); unparseable JSON is skipped without failing boot; re-running is
/// a no-op. Mirrors <see cref="BlockDeprecatedMigrationTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenReservedPrefixMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task LegacyJsonPrefixes_CopiedToReservedNamespaceRows()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-mig','mig')");
            await setup.ExecuteAsync(
                """INSERT INTO org_settings (org_id, maven_reserved_prefixes) VALUES ('o-mig', '["com.acme"," org.internal "]')""");
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-bad','bad')");
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, maven_reserved_prefixes) VALUES ('o-bad', 'not-json')");
            // Re-arm the one-shot so re-init runs it against the seeded rows.
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'migrate_maven_reserved_prefixes_to_table'");
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var patterns = (await verify.QueryAsync<string>(
            "SELECT pattern FROM reserved_namespace WHERE org_id = 'o-mig' AND ecosystem = 'maven' ORDER BY pattern"))
            .ToList();
        Assert.Equal(["com.acme", "org.internal"], patterns); // entries trimmed
        long badRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM reserved_namespace WHERE org_id = 'o-bad'");
        Assert.Equal(0, badRows); // unparseable JSON skipped, boot not failed

        // Idempotence: re-arming and re-running must not duplicate rows (ON CONFLICT DO NOTHING).
        await using (var rearm = await _db.OpenAsync())
        {
            await rearm.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'migrate_maven_reserved_prefixes_to_table'");
        }
        await new SchemaInitializer(_db).InitializeAsync();
        await using var verify2 = await _db.OpenAsync();
        long count = await verify2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM reserved_namespace WHERE org_id = 'o-mig'");
        Assert.Equal(2, count);
    }
}
