using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// One-shot backfill <c>seed_terraform_upstream_registries</c>. Terraform joined the default
/// upstream sources after the earlier backfills had already run, so an org created before it
/// carries no <c>terraform</c> row. That is not a lost fallback: <c>TerraformController</c>
/// resolves a requested provider's registry hostname against the org's configured upstreams and
/// mirrors nothing when the list is empty, so the whole ecosystem is dark until the row exists.
///
/// The scoping half matters as much as the seeding half — the backfill must not resurrect an
/// upstream the operator deliberately deleted for some *other* ecosystem, which is why it selects
/// terraform alone rather than re-running the full default set.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerraformUpstreamBackfillMigrationTests : IAsyncLifetime
{
    private const string Marker = "seed_terraform_upstream_registries";

    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task OrgWithoutTerraformRow_GetsTheDefaultRegistrySeeded()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await SeedPreTerraformOrgAsync("o-old", "old");

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var urls = (await verify.QueryAsync<string>(
            "SELECT url FROM upstream_registry WHERE org_id = 'o-old' AND ecosystem = 'terraform'"))
            .ToList();
        Assert.Equal(["https://registry.terraform.io"], urls);
    }

    [Fact]
    public async Task OrgWithAConfiguredTerraformRow_IsLeftAlone()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await SeedPreTerraformOrgAsync("o-custom", "custom");
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                VALUES ('u-custom', 'o-custom', 'terraform', 'https://tf.internal.example', 0)
                """);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var urls = (await verify.QueryAsync<string>(
            "SELECT url FROM upstream_registry WHERE org_id = 'o-custom' AND ecosystem = 'terraform'"))
            .ToList();
        // The public default must not be appended alongside a deliberate private mirror: the
        // per-(org, ecosystem) existence check is what keeps the operator's list authoritative.
        Assert.Equal(["https://tf.internal.example"], urls);
    }

    [Fact]
    public async Task DeletedUpstreamForAnotherEcosystem_IsNotResurrected()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await SeedPreTerraformOrgAsync("o-scoped", "scoped");
        await using (var setup = await _db.OpenAsync())
        {
            // An operator who removed npm to disable npm proxying. A backfill that re-ran the full
            // default set would silently re-enable it.
            await setup.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                VALUES ('u-cargo', 'o-scoped', 'cargo', 'https://index.crates.io', 0)
                """);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long npmRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = 'o-scoped' AND ecosystem = 'npm'");
        Assert.Equal(0, npmRows);
        long terraformRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = 'o-scoped' AND ecosystem = 'terraform'");
        Assert.Equal(1, terraformRows);
    }

    [Fact]
    public async Task ReRunningTheBackfill_DoesNotDuplicateTheRow()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await SeedPreTerraformOrgAsync("o-idem", "idem");
        await new SchemaInitializer(_db).InitializeAsync();

        await using (var rearm = await _db.OpenAsync())
        {
            await rearm.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @Marker", new { Marker });
        }
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long rows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'terraform'",
            new { orgId = "o-idem" });
        Assert.Equal(1, rows);
    }

    /// <summary>
    /// An org as it exists on an instance that upgraded past the earlier backfills: inserted
    /// directly rather than through <see cref="OrgRepository"/>, so <see cref="UpstreamRegistrySeeder"/>
    /// never ran for it. Re-arms the one-shot, which on a fresh database already ran against zero
    /// orgs and recorded itself.
    /// </summary>
    private async Task SeedPreTerraformOrgAsync(string orgId, string slug)
    {
        await using var setup = await _db.OpenAsync();
        await setup.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@orgId, @slug)", new { orgId, slug });
        await setup.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @Marker", new { Marker });
    }
}
