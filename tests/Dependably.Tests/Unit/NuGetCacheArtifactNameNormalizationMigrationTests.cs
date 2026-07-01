using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression for the NuGet cache_artifact name-case mismatch. The backfill migration wrote
/// <c>p.name</c> (canonical display case, e.g. 'Newtonsoft.Json') into <c>cache_artifact.name</c>
/// instead of <c>p.purl_name</c> (the lowercased join key). The cross-plane join
/// <c>ca.name = p.purl_name</c> therefore never matched these rows, causing affected NuGet packages
/// to show a 0 version count in the dashboard. The <c>normalize_nuget_cache_artifact_names</c>
/// one-shot repairs existing databases by deleting colliding mixed-case duplicates and then
/// lowercasing the remainder.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetCacheArtifactNameNormalizationMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // Seed a fresh schema, then inject a mixed-case cache_artifact row to simulate the state
    // left by the backfill migration before the root-cause fix. Re-arm the target migration
    // by deleting it from the ledger so the next InitializeAsync will run it.
    private async Task SeedMixedCaseRowAsync(string orgId, string orgSlug,
        string packageName, string purlName, string caId,
        string version, string filename, bool addTenantAccess = true)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var setup = await _db.OpenAsync();

        await setup.ExecuteAsync(
            "INSERT OR IGNORE INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = orgSlug });
        await setup.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES (@id, @orgId, 'nuget', @name, @purlName, 1)",
            new { id = "pkg-" + orgId, orgId, name = packageName, purlName });
        await setup.ExecuteAsync(
            "INSERT OR IGNORE INTO cache_artifact " +
            "    (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES (@id, 'nuget', @name, @version, @filename, 'proxy/deadbeef', 'deadbeef')",
            new { id = caId, name = packageName, version, filename });

        if (addTenantAccess)
        {
            await setup.ExecuteAsync(
                "INSERT OR IGNORE INTO tenant_artifact_access (org_id, cache_artifact_id) " +
                "VALUES (@orgId, @caId)",
                new { orgId, caId });
        }

        // Re-arm the migration so the next InitializeAsync runs it.
        await setup.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = 'normalize_nuget_cache_artifact_names'");
    }

    [Fact]
    public async Task Migration_LowercasesName_AndJoinMatchesPackagePurlName()
    {
        const string orgId = "org-nuget-case";
        const string caId = "ca-newtonsoft";

        await SeedMixedCaseRowAsync(
            orgId, "nuget-case",
            packageName: "Newtonsoft.Json",
            purlName: "newtonsoft.json",
            caId: caId,
            version: "13.0.1",
            filename: "newtonsoft.json.13.0.1.nupkg");

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // The cache_artifact name must now be lowercased.
        string? name = await verify.ExecuteScalarAsync<string?>(
            "SELECT name FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Equal("newtonsoft.json", name);

        // The join ca.name = p.purl_name must now find at least one matching row.
        long count = await verify.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact ca
            JOIN packages p ON p.ecosystem = ca.ecosystem AND p.purl_name = ca.name
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
              AND taa.org_id = p.org_id
            WHERE ca.ecosystem = 'nuget' AND ca.version = '13.0.1' AND p.org_id = @orgId
            """,
            new { orgId });
        Assert.True(count >= 1);
    }

    [Fact]
    public async Task Migration_DeletesColliding_MixedCaseRow_WhenLowercaseTwinExists()
    {
        const string orgId = "org-nuget-collision";
        const string caIdMixed = "ca-mex-logging-mixed";
        const string caIdLower = "ca-mex-logging-lower";

        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                "INSERT OR IGNORE INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = orgId, slug = "nuget-collision" });

            // Seed the collision pair: both mixed-case and lowercase at the same coordinate.
            await setup.ExecuteAsync(
                "INSERT INTO cache_artifact " +
                "    (id, ecosystem, name, version, filename, blob_key, content_hash) " +
                "VALUES (@id, 'nuget', @name, '10.0.9', 'microsoft.extensions.logging.10.0.9.nupkg', " +
                "        'proxy/aabbcc', 'aabbcc')",
                new { id = caIdMixed, name = "Microsoft.Extensions.Logging" });
            await setup.ExecuteAsync(
                "INSERT INTO cache_artifact " +
                "    (id, ecosystem, name, version, filename, blob_key, content_hash) " +
                "VALUES (@id, 'nuget', @name, '10.0.9', 'microsoft.extensions.logging.10.0.9.nupkg', " +
                "        'proxy/aabbcc', 'aabbcc')",
                new { id = caIdLower, name = "microsoft.extensions.logging" });

            // tenant_artifact_access for the mixed-case row (should cascade-delete).
            await setup.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) " +
                "VALUES (@orgId, @caId)",
                new { orgId, caId = caIdMixed });

            // Re-arm the migration.
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'normalize_nuget_cache_artifact_names'");
        }

        // Must not throw a UNIQUE violation despite the collision.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // Exactly one row at the lowercased coordinate must survive.
        long rowCount = await verify.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'nuget' AND version = '10.0.9'
              AND filename = 'microsoft.extensions.logging.10.0.9.nupkg'
            """);
        Assert.Equal(1, rowCount);

        // The surviving row carries the lowercase name.
        string? survivingName = await verify.ExecuteScalarAsync<string?>(
            "SELECT name FROM cache_artifact WHERE id = @id", new { id = caIdLower });
        Assert.Equal("microsoft.extensions.logging", survivingName);

        // The mixed-case row and its tenant_artifact_access must be gone.
        long mixedCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id = caIdMixed });
        Assert.Equal(0, mixedCount);
        long taaCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @caId",
            new { caId = caIdMixed });
        Assert.Equal(0, taaCount);
    }
}
