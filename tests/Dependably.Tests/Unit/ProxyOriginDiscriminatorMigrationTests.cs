using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression for the proxy-purge discriminator bug. When the <c>origin</c> column was added with
/// <c>DEFAULT 'proxy'</c>, pre-existing hosted artifacts received that default even though their
/// <c>blob_key</c> starts with <c>hosted/</c> not <c>proxy/</c>. The
/// <c>migrate_proxy_versions_to_cache_plane</c> and <c>delete_migrated_proxy_package_versions</c>
/// migrations then treated those rows as proxy artifacts and hard-deleted them.
///
/// The fix uses a hosted-prefix EXCLUSION (NOT LIKE 'hosted/%') rather than a proxy-prefix allowlist.
/// Proxy rows can carry any of the prefixes proxy/, cargo/, or go/ — excluding only the hosted/
/// prefix ensures all genuine proxy rows are migrated regardless of ecosystem.
/// <list type="bullet">
///   <item><c>backfill_hosted_origin_by_blob_key</c> reclassifies only <c>blob_key LIKE 'hosted/%'</c>
///   rows to <c>'uploaded'</c> before the cache-plane migrate runs.</item>
///   <item>The migrate SELECT and purge DELETE use <c>AND blob_key NOT LIKE 'hosted/%'</c>
///   so that cargo/ and go/ proxy rows are included alongside proxy/ rows.</item>
/// </list>
/// </summary>
[Trait("Category", "Schema")]
public sealed class ProxyOriginDiscriminatorMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // Seed the DB to the state just before the three proxy-migration one-shots run:
    //   - Full schema applied (so all tables exist).
    //   - backfill_hosted_origin_by_blob_key removed from the ledger (will run).
    //   - migrate_proxy_versions_to_cache_plane removed from the ledger (will run).
    //   - delete_migrated_proxy_package_versions removed from the ledger (will run).
    //   - A legacy HOSTED row with origin='proxy' (mis-defaulted) and blob_key='hosted/…'.
    //   - A genuine npm PROXY row with origin='proxy' and blob_key='proxy/{sha}/{file}'.
    //   - A genuine Cargo PROXY row with origin='proxy' and blob_key='cargo/{org}/{name}/{ver}.crate'.
    //   - A genuine Go PROXY row with origin='proxy' and blob_key='go/{org}/{module}/{ver}/{ext}'.
    private async Task<(string HostedVersionId, string ProxyVersionId, string CargoVersionId, string GoVersionId)> SeedAsync()
    {
        // Full init so all tables, additive columns, and earlier one-shots are applied.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Re-arm the three one-shots that this test exercises.
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('backfill_hosted_origin_by_blob_key'," +
            " 'migrate_proxy_versions_to_cache_plane'," +
            " 'delete_migrated_proxy_package_versions')");

        // Org for all packages.
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-disc','disc')");

        // Hosted package — user published before the origin column existed; the ALTER TABLE
        // DEFAULT='proxy' backfilled origin='proxy' even though this is a real hosted artifact.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-hosted','o-disc','npm','my-pkg','my-pkg',0)");
        string hostedId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-hosted','1.0.0','pkg:npm/my-pkg@1.0.0','hosted/o-disc/npm/my-pkg/1.0.0/my-pkg-1.0.0.tgz','my-pkg-1.0.0.tgz',1024,'proxy')",
            new { id = hostedId });

        // npm Proxy package — genuine upstream-cached artifact with a 'proxy/{sha}/{file}' blob_key.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-proxy','o-disc','npm','left-pad','left-pad',1)");
        string proxyId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-proxy','1.0.0','pkg:npm/left-pad@1.0.0','proxy/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890/left-pad-1.0.0.tgz','left-pad-1.0.0.tgz',512,'proxy')",
            new { id = proxyId });

        // Cargo proxy package — genuine upstream-cached crate with a 'cargo/{org}/{name}/{ver}.crate' blob_key.
        // Cargo proxy rows were written before the cache-plane dual-write backfill landed, so they
        // carry origin='proxy' with a cargo/ prefix and no pre-existing cache_artifact row.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-cargo','o-disc','cargo','serde','serde',1)");
        string cargoId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-cargo','1.0.0','pkg:cargo/serde@1.0.0','cargo/o-disc/serde/1.0.0.crate','serde-1.0.0.crate',8192,'proxy')",
            new { id = cargoId });

        // Go proxy package — genuine upstream-cached module with a 'go/{org}/{module}/{ver}/{ext}' blob_key.
        // Same scenario as Cargo: written before the cache-plane dual-write backfill landed.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-go','o-disc','go','github.com/user/pkg','github.com/user/pkg',1)");
        string goId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-go','v1.2.3','pkg:golang/github.com/user/pkg@v1.2.3','go/o-disc/github.com/user/pkg/v1.2.3/zip','pkg-v1.2.3.zip',4096,'proxy')",
            new { id = goId });

        return (hostedId, proxyId, cargoId, goId);
    }

    // A mis-defaulted hosted row (origin='proxy', blob_key='hosted/…') must survive both the
    // backfill reclassification and the purge step. After re-init:
    //   - The row must still exist in package_versions.
    //   - Its origin must be 'uploaded' (backfill reclassified it).
    //   - It must NOT appear in cache_artifact (was never a proxy artifact).
    [Fact]
    public async Task HostedRow_MisDefaultedToProxy_SurvivesMigrateAndPurge()
    {
        var (hostedId, _, _, _) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Row must still be in package_versions.
        string? origin = await conn.ExecuteScalarAsync<string?>(
            "SELECT origin FROM package_versions WHERE id = @id", new { id = hostedId });
        Assert.NotNull(origin);
        Assert.Equal("uploaded", origin); // reclassified by backfill

        // Row must NOT have been migrated to the global cache plane.
        long cacheRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'my-pkg' AND version = '1.0.0'");
        Assert.Equal(0, cacheRows);

        // Tenant access must NOT exist for this artifact on the cache plane.
        long accessRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ca.ecosystem = 'npm' AND ca.name = 'my-pkg'");
        Assert.Equal(0, accessRows);
    }

    // A genuine npm proxy row (origin='proxy', blob_key='proxy/{sha}/{file}') must be migrated to
    // cache_artifact and then removed from package_versions by the purge step.
    [Fact]
    public async Task ProxyRow_IsMigratedToCachePlane_AndRemovedFromPackageVersions()
    {
        var (_, proxyId, _, _) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Row must have been deleted from package_versions by the purge.
        string? stillExists = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = proxyId });
        Assert.Null(stillExists);

        // Row must have been migrated onto the global cache plane.
        long cacheRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'left-pad' AND version = '1.0.0'");
        Assert.Equal(1, cacheRows);

        // Tenant access must exist for the org on the cache plane.
        long accessRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ta.org_id = 'o-disc' AND ca.name = 'left-pad'");
        Assert.Equal(1, accessRows);
    }

    // A genuine Cargo proxy row (origin='proxy', blob_key='cargo/{org}/{name}/{ver}.crate') must be
    // migrated to cache_artifact and removed from package_versions. The narrow 'proxy/%' allowlist
    // on the previous branch would have reclassified this row as 'uploaded' in the backfill and
    // then excluded it from the migrate — stranding the crate on the wrong serve path.
    [Fact]
    public async Task CargoProxyRow_IsMigratedToCachePlane_AndRemovedFromPackageVersions()
    {
        var (_, _, cargoId, _) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Row must have been deleted from package_versions by the purge.
        string? stillExists = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = cargoId });
        Assert.Null(stillExists);

        // Row must have been migrated onto the global cache plane.
        long cacheRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'cargo' AND name = 'serde' AND version = '1.0.0'");
        Assert.Equal(1, cacheRows);

        // Tenant access must exist for the org on the cache plane.
        long accessRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ta.org_id = 'o-disc' AND ca.name = 'serde'");
        Assert.Equal(1, accessRows);
    }

    // A genuine Go proxy row (origin='proxy', blob_key='go/{org}/{module}/{ver}/{ext}') must be
    // migrated to cache_artifact and removed from package_versions. The narrow 'proxy/%' allowlist
    // on the previous branch would have reclassified this row as 'uploaded' in the backfill and
    // then excluded it from the migrate — stranding the module zip on the wrong serve path.
    [Fact]
    public async Task GoProxyRow_IsMigratedToCachePlane_AndRemovedFromPackageVersions()
    {
        var (_, _, _, goId) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Row must have been deleted from package_versions by the purge.
        string? stillExists = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = goId });
        Assert.Null(stillExists);

        // Row must have been migrated onto the global cache plane.
        long cacheRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'go' AND name = 'github.com/user/pkg' AND version = 'v1.2.3'");
        Assert.Equal(1, cacheRows);

        // Tenant access must exist for the org on the cache plane.
        long accessRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ta.org_id = 'o-disc' AND ca.name = 'github.com/user/pkg'");
        Assert.Equal(1, accessRows);
    }

    // Mixed scenario: one hosted row (mis-defaulted) and one proxy row co-exist. After re-init
    // the hosted row survives and the proxy row is migrated+purged — partial success within
    // the same migration pass.
    [Fact]
    public async Task MixedScenario_HostedRowSurvives_ProxyRowMigrated_InSamePass()
    {
        var (hostedId, proxyId, _, _) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Hosted row: still present, reclassified.
        string? hostedOrigin = await conn.ExecuteScalarAsync<string?>(
            "SELECT origin FROM package_versions WHERE id = @id", new { id = hostedId });
        Assert.Equal("uploaded", hostedOrigin);

        // npm Proxy row: purged from package_versions.
        string? proxyStillExists = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = proxyId });
        Assert.Null(proxyStillExists);

        // Cache plane has exactly the proxy artifact, not the hosted one.
        long totalCacheRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm'");
        Assert.Equal(1, totalCacheRows);

        string? cachedName = await conn.ExecuteScalarAsync<string?>(
            "SELECT name FROM cache_artifact WHERE ecosystem = 'npm'");
        Assert.Equal("left-pad", cachedName);
    }

    // Complement invariant: after re-init every row that entered with origin='proxy' must end up
    // either migrated+deleted (genuine proxy: proxy/, cargo/, go/ prefixes) or surviving as
    // origin='uploaded' (mis-defaulted hosted: hosted/ prefix). No row may be stranded as
    // origin='proxy' in package_versions.
    [Fact]
    public async Task ComplementInvariant_NoRowStrandedAsOriginProxy()
    {
        await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // After all three one-shots run, no row in package_versions should still carry origin='proxy'.
        long proxyRowsRemaining = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE origin = 'proxy'");
        Assert.Equal(0, proxyRowsRemaining);
    }

    // Two tenants each have a proxy package_versions row for the same upstream artifact
    // (same ecosystem/name/version/filename coordinate, same blob_key). The first tenant's row
    // carries no published_at or provenance facts; the second tenant's row carries both.
    //
    // The migration loops over rows sequentially on a single connection. The second tenant's row
    // finds the cache_artifact row already present from the first pass (initial SELECT returns
    // non-null caId), so it takes the else-branch and reaches the unconditional COALESCE-merge
    // UPDATE directly. This test verifies that the UPDATE fills null global facts from the
    // incoming row (existing-wins: COALESCE keeps existing non-null values and fills only nulls)
    // and that both tenants receive tenant_artifact_access rows pointing at the single
    // cache_artifact. It is a regression guard against removing or reversing the COALESCE
    // direction on the unconditional UPDATE in the else-branch.
    [Fact]
    public async Task ElsePath_GlobalFacts_AreMergedFromSecondTenantRow()
    {
        // Full init so all tables and earlier one-shots are applied.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Re-arm migrate and delete one-shots.
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('migrate_proxy_versions_to_cache_plane'," +
            " 'delete_migrated_proxy_package_versions')");

        // Two separate tenants, each with their own packages row for the same upstream artifact.
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-merge1','merge1')");
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-merge2','merge2')");

        // Tenant 1 packages row — no published_at, no provenance facts.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-merge1','o-merge1','npm','semver','semver',1)");
        string firstId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions " +
            "(id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-merge1','7.0.0','pkg:npm/semver@7.0.0'," +
            "'proxy/aabbccdd1122334455667788990011223344556677889900aabbccddeeff0011/semver-7.0.0.tgz'," +
            "'semver-7.0.0.tgz',2048,'proxy')",
            new { id = firstId });

        // Tenant 2 packages row — same upstream artifact, carries published_at + provenance facts.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-merge2','o-merge2','npm','semver','semver',1)");
        string secondId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions " +
            "(id, package_id, version, purl, blob_key, filename, size_bytes, origin," +
            " published_at, provenance_status, provenance_signer) " +
            "VALUES (@id,'pkg-merge2','7.0.0','pkg:npm/semver@7.0.0'," +
            "'proxy/aabbccdd1122334455667788990011223344556677889900aabbccddeeff0011/semver-7.0.0.tgz'," +
            "'semver-7.0.0.tgz',2048,'proxy'," +
            "'2024-01-15T00:00:00Z','verified','npm-provenance')",
            new { id = secondId });

        // Run the migrate and purge one-shots.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // Exactly one cache_artifact row for this coordinate (global dedup).
        long caCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'semver' AND version = '7.0.0'");
        Assert.Equal(1, caCount);

        // The COALESCE-merge must have applied the second tenant's facts onto the cache_artifact.
        // Both provenance and published_at must be non-null — if the pre-existing path skipped the
        // merge, these would still be null.
        string? publishedAt = await verify.ExecuteScalarAsync<string?>(
            "SELECT published_at FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'semver' AND version = '7.0.0'");
        Assert.Equal("2024-01-15T00:00:00Z", publishedAt);

        string? provenanceStatus = await verify.ExecuteScalarAsync<string?>(
            "SELECT provenance_status FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'semver' AND version = '7.0.0'");
        Assert.Equal("verified", provenanceStatus);

        string? provenanceSigner = await verify.ExecuteScalarAsync<string?>(
            "SELECT provenance_signer FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'semver' AND version = '7.0.0'");
        Assert.Equal("npm-provenance", provenanceSigner);

        // Both tenants must have tenant_artifact_access rows pointing at the single cache_artifact.
        long accessCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ca.ecosystem = 'npm' AND ca.name = 'semver' AND ca.version = '7.0.0'");
        Assert.Equal(2, accessCount);
    }
}
