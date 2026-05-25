using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class SchemaAdditionsTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Theory]
    [InlineData("claim")]
    [InlineData("claim_history")]
    [InlineData("cache_artifact")]
    [InlineData("tenant_artifact_access")]
    [InlineData("metadata_cache")]
    [InlineData("audit_event")]
    [InlineData("tenant_storage")]
    [InlineData("tenant_provisioning_jobs")]
    public async Task MultitenantTables_Exist(string table)
    {
        await using var conn = await _db.OpenAsync();
        var name = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=@table",
            new { table });
        Assert.Equal(table, name);
    }

    [Fact]
    public async Task PackageVersions_HasOriginColumn_DefaultsToProxy()
    {
        await using var conn = await _db.OpenAsync();
        // Insert prerequisite rows
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('p1','o1','npm','x','x')");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key) VALUES ('v1','p1','1.0.0','pkg:npm/x@1.0.0','blob1')");

        var origin = await conn.QuerySingleAsync<string>(
            "SELECT origin FROM package_versions WHERE id = 'v1'");
        Assert.Equal("proxy", origin);
    }

    [Fact]
    public async Task Claim_StateCheckConstraint_RejectsUnknownState()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO claim (id, org_id, ecosystem, name, state, reason) " +
            "VALUES ('c1','o1','npm','x','bogus','test')"));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CacheArtifact_UniqueOnCoordinate()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('c1','npm','lodash','4.17.21','lodash-4.17.21.tgz','k','h')");
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('c2','npm','lodash','4.17.21','lodash-4.17.21.tgz','k2','h2')"));
        Assert.Contains("UNIQUE", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AuditEvent_OutcomeCheckConstraint()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO audit_event (event_id, event_type, org_id, tenant_resolver, actor_type, outcome, payload) " +
            "VALUES ('e1','test','o1','single','user','maybe','{}')"));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunOnce_FirstRun_InsertsRowInAppliedMigrations()
    {
        // _db is already initialized once by IAsyncLifetime.InitializeAsync
        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM _applied_migrations");
        Assert.True(count > 0);
    }

    [Fact]
    public async Task RunOnce_AlreadyApplied_SkipsOnSecondRun_IdempotentRowCount()
    {
        await using var db = new TestMetadataStore();
        var initializer = new SchemaInitializer(db);

        await initializer.InitializeAsync();
        await using var conn1 = await db.OpenAsync();
        var countAfterFirst = await conn1.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM _applied_migrations");

        await initializer.InitializeAsync();
        await using var conn2 = await db.OpenAsync();
        var countAfterSecond = await conn2.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM _applied_migrations");

        Assert.Equal(countAfterFirst, countAfterSecond);
    }

    [Fact]
    public async Task AdditiveMigrations_InitializeTwice_DoesNotThrow()
    {
        await using var db = new TestMetadataStore();
        var initializer = new SchemaInitializer(db);

        await initializer.InitializeAsync();
        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);
    }

    [Fact]
    public async Task Orgs_HasStatusColumn_DefaultsToActive()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-status', 'status-default')");
        var status = await conn.QuerySingleAsync<string>(
            "SELECT status FROM orgs WHERE id = 'o-status'");
        Assert.Equal("active", status);
    }

    [Fact]
    public async Task Orgs_StatusCheckConstraint_RejectsUnknownState()
    {
        await using var conn = await _db.OpenAsync();
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES ('o-bad', 'status-bad', 'bogus')"));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task Orgs_StatusCheckConstraint_AcceptsKnownStates(string state)
    {
        await using var conn = await _db.OpenAsync();
        var id = $"o-{state}";
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@id, @slug, @state)",
            new { id, slug = $"slug-{state}", state });
        var stored = await conn.QuerySingleAsync<string>(
            "SELECT status FROM orgs WHERE id = @id", new { id });
        Assert.Equal(state, stored);
    }

    [Fact]
    public async Task Orgs_FeaturesColumn_DefaultsToEmptyJsonObject()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-feat', 'features-default')");
        var features = await conn.QuerySingleAsync<string>(
            "SELECT features FROM orgs WHERE id = 'o-feat'");
        Assert.Equal("{}", features);
    }

    [Fact]
    public async Task Orgs_RegionColumn_DefaultsToNull()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-region', 'region-default')");
        var region = await conn.QuerySingleAsync<string?>(
            "SELECT region FROM orgs WHERE id = 'o-region'");
        Assert.Null(region);
    }

    [Fact]
    public async Task TenantProvisioningJobs_StateCheckConstraint_RejectsUnknown()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-prov', 'prov')");
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO tenant_provisioning_jobs (id, org_id, kind, state) " +
            "VALUES ('j1','o-prov','registry_bucket_create','bogus')"));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TenantProvisioningJobs_UniqueOnOrgKind_BlocksDuplicateInsert()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-prov2', 'prov2')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_provisioning_jobs (id, org_id, kind) " +
            "VALUES ('j1','o-prov2','registry_bucket_create')");
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO tenant_provisioning_jobs (id, org_id, kind) " +
            "VALUES ('j2','o-prov2','registry_bucket_create')"));
        Assert.Contains("UNIQUE", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TenantStorage_NullableFields_AcceptEmptyRegistryConfig()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-store', 'store')");
        await conn.ExecuteAsync("INSERT INTO tenant_storage (org_id) VALUES ('o-store')");
        var row = await conn.QuerySingleAsync<(string? bucket, string? region, string? endpoint, int forcePathStyle)>(
            "SELECT registry_bucket, registry_region, registry_endpoint, registry_force_path_style " +
            "FROM tenant_storage WHERE org_id = 'o-store'");
        Assert.Null(row.bucket);
        Assert.Null(row.region);
        Assert.Null(row.endpoint);
        Assert.Equal(0, row.forcePathStyle);
    }

    [Fact]
    public async Task Orgs_HasParentTenantIdColumn_Nullable_NoForeignKey_WithIndex()
    {
        await using var conn = await _db.OpenAsync();

        var column = await conn.QuerySingleOrDefaultAsync<(string name, int notnull)>(
            "SELECT name, \"notnull\" FROM pragma_table_info('orgs') WHERE name = 'parent_tenant_id'");
        Assert.Equal("parent_tenant_id", column.name);
        Assert.Equal(0, column.notnull);

        var fkCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('orgs') WHERE \"from\" = 'parent_tenant_id'");
        Assert.Equal(0, fkCount);

        var indexName = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_orgs_parent_tenant_id'");
        Assert.Equal("idx_orgs_parent_tenant_id", indexName);

        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-null', 'parent-null')");
        var stored = await conn.QuerySingleAsync<string?>(
            "SELECT parent_tenant_id FROM orgs WHERE id = 'o-null'");
        Assert.Null(stored);
    }
}
