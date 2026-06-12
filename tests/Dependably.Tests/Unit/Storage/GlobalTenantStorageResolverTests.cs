using Dapper;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Community-edition resolver behaviour. Asserts the bridge model's pool invariant
/// (same singleton for any tenant) and the defensive gate checks on
/// <c>orgs.status</c> + <c>tenant_provisioning_jobs.state</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class GlobalTenantStorageResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _cache = new();
    private readonly InMemoryBlobStore _registry = new();
    private GlobalTenantStorageResolver _sut = null!;
    private TieredBlobStorage _tiered = null!;

    public async Task InitializeAsync()
    {
        await new Dependably.Infrastructure.SchemaInitializer(_db).InitializeAsync();
        _tiered = new TieredBlobStorage(_cache, _registry);
        _sut = new GlobalTenantStorageResolver(_db, _tiered);

        await using var conn = await _db.OpenAsync();
        // Standard "ready" tenant — every test that needs an active tenant uses this id.
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('t-active', 'active-tenant')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Pool invariant ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetRegistryAsync_DifferentTenantIds_ReturnSameSingleton()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('t-other', 'other-tenant')");

        var a = await _sut.GetRegistryAsync("t-active");
        var b = await _sut.GetRegistryAsync("t-other");

        // Bridge model in community: one shared registry bucket, no per-tenant routing.
        // Enterprise's resolver would return different instances here.
        Assert.Same(a, b);
        Assert.Same(_registry, a);
    }

    [Fact]
    public void Cache_ReturnsSingletonWithoutTenantContext()
    {
        // Cache is shared across all tenants by design (proxy/{sha256} is content-addressed).
        // No tenantId parameter — direct property access matches the pool-cache invariant.
        Assert.Same(_cache, _sut.Cache);
    }

    // ── Status gate ───────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task GetRegistryAsync_StatusNotActive_ThrowsTenantNotReady(string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE orgs SET status = @status WHERE id = 't-active'",
            new { status });

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(
            () => _sut.GetRegistryAsync("t-active"));
        Assert.Equal("t-active", ex.TenantId);
        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);
        // Detail keeps the specific status value for operators / log lines.
        Assert.Contains(status, ex.Detail);
    }

    [Fact]
    public async Task GetRegistryAsync_OrgRowMissing_ThrowsTenantNotReady()
    {
        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(
            () => _sut.GetRegistryAsync("t-does-not-exist"));
        Assert.Equal("t-does-not-exist", ex.TenantId);
        Assert.Equal(TenantNotReadyReason.NotFound, ex.Reason);
        Assert.Contains("not found", ex.Detail);
    }

    // ── Provisioning-state gate ───────────────────────────────────────────────────

    [Fact]
    public async Task GetRegistryAsync_ProvisioningRowAbsent_CountsAsReady()
    {
        // Community has no async provisioning; the table is empty in the happy path.
        // Absent row must NOT raise — that would block every community write.
        var store = await _sut.GetRegistryAsync("t-active");
        Assert.Same(_registry, store);
    }

    [Fact]
    public async Task GetRegistryAsync_ProvisioningStateReady_Succeeds()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO tenant_provisioning_jobs (id, org_id, kind, state) " +
            "VALUES ('j1', 't-active', 'registry_bucket_create', 'ready')");

        var store = await _sut.GetRegistryAsync("t-active");
        Assert.Same(_registry, store);
    }

    [Theory]
    [InlineData("creating", TenantNotReadyReason.ProvisioningPending)]
    [InlineData("failed", TenantNotReadyReason.ProvisioningFailed)]
    public async Task GetRegistryAsync_ProvisioningStateNotReady_ThrowsTenantNotReady(
        string state, TenantNotReadyReason expectedReason)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO tenant_provisioning_jobs (id, org_id, kind, state) " +
            "VALUES ('j1', 't-active', 'registry_bucket_create', @state)",
            new { state });

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(
            () => _sut.GetRegistryAsync("t-active"));
        Assert.Equal("t-active", ex.TenantId);
        Assert.Equal(expectedReason, ex.Reason);
        Assert.Contains(state, ex.Detail);
    }

    [Fact]
    public async Task GetRegistryAsync_ProvisioningRow_OtherKind_DoesNotGate()
    {
        // The gate is per-kind. A 'creating' row for a different provisioning kind (e.g.
        // a future kms_key_provision) must not block registry writes.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO tenant_provisioning_jobs (id, org_id, kind, state) " +
            "VALUES ('j1', 't-active', 'kms_key_provision', 'creating')");

        var store = await _sut.GetRegistryAsync("t-active");
        Assert.Same(_registry, store);
    }

    // ── Cross-tenant data-path invariant (community pool) ─────────────────────────

    [Fact]
    public async Task CrossTenant_InPoolMode_StoresAreShared_KeyIsolationIsApiLayerResponsibility()
    {
        // In community pool mode the resolver returns the same singleton for every tenant,
        // so cross-tenant data isolation rests on key construction in the API layer (the
        // controller uses CurrentTenantId() when calling BlobKeys.Hosted). This test pins
        // the invariant: if a caller bypasses the API layer and writes orgB's hosted key
        // through the resolver, the bytes ARE retrievable from orgA's resolver — exactly
        // because they share the same backing store.
        //
        // Enterprise silo mode flips this: separate buckets per tenant make this scenario
        // return 404 from orgA's resolver. That assertion lives in the enterprise tree.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('t-other', 'other-tenant')");

        var aStore = await _sut.GetRegistryAsync("t-active");
        var bStore = await _sut.GetRegistryAsync("t-other");

        string keyOfB = BlobKeys.Hosted("t-other", "npm", "x", "1.0", "x-1.0.tgz");
        await bStore.PutAsync(keyOfB, new MemoryStream([1, 2, 3]));

        // Documents the community pool behaviour: orgA's store CAN read orgB's key
        // because there is only one bucket. The API layer prevents the cross-tenant
        // request from ever being constructed (CurrentTenantId() flows into the key).
        Assert.True(await aStore.ExistsAsync(keyOfB));
    }
}
