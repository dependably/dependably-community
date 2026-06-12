using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for the system-admin storage-quota knob — the same surface the
/// SystemTenants.svelte UI calls. Unit tests cover the controller-method contract; this
/// fixture runs through the full HTTP pipeline (auth, route scoping, JSON serialization,
/// list-endpoint projection) so a regression in any of those layers shows up here.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemTenantQuotaTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemTenantQuotaTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(HttpClient client, string slug)> CreateTenantAsync()
    {
        string slug = "q-" + Guid.NewGuid().ToString("N")[..8];
        var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}-owner@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return (client, slug);
    }

    [Fact]
    public async Task SetQuota_PositiveBytes_PersistsAndShowsUpInList()
    {
        var (client, slug) = await CreateTenantAsync();
        try
        {
            var resp = await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/storage-quota",
                new { quotaBytes = 5_368_709_120L });  // 5 GiB

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            // List endpoint must surface the new value so the UI table can render it.
            var listResp = await client.GetAsync("/api/v1/system/tenants?limit=200");
            var doc = JsonDocument.Parse(await listResp.Content.ReadAsStringAsync());
            var match = doc.RootElement.GetProperty("items").EnumerateArray()
                .FirstOrDefault(i => i.GetProperty("slug").GetString() == slug);
            Assert.True(match.ValueKind != JsonValueKind.Undefined, "Tenant must be in list.");
            Assert.Equal(5_368_709_120L, match.GetProperty("storageQuotaBytes").GetInt64());
        }
        finally { client.Dispose(); }
    }

    [Fact]
    public async Task SetQuota_Null_ClearsTheCap_AndListShowsNull()
    {
        var (client, slug) = await CreateTenantAsync();
        try
        {
            // First set a cap, then clear it.
            await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/storage-quota", new { quotaBytes = 1_000L });

            var clear = await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/storage-quota", new { quotaBytes = (long?)null });
            Assert.Equal(HttpStatusCode.OK, clear.StatusCode);

            var listResp = await client.GetAsync("/api/v1/system/tenants?limit=200");
            var doc = JsonDocument.Parse(await listResp.Content.ReadAsStringAsync());
            var match = doc.RootElement.GetProperty("items").EnumerateArray()
                .First(i => i.GetProperty("slug").GetString() == slug);
            Assert.Equal(JsonValueKind.Null, match.GetProperty("storageQuotaBytes").ValueKind);
        }
        finally { client.Dispose(); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task SetQuota_ZeroOrNegative_Returns422(long bytes)
    {
        var (client, slug) = await CreateTenantAsync();
        try
        {
            var resp = await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/storage-quota", new { quotaBytes = bytes });
            Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        }
        finally { client.Dispose(); }
    }

    [Fact]
    public async Task SetQuota_UnknownSlug_Returns404()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PatchAsJsonAsync(
            "/api/v1/system/tenants/ghost-quota/storage-quota", new { quotaBytes = 1_000L });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SetQuota_TenantJwt_AtSystemRoute_Returns404()
    {
        // Cross-realm rejection: a tenant-scope JWT must not be able to set tenant quotas.
        // RouteScopeFilter returns 404 (not 403) to avoid leaking surface existence to
        // non-system callers.
        var (sysClient, slug) = await CreateTenantAsync();
        sysClient.Dispose();

        using var tenantClient = _factory.CreateClient();
        var resp = await tenantClient.PatchAsJsonAsync(
            $"/api/v1/system/tenants/{slug}/storage-quota", new { quotaBytes = 1_000L });
        Assert.True(
            resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized,
            $"Unauthenticated tenant call to /system/tenants/.../storage-quota must NOT succeed; got {(int)resp.StatusCode}.");
    }
}
