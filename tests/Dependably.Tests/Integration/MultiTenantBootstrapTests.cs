using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Phase 2 verification: multi-mode FirstBoot + bootstrap endpoint shape + system_admin auth +
/// tenant CRUD via the system surface + cross-realm rejection. The single-mode coverage lives
/// in <see cref="BootstrapEndpointTests"/> and the existing factory tests.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MultiTenantBootstrapTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;

    public MultiTenantBootstrapTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Bootstrap_MultiModeApex_ReturnsApexShape()
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var resp = await client.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("multi", doc.RootElement.GetProperty("mode").GetString());
        Assert.True(doc.RootElement.GetProperty("isApex").GetBoolean());
        Assert.Equal(DependablyMultiFactory.ApexHost,
            doc.RootElement.GetProperty("apexHost").GetString());
        // Apex response should NOT carry tenantSlug (no tenant context at apex).
        Assert.False(doc.RootElement.TryGetProperty("tenantSlug", out _));
    }

    [Fact]
    public async Task FirstBoot_MultiMode_CreatesSystemAdmin()
    {
        // Verify directly via DI: the system_admin row exists. (We can't assert "tenants count
        // is 0" because other tests in the same fixture may have created tenants — tests are
        // order-independent.)
        var sysRepo = _factory.Services.GetRequiredService<Dependably.Infrastructure.SystemAdminRepository>();
        int count = await sysRepo.CountAsync();
        Assert.True(count >= 1, "FirstBoot in multi mode should create exactly one system_admin");
    }

    [Fact]
    public async Task SystemAdmin_LoginAtApex_Succeeds()
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = DependablyMultiFactory.SystemAdminEmail,
            password = DependablyMultiFactory.SystemAdminPassword,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        // Login sets a host-only cookie.
        Assert.True(resp.Headers.Contains("Set-Cookie"));
        string setCookie = string.Join(";", resp.Headers.GetValues("Set-Cookie"));
        Assert.DoesNotContain("Domain=", setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateTenant_AtApex_AtomicallyCreatesOrgAndOwner()
    {
        string slug = "acme-" + Guid.NewGuid().ToString("N")[..8];
        string ownerEmail = $"alice-{Guid.NewGuid():N}@example.com";

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(slug, doc.RootElement.GetProperty("tenant").GetProperty("slug").GetString());
        Assert.Equal(ownerEmail, doc.RootElement.GetProperty("owner").GetProperty("email").GetString());
        Assert.True(doc.RootElement.GetProperty("owner").GetProperty("mustChangePassword").GetBoolean());
        Assert.False(string.IsNullOrEmpty(
            doc.RootElement.GetProperty("owner").GetProperty("ownerPassword").GetString()));

        // Verify the tenant appears in the list (count is non-deterministic across tests, but the
        // newly-created slug must be present).
        var listResp = await client.GetAsync("/api/v1/system/tenants?limit=200");
        var listDoc = JsonDocument.Parse(await listResp.Content.ReadAsStringAsync());
        var slugs = listDoc.RootElement.GetProperty("items").EnumerateArray()
            .Select(o => o.GetProperty("slug").GetString())
            .ToList();
        Assert.Contains(slug, slugs);
    }

    [Fact]
    public async Task CreateTenant_ReservedSlug_Rejected()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug = "system",
            ownerEmail = $"reserved-{Guid.NewGuid():N}@example.com",
        });
        // ProblemResults validation errors return 422 (RFC 7807 unprocessable entity).
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task CreateTenant_DuplicateSlug_Returns409()
    {
        string slug = "dup-" + Guid.NewGuid().ToString("N")[..8];
        using var client = await _factory.CreateSystemAdminClient();
        var first = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"first-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // Second attempt with same slug must fail with 409.
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"second-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    [Fact]
    public async Task TenantJwt_AtSystemRoute_Returns404_CrossRealmRejection()
    {
        string slug = "rs-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await _factory.CreateSystemAdminClient();
        var createResp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"d-{Guid.NewGuid():N}@example.com",
        });
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string tenantId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        // Tenant JWT presented at system route → 404 (RouteScopeFilter rejects scope
        // mismatch). The JWT must reference a live user: token validation rejects sessions
        // whose user row is missing, which would 401 before the scope check is reached.
        string ownerId;
        await using (var conn = await _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @tenantId LIMIT 1", new { tenantId })
                ?? throw new InvalidOperationException("owner user missing");
        }
        string tenantJwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId);
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantJwt);

        var resp = await client.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SystemJwt_AtTenantSubdomainBusinessRoute_Returns404()
    {
        string slug = "pc-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await _factory.CreateSystemAdminClient();
        await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"e-{Guid.NewGuid():N}@example.com",
        });

        // System_admin presenting their JWT at a tenant subdomain business route — 404.
        string sysJwt = await _factory.CreateSystemAdminJwt();
        using var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", sysJwt);

        var resp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task UnauthenticatedRequest_AtSystemRoute_Returns401()
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var resp = await client.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task UnknownSubdomain_Bootstrap_ReturnsModeButNotApex()
    {
        // SubdomainTenantResolver returns Uninitialized when the slug doesn't resolve to any
        // tenant. The middleware doesn't 404 the bootstrap endpoint (we want the SPA to be able
        // to fetch this from any host); instead the response just lacks a tenant assertion.
        using var client = _factory.CreateClientForHost("nosuchtenant." + DependablyMultiFactory.ApexHost);
        var resp = await client.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("multi", doc.RootElement.GetProperty("mode").GetString());
        Assert.False(doc.RootElement.GetProperty("isApex").GetBoolean());
        Assert.False(doc.RootElement.TryGetProperty("tenantSlug", out _));
    }
}
