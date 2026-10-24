using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>DEPLOYMENT_MODE=multi</c> with <c>TENANT_DOMAIN</c> set: the system-admin apex
/// (<c>ops.example.test</c>) sits beside the tenants (<c>slug.example.test</c>) instead of being
/// their parent. Each positive probe is paired with a must-not twin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantDomainRoutingTests : IAsyncLifetime
{
    private const string Apex = "ops.example.test";
    private const string TenantDomain = "example.test";

    private readonly DependablyMultiFactory _factory = new()
    {
        Settings = new Dictionary<string, string>
        {
            ["APEX_HOST"] = Apex,
            ["TENANT_DOMAIN"] = TenantDomain,
        },
    };

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private async Task<HttpClient> SystemAdminClientAsync()
    {
        string jwt = await _factory.CreateSystemAdminJwt();
        var client = _factory.CreateClientForHost(Apex);
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static async Task<JsonElement> JsonOf(HttpResponseMessage resp)
    {
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    [Fact]
    public async Task Bootstrap_AtApex_ReportsApexAndTenantDomain()
    {
        using var client = _factory.CreateClientForHost(Apex);

        var root = await JsonOf(await client.GetAsync("/api/v1/bootstrap"));

        Assert.True(root.GetProperty("isApex").GetBoolean());
        Assert.Equal(Apex, root.GetProperty("apexHost").GetString());
        Assert.Equal(TenantDomain, root.GetProperty("tenantDomain").GetString());
    }

    [Fact]
    public async Task ApexLabel_CannotBeCreatedAsATenant_OrdinarySlugCan()
    {
        using var sys = await SystemAdminClientAsync();

        var reserved = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug = "ops",
            ownerEmail = $"owner-{Guid.NewGuid():N}@example.com",
        });
        var twin = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug = "acme",
            ownerEmail = $"owner-{Guid.NewGuid():N}@example.com",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, reserved.StatusCode);
        Assert.Equal(HttpStatusCode.OK, twin.StatusCode);
    }

    [Fact]
    public async Task TenantHost_ResolvesUnderTenantDomain_AndDeeperOrApexChildHostsDoNot()
    {
        using (var sys = await SystemAdminClientAsync())
        {
            var created = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
            {
                slug = "widgets",
                ownerEmail = $"owner-{Guid.NewGuid():N}@example.com",
            });
            Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        }

        // Positive: the tenant resolves at slug.<tenantDomain>, so a protocol route reaches the
        // tenant (anything but the not-found a tenant-less host receives).
        using var tenant = _factory.CreateClientForHost($"widgets.{TenantDomain}");
        var tenantResp = await tenant.GetAsync("/npm/some-package");
        var bootstrap = await JsonOf(await tenant.GetAsync("/api/v1/bootstrap"));

        // Twins: same slug one label deeper, under the apex, or under a second label.
        using var underApex = _factory.CreateClientForHost($"widgets.{Apex}");
        using var deeper = _factory.CreateClientForHost($"widgets.team.{TenantDomain}");

        Assert.NotEqual(HttpStatusCode.NotFound, tenantResp.StatusCode);
        Assert.False(bootstrap.GetProperty("isApex").GetBoolean());
        Assert.Equal(TenantDomain, bootstrap.GetProperty("tenantDomain").GetString());

        // These hosts pass the wildcard host filter (suffix match at any depth) and are refused by
        // tenant resolution with the 404 a tenant-less protocol request receives.
        Assert.Equal(HttpStatusCode.NotFound, (await underApex.GetAsync("/npm/some-package")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await deeper.GetAsync("/npm/some-package")).StatusCode);
    }

    [Fact]
    public async Task HostFilter_AdmitsTenantDomainWildcard_RejectsForeignHost()
    {
        using var foreign = _factory.CreateClientForHost("acme.other.test");
        using var admitted = _factory.CreateClientForHost($"acme.{TenantDomain}");

        var foreignResp = await foreign.GetAsync("/health");
        var admittedResp = await admitted.GetAsync("/health");

        Assert.Equal(HttpStatusCode.BadRequest, foreignResp.StatusCode);
        Assert.NotEqual(HttpStatusCode.BadRequest, admittedResp.StatusCode);
    }
}
