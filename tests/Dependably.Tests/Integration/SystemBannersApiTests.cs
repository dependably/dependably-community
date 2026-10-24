using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// System banner writes end to end on the apex host. The <c>enabled</c> flag is stored in an
/// INTEGER column on both providers, so a create, a disable and a re-enable each round-trip the
/// flag through the database; on Postgres a boolean parameter bound to that column is refused.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemBannersApiTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private const string Starts = "2020-01-01T00:00:00Z";
    private const string Ends = "2099-01-01T00:00:00Z";

    private readonly DependablyMultiFactory _factory;
    public SystemBannersApiTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static object Body(string body, bool enabled) => new
    {
        severity = "warn",
        body,
        linkUrl = (string?)null,
        linkLabel = (string?)null,
        targetRole = "all",
        startsAt = Starts,
        endsAt = Ends,
        enabled,
    };

    private static async Task<JsonElement> FindAsync(HttpClient c, string id)
    {
        var resp = await c.GetAsync("/api/v1/system/banners");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var list = await resp.Content.ReadFromJsonAsync<JsonElement>();
        return list.EnumerateArray().Single(b => b.GetProperty("id").GetString() == id);
    }

    [Fact]
    public async Task CreateDisableReenable_RoundTripsTheEnabledFlag()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        string body = "Registry maintenance window " + Guid.NewGuid().ToString("N")[..8];

        var create = await sysAdmin.PostAsJsonAsync("/api/v1/system/banners", Body(body, enabled: true));
        Assert.True(create.StatusCode == HttpStatusCode.Created, await create.Content.ReadAsStringAsync());
        var created = await create.Content.ReadFromJsonAsync<JsonElement>();
        string id = created.GetProperty("id").GetString()!;
        Assert.True(created.GetProperty("enabled").GetBoolean());
        Assert.True((await FindAsync(sysAdmin, id)).GetProperty("enabled").GetBoolean());

        var disable = await sysAdmin.PutAsJsonAsync($"/api/v1/system/banners/{id}", Body(body, enabled: false));
        Assert.Equal(HttpStatusCode.NoContent, disable.StatusCode);
        Assert.False((await FindAsync(sysAdmin, id)).GetProperty("enabled").GetBoolean());

        var reenable = await sysAdmin.PutAsJsonAsync($"/api/v1/system/banners/{id}", Body(body, enabled: true));
        Assert.Equal(HttpStatusCode.NoContent, reenable.StatusCode);
        Assert.True((await FindAsync(sysAdmin, id)).GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task CreateDisabled_IsStoredDisabled()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        string body = "Draft notice " + Guid.NewGuid().ToString("N")[..8];

        var create = await sysAdmin.PostAsJsonAsync("/api/v1/system/banners", Body(body, enabled: false));
        Assert.True(create.StatusCode == HttpStatusCode.Created, await create.Content.ReadAsStringAsync());
        string id = (await create.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;

        Assert.False((await FindAsync(sysAdmin, id)).GetProperty("enabled").GetBoolean());
    }
}
