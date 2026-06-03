using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Management-API surface for per-org upstream proxy registries: CRUD + reorder, the
/// tenant:configure gate, SSRF rejection (reusing UpstreamUrlValidator), and ecosystem
/// validation. The fetch-side "empty list = disabled" contract is covered separately in the
/// per-ecosystem proxy tests.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UpstreamRegistryApiTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public UpstreamRegistryApiTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        var id = await _factory.CreateUser($"ur-{Guid.NewGuid():N}@example.com", "Password12345");
        var jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    [Fact]
    public async Task AddListReorderDelete_RoundTrip()
    {
        using var c = await AdminClient();
        var urlA = $"https://mirror-a-{Guid.NewGuid():N}.example.com";
        var urlB = $"https://mirror-b-{Guid.NewGuid():N}.example.com";

        var addA = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "pypi", url = urlA, name = "A" });
        Assert.Equal(HttpStatusCode.Created, addA.StatusCode);
        var idA = (await JsonDocument.ParseAsync(await addA.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString();

        var addB = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "pypi", url = urlB });
        Assert.Equal(HttpStatusCode.Created, addB.StatusCode);
        var idB = (await JsonDocument.ParseAsync(await addB.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString();

        // Reorder so B precedes A.
        var reorder = await c.PutAsJsonAsync("/api/v1/upstream-registries/pypi/order",
            new { ids = new[] { idB, idA } });
        Assert.Equal(HttpStatusCode.NoContent, reorder.StatusCode);

        var list = await c.GetAsync("/api/v1/upstream-registries");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        var pypi = items.EnumerateArray()
            .Where(e => e.GetProperty("ecosystem").GetString() == "pypi")
            .OrderBy(e => e.GetProperty("position").GetInt32())
            .Select(e => e.GetProperty("url").GetString())
            .ToList();
        Assert.Equal(urlB, pypi[0]);
        Assert.Equal(urlA, pypi[1]);

        Assert.Equal(HttpStatusCode.NoContent,
            (await c.DeleteAsync($"/api/v1/upstream-registries/{idA}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await c.DeleteAsync($"/api/v1/upstream-registries/{idB}")).StatusCode);
    }

    [Fact]
    public async Task Add_PrivateRangeUrl_RejectedAsSsrf()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "npm", url = "http://169.254.169.254/latest/meta-data" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Add_UnknownEcosystem_Rejected()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "cargo", url = "https://crates.io" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Add_ByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "pypi", url = "https://pypi.org" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
