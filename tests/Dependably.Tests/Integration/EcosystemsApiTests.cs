using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dependably.Api.Setup;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>GET /api/v1/ecosystems</c>: the vocabulary and per-plane support matrix a client reads
/// instead of hardcoding a copy of <see cref="UpstreamRegistryRepository.SupportedEcosystems"/>,
/// <see cref="PackageLookupService.SupportedEcosystems"/>, and
/// <see cref="SetupRecipeCatalog.Ecosystems"/>. Asserts the response is drawn from exactly those
/// three constants (not a hand-maintained copy that can drift from them) and that the derived
/// <c>items</c> booleans agree with the plane membership they are derived from.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EcosystemsApiTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public EcosystemsApiTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> PullClient()
    {
        // "Pull-scoped": a read-only PAT carrying exactly the capability this route requires,
        // the same shape PatReadSurfaceTests uses for every other read:packages surface.
        string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);
        return client;
    }

    [Fact]
    public async Task Get_WithPullToken_Returns200()
    {
        using var client = await PullClient();

        using var resp = await client.GetAsync("/api/v1/ecosystems");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Unauthenticated_Returns401()
    {
        using var client = _factory.CreateClient();

        using var resp = await client.GetAsync("/api/v1/ecosystems");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Get_UserPatWithoutReadPackages_Returns403()
    {
        // Carries a different read leaf only — proves the capability gate, not just the scheme,
        // matching PatReadSurfaceTests.ListPackages_UserPatWithoutReadPackages_Returns403.
        string pat = await _factory.CreateAdminUserToken("""["read:audit"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        using var resp = await client.GetAsync("/api/v1/ecosystems");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Get_JwtSessionMemberWithoutReadPackages_Returns403()
    {
        // A JWT session narrowed to a capability that is not read:packages — the session-scheme
        // counterpart to the PAT case above, same shape as
        // TrustAnchorControllerTests.ReadTenantOnlyClient.
        string userId = await _factory.CreateUser(
            $"eco-readonly-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwtWithCaps(userId, ["read:tenant"]);
        using var client = _factory.CreateClientWithBearer(jwt);

        using var resp = await client.GetAsync("/api/v1/ecosystems");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Planes_DeepEqualTheirSourceConstants_InOrder()
    {
        using var client = await PullClient();
        var body = await GetBodyAsync(client);

        Assert.Equal(
            UpstreamRegistryRepository.SupportedEcosystems,
            StringArray(body.GetProperty("planes").GetProperty("registry")));
        Assert.Equal(
            PackageLookupService.SupportedEcosystems,
            StringArray(body.GetProperty("planes").GetProperty("lookup")));
        Assert.Equal(
            SetupRecipeCatalog.Ecosystems,
            StringArray(body.GetProperty("planes").GetProperty("setup")));
    }

    [Fact]
    public async Task EveryLookupAndSetupId_IsAlsoARegistryId()
    {
        using var client = await PullClient();
        var body = await GetBodyAsync(client);
        var planes = body.GetProperty("planes");

        var registry = StringArray(planes.GetProperty("registry")).ToHashSet(StringComparer.Ordinal);
        foreach (string id in StringArray(planes.GetProperty("lookup")))
        {
            Assert.Contains(id, registry);
        }

        foreach (string id in StringArray(planes.GetProperty("setup")))
        {
            Assert.Contains(id, registry);
        }
    }

    [Fact]
    public async Task Items_HasOneEntryPerRegistryId_WithBooleansConsistentWithThePlanes()
    {
        using var client = await PullClient();
        var body = await GetBodyAsync(client);
        var planes = body.GetProperty("planes");

        string[] registry = StringArray(planes.GetProperty("registry"));
        var lookup = StringArray(planes.GetProperty("lookup")).ToHashSet(StringComparer.Ordinal);
        var setup = StringArray(planes.GetProperty("setup")).ToHashSet(StringComparer.Ordinal);

        var items = body.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(registry.Length, items.Count);

        // items is ordered by planes.registry order (the contract's own stated semantics), not
        // just the same set — a reorder here would still pass every per-item boolean check below.
        Assert.Equal(registry, items.Select(i => i.GetProperty("id").GetString()).ToArray());

        foreach (var item in items)
        {
            string id = item.GetProperty("id").GetString()!;
            Assert.Contains(id, registry);
            Assert.True(item.GetProperty("registry").GetBoolean());
            Assert.Equal(lookup.Contains(id), item.GetProperty("lookup").GetBoolean());
            Assert.Equal(setup.Contains(id), item.GetProperty("setup").GetBoolean());
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private static async Task<JsonElement> GetBodyAsync(HttpClient client)
    {
        using var resp = await client.GetAsync("/api/v1/ecosystems");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private static string[] StringArray(JsonElement array) =>
        array.EnumerateArray().Select(e => e.GetString()!).ToArray();
}
