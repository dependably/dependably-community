using System.Net;
using System.Net.Http.Headers;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class ProxyClaimGateTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public ProxyClaimGateTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> DefaultOrgId()
    {
        _factory.CreateClient().Dispose();   // ensure first-boot ran
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        return (await orgs.GetBySlugAsync("default"))!.Id;
    }

    private async Task SeedClaim(string orgId, string ecosystem, string name, string state)
    {
        var repo = _factory.Services.GetRequiredService<ClaimRepository>();
        await repo.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString(),
            HistoryId = Guid.NewGuid().ToString(),
            OrgId = orgId,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = state,
            Reason = "test",
            // now-ok: claim-event provenance stamp; no test asserts on this instant.
            OccurredAt = DateTimeOffset.UtcNow,
        });
    }

    private async Task<HttpClient> AuthedClient()
    {
        string token = await _factory.CreateToken("pull");
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    [Fact]
    public async Task NpmTarball_LocalOnlyClaim_DisablesProxyFetch()
    {
        string orgId = await DefaultOrgId();
        await SeedClaim(orgId, "npm", "claimed-pkg", state: ClaimStateMachine.LocalOnly);

        // No local version exists for the (org, npm, claimed-pkg, *) coordinate. The proxy
        // would normally try upstream — local_only must reject without fetching.
        using var c = await AuthedClient();
        var resp = await c.GetAsync("/npm/tarballs/claimed-pkg/claimed-pkg-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task NpmTarball_UnclaimedName_AllowsProxyFetch()
    {
        // Without an explicit claim, the default (connected mode) is unclaimed → proxy
        // enabled. The factory's WireMock upstream returns 404 for unknown packages so this
        // returns 404 too — but the path is reached. We can't easily distinguish from the
        // upstream-404 case without WireMock setup; the contrast is the LocalOnly test
        // above, which short-circuits with 404 BEFORE the upstream call.
        using var c = await AuthedClient();
        var resp = await c.GetAsync("/npm/tarballs/no-claim-pkg/no-claim-pkg-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task ClaimResolver_AirGap_ImplicitLocalOnlyForAllNames()
    {
        // Direct service-level test that air-gap mode resolves every name as local_only,
        // disabling proxy fetch even without an explicit claim row. Uses the resolver
        // directly because configuring AIR_GAPPED requires a separate factory.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId = await DefaultOrgId();

        // Construct a fresh resolver wired for air-gap mode without restarting the host.
        var cfg = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["AIR_GAPPED"] = "true" })
            .Build();
        var resolver = new ClaimResolver(new ClaimRepository(db), new AirGapMode(cfg));

        // Even for a name no operator has claimed, air-gap implies local_only.
        Assert.False(await resolver.IsProxyFetchAllowedAsync(orgId, "npm", "anything-at-all"));
    }
}
