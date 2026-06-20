using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the per-tenant air-gap isolation property: air-gapping one tenant does not change
/// another tenant's posture. Uses a multi-mode fixture (DEPLOYMENT_MODE=multi) so each tenant is
/// genuinely reachable by its <c>{slug}.localhost</c> subdomain — the single-mode air-gap tests
/// cannot express this because single mode resolves every request to the one default org.
///
/// Two tenants are created via the system API; tenant A is air-gapped and tenant B is not. The
/// same uncached npm package is requested on each subdomain: A returns 404 (passthrough forced
/// off), B returns 200 (passthrough reaches the stubbed upstream).
/// </summary>
[Trait("Category", "Integration")]
public sealed class MultiTenantAirGapIsolationTests : IClassFixture<DependablyMultiUpstreamFactory>
{
    private readonly DependablyMultiUpstreamFactory _factory;
    public MultiTenantAirGapIsolationTests(DependablyMultiUpstreamFactory factory) => _factory = factory;

    [Fact]
    public async Task OneTenantAirGapped_OtherTenantStillServesViaPassthrough()
    {
        string pkg = $"airgap-iso-{Guid.NewGuid():N}";
        StubNpmPackument(pkg);

        var airGapped = await _factory.CreateTenantAsync("airgapped");
        var connected = await _factory.CreateTenantAsync("connected");

        // Tenant A: air-gapped on. Tenant B: explicitly air-gapped off (deterministic baseline).
        await SetAirGapped(airGapped, on: true);
        await SetAirGapped(connected, on: false);

        // Air-gapped tenant A → passthrough off → 404 for the uncached package, even though the
        // upstream would serve it.
        using var a = await TenantPullClient(airGapped);
        var ra = await a.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.NotFound, ra.StatusCode);

        // Connected tenant B → passthrough reaches the stubbed upstream → 200. This is the
        // isolation signal: A's air-gap did not affect B.
        using var b = await TenantPullClient(connected);
        var rb = await b.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, rb.StatusCode);
    }

    // Toggles a tenant's air-gap setting via PUT /api/v1/settings on its own subdomain, signed
    // with an owner JWT for that tenant (TenantConfigure capability).
    private async Task SetAirGapped((string Slug, string TenantId, string OwnerId) tenant, bool on)
    {
        string jwt = await _factory.CreateTenantJwt(tenant.OwnerId, tenant.TenantId);
        using var admin = _factory.CreateTenantClient(tenant.Slug);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await admin.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true,
            allowlistMode = false,
            airGapped = on,
        });
        resp.EnsureSuccessStatusCode();
    }

    // A pull-token Bearer client pinned to the tenant's subdomain host.
    private async Task<HttpClient> TenantPullClient((string Slug, string TenantId, string OwnerId) tenant)
    {
        string token = await _factory.CreatePullToken(tenant.TenantId);
        var client = _factory.CreateTenantClient(tenant.Slug);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    // Stubs the upstream npm packument so a connected tenant's metadata GET resolves to 200.
    private void StubNpmPackument(string pkg)
    {
        string packument = JsonSerializer.Serialize(new
        {
            name = pkg,
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new
                {
                    name = pkg,
                    version = "1.0.0",
                    dist = new { tarball = $"{_factory.MockUpstream.Urls[0]}/{pkg}/-/{pkg}-1.0.0.tgz" },
                },
            },
        });
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{pkg}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(packument));
    }
}
