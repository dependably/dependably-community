using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the pre-adoption lookup is tenant-scoped end-to-end over real HTTP: two tenants with
/// different <c>block_deprecated</c> policy get different verdicts for the identical deprecated
/// package — the acceptance criterion "two orgs with different policies get different verdicts".
/// Deprecation is chosen (over malware/CVE) because it is derivable straight from the stubbed npm
/// packument with no dependency on the OSV client's own upstream wiring. Uses the multi-mode
/// fixture (DEPLOYMENT_MODE=multi) so each tenant is genuinely reachable by its own subdomain,
/// mirroring <see cref="MultiTenantAirGapIsolationTests"/>.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PackageLookupTenantPolicyTests : IClassFixture<DependablyMultiUpstreamFactory>
{
    private readonly DependablyMultiUpstreamFactory _factory;
    public PackageLookupTenantPolicyTests(DependablyMultiUpstreamFactory factory) => _factory = factory;

    [Fact]
    public async Task StrictOrgBlocksDeprecated_LenientOrgWarns_ForTheIdenticalPackage()
    {
        string pkg = $"lookup-deprecated-{Guid.NewGuid():N}"[..24];
        StubDeprecatedNpmPackument(pkg);

        var strict = await _factory.CreateTenantAsync("strict");
        var lenient = await _factory.CreateTenantAsync("lenient");
        await SetBlockDeprecated(strict, "block_all");
        await SetBlockDeprecated(lenient, "warn");

        using var strictClient = await TenantOwnerClient(strict);
        using var lenientClient = await TenantOwnerClient(lenient);

        var strictResp = await strictClient.GetAsync($"/api/v1/lookup?ecosystem=npm&name={pkg}&version=1.0.0");
        var lenientResp = await lenientClient.GetAsync($"/api/v1/lookup?ecosystem=npm&name={pkg}&version=1.0.0");

        Assert.Equal(HttpStatusCode.OK, strictResp.StatusCode);
        Assert.Equal(HttpStatusCode.OK, lenientResp.StatusCode);

        using var strictDoc = JsonDocument.Parse(await strictResp.Content.ReadAsStringAsync());
        using var lenientDoc = JsonDocument.Parse(await lenientResp.Content.ReadAsStringAsync());

        Assert.Equal("blocked", strictDoc.RootElement.GetProperty("verdict").GetString());
        Assert.Equal("Deprecated", strictDoc.RootElement.GetProperty("blockedReason").GetString());
        Assert.NotEqual("blocked", lenientDoc.RootElement.GetProperty("verdict").GetString());
    }

    private void StubDeprecatedNpmPackument(string name)
    {
        string json = $$"""
            {
              "name": "{{name}}",
              "dist-tags": { "latest": "1.0.0" },
              "versions": {
                "1.0.0": {
                  "name": "{{name}}", "version": "1.0.0", "license": "MIT",
                  "deprecated": "no longer maintained"
                }
              },
              "time": { "1.0.0": "2024-03-01T00:00:00.000Z" }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(json));
    }

    private async Task SetBlockDeprecated((string Slug, string TenantId, string OwnerId) tenant, string mode)
    {
        string jwt = await _factory.CreateTenantJwt(tenant.OwnerId, tenant.TenantId);
        using var admin = _factory.CreateTenantClient(tenant.Slug);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await admin.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockDeprecated = mode,
        });
        resp.EnsureSuccessStatusCode();
    }

    private async Task<HttpClient> TenantOwnerClient((string Slug, string TenantId, string OwnerId) tenant)
    {
        string jwt = await _factory.CreateTenantJwt(tenant.OwnerId, tenant.TenantId);
        var client = _factory.CreateTenantClient(tenant.Slug);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }
}
