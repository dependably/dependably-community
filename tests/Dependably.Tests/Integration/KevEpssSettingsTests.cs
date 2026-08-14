using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Covers the /api/v1/proxy-settings surface for the KEV/EPSS policy fields: round-trip,
/// the opt-in defaults when the fields are absent, and validation. Gate behaviour itself is
/// covered at the unit level (BlockGateServiceTests) — the download path plumbing is shared
/// with the malicious gate, which has end-to-end coverage in MaliciousGateTests.
/// </summary>
[Trait("Category", "Integration")]
public sealed class KevEpssSettingsTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public KevEpssSettingsTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task ProxySettings_Put_RoundTripsKevAndEpss()
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockKev = "warn",
            maxEpssTolerance = 0.35,
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("warn", doc.RootElement.GetProperty("block_kev").GetString());
        Assert.Equal(0.35, doc.RootElement.GetProperty("max_epss_tolerance").GetDouble());
    }

    // block_kev is opt-in — pre-gate automation, which predates this field and so can never have
    // set it, must not land on a blocking mode. That guarantee holds structurally, independent of
    // whether an absent field is left unchanged or reset: the schema default is 'off' (Schema.sql),
    // every org-creation path inserts a bare row (OrgRepository.InsertAsync, FirstBootService,
    // AdminBootstrapper, SystemController), and both the GET fallback and the INSERT-arm COALESCE
    // land 'off'/null. Leave-unchanged only changes the outcome for a row a client DELIBERATELY
    // wrote to — that is exactly what this test pins. block_kev's explicit "off" spelling is
    // unaffected — the gate can still be turned off on purpose.
    [Fact]
    public async Task ProxySettings_Put_AbsentBlockKev_LeavesStoredModeUnchanged()
    {
        using var c = await AdminClient();
        var seed = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockKev = "block",
        });
        Assert.Equal(HttpStatusCode.NoContent, seed.StatusCode);

        // Second write omits block_kev entirely — models a partial PUT touching an unrelated
        // field only.
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 6.5,
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("block", doc.RootElement.GetProperty("block_kev").GetString());
    }

    [Fact]
    public async Task ProxySettings_Put_AbsentMaxEpssTolerance_LeavesStoredValueUnchanged()
    {
        // max_epss_tolerance keeps its tri-state Optional<T> binding (see ProxyPolicySettings):
        // a genuinely absent field must not clear a deliberately configured ceiling.
        using var c = await AdminClient();
        var seed = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            maxEpssTolerance = 0.5,
        });
        Assert.Equal(HttpStatusCode.NoContent, seed.StatusCode);

        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 6.5,
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(0.5, doc.RootElement.GetProperty("max_epss_tolerance").GetDouble());
    }

    [Fact]
    public async Task ProxySettings_Put_ExplicitNullMaxEpssTolerance_StillClears()
    {
        // Adversarial twin, and the shape the SPA actually sends: OrgSettings.svelte's
        // buildProxyPayload() always includes maxEpssTolerance in the body, as an explicit JSON
        // null when the operator clears the input. Leave-unchanged-on-absent must not swallow
        // that deliberate clear — explicit null (present, null) still disables the gate.
        using var c = await AdminClient();
        var seed = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            maxEpssTolerance = 0.5,
        });
        Assert.Equal(HttpStatusCode.NoContent, seed.StatusCode);

        using var req = new HttpRequestMessage(HttpMethod.Put, "/api/v1/proxy-settings")
        {
            Content = JsonContent.Create(JsonDocument.Parse(
                """{"proxyPassthroughEnabled":true,"maxOsvScoreTolerance":10.0,"maxEpssTolerance":null}""").RootElement),
        };
        var put = await c.SendAsync(req);
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("max_epss_tolerance").ValueKind);
    }

    [Theory]
    [InlineData("block_new")] // valid for block_deprecated, not here
    [InlineData("yes")]
    public async Task ProxySettings_Put_InvalidBlockKev_Returns422(string mode)
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockKev = mode,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.5)]
    public async Task ProxySettings_Put_EpssOutOfRange_Returns422(double tolerance)
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            maxEpssTolerance = tolerance,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
    }
}
