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

    [Fact]
    public async Task ProxySettings_Put_AbsentFields_DefaultToOptOut()
    {
        // Both policies are opt-in: a payload without the fields resets to off/null
        // (back-compat — existing automation must not opt orgs into new blocking).
        using var c = await AdminClient();
        var seed = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockKev = "block",
            maxEpssTolerance = 0.5,
        });
        Assert.Equal(HttpStatusCode.NoContent, seed.StatusCode);

        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("off", doc.RootElement.GetProperty("block_kev").GetString());
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
