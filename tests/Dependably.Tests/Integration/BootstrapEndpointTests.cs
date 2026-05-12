using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Phase 1 — verifies the public <c>GET /api/v1/bootstrap</c> endpoint and the tenant resolution
/// pipeline behind it. The default test factory configures single-tenant mode, so all assertions
/// below target single-mode shape.
/// </summary>
[Trait("Category", "Integration")]
public sealed class BootstrapEndpointTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public BootstrapEndpointTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Bootstrap_SingleMode_ReturnsModeAndTenantSlug()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("single", doc.RootElement.GetProperty("mode").GetString());
        Assert.Equal("default", doc.RootElement.GetProperty("tenantSlug").GetString());
        Assert.False(doc.RootElement.GetProperty("isApex").GetBoolean());
        Assert.True(doc.RootElement.TryGetProperty("capabilities", out _));
    }

    [Fact]
    public async Task Bootstrap_NoAuthRequired()
    {
        using var client = _factory.CreateClient();
        // No Authorization header, no cookie — should still succeed.
        var resp = await client.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Bootstrap_SetsNoStoreCacheHeader()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/bootstrap");
        Assert.Contains("no-store", resp.Headers.CacheControl?.ToString() ?? "");
    }
}
