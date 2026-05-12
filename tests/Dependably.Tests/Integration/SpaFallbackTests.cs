using System.Net;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for the SPA fallback: deep links whose final URL segment contains a
/// dot (e.g. /package/nuget/microsoft.extensions.dependencyinjection) must reach the fallback
/// handler instead of being filtered out by the default `{*path:nonfile}` route constraint
/// that <see cref="Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions.MapFallback"/>
/// applies when called without an explicit pattern.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SpaFallbackTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SpaFallbackTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task DeepLink_WithDottedFinalSegment_ReachesSpaFallback()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/package/nuget/microsoft.extensions.dependencyinjection");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task DeepLink_WithoutDots_ReachesSpaFallback()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/package/pypi/django");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task NonSpaPrefix_StillReturns404()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/this-endpoint-does-not-exist");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// A cached index.html that references stale asset hashes (e.g. /assets/index-stale.css)
    /// must produce a 404, not a 200 with HTML body — otherwise the browser refuses the
    /// resource with a MIME mismatch error and the page renders unstyled / unscripted.
    /// </summary>
    [Fact]
    public async Task MissingDottedAsset_OutsideSpaRoute_Returns404()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/assets/index-does-not-exist.css");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
