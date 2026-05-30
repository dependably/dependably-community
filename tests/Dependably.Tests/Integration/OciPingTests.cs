using System.Net;
using System.Net.Http;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for the Distribution Spec <c>/v2/</c> auth probe. The endpoint must
/// respond 200 with the <c>Docker-Distribution-API-Version: registry/2.0</c> header on both
/// GET and HEAD, with and without a trailing slash — Docker daemons normalize one way or
/// the other depending on the client version.
///
/// Originally regressed because the controller declared sibling Ping actions
/// (<c>/v2</c>, <c>/v2/</c>) alongside the catch-all dispatcher (<c>/v2/{**path}</c>).
/// ASP.NET endpoint routing treats <c>/v2</c> and <c>/v2/</c> as the same template AND
/// <c>{**path}</c> matches zero segments, so every probe matched three endpoints and the
/// matcher threw <c>AmbiguousMatchException</c>. The fix collapses to one dispatcher per
/// verb that short-circuits when the catch-all is empty; these tests would have caught
/// the original bug immediately.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciPingTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string ApiVersionHeader = "Docker-Distribution-API-Version";
    private const string ExpectedApiVersion = "registry/2.0";

    private readonly DependablyFactory _factory;

    public OciPingTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Get_V2_Returns200WithApiVersionHeader()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/v2");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
    }

    [Fact]
    public async Task Get_V2_TrailingSlash_Returns200WithApiVersionHeader()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/v2/");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
    }

    [Fact]
    public async Task Head_V2_Returns200WithApiVersionHeaderAndEmptyBody()
    {
        using var client = _factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Head, "/v2");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
        var body = await resp.Content.ReadAsByteArrayAsync();
        Assert.Empty(body);
    }

    [Fact]
    public async Task Head_V2_TrailingSlash_Returns200WithApiVersionHeaderAndEmptyBody()
    {
        using var client = _factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Head, "/v2/");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
        var body = await resp.Content.ReadAsByteArrayAsync();
        Assert.Empty(body);
    }
}
