using System.Net;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Coverage for the Distribution Spec <c>/v2/</c> auth-discovery probe. Two contracts:
///
/// 1. <b>Auth discovery.</b> docker/skopeo/containerd ping <c>/v2/</c> first and read
///    <c>WWW-Authenticate</c> to decide whether — and how — to authenticate. An
///    unauthenticated ping must answer <c>401</c> with a <c>Basic</c> challenge (a 200
///    would make clients send every later request, including the manifest <c>PUT</c>,
///    anonymously, so push fails at the first authed write). A ping that carries valid
///    credentials answers <c>200</c>. Both responses keep the
///    <c>Docker-Distribution-API-Version: registry/2.0</c> header so clients still
///    recognise a v2 registry.
///
/// 2. <b>Route normalization.</b> Both <c>/v2</c> and <c>/v2/</c>, on GET and HEAD, hit the
///    same probe — Docker daemons normalize one way or the other depending on client
///    version. The controller declares one dispatcher per verb (<c>/v2/{**path}</c>) that
///    short-circuits when the catch-all path is empty; an earlier design with sibling
///    <c>/v2</c> + <c>/v2/</c> Ping actions made every probe match three endpoints and threw
///    <c>AmbiguousMatchException</c>. These tests pin both segments resolve.
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

    [Theory]
    [InlineData("/v2")]
    [InlineData("/v2/")]
    public async Task Get_V2_NoToken_Returns401WithBasicChallengeAndApiVersionHeader(string path)
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal("Basic", resp.Headers.WwwAuthenticate.Single().Scheme);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
    }

    [Theory]
    [InlineData("/v2")]
    [InlineData("/v2/")]
    public async Task Head_V2_NoToken_Returns401WithBasicChallenge(string path)
    {
        using var client = _factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Head, path);
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal("Basic", resp.Headers.WwwAuthenticate.Single().Scheme);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
    }

    [Fact]
    public async Task Get_V2_WithToken_Returns200WithApiVersionHeader()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync("/v2/");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues(ApiVersionHeader, out var values), $"Missing {ApiVersionHeader} header.");
        Assert.Equal(ExpectedApiVersion, Assert.Single(values));
    }
}
