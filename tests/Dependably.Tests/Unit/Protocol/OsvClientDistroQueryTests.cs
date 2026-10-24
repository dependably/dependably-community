using System.Net;
using System.Text.Json;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The remote (default <c>OSV_MODE</c>) release-scoped query. api.osv.dev answers an unknown
/// release of a known distro family with an empty 200, so these pin that such an answer can never
/// read as a consulted-and-clean feed, plus the request shape and paging.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvClientDistroQueryTests : IDisposable
{
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly OsvClient _sut;

    public OsvClientDistroQueryTests() =>
        _sut = new OsvClient(new Factory(_server.Urls[0] + "/"), NullLogger<OsvClient>.Instance);

    public void Dispose() => _server.Stop();

    private static DistroScope Scope(string ecosystem, string distro) =>
        DistroScopes.TryParse(ecosystem, distro, out var scope) ? scope! : throw new InvalidOperationException(distro);

    private void StubQuery(HttpStatusCode status, string body) =>
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(status).WithBody(body));

    [Fact]
    public async Task Request_CarriesVersionNameAndReleaseQualifiedEcosystem()
    {
        StubQuery(HttpStatusCode.OK, """{"vulns":[{"id":"ALPINE-1","summary":"s"}]}""");

        var result = await _sut.TryQueryDistroPackageAsync(Scope("apk", "v3.20"), "openssl", "3.1.0-r0");

        Assert.True(result.Reached);
        Assert.True(result.Covered);
        Assert.Equal("ALPINE-1", Assert.Single(result.Advisories).Id);
        var entry = Assert.Single(_server.LogEntries);
        using var body = JsonDocument.Parse(entry.RequestMessage!.Body!);
        Assert.Equal("3.1.0-r0", body.RootElement.GetProperty("version").GetString());
        Assert.Equal("openssl", body.RootElement.GetProperty("package").GetProperty("name").GetString());
        Assert.Equal("Alpine:v3.20", body.RootElement.GetProperty("package").GetProperty("ecosystem").GetString());
        Assert.False(body.RootElement.TryGetProperty("page_token", out _));
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task NonSuccess_IsNotReached(HttpStatusCode status)
    {
        StubQuery(status, "{}");

        var result = await _sut.TryQueryDistroPackageAsync(Scope("rpm", "Rocky Linux:9"), "openssl", "1:3.0.7-24.el9");

        Assert.False(result.Reached);
        Assert.False(result.Covered);
        Assert.Empty(result.Advisories);
    }

    [Theory]
    [InlineData("apk", "v3.99")]
    [InlineData("apk", "v3.1")]
    [InlineData("rpm", "Rocky Linux:11")]
    [InlineData("rpm", "AlmaLinux:99")]
    [InlineData("rpm", "Red Hat:enterprise_linux:7::baseos")]
    public async Task EmptyAnswerForAReleaseOsvDoesNotCarry_IsUncovered_AndNeverQueried(string ecosystem, string distro)
    {
        // api.osv.dev answers these with 200 {} — the stub does the same, and must not be reached.
        StubQuery(HttpStatusCode.OK, "{}");

        var result = await _sut.TryQueryDistroPackageAsync(Scope(ecosystem, distro), "openssl", "1.0-1");

        Assert.True(result.Reached);
        Assert.False(result.Covered);
        Assert.Empty(result.Advisories);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task EmptyAnswerForAKnownRelease_IsACoveredCleanAnswer()
    {
        StubQuery(HttpStatusCode.OK, "{}");

        var result = await _sut.TryQueryDistroPackageAsync(Scope("rpm", "Rocky Linux:9"), "openssl", "1:3.0.7-99.el9");

        Assert.True(result.Reached);
        Assert.True(result.Covered);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task PagedAnswer_IsFollowedThroughNextPageToken()
    {
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .InScenario("pages").WillSetStateTo("second")
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithBody("""{"vulns":[{"id":"RLSA-1"}],"next_page_token":"t2"}"""));
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .InScenario("pages").WhenStateIs("second")
            .RespondWith(Response.Create().WithStatusCode(200).WithBody("""{"vulns":[{"id":"RLSA-2"}]}"""));

        var result = await _sut.TryQueryDistroPackageAsync(Scope("rpm", "Rocky Linux:9"), "kernel", "0:0-1");

        Assert.True(result.Reached);
        Assert.Equal(["RLSA-1", "RLSA-2"], result.Advisories.Select(a => a.Id).ToArray());
        Assert.Equal(2, _server.LogEntries.Count);
        using var second = JsonDocument.Parse(_server.LogEntries[^1].RequestMessage!.Body!);
        Assert.Equal("t2", second.RootElement.GetProperty("page_token").GetString());
    }

    [Fact]
    public async Task EndlessPaging_IsNotReached_NeverServedTruncatedAsComplete()
    {
        StubQuery(HttpStatusCode.OK, """{"vulns":[{"id":"RLSA-1"}],"next_page_token":"again"}""");

        var result = await _sut.TryQueryDistroPackageAsync(Scope("rpm", "Rocky Linux:9"), "kernel", "0:0-1");

        Assert.False(result.Reached);
        Assert.Empty(result.Advisories);
    }

    private sealed class Factory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public Factory(string baseUrl) => _client = new HttpClient { BaseAddress = new Uri(baseUrl) };
        public HttpClient CreateClient(string name) => _client;
    }
}
