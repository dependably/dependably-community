using System.Net;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// OSV pages a result with <c>next_page_token</c>. An advisory on a later page must be found, and a
/// chain that cannot be finished must read as unreached, never as a clean version.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvClientPagingTests : IDisposable
{
    private const string Purl = "pkg:npm/left-pad@1.0.0";
    private const string OtherPurl = "pkg:npm/other@2.0.0";

    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly OsvClient _sut;

    public OsvClientPagingTests() =>
        _sut = new OsvClient(new Factory(_server.Urls[0] + "/"), NullLogger<OsvClient>.Instance);

    public void Dispose() => _server.Stop();

    private void Stub(string path, string? bodyContains, int priority, HttpStatusCode status, string body)
    {
        var req = Request.Create().WithPath(path).UsingPost();
        if (bodyContains is not null)
        {
            req = req.WithBody(new WildcardMatcher($"*{bodyContains}*"));
        }
        _server.Given(req).AtPriority(priority)
            .RespondWith(Response.Create().WithStatusCode(status).WithBody(body));
    }

    [Fact]
    public async Task Query_FollowsNextPageToken_AndReturnsEveryPage()
    {
        Stub("/query", "\"page_token\":\"tok2\"", 1, HttpStatusCode.OK, """{"vulns":[{"id":"GHSA-PAGE2","summary":"s"}]}""");
        Stub("/query", null, 5, HttpStatusCode.OK, """{"vulns":[{"id":"GHSA-PAGE1","summary":"s"}],"next_page_token":"tok2"}""");

        var result = await _sut.TryQueryAsync(Purl);

        Assert.True(result.Reached);
        Assert.Equal(["GHSA-PAGE1", "GHSA-PAGE2"], result.Advisories.Select(a => a.Id).ToArray());
    }

    [Fact]
    public async Task Query_EndlessPaging_IsUnreached_NotServedTruncated()
    {
        Stub("/query", null, 5, HttpStatusCode.OK, """{"vulns":[{"id":"GHSA-X","summary":"s"}],"next_page_token":"again"}""");

        var result = await _sut.TryQueryAsync(Purl);

        Assert.False(result.Reached);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task Query_LaterPageFails_IsUnreached()
    {
        Stub("/query", "\"page_token\":\"tok2\"", 1, HttpStatusCode.InternalServerError, "{}");
        Stub("/query", null, 5, HttpStatusCode.OK, """{"vulns":[{"id":"GHSA-PAGE1","summary":"s"}],"next_page_token":"tok2"}""");

        var result = await _sut.TryQueryAsync(Purl);

        Assert.False(result.Reached);
    }

    [Fact]
    public async Task Batch_PagedResult_IsCompletedWhileUnpagedNeighbourIsUntouched()
    {
        Stub("/querybatch", null, 5, HttpStatusCode.OK,
            """{"results":[{"vulns":[{"id":"GHSA-PAGE1"}],"next_page_token":"tok2"},{"vulns":[{"id":"GHSA-OTHER"}]}]}""");
        Stub("/query", "\"page_token\":\"tok2\"", 1, HttpStatusCode.OK, """{"vulns":[{"id":"GHSA-PAGE2","summary":"s"}]}""");
        Stub("/query", null, 5, HttpStatusCode.OK, """{"vulns":[{"id":"GHSA-PAGE1","summary":"s"}],"next_page_token":"tok2"}""");
        _server.Given(Request.Create().WithPath("/vulns/GHSA-OTHER").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("""{"id":"GHSA-OTHER","summary":"s"}"""));

        var result = await _sut.TryQueryBatchAsync([Purl, OtherPurl]);

        Assert.True(result.Reached);
        Assert.Equal(["GHSA-PAGE1", "GHSA-PAGE2"], result.Results[0].Select(a => a.Id).ToArray());
        Assert.Equal("GHSA-OTHER", Assert.Single(result.Results[1]).Id);
    }

    [Fact]
    public async Task Batch_PagedResultInTheMiddle_IsCompletedForItsOwnPurl()
    {
        const string ThirdPurl = "pkg:npm/third@3.0.0";
        Stub("/querybatch", null, 5, HttpStatusCode.OK,
            """{"results":[{"vulns":[]},{"vulns":[{"id":"GHSA-PAGE1"}],"next_page_token":"tok2"},{"vulns":[]}]}""");
        // Only the paged purl's own query is answered, so re-querying a neighbour fails the batch.
        Stub("/query", $"{Purl}*\"page_token\":\"tok2\"", 1, HttpStatusCode.OK,
            """{"vulns":[{"id":"GHSA-PAGE2","summary":"s"}]}""");
        Stub("/query", Purl, 5, HttpStatusCode.OK,
            """{"vulns":[{"id":"GHSA-PAGE1","summary":"s"}],"next_page_token":"tok2"}""");

        var result = await _sut.TryQueryBatchAsync([OtherPurl, Purl, ThirdPurl]);

        Assert.True(result.Reached);
        Assert.Empty(result.Results[0]);
        Assert.Equal(["GHSA-PAGE1", "GHSA-PAGE2"], result.Results[1].Select(a => a.Id).ToArray());
        Assert.Empty(result.Results[2]);
    }

    [Fact]
    public async Task Batch_PagedResultWhoseChainFails_MakesTheBatchUnreached()
    {
        Stub("/querybatch", null, 5, HttpStatusCode.OK,
            """{"results":[{"vulns":[{"id":"GHSA-PAGE1"}],"next_page_token":"tok2"},{"vulns":[]}]}""");
        Stub("/query", null, 5, HttpStatusCode.InternalServerError, "{}");

        var result = await _sut.TryQueryBatchAsync([Purl, OtherPurl]);

        Assert.False(result.Reached);
        Assert.All(result.Results, r => Assert.Empty(r));
    }

    private sealed class Factory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public Factory(string baseUrl) => _client = new HttpClient { BaseAddress = new Uri(baseUrl) };
        public HttpClient CreateClient(string name) => _client;
    }
}
