using System.Net;
using System.Text;
using Dependably.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Covers <see cref="HttpThreatFeedSource"/>'s feed parsing against canned responses:
/// KEV entry extraction with malformed entries skipped, EPSS string-encoded score parsing,
/// the queried-vs-scored distinction for CVEs unknown to EPSS, and per-batch failure
/// isolation (one failing batch must not lose the others).
/// </summary>
[Trait("Category", "Unit")]
public sealed class HttpThreatFeedSourceTests
{
    private static HttpThreatFeedSource Build(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        return new HttpThreatFeedSource(
            new SingleHandlerFactory(new DelegateHandler(responder)),
            new ConfigurationBuilder().Build(),
            NullLogger<HttpThreatFeedSource>.Instance);
    }

    [Fact]
    public async Task Kev_ParsesCveIds_AndSkipsMalformedEntries()
    {
        var source = Build(_ => Json("""
            {"vulnerabilities":[
                {"cveID":"CVE-2021-44228","vendorProject":"Apache"},
                {"vendorProject":"missing-id"},
                {"cveID":""},
                {"cveID":"CVE-2024-3094"},
                {"cveID":"CVE-2024-3094"}
            ]}
            """));

        var ids = await source.GetKevCveIdsAsync();

        Assert.Equal(2, ids.Count);
        Assert.Contains("CVE-2021-44228", ids);
        Assert.Contains("cve-2024-3094", ids); // case-insensitive set
    }

    [Fact]
    public async Task Kev_HttpFailure_Throws()
    {
        var source = Build(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        await Assert.ThrowsAsync<HttpRequestException>(() => source.GetKevCveIdsAsync());
    }

    [Fact]
    public async Task Epss_ParsesStringScores_AndMarksWholeBatchQueried()
    {
        var source = Build(_ => Json("""
            {"data":[
                {"cve":"CVE-2024-0001","epss":"0.97558","percentile":"0.99"},
                {"cve":"CVE-2024-0002","epss":"not-a-number"}
            ]}
            """));

        var result = await source.GetEpssScoresAsync(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]);

        Assert.Equal(0.97558, Assert.Contains("CVE-2024-0001", result.Scores));
        Assert.False(result.Scores.ContainsKey("CVE-2024-0002")); // malformed score skipped
        // All three were queried successfully — absence means "unknown to EPSS", not failure.
        Assert.Equal(3, result.Queried.Count);
        Assert.Contains("CVE-2024-0003", result.Queried);
    }

    [Fact]
    public async Task Epss_OneFailedBatch_OthersStillParsed()
    {
        // 150 CVEs = two batches of 100/50. The first request fails; the second succeeds.
        // The mixed outcome must surface as: batch-1 CVEs absent from Queried (retryable),
        // batch-2 CVEs queried and scored where known.
        var cves = Enumerable.Range(1, 150).Select(i => $"CVE-2024-{i:D4}").ToList();
        int call = 0;
        var source = Build(req =>
        {
            call++;
            return call == 1
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                : Json($$"""{"data":[{"cve":"{{cves[100]}}","epss":"0.42"}]}""");
        });

        var result = await source.GetEpssScoresAsync(cves);

        Assert.Equal(2, call);
        Assert.Equal(50, result.Queried.Count);
        Assert.DoesNotContain(cves[0], result.Queried);
        Assert.Contains(cves[100], result.Queried);
        Assert.Equal(0.42, Assert.Contains(cves[100], result.Scores));
    }

    // ── plumbing ──────────────────────────────────────────────────────────────

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    private sealed class DelegateHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        public DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_responder(request));
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }
}
