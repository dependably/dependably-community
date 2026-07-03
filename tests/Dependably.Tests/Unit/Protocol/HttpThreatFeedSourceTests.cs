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
    // One byte over the source's feed-response cap.
    private const int OverCapSize = (int)HttpThreatFeedSource.MaxFeedResponseBytes + 1;

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

    /// <summary>
    /// Regression: an oversized KEV feed response (attacker-controlled or compromised mirror,
    /// or a misconfigured KEV_FEED_URL pointing at something huge) must not be buffered
    /// unbounded. No Content-Length is set so the counted-copy loop — not the declared-length
    /// fast path — has to enforce the cap.
    /// </summary>
    [Fact]
    public async Task Kev_OversizedResponse_ThrowsTooLarge()
    {
        var source = Build(_ =>
        {
            byte[] body = new byte[OverCapSize];
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentLength = null;
            return response;
        });

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() => source.GetKevCveIdsAsync());
    }

    /// <summary>
    /// Regression: the KEV fetch must use <c>HttpCompletionOption.ResponseHeadersRead</c>.
    /// The default (ResponseContentRead) has HttpClient itself buffer the whole body via
    /// <c>SerializeToStreamAsync</c> before the cap check ever runs, silently defeating a
    /// declared-Content-Length fast path that assumes the body is untouched. This content
    /// throws if its body is ever serialized, so a Content-Length-only cap check without
    /// ResponseHeadersRead trips it during <c>SendAsync</c> itself rather than throwing the
    /// expected <see cref="UpstreamResponseTooLargeException"/>.
    /// </summary>
    [Fact]
    public async Task Kev_DeclaredOversizeContentLength_FailsBeforeReadingBody()
    {
        var source = Build(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new PoisonContent(OverCapSize),
        });

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() => source.GetKevCveIdsAsync());
    }

    /// <summary>HttpContent that declares a Content-Length but throws if its body is ever read.</summary>
    private sealed class PoisonContent : HttpContent
    {
        private readonly long _declaredLength;

        public PoisonContent(long declaredLength) => _declaredLength = declaredLength;

        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
            => throw new InvalidOperationException("Body must not be read when Content-Length exceeds the cap.");

        protected override bool TryComputeLength(out long length)
        {
            length = _declaredLength;
            return true;
        }
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

    /// <summary>
    /// Mixed partial-failure regression: one EPSS batch returns an oversized body (over the
    /// feed-response cap, no Content-Length so the counted-copy loop enforces it) while the
    /// other batch succeeds in the same call. The oversized batch's CVEs stay unqueried
    /// (retryable next pass) without aborting the successful batch — mirroring the existing
    /// one-failed-batch isolation, now for the size-cap failure mode specifically.
    /// </summary>
    [Fact]
    public async Task Epss_OneBatchOversized_OtherBatchStillParsed()
    {
        var cves = Enumerable.Range(1, 150).Select(i => $"CVE-2024-{i:D4}").ToList();
        int call = 0;
        var source = Build(req =>
        {
            call++;
            if (call == 1)
            {
                byte[] body = new byte[OverCapSize];
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
                response.Content.Headers.ContentLength = null;
                return response;
            }

            return Json($$"""{"data":[{"cve":"{{cves[100]}}","epss":"0.42"}]}""");
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
