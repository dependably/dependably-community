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

    // ── KEV entry context: the fields the catalogue carries beyond membership ──────────────

    [Fact]
    public async Task Kev_KnownRansomwareUse_IsTriState_NotABoolean()
    {
        // The whole point of the column. "Known" and "Unknown" are both CISA assertions; a
        // missing field is the absence of one. Collapsing the last two would let a gate arm read
        // "the source never said" as "the source said no", which is a fail-open.
        var source = Build(_ => Json("""
            {"vulnerabilities":[
                {"cveID":"CVE-2021-44228","knownRansomwareCampaignUse":"Known"},
                {"cveID":"CVE-2024-3094","knownRansomwareCampaignUse":"Unknown"},
                {"cveID":"CVE-2024-0001"},
                {"cveID":"CVE-2024-0002","knownRansomwareCampaignUse":"Maybe"},
                {"cveID":"CVE-2024-0003","knownRansomwareCampaignUse":null}
            ]}
            """));

        var catalog = await source.GetKevCatalogAsync();

        Assert.True(catalog["CVE-2021-44228"].KnownRansomwareCampaignUse);
        Assert.False(catalog["CVE-2024-3094"].KnownRansomwareCampaignUse);
        Assert.Null(catalog["CVE-2024-0001"].KnownRansomwareCampaignUse);
        // A value this code has never seen reads as "no assertion", not as a guess either way.
        Assert.Null(catalog["CVE-2024-0002"].KnownRansomwareCampaignUse);
        Assert.Null(catalog["CVE-2024-0003"].KnownRansomwareCampaignUse);
    }

    [Fact]
    public async Task Kev_ParsesTheCatalogueDates()
    {
        var source = Build(_ => Json("""
            {"vulnerabilities":[
                {"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","dueDate":"2021-12-24"},
                {"cveID":"CVE-2024-3094","dateAdded":"  2024-03-29  "},
                {"cveID":"CVE-2024-0001","dateAdded":""}
            ]}
            """));

        var catalog = await source.GetKevCatalogAsync();

        Assert.Equal("2021-12-10", catalog["CVE-2021-44228"].DateAdded);
        Assert.Equal("2021-12-24", catalog["CVE-2021-44228"].DueDate);
        Assert.Equal("2024-03-29", catalog["CVE-2024-3094"].DateAdded);
        // Absent and blank both mean "no date", never an empty string in the column.
        Assert.Null(catalog["CVE-2024-3094"].DueDate);
        Assert.Null(catalog["CVE-2024-0001"].DateAdded);
    }

    [Fact]
    public async Task Kev_MembershipSurvivesEntriesWithNoContextAtAll()
    {
        // The adversarial twin for the two tests above: parsing the new fields must not have made
        // a bare entry — which is most of the catalogue's shape historically — fail to register.
        var source = Build(_ => Json("""
            {"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}
            """));

        var catalog = await source.GetKevCatalogAsync();

        Assert.True(catalog.ContainsKey("CVE-2021-44228"));
        Assert.Equal(new KevEntry(null, null, null), catalog["CVE-2021-44228"]);
    }

    [Fact]
    public async Task Kev_ParsesRequiredActionCwesAndNotes()
    {
        var source = Build(_ => Json("""
            {"vulnerabilities":[
                {"cveID":"CVE-2021-44228",
                 "requiredAction":"Apply updates per vendor instructions.",
                 "cwes":["CWE-502","CWE-400"],
                 "notes":"https://vendor.example/advisory ; https://vendor.example/patch"}
            ]}
            """));

        var catalog = await source.GetKevCatalogAsync();
        var entry = catalog["CVE-2021-44228"];

        Assert.Equal("Apply updates per vendor instructions.", entry.RequiredAction);
        Assert.Equal(["CWE-502", "CWE-400"], entry.Cwes);
        Assert.Equal("https://vendor.example/advisory ; https://vendor.example/patch", entry.Notes);
    }

    [Fact]
    public async Task Kev_MissingRequiredActionCwesAndNotes_ParseAsNull_NotThrowing()
    {
        // A malformed or absent field on any single entry must never abort the pass — same
        // fail-soft posture as the existing cveID/date/ransomware parsing.
        var source = Build(_ => Json("""
            {"vulnerabilities":[
                {"cveID":"CVE-2021-44228"},
                {"cveID":"CVE-2024-0001","requiredAction":123,"cwes":"not-an-array","notes":null}
            ]}
            """));

        var catalog = await source.GetKevCatalogAsync();

        Assert.Null(catalog["CVE-2021-44228"].RequiredAction);
        Assert.Null(catalog["CVE-2021-44228"].Cwes);
        Assert.Null(catalog["CVE-2021-44228"].Notes);

        // Wrong-shaped values (a number where a string was expected, a string where an array
        // was expected) read as absent rather than throwing or aborting the batch.
        Assert.Null(catalog["CVE-2024-0001"].RequiredAction);
        Assert.Null(catalog["CVE-2024-0001"].Cwes);
        Assert.Null(catalog["CVE-2024-0001"].Notes);
    }

    [Fact]
    public async Task Kev_EmptyCwesArray_IsDistinctFromMissingCwesField()
    {
        // "CISA explicitly recorded zero classifications" (empty, non-null list) is a different
        // fact from "CISA never asked the question" (null) — the two must not collapse.
        var source = Build(_ => Json("""
            {"vulnerabilities":[
                {"cveID":"CVE-2021-44228","cwes":[]},
                {"cveID":"CVE-2024-0001"}
            ]}
            """));

        var catalog = await source.GetKevCatalogAsync();

        Assert.NotNull(catalog["CVE-2021-44228"].Cwes);
        Assert.Empty(catalog["CVE-2021-44228"].Cwes!);
        Assert.Null(catalog["CVE-2024-0001"].Cwes);
    }

    // ── EPSS percentile ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Epss_PercentileIsOptional_AndAScoreSurvivesWithoutOne()
    {
        // The percentile must never gate the probability: the existing EPSS arm depends on the
        // probability, so a feed row missing or malforming the percentile has to still yield a
        // usable score rather than being dropped.
        var source = Build(_ => Json("""
            {"data":[
                {"cve":"CVE-2024-0001","epss":"0.5","percentile":"0.97"},
                {"cve":"CVE-2024-0002","epss":"0.4"},
                {"cve":"CVE-2024-0003","epss":"0.3","percentile":"not-a-number"},
                {"cve":"CVE-2024-0004","epss":"0.2","percentile":"1.5"}
            ]}
            """));

        var result = await source.GetEpssScoresAsync(
            ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"]);

        Assert.Equal(0.97, result.Scores["CVE-2024-0001"].Percentile);
        Assert.Null(result.Scores["CVE-2024-0002"].Percentile);
        Assert.Null(result.Scores["CVE-2024-0003"].Percentile);
        // Out of range is dropped, not clamped: a percentile of 1.5 means the feed changed shape,
        // and recording a guess would put a wrong number behind a gate threshold.
        Assert.Null(result.Scores["CVE-2024-0004"].Percentile);

        // Every one still carries its probability.
        Assert.Equal(0.5, result.Scores["CVE-2024-0001"].Probability);
        Assert.Equal(0.4, result.Scores["CVE-2024-0002"].Probability);
        Assert.Equal(0.3, result.Scores["CVE-2024-0003"].Probability);
        Assert.Equal(0.2, result.Scores["CVE-2024-0004"].Probability);
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

        var ids = await source.GetKevCatalogAsync();

        Assert.Equal(2, ids.Count);
        Assert.Contains("CVE-2021-44228", ids);
        Assert.Contains("cve-2024-3094", ids); // case-insensitive set
    }

    [Fact]
    public async Task Kev_HttpFailure_Throws()
    {
        var source = Build(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        await Assert.ThrowsAsync<HttpRequestException>(() => source.GetKevCatalogAsync());
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

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() => source.GetKevCatalogAsync());
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

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() => source.GetKevCatalogAsync());
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

        var first = Assert.Contains("CVE-2024-0001", result.Scores);
        Assert.Equal(0.97558, first.Probability);
        // The percentile rides alongside the probability rather than being dropped.
        Assert.Equal(0.99, first.Percentile);
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
        Assert.Equal(0.42, Assert.Contains(cves[100], result.Scores).Probability);
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
        Assert.Equal(0.42, Assert.Contains(cves[100], result.Scores).Probability);
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
