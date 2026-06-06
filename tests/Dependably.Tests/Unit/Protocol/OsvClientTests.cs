using System.Net;
using System.Text.Json;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Coverage tests for <see cref="OsvClient"/>. Each test spins up a WireMock server
/// stubbing the relevant OSV endpoints (querybatch, query, vulns/{id}) and points
/// the OsvClient HttpClient at it. We never hit live api.osv.dev.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvClientTests : IDisposable
{
    private readonly WireMockServer _server;
    private readonly OsvClient _sut;

    public OsvClientTests()
    {
        _server = WireMockServer.Start();
        _sut = new OsvClient(new SingleHandlerFactory(_server.Urls[0] + "/"),
            NullLogger<OsvClient>.Instance);
    }

    public void Dispose() => _server.Stop();

    // ── QueryAsync (single PURL) ───────────────────────────────────────────────

    [Fact]
    public async Task QueryAsync_SuccessfulResponseWithVulns_ReturnsHydrated()
    {
        var vulnJson = """
            {"vulns":[{"id":"GHSA-aaaa","summary":"hello"}]}
            """;
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(vulnJson));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Single(result);
        Assert.Equal("GHSA-aaaa", result[0].Id);
        Assert.True(result[0].IsHydrated);
        Assert.Equal("hello", result[0].Summary);
    }

    [Fact]
    public async Task QueryAsync_NonSuccessStatus_ReturnsEmptyAndLogs()
    {
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Empty(result);
    }

    [Fact]
    public async Task QueryAsync_NullVulnsInResponse_ReturnsEmpty()
    {
        // result?.Vulns null branch
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("{}"));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Empty(result);
    }

    // ── QueryBatchAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task QueryBatchAsync_SuccessfulBatch_HydratesPerVuln()
    {
        var batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-1","modified":"2026-01-01T00:00:00Z"}]},
              {"vulns":[]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));

        // vuln detail (hydration)
        _server.Given(Request.Create().WithPath("/vulns/GHSA-1").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-1","summary":"hydrated"}"""));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0" });

        Assert.Equal(2, result.Count);
        Assert.Single(result[0]);
        Assert.True(result[0][0].IsHydrated);
        Assert.Equal("hydrated", result[0][0].Summary);
        Assert.Empty(result[1]);
    }

    [Fact]
    public async Task QueryBatchAsync_HttpFailure_ReturnsEmptyListPerPurl()
    {
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.BadGateway));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0" });

        Assert.Equal(2, result.Count);
        Assert.All(result, Assert.Empty);
    }

    [Fact]
    public async Task QueryBatchAsync_NullResultsInResponse_FallsBackToPerPurlEmpty()
    {
        // batchResult?.Results null branch — body has no results key
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("{}"));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0" });

        Assert.Equal(2, result.Count);
        Assert.All(result, Assert.Empty);
    }

    [Fact]
    public async Task QueryBatchAsync_VulnWithoutId_IsSkippedFromHydration()
    {
        // string.IsNullOrEmpty(id) branch — and per-PURL fallback to stripped record
        var batchJson = """
            {"results":[
              {"vulns":[{"modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        Assert.Single(result);
        Assert.Single(result[0]);
        Assert.False(result[0][0].IsHydrated);
    }

    [Fact]
    public async Task QueryBatchAsync_HydrationFailure_FallsBackToStripped()
    {
        // FetchAdvisoryAsync non-success branch: 404 ⇒ null ⇒ stripped fallback.
        var batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-MISS","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-MISS").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        Assert.Single(result[0]);
        Assert.False(result[0][0].IsHydrated);
        Assert.Equal("GHSA-MISS", result[0][0].Id);
    }

    [Fact]
    public async Task QueryBatchAsync_HydrationCap_LogsAndTruncates()
    {
        // uniqueIds.Count > MaxHydrationsPerBatch (500) branch — generate 600 distinct IDs.
        var vulnsArr = new List<object>();
        for (int i = 0; i < 600; i++)
            vulnsArr.Add(new { id = $"GHSA-{i:D4}", modified = "2026-01-01T00:00:00Z" });

        var batchJson = JsonSerializer.Serialize(new
        {
            results = new[] { new { vulns = vulnsArr.ToArray() } }
        });

        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));

        // Every /vulns/{id} GET succeeds. Of 600 raw vulns, only 500 should hydrate;
        // the remainder fall back to stripped records.
        _server.Given(Request.Create().WithPath(new RegexMatcher("^/vulns/.*$")).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-x","summary":"hydrated"}"""));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        Assert.Single(result);
        Assert.Equal(600, result[0].Count);
        var hydratedCount = result[0].Count(a => a.IsHydrated);
        var strippedCount = result[0].Count(a => !a.IsHydrated);
        Assert.Equal(500, hydratedCount);
        Assert.Equal(100, strippedCount);
    }

    // ── Raw advisory JSON capture (osv_json persistence) ────────────────────────

    [Fact]
    public async Task QueryAsync_HydratedAdvisory_CapturesRawJsonPerElement()
    {
        // /query returns {"vulns":[…]}; each advisory must carry the raw JSON of its own
        // array element (not the whole envelope) for persistence into vulnerabilities.osv_json.
        var vulnJson = """
            {"vulns":[
              {"id":"GHSA-aaaa","summary":"hello","details":"# heading","references":[{"type":"WEB","url":"https://example.test"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(vulnJson));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Single(result);
        Assert.True(result[0].IsHydrated);
        Assert.NotNull(result[0].RawJson);
        using var parsed = JsonDocument.Parse(result[0].RawJson!);
        Assert.Equal("GHSA-aaaa", parsed.RootElement.GetProperty("id").GetString());
        // The captured text is the advisory element, not the {"vulns":[…]} envelope.
        Assert.False(parsed.RootElement.TryGetProperty("vulns", out _));
        Assert.Equal("# heading", parsed.RootElement.GetProperty("details").GetString());
    }

    [Fact]
    public async Task QueryBatchAsync_HydratedAdvisory_CapturesRawJsonFromVulnsEndpoint()
    {
        var batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-1","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-1").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-1","summary":"hydrated","withdrawn":"2026-02-01T00:00:00Z"}"""));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        var advisory = Assert.Single(result[0]);
        Assert.True(advisory.IsHydrated);
        Assert.NotNull(advisory.RawJson);
        using var parsed = JsonDocument.Parse(advisory.RawJson!);
        Assert.Equal("GHSA-1", parsed.RootElement.GetProperty("id").GetString());
        Assert.Equal("2026-02-01T00:00:00Z", parsed.RootElement.GetProperty("withdrawn").GetString());
    }

    [Fact]
    public async Task QueryBatchAsync_StrippedFallback_HasNullRawJson()
    {
        // Hydration 404s ⇒ stripped record ⇒ IsHydrated false ⇒ RawJson null, so the upsert's
        // COALESCE can never clobber a previously-stored full advisory with this batch's stub.
        var batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-MISS","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-MISS").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        var advisory = Assert.Single(result[0]);
        Assert.False(advisory.IsHydrated);
        Assert.Null(advisory.RawJson);
    }

    [Fact]
    public async Task QueryBatchAsync_MixedHydration_CapturesRawJsonOnlyForHydrated()
    {
        // Mixed/partial batch: one advisory hydrates (RawJson set), the other 404s (RawJson null).
        var batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-OK","modified":"2026-01-01T00:00:00Z"}]},
              {"vulns":[{"id":"GHSA-FAIL","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-OK").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-OK","summary":"good"}"""));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-FAIL").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/ok@1.0.0", "pkg:npm/fail@1.0.0" });

        var ok = Assert.Single(result[0]);
        Assert.True(ok.IsHydrated);
        Assert.NotNull(ok.RawJson);
        Assert.Contains("GHSA-OK", ok.RawJson);

        var fail = Assert.Single(result[1]);
        Assert.False(fail.IsHydrated);
        Assert.Null(fail.RawJson);
    }

    // ── Retry behaviour ────────────────────────────────────────────────────────

    [Fact]
    public async Task QueryAsync_429ThenSuccess_RetriesAndReturnsAdvisories()
    {
        // First call 429 (with Retry-After=0 to keep the test fast), then 200.
        // Exercises the SendWithRetryAsync retry loop + the int.TryParse Retry-After branch.
        var scenario = "rate-limit";
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .InScenario(scenario).WillSetStateTo("retry")
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.TooManyRequests)
                .WithHeader("Retry-After", "0"));

        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .InScenario(scenario).WhenStateIs("retry")
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"vulns":[{"id":"GHSA-RETRY","summary":"ok"}]}"""));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Single(result);
        Assert.Equal("GHSA-RETRY", result[0].Id);
    }

    [Fact]
    public async Task QueryAsync_429ExhaustsAllRetries_ReturnsEmpty()
    {
        // Always 429 with Retry-After=0 (instant retry) — loop exhausts all 3 attempts
        // and returns the synthetic 429 ⇒ QueryAsync returns []. Covers the for-loop exit.
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.TooManyRequests)
                .WithHeader("Retry-After", "0"));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Empty(result);
    }

    [Fact]
    public async Task QueryAsync_429WithUnparseableRetryAfter_StillRetriesAndSucceeds()
    {
        // int.TryParse fails branch — Retry-After: "soon" — delay stays at default (1000ms).
        // Second attempt succeeds, so the retry path is taken without cancellation needed.
        var scenario = "bad-retry-after";
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .InScenario(scenario).WillSetStateTo("after-bad")
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.TooManyRequests)
                .WithHeader("Retry-After", "not-a-number"));

        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .InScenario(scenario).WhenStateIs("after-bad")
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"vulns":[{"id":"GHSA-OK"}]}"""));

        var result = await _sut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Single(result);
        Assert.Equal("GHSA-OK", result[0].Id);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Minimal IHttpClientFactory returning a single HttpClient whose BaseAddress
    /// points at the WireMock server (mirrors how OsvClient is wired in Program.cs).
    /// </summary>
    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(string baseUrl) =>
            _client = new HttpClient { BaseAddress = new Uri(baseUrl) };
        public HttpClient CreateClient(string name) => _client;
    }
}
