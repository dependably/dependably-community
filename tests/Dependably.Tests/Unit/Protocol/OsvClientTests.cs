using System.Net;
using System.Text.Json;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

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
        string vulnJson = """
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

    // ── TryQueryAsync (reachability signal for PackageLookupService) ───────────

    [Fact]
    public async Task TryQueryAsync_SuccessfulResponseWithVulns_ReportsReached()
    {
        string vulnJson = """
            {"vulns":[{"id":"GHSA-aaaa","summary":"hello"}]}
            """;
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(vulnJson));

        var result = await _sut.TryQueryAsync("pkg:npm/foo@1.0.0");

        Assert.True(result.Reached);
        Assert.Single(result.Advisories);
        Assert.Equal("GHSA-aaaa", result.Advisories[0].Id);
    }

    [Fact]
    public async Task TryQueryAsync_ReachedButGenuinelyEmpty_ReportsReachedWithNoAdvisories()
    {
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("""{"vulns":[]}"""));

        var result = await _sut.TryQueryAsync("pkg:npm/foo@1.0.0");

        Assert.True(result.Reached);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task TryQueryAsync_ServerError_ReportsUnreached()
    {
        // 5xx is exactly the outage mode QueryAsync swallows into an empty list with no
        // exception — TryQueryAsync must still flag it as unreached.
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));

        var result = await _sut.TryQueryAsync("pkg:npm/foo@1.0.0");

        Assert.False(result.Reached);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task TryQueryAsync_ConnectionRefused_ReportsUnreached()
    {
        // A real network failure (connection refused): the exact case
        // OsvClient.QueryAsync's HttpRequestException catch swallows into []. Points the
        // client at a port nothing is listening on, exercising the real HttpClient/socket
        // path rather than a stubbed exception.
        var unreachableClient = new OsvClient(
            new SingleHandlerFactory("http://127.0.0.1:1/"), NullLogger<OsvClient>.Instance);

        var result = await unreachableClient.TryQueryAsync("pkg:npm/foo@1.0.0");

        Assert.False(result.Reached);
        Assert.Empty(result.Advisories);
    }

    // ── QueryBatchAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task QueryBatchAsync_SuccessfulBatch_HydratesPerVuln()
    {
        string batchJson = """
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
        string batchJson = """
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
        // An unreached hydration (503) with an unreachable re-query leaves the stripped record.
        string batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-MISS","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-MISS").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));

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
        {
            vulnsArr.Add(new { id = $"GHSA-{i:D4}", modified = "2026-01-01T00:00:00Z" });
        }

        string batchJson = JsonSerializer.Serialize(new
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
        int hydratedCount = result[0].Count(a => a.IsHydrated);
        int strippedCount = result[0].Count(a => !a.IsHydrated);
        Assert.Equal(500, hydratedCount);
        Assert.Equal(100, strippedCount);
    }

    // ── Raw advisory JSON capture (osv_json persistence) ────────────────────────

    [Fact]
    public async Task QueryAsync_HydratedAdvisory_CapturesRawJsonPerElement()
    {
        // /query returns {"vulns":[…]}; each advisory must carry the raw JSON of its own
        // array element (not the whole envelope) for persistence into vulnerabilities.osv_json.
        string vulnJson = """
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
        string batchJson = """
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
        // Hydration 503s ⇒ stripped record ⇒ IsHydrated false ⇒ RawJson null, so the upsert's
        // COALESCE can never clobber a previously-stored full advisory with this batch's stub.
        string batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-MISS","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-MISS").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        var advisory = Assert.Single(result[0]);
        Assert.False(advisory.IsHydrated);
        Assert.Null(advisory.RawJson);
    }

    [Fact]
    public async Task QueryBatchAsync_MixedHydration_CapturesRawJsonOnlyForHydrated()
    {
        // Mixed/partial batch: one advisory hydrates (RawJson set), the other 503s (RawJson null).
        string batchJson = """
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
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));

        var result = await _sut.QueryBatchAsync(new[] { "pkg:npm/ok@1.0.0", "pkg:npm/fail@1.0.0" });

        var ok = Assert.Single(result[0]);
        Assert.True(ok.IsHydrated);
        Assert.NotNull(ok.RawJson);
        Assert.Contains("GHSA-OK", ok.RawJson);

        var fail = Assert.Single(result[1]);
        Assert.False(fail.IsHydrated);
        Assert.Null(fail.RawJson);
    }

    // ── TryQueryBatchAsync: an incomplete answer is never a clean one ────────────

    [Fact]
    public async Task TryQueryBatchAsync_BodyWithoutResults_ReportsUnreached()
    {
        // A 200 with no results array answers nothing for any purl. Reported reached, every purl
        // would read as screened and clean.
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("{}"));

        var result = await _sut.TryQueryBatchAsync(new[] { "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0" });

        Assert.False(result.Reached);
        Assert.Equal(2, result.Results.Count);
        Assert.All(result.Results, Assert.Empty);
    }

    [Fact]
    public async Task TryQueryBatchAsync_BodyWithEmptyResults_IsReached()
    {
        // Twin: a results array, even one with empty slots, is a real answer.
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("""{"results":[{},{}]}"""));

        var result = await _sut.TryQueryBatchAsync(new[] { "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0" });

        Assert.True(result.Reached);
        Assert.All(result.Results, Assert.Empty);
    }

    [Fact]
    public async Task TryQueryBatchAsync_HydrationTimesOut_LeavesThatIdUnhydratedAndKeepsTheBatch()
    {
        // The HttpClient timeout surfaces as a TaskCanceledException while the caller's token is
        // live. It is a failed hydration of one id, not a cancellation of the whole batch.
        string batchJson = """
            {"results":[
              {"vulns":[{"id":"GHSA-FAST","modified":"2026-01-01T00:00:00Z"}]},
              {"vulns":[{"id":"GHSA-SLOW","modified":"2026-01-01T00:00:00Z"}]}
            ]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-FAST").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-FAST","summary":"fast"}"""));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-SLOW").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-SLOW","summary":"slow"}""")
                .WithDelay(TimeSpan.FromSeconds(10)));
        var sut = new OsvClient(
            new TimeoutHandlerFactory(_server.Urls[0] + "/", TimeSpan.FromSeconds(2)),
            NullLogger<OsvClient>.Instance);

        var result = await sut.TryQueryBatchAsync(new[] { "pkg:npm/fast@1.0.0", "pkg:npm/slow@1.0.0" });

        Assert.True(result.Reached);
        Assert.True(Assert.Single(result.Results[0]).IsHydrated);
        var slow = Assert.Single(result.Results[1]);
        Assert.Equal("GHSA-SLOW", slow.Id);
        Assert.False(slow.IsHydrated);
    }

    [Fact]
    public async Task TryQueryBatchAsync_MoreIdsThanTheHydrationCap_ResolvesThePurlThroughTheFullQuery()
    {
        // The cap takes the same ids in the same order on every pass, so an overflowing purl would
        // never resolve by hydration alone. It is re-queried through /query, which returns the
        // complete hydrated list.
        var ids = Enumerable.Range(0, 600).Select(i => $"GHSA-cap0-{i:D4}").ToList();
        string batchJson = JsonSerializer.Serialize(new
        {
            results = new[] { new { vulns = ids.Select(id => new { id, modified = "2026-01-01T00:00:00Z" }).ToArray() } },
        });
        string fullJson = JsonSerializer.Serialize(new { vulns = ids.Select(id => new { id, summary = "full" }).ToArray() });
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath(new RegexMatcher("^/vulns/.*$")).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("""{"id":"GHSA-x","summary":"hydrated"}"""));
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(fullJson));

        var result = await _sut.TryQueryBatchAsync(new[] { "pkg:pypi/tensorflow@1.0.0" });

        Assert.True(result.Reached);
        Assert.Equal(600, result.Results[0].Count);
        Assert.All(result.Results[0], a => Assert.True(a.IsHydrated));
        Assert.Equal(ids.ToHashSet(), result.Results[0].Select(a => a.Id).ToHashSet());
    }

    [Fact]
    public async Task TryQueryBatchAsync_HydrationUnreached_PurlResolvedThroughTheFullQuery()
    {
        // GET /vulns/{id} answered 503; the purl's own /query still answers in full.
        string batchJson = """{"results":[{"vulns":[{"id":"GHSA-5030-0001","modified":"2026-01-01T00:00:00Z"}]}]}""";
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-5030-0001").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));
        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"vulns":[{"id":"GHSA-5030-0001","summary":"full"}]}"""));

        var result = await _sut.TryQueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        var advisory = Assert.Single(result.Results[0]);
        Assert.True(advisory.IsHydrated);
        Assert.Equal("full", advisory.Summary);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task TryQueryBatchAsync_HydrationAnsweredUnknown_DropsTheId(HttpStatusCode status)
    {
        // OSV saying it holds no such id (a withdrawn record) is a reached answer: the id is
        // dropped, exactly as TryGetAdvisoryAsync defines it, rather than deferring the purl forever.
        string batchJson = """
            {"results":[{"vulns":[
              {"id":"GHSA-gone-0001","modified":"2026-01-01T00:00:00Z"},
              {"id":"GHSA-live-0001","modified":"2026-01-01T00:00:00Z"}
            ]}]}
            """;
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-gone-0001").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(status));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-live-0001").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("""{"id":"GHSA-live-0001"}"""));

        var result = await _sut.TryQueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        Assert.True(result.Reached);
        var live = Assert.Single(result.Results[0]);
        Assert.Equal("GHSA-live-0001", live.Id);
        Assert.True(live.IsHydrated);
    }

    [Fact]
    public async Task TryQueryBatchAsync_CallerCancelsDuringHydration_Propagates()
    {
        // Twin: the caller's own cancellation is not a failed hydration and still stops the call.
        string batchJson = """{"results":[{"vulns":[{"id":"GHSA-SLOW","modified":"2026-01-01T00:00:00Z"}]}]}""";
        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(batchJson));
        _server.Given(Request.Create().WithPath("/vulns/GHSA-SLOW").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"id":"GHSA-SLOW"}""")
                .WithDelay(TimeSpan.FromSeconds(10)));
        // now-ok: the cancellation has to land while a real HTTP request is in flight.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _sut.TryQueryBatchAsync(new[] { "pkg:npm/slow@1.0.0" }, cts.Token));
    }

    // ── Retry behaviour ────────────────────────────────────────────────────────

    [Fact]
    public async Task QueryAsync_429ThenSuccess_RetriesAndReturnsAdvisories()
    {
        // First call 429 (with Retry-After=0 to keep the test fast), then 200.
        // Exercises the SendWithRetryAsync retry loop + the int.TryParse Retry-After branch.
        string scenario = "rate-limit";
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
        string scenario = "bad-retry-after";
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

    // ── Size-cap degradation ───────────────────────────────────────────────────

    [Fact]
    public async Task QueryAsync_OversizedResponse_DegradesgracefullyToEmpty()
    {
        // A response whose body exceeds MaxResponseContentBufferSize triggers
        // HttpRequestException from ReadAsStringAsync. QueryAsync must return []
        // with no exception escaping to the caller.
        var cappedSut = new OsvClient(
            new SizeCappedHandlerFactory(_server.Urls[0] + "/", maxBodyBytes: 10),
            NullLogger<OsvClient>.Instance);

        _server.Given(Request.Create().WithPath("/query").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"vulns":[{"id":"GHSA-big","summary":"hello world this is a long body exceeding the tiny cap"}]}"""));

        var result = await cappedSut.QueryAsync("pkg:npm/foo@1.0.0");

        Assert.Empty(result);
    }

    [Fact]
    public async Task QueryBatchAsync_OversizedResponse_DegradesgracefullyToEmptyPerPurl()
    {
        // Oversized querybatch body => HttpRequestException => per-PURL empty lists returned,
        // no exception escapes. Mirrors the HTTP-failure path shape (same return value).
        var cappedSut = new OsvClient(
            new SizeCappedHandlerFactory(_server.Urls[0] + "/", maxBodyBytes: 10),
            NullLogger<OsvClient>.Instance);

        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"results":[{"vulns":[{"id":"GHSA-big","modified":"2026-01-01T00:00:00Z"}]},{"vulns":[]}]}"""));

        var result = await cappedSut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0" });

        Assert.Equal(2, result.Count);
        Assert.All(result, Assert.Empty);
    }

    [Fact]
    public async Task QueryBatchAsync_OversizedQueryBatchButHydrationOk_HydrationNotAttempted()
    {
        // When the /querybatch envelope itself is oversized, we never reach the hydration
        // fan-out — the graceful empty return means no /vulns/{id} calls are issued.
        // This is the mixed-failure scenario: batch body too large, individual hydrations
        // would have succeeded if attempted. Confirms the cap fires before the hydration loop.
        var cappedSut = new OsvClient(
            new SizeCappedHandlerFactory(_server.Urls[0] + "/", maxBodyBytes: 10),
            NullLogger<OsvClient>.Instance);

        _server.Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody("""{"results":[{"vulns":[{"id":"GHSA-big","modified":"2026-01-01T00:00:00Z"}]}]}"""));

        // If a /vulns/ call were made (which it must not be), the server has no stub for it
        // and WireMock would return 404 — but we assert no hydrated records appear.
        var result = await cappedSut.QueryBatchAsync(new[] { "pkg:npm/a@1.0.0" });

        Assert.Single(result);
        Assert.Empty(result[0]);
        // Confirm no hydration requests reached the server.
        bool anyVulnsCall = _server.LogEntries.Any(e => e.RequestMessage?.Path?.StartsWith("/vulns/") == true);
        Assert.False(anyVulnsCall);
    }

    // ── HasCoverageFor (remote path is unaffected by #608) ─────────────────────
    // The remote client makes no HTTP call for this member at all — coverage is exactly the
    // static OsvFeedCoverage gate, unlike LocalOsvSource's dynamic per-dump signal for RPM. These
    // pin that the fix for #608 (scoped to OSV_MODE=local) leaves the remote path's own RPM
    // behaviour — always query, always stamp on a reached answer — completely unchanged.

    [Fact]
    public async Task HasCoverageFor_Rpm_AlwaysTrue()
    {
        // RPM keeps scanning and stamping via the remote path exactly as before this fix: the
        // live osv.dev API resolves pkg:rpm purls against its own distro feeds server-side, with
        // no dump-coverage question on this end.
        Assert.True(await _sut.HasCoverageFor("rpm"));
    }

    [Fact]
    public async Task HasCoverageFor_NpmAndOtherFeedEcosystems_AreTrue()
    {
        Assert.True(await _sut.HasCoverageFor("npm"));
        Assert.True(await _sut.HasCoverageFor("pypi"));
    }

    [Fact]
    public async Task HasCoverageFor_StaticNoFeedEcosystems_AreFalse()
    {
        Assert.False(await _sut.HasCoverageFor("oci"));
        Assert.False(await _sut.HasCoverageFor("terraform"));
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

    /// <summary>IHttpClientFactory whose client gives up after a timeout, as the registered "osv" client does.</summary>
    private sealed class TimeoutHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public TimeoutHandlerFactory(string baseUrl, TimeSpan timeout) =>
            _client = new HttpClient { BaseAddress = new Uri(baseUrl), Timeout = timeout };
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>
    /// IHttpClientFactory that applies a tiny MaxResponseContentBufferSize so tests can
    /// exercise the size-cap degradation path without serving megabytes of data.
    /// </summary>
    private sealed class SizeCappedHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SizeCappedHandlerFactory(string baseUrl, long maxBodyBytes) =>
            _client = new HttpClient
            {
                BaseAddress = new Uri(baseUrl),
                MaxResponseContentBufferSize = maxBodyBytes,
            };
        public HttpClient CreateClient(string name) => _client;
    }
}
