using System.Net;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The enrichment client against a stubbed producer. <b>The producer's
/// <c>POST /lookup/batch</c> does not exist yet</b> — these stubs encode the contract the
/// enrichment-overlay design records (purls in, results parallel to inputs, an explicit
/// <c>status</c> per advisory, a per-source freshness array, bearer auth, a 1000-purl cap that is
/// rejected rather than truncated) and nothing else. They pin this client's behaviour against
/// that contract; they cannot pin the contract itself.
///
/// <para>
/// Every negative assertion here is paired with a twin that discriminates it. "A 429 is
/// unreached" says nothing unless a 200 over the same wiring is reached; "an unconfigured
/// connection makes no request" says nothing unless a configured one does.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerEnrichmentClientTests : IDisposable
{
    private const string Purl = "pkg:npm/left-pad@1.3.0";

    /// <summary>
    /// A lookup target with no CVE hints — the shape a caller uses when it has only a purl.
    /// The hints are exercised separately; every case here is about the response contract.
    /// </summary>
    private static EnrichmentLookupTarget Target(string purl) => new(purl, []);
    private const string OtherPurl = "pkg:pypi/requests@2.31.0";

    private readonly WireMockServer _server = WireMockServer.Start();

    public void Dispose() => _server.Stop();

    // ── Reached: the twin that makes every unreached assertion below mean something ───

    [Fact]
    public async Task A_reached_response_carrying_enrichment_applies_it()
    {
        StubLookup($$"""
            {
              "results": [
                {
                  "purl": "{{Purl}}",
                  "advisories": [
                    {
                      "vuln_id": "GHSA-aaaa-bbbb-cccc",
                      "canonical_cve": "CVE-2026-1000",
                      "status": "active",
                      "nist_band": "HIGH", "nist_score": 8.1,
                      "ssvc_exploitation": "active", "ssvc_automatable": "yes", "ssvc_technical_impact": "total"
                    }
                  ]
                }
              ],
              "freshness": [
                { "source": "nvd", "last_ingest": "2026-06-14T03:00:00Z" },
                { "source": "vulnrichment", "last_ingest": "2026-06-13T03:00:00Z" }
              ]
            }
            """);

        var clock = TestTime.Frozen();
        var result = await Build(clock).TryLookupBatchAsync([Target(Purl)]);

        Assert.True(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.None, result.Reason);
        // The local freshness fact is the injected clock's instant, exactly.
        Assert.Equal(TestTime.KnownNow, result.CheckedAt);
        // The producer-asserted fact is separate, and per source.
        Assert.Equal(new DateTimeOffset(2026, 6, 14, 3, 0, 0, TimeSpan.Zero), result.AssertedAsOf(EnrichmentSignal.Nvd));
        Assert.Equal(new DateTimeOffset(2026, 6, 13, 3, 0, 0, TimeSpan.Zero), result.AssertedAsOf(EnrichmentSignal.Ssvc));

        var advisory = Assert.Single(Assert.Single(result.Results));
        Assert.Equal("GHSA-aaaa-bbbb-cccc", advisory.AdvisoryId);
        Assert.Equal("CVE-2026-1000", advisory.Cve);
        Assert.Equal(EnrichmentAdvisoryStatus.Active, advisory.Status);
        Assert.Equal("HIGH", advisory.Nvd!.Severity);
        Assert.Equal(8.1, advisory.Nvd.Score);
        Assert.Equal("active", advisory.Ssvc!.Exploitation);
        Assert.Equal("yes", advisory.Ssvc.Automatable);
        Assert.Equal("total", advisory.Ssvc.TechnicalImpact);

        // Reachable under either key the caller might hold.
        Assert.Equal(EnrichmentDisposition.Apply, result.Decide("CVE-2026-1000").Disposition);
        Assert.Equal(EnrichmentDisposition.Apply, result.Decide("GHSA-aaaa-bbbb-cccc").Disposition);
    }

    [Fact]
    public async Task A_reached_response_carrying_nothing_is_reached_and_empty()
    {
        // The genuine all-clean answer. It must be distinguishable from every unreached result
        // below by exactly one thing: Reached.
        StubLookup($$"""
            { "results": [ { "purl": "{{Purl}}", "advisories": [] } ], "freshness": [] }
            """);

        var result = await Build().TryLookupBatchAsync([Target(Purl)]);

        Assert.True(result.Reached);
        Assert.Empty(Assert.Single(result.Results));
        Assert.Equal(EnrichmentDisposition.NoSignal, result.Decide("CVE-2026-1000").Disposition);
    }

    // ── Status: the only thing that ever clears ──────────────────────────────

    [Theory]
    [InlineData("withdrawn", EnrichmentAdvisoryStatus.Withdrawn)]
    [InlineData("rejected", EnrichmentAdvisoryStatus.Rejected)]
    public async Task An_explicit_negative_status_clears(string status, EnrichmentAdvisoryStatus expected)
    {
        StubAdvisory($$"""
            { "vuln_id": "GHSA-x", "canonical_cve": "CVE-2026-1000", "status": "{{status}}" }
            """);

        var decision = (await Build().TryLookupBatchAsync([Target(Purl)])).Decide("CVE-2026-1000");

        Assert.Equal(EnrichmentDisposition.Clear, decision.Disposition);
        Assert.Equal(expected, decision.Advisory!.Status);
    }

    [Fact]
    public async Task A_disputed_advisory_is_surfaced_rather_than_dropped()
    {
        StubAdvisory("""
            { "vuln_id": "GHSA-x", "canonical_cve": "CVE-2026-1000", "status": "disputed",
              "nist_band": "MEDIUM", "nist_score": 5.3 }
            """);

        var decision = (await Build().TryLookupBatchAsync([Target(Purl)])).Decide("CVE-2026-1000");

        // Disputed is contested, not retracted: it applies, carrying the status so a caller can
        // render the dispute rather than silently treating it as clean.
        Assert.Equal(EnrichmentDisposition.Apply, decision.Disposition);
        Assert.Equal(EnrichmentAdvisoryStatus.Disputed, decision.Advisory!.Status);
        Assert.Equal("MEDIUM", decision.Advisory.Nvd!.Severity);
    }

    [Fact]
    public async Task An_advisory_absent_from_a_reached_response_is_no_signal_never_a_clear()
    {
        // The twin of the withdrawn case above: same reached response, same caller question, and
        // the advisory simply is not in it. If absence cleared, a producer-side filter defect and
        // a genuine withdrawal would un-flag a vulnerability by the same mechanism.
        StubAdvisory("""
            { "vuln_id": "GHSA-other", "canonical_cve": "CVE-2026-9999", "status": "active" }
            """);

        var result = await Build().TryLookupBatchAsync([Target(Purl)]);

        Assert.True(result.Reached);
        var decision = result.Decide("CVE-2026-1000");
        Assert.Equal(EnrichmentDisposition.NoSignal, decision.Disposition);
        Assert.Null(decision.Advisory);
    }

    [Fact]
    public async Task A_status_this_client_cannot_interpret_is_no_signal()
    {
        // Not a clear (it might mean anything) and not an apply (we cannot vouch for it).
        StubAdvisory("""
            { "vuln_id": "GHSA-x", "canonical_cve": "CVE-2026-1000", "status": "quarantined",
              "nist_band": "CRITICAL", "nist_score": 9.8 }
            """);

        var decision = (await Build().TryLookupBatchAsync([Target(Purl)])).Decide("CVE-2026-1000");

        Assert.Equal(EnrichmentDisposition.NoSignal, decision.Disposition);
        Assert.Equal(EnrichmentAdvisoryStatus.Unrecognized, decision.Advisory!.Status);
    }

    // ── Unreached: every refusal, outage and unusable answer ─────────────────

    [Theory]
    [InlineData(500, EnrichmentUnreachedReason.ServerError)]
    [InlineData(503, EnrichmentUnreachedReason.ServerError)]
    [InlineData(429, EnrichmentUnreachedReason.RateLimited)]
    [InlineData(402, EnrichmentUnreachedReason.RateLimited)]
    [InlineData(401, EnrichmentUnreachedReason.Unauthorized)]
    [InlineData(403, EnrichmentUnreachedReason.Unauthorized)]
    [InlineData(400, EnrichmentUnreachedReason.Refused)]
    [InlineData(413, EnrichmentUnreachedReason.Refused)]
    public async Task A_refusal_is_unreached_and_never_a_clean_empty_answer(
        int status, EnrichmentUnreachedReason expected)
    {
        _server.Given(Request.Create().WithPath("/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(status));

        var result = await Build().TryLookupBatchAsync([Target(Purl), Target(OtherPurl)]);

        Assert.False(result.Reached);
        Assert.Equal(expected, result.Reason);
        // No local stamp may advance on a refusal — that stamp is what re-enables the gate arms.
        Assert.Null(result.CheckedAt);
        // Results are still full-length and empty, which is exactly why Reached has to carry it.
        Assert.Equal(2, result.Results.Count);
        Assert.All(result.Results, Assert.Empty);
        Assert.Equal(EnrichmentDisposition.NoSignal, result.Decide("CVE-2026-1000").Disposition);
    }

    [Fact]
    public async Task A_timeout_is_unreached()
    {
        _server.Given(Request.Create().WithPath("/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithDelay(TimeSpan.FromSeconds(10)));

        var result = await Build(httpTimeout: TimeSpan.FromMilliseconds(250)).TryLookupBatchAsync([Target(Purl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.Timeout, result.Reason);
        Assert.Null(result.CheckedAt);
    }

    [Fact]
    public async Task A_transport_failure_is_unreached()
    {
        // A base URL pointing at nothing: no listener, so the dial itself fails.
        var client = Build(baseUrl: "http://127.0.0.1:1/tracker");

        var result = await client.TryLookupBatchAsync([Target(Purl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.Transport, result.Reason);
    }

    [Fact]
    public async Task An_unparseable_body_is_unreached_rather_than_empty()
    {
        _server.Given(Request.Create().WithPath("/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody("<html>who knows</html>"));

        var result = await Build().TryLookupBatchAsync([Target(Purl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.MalformedResponse, result.Reason);
    }

    [Fact]
    public async Task A_result_count_that_does_not_match_the_request_is_unreached()
    {
        // Results are parallel to inputs by contract. A short array cannot be attributed, and
        // guessing would hand one package's enrichment to another.
        StubLookup($$"""
            { "results": [ { "purl": "{{Purl}}", "advisories": [] } ] }
            """);

        var result = await Build().TryLookupBatchAsync([Target(Purl), Target(OtherPurl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.MalformedResponse, result.Reason);
    }

    [Fact]
    public async Task A_result_answering_for_a_different_purl_is_unreached()
    {
        StubLookup($$"""
            { "results": [ { "purl": "{{OtherPurl}}", "advisories": [] } ] }
            """);

        var result = await Build().TryLookupBatchAsync([Target(Purl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.MalformedResponse, result.Reason);
    }

    // ── The batch cap: refused whole, never trimmed ──────────────────────────

    [Fact]
    public async Task A_batch_over_the_producer_cap_is_refused_without_a_request()
    {
        StubLookup("""{ "results": [] }""");
        var purls = Enumerable.Range(0, VulnTrackerSettings.MaxBatchSize + 1)
            .Select(i => Target($"pkg:npm/p{i}@1.0.0")).ToList();

        var result = await Build().TryLookupBatchAsync(purls);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.BatchTooLarge, result.Reason);
        Assert.Equal(purls.Count, result.Results.Count);
        // Nothing was truncated to fit, because nothing was sent.
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task A_batch_exactly_at_the_producer_cap_is_sent()
    {
        // The twin. Without it, the refusal above would also pass a client that refuses
        // everything.
        var purls = Enumerable.Range(0, VulnTrackerSettings.MaxBatchSize)
            .Select(i => Target($"pkg:npm/p{i}@1.0.0")).ToList();
        StubLookup("{ \"results\": [" + string.Join(",", purls.Select(p => $$"""{"purl":"{{p.Purl}}","advisories":[]}""")) + "] }");

        var result = await Build().TryLookupBatchAsync(purls);

        Assert.True(result.Reached);
        Assert.Single(_server.LogEntries);
    }

    // ── No connection, no call ───────────────────────────────────────────────

    [Fact]
    public async Task An_unconfigured_connection_makes_no_request()
    {
        StubLookup("""{ "results": [] }""");

        var result = await Build(baseUrl: null).TryLookupBatchAsync([Target(Purl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.NotConfigured, result.Reason);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task A_connection_switched_off_makes_no_request()
    {
        StubLookup("""{ "results": [] }""");

        var result = await Build(enabled: false).TryLookupBatchAsync([Target(Purl)]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.NotConfigured, result.Reason);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task An_empty_request_makes_no_request()
    {
        StubLookup("""{ "results": [] }""");

        var result = await Build().TryLookupBatchAsync([]);

        Assert.False(result.Reached);
        Assert.Equal(EnrichmentUnreachedReason.EmptyRequest, result.Reason);
        Assert.Empty(_server.LogEntries);
    }

    // ── Request shape ────────────────────────────────────────────────────────

    [Fact]
    public async Task The_request_presents_the_configured_bearer_token_and_the_requested_purls()
    {
        StubLookup($$"""{ "results": [ { "purl": "{{Purl}}", "advisories": [] } ] }""");

        await Build(token: "vt_secret_token").TryLookupBatchAsync([Target(Purl)]);

        var request = SingleRequest();
        Assert.Equal("Bearer vt_secret_token", Assert.Single(request.Headers!["Authorization"]));
        Assert.Contains(Purl, request.Body);
        Assert.Contains("purls", request.Body);
    }

    [Fact]
    public async Task A_connection_with_no_token_presents_no_authorization_header()
    {
        // The twin: a credential-less tracker is a legitimate self-hosted shape, and the header
        // must be absent rather than sent empty.
        StubLookup($$"""{ "results": [ { "purl": "{{Purl}}", "advisories": [] } ] }""");

        await Build(token: null).TryLookupBatchAsync([Target(Purl)]);

        Assert.False(SingleRequest().Headers!.ContainsKey("Authorization"));
    }

    [Fact]
    public async Task A_base_url_carrying_a_path_prefix_keeps_it()
    {
        _server.Given(Request.Create().WithPath("/api/v1/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithBody($$"""{ "results": [ { "purl": "{{Purl}}", "advisories": [] } ] }"""));

        var result = await Build(baseUrl: _server.Urls[0] + "/api/v1/").TryLookupBatchAsync([Target(Purl)]);

        Assert.True(result.Reached);
        Assert.Equal("/api/v1/lookup/batch", SingleRequest().Path);
    }

    // ── Value normalization: an uninterpretable value reads as unknown ───────

    [Fact]
    public async Task Values_outside_the_recorded_sets_are_dropped_rather_than_carried()
    {
        // The stored columns admit a closed token set each, and the gate arms read an absent
        // value as unknown. Carrying "SEVERE" or a score of 42 would either fail the write or
        // get compared against an operator's tolerance.
        StubAdvisory("""
            { "vuln_id": "GHSA-x", "canonical_cve": "CVE-2026-1000", "status": "active",
              "nist_band": "SEVERE", "nist_score": 42,
              "ssvc_exploitation": "maybe", "ssvc_automatable": "sometimes", "ssvc_technical_impact": "catastrophic" }
            """);

        var advisory = (await Build().TryLookupBatchAsync([Target(Purl)])).Decide("CVE-2026-1000").Advisory!;

        Assert.Null(advisory.Nvd);
        Assert.Null(advisory.Ssvc);
    }

    [Fact]
    public async Task A_none_band_is_a_real_band_and_is_kept()
    {
        // NVD assigns NONE to a 0.0 base score; the column admits it deliberately.
        StubAdvisory("""
            { "vuln_id": "GHSA-x", "canonical_cve": "CVE-2026-1000", "status": "active",
              "nist_band": "none", "nist_score": 0.0,
              "ssvc_exploitation": "NONE", "ssvc_automatable": "No", "ssvc_technical_impact": "Partial" }
            """);

        var advisory = (await Build().TryLookupBatchAsync([Target(Purl)])).Decide("CVE-2026-1000").Advisory!;

        Assert.Equal("NONE", advisory.Nvd!.Severity);
        Assert.Equal(0.0, advisory.Nvd.Score);
        Assert.Equal("none", advisory.Ssvc!.Exploitation);
        Assert.Equal("no", advisory.Ssvc.Automatable);
        Assert.Equal("partial", advisory.Ssvc.TechnicalImpact);
    }

    // ── Freshness: reachable is not the same as current ──────────────────────

    [Fact]
    public async Task A_reached_response_asserting_no_freshness_leaves_the_producer_stamp_unknown()
    {
        // A producer whose ingest broke still answers. With no asserted as-of there is no upper
        // bound on staleness, and null is what says so — the local stamp alone never certifies it.
        StubLookup($$"""{ "results": [ { "purl": "{{Purl}}", "advisories": [] } ] }""");

        var result = await Build().TryLookupBatchAsync([Target(Purl)]);

        Assert.True(result.Reached);
        Assert.NotNull(result.CheckedAt);
        Assert.Null(result.AssertedAsOf(EnrichmentSignal.Nvd));
        Assert.Null(result.AssertedAsOf(EnrichmentSignal.Ssvc));
    }

    [Fact]
    public async Task An_unusable_asserted_instant_reads_as_unknown_without_discarding_the_response()
    {
        StubLookup($$"""
            {
              "results": [ { "purl": "{{Purl}}", "advisories": [] } ],
              "freshness": [ { "source": "nvd", "last_ingest": "whenever" } ]
            }
            """);

        var result = await Build().TryLookupBatchAsync([Target(Purl)]);

        Assert.True(result.Reached);
        Assert.Null(result.AssertedAsOf(EnrichmentSignal.Nvd));
    }

    [Fact]
    public async Task A_caller_cancellation_is_not_swallowed_as_an_unreached_result()
    {
        // Shutdown is not a tracker failure, and must not be recorded as one.
        _server.Given(Request.Create().WithPath("/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithDelay(TimeSpan.FromSeconds(10)));
        using var cts = new CancellationTokenSource();
        var pending = Build().TryLookupBatchAsync([Target(Purl)], cts.Token);

        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    // ── Handshake: a deliberate identity announcement, distinct from a lookup ────

    [Fact]
    public async Task A_reached_handshake_sends_the_client_identity_and_bearer_token()
    {
        StubHandshake(200);

        bool sent = await Build(token: "vt_secret_token").TryHandshakeAsync();

        Assert.True(sent);
        var request = SingleRequest();
        Assert.Equal("/client/handshake", request.Path);
        Assert.Equal("Bearer vt_secret_token", Assert.Single(request.Headers!["Authorization"]));
        Assert.Contains("\"client_name\":\"dependably-community\"", request.Body);
        Assert.Contains("\"client_version\":", request.Body);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task A_non_2xx_handshake_response_is_false(int status)
    {
        StubHandshake(status);

        Assert.False(await Build().TryHandshakeAsync());
    }

    [Fact]
    public async Task A_handshake_transport_failure_is_false_not_thrown()
    {
        // Mirrors TryLookupBatchAsync's own contract: a remote failure never throws.
        var client = Build(baseUrl: "http://127.0.0.1:1/tracker");

        Assert.False(await client.TryHandshakeAsync());
    }

    [Fact]
    public async Task An_unconfigured_connection_sends_no_handshake()
    {
        StubHandshake(200);

        Assert.False(await Build(baseUrl: null).TryHandshakeAsync());
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task A_connection_switched_off_sends_no_handshake()
    {
        StubHandshake(200);

        Assert.False(await Build(enabled: false).TryHandshakeAsync());
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task A_handshake_caller_cancellation_is_not_swallowed()
    {
        _server.Given(Request.Create().WithPath("/client/handshake").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithDelay(TimeSpan.FromSeconds(10)));
        using var cts = new CancellationTokenSource();
        var pending = Build().TryHandshakeAsync(cts.Token);

        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    private void StubHandshake(int status) =>
        _server.Given(Request.Create().WithPath("/client/handshake").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(status));

    // ── Harness ──────────────────────────────────────────────────────────────

    /// <summary>The one request the stub server received, or a failure if there was not exactly one.</summary>
    private WireMock.IRequestMessage SingleRequest()
    {
        var entry = Assert.Single(_server.LogEntries);
        Assert.NotNull(entry);
        var request = entry.RequestMessage;
        Assert.NotNull(request);
        return request;
    }

    private void StubLookup(string body) =>
        _server.Given(Request.Create().WithPath("/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json").WithBody(body));

    /// <summary>Stubs a single-purl response carrying exactly one advisory object.</summary>
    private void StubAdvisory(string advisoryJson) =>
        StubLookup($$"""
            { "results": [ { "purl": "{{Purl}}", "advisories": [ {{advisoryJson}} ] } ] }
            """);

    private VulnTrackerEnrichmentClient Build(
        FakeTimeProvider? clock = null,
        string? baseUrl = "",
        string? token = "vt_token",
        bool enabled = true,
        TimeSpan? httpTimeout = null)
    {
        clock ??= TestTime.Frozen();
        var rows = new Dictionary<string, string?>
        {
            ["vuln_tracker_enabled"] = enabled ? "1" : "0",
            ["vuln_tracker_base_url"] = baseUrl == "" ? _server.Urls[0] : baseUrl,
            ["vuln_tracker_token"] = token,
        };

        var config = new InstanceVulnTrackerConfig(
            (key, _) => Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null),
            clock);

        return new VulnTrackerEnrichmentClient(
            new SingleClientFactory(httpTimeout),
            config,
            clock,
            NullLogger<VulnTrackerEnrichmentClient>.Instance);
    }

    /// <summary>
    /// Stands in for the named "vulntracker" client. Deliberately carries no BaseAddress: the
    /// production registration carries none either, because the address is instance state the
    /// client resolves per call.
    /// </summary>
    private sealed class SingleClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;

        public SingleClientFactory(TimeSpan? timeout) =>
            _client = timeout is { } t ? new HttpClient { Timeout = t } : new HttpClient();

        public HttpClient CreateClient(string name) => _client;
    }
}
