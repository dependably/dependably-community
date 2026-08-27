using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The operator-initiated connection test.
///
/// <para>
/// The probe exists because a scan pass is a slow way to learn that a credential is wrong, and
/// three of its properties are the ones that would make it worse than useless if they broke:
/// it must not dial a connection the operator has switched off, it must not move the health row
/// that describes the scan path, and it must not report an unconfigured integration as a broken
/// one.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerProbeTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private VulnTrackerHealthRepository Health() => new(_db, _clock);

    // ── Doubles ───────────────────────────────────────────────────────────────

    /// <summary>Records exactly what the probe asked for, so the outbound payload can be asserted.</summary>
    private sealed class RecordingSource : IVulnerabilityEnrichmentSource
    {
        private readonly Func<VulnerabilityEnrichmentBatchResult> _answer;
        public List<IReadOnlyList<EnrichmentLookupTarget>> Requests { get; } = [];

        public RecordingSource(Func<VulnerabilityEnrichmentBatchResult> answer) => _answer = answer;

        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
        {
            Requests.Add([.. targets]);
            return Task.FromResult(_answer());
        }
    }

    private sealed class ThrowingSource : IVulnerabilityEnrichmentSource
    {
        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
            => throw new InvalidOperationException("client fault");
    }

    /// <summary>Fails the test if it is called at all — for the arms that must make no request.</summary>
    private sealed class ForbiddenSource : IVulnerabilityEnrichmentSource
    {
        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
            => throw new InvalidOperationException(
                "The probe dialled a connection it should have refused to dial.");
    }

    private static VulnerabilityEnrichmentBatchResult Reached() =>
        new(results: [[]], reached: true, checkedAt: TestTime.KnownNow,
            freshness:
            [
                new EnrichmentSourceFreshness("nvd", TestTime.KnownNow.AddHours(-3)),
                new EnrichmentSourceFreshness("vulnrichment", TestTime.KnownNow.AddDays(-1)),
            ],
            reason: EnrichmentUnreachedReason.None);

    private static VulnerabilityEnrichmentBatchResult Unreached(EnrichmentUnreachedReason reason) =>
        VulnerabilityEnrichmentBatchResult.Unreached(1, reason);

    /// <summary>A tracker connection with an explicit enabled/base-URL combination.</summary>
    private static InstanceVulnTrackerConfig Connection(bool enabled, string? baseUrl)
    {
        var rows = new Dictionary<string, string?>
        {
            ["vuln_tracker_enabled"] = enabled ? "1" : "0",
            ["vuln_tracker_base_url"] = baseUrl,
        };
        return new InstanceVulnTrackerConfig(
            (key, _) => Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null),
            TimeProvider.System);
    }

    private Task<VulnTrackerProbeResult?> ProbeAsync(
        InstanceVulnTrackerConfig tracker, IVulnerabilityEnrichmentSource source)
        => VulnTrackerProbe.TryProbeAsync(tracker, source, Health(), _clock, CancellationToken.None);

    private async Task<int> FetchRowCountAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM vuln_tracker_fetch_log");
    }

    // ── Nothing to dial ───────────────────────────────────────────────────────

    [Fact]
    public async Task NoConnectionConfigured_MakesNoRequestAndRecordsNothing()
    {
        // Null is the caller's cue to answer 422. An unconfigured integration is not a broken
        // one, and a fetch row here would put a failure in the operator's log for a connection
        // that does not exist.
        Assert.Null(await ProbeAsync(Connection(enabled: true, baseUrl: null), new ForbiddenSource()));
        Assert.Equal(0, await FetchRowCountAsync());
    }

    [Fact]
    public async Task PausedConnection_IsNotDialledEvenThoughItIsFullyConfigured()
    {
        // The load-bearing one. "Paused" has to mean no outbound request at all — a test button
        // that dialled a switched-off tracker would quietly make the operator's off switch mean
        // something weaker than it says.
        Assert.Null(await ProbeAsync(
            Connection(enabled: false, baseUrl: "https://tracker.example.com"), new ForbiddenSource()));
        Assert.Equal(0, await FetchRowCountAsync());
    }

    [Fact]
    public async Task ActiveConnection_IsDialled()
    {
        // Adversarial twin of both refusals above: proves they are the enabled/base-URL checks
        // rejecting the dial, not the probe being inert for everyone.
        var source = new RecordingSource(Reached);

        var probe = await ProbeAsync(Connection(true, "https://tracker.example.com"), source);

        Assert.NotNull(probe);
        Assert.True(probe!.Reached);
        Assert.Single(source.Requests);
    }

    // ── What leaves the deployment ────────────────────────────────────────────

    [Fact]
    public async Task TheProbePayload_IsOneSyntheticPurlAndNothingElse()
    {
        // The probe answers "can we reach it", so it has no reason to name anything real. A
        // tenant purl reaching the producer from a button press would be a disclosure that no
        // amount of deduplication on the scan path would account for.
        var source = new RecordingSource(Reached);

        await ProbeAsync(Connection(true, "https://tracker.example.com"), source);

        var targets = Assert.Single(source.Requests);
        var target = Assert.Single(targets);
        Assert.Equal(VulnTrackerProbe.ProbePurl, target.Purl);
        Assert.Empty(target.Cves);
    }

    // ── What it reports ───────────────────────────────────────────────────────

    [Fact]
    public async Task ReachedProbe_ReportsTheProducersFreshnessVerbatim()
    {
        var probe = await ProbeAsync(
            Connection(true, "https://tracker.example.com"), new RecordingSource(Reached));

        Assert.True(probe!.Reached);
        Assert.Equal("none", probe.Reason);
        Assert.Collection(probe.Freshness,
            f => { Assert.Equal("nvd", f.Source); Assert.Equal(TestTime.KnownNow.AddHours(-3).ToUtcIso(), f.AsOf); },
            f => { Assert.Equal("vulnrichment", f.Source); Assert.Equal(TestTime.KnownNow.AddDays(-1).ToUtcIso(), f.AsOf); });
    }

    [Theory]
    [InlineData(EnrichmentUnreachedReason.Unauthorized, "unauthorized")]
    [InlineData(EnrichmentUnreachedReason.RateLimited, "rateLimited")]
    [InlineData(EnrichmentUnreachedReason.Timeout, "timeout")]
    [InlineData(EnrichmentUnreachedReason.Transport, "transport")]
    [InlineData(EnrichmentUnreachedReason.ServerError, "serverError")]
    [InlineData(EnrichmentUnreachedReason.MalformedResponse, "malformedResponse")]
    public async Task UnreachedProbe_ReportsWhichRefusalItWas(
        EnrichmentUnreachedReason reason, string expected)
    {
        // A wrong credential, a quota wall and an outage need three different fixes, so the probe
        // that exists to save an operator a scan pass has to tell them apart.
        var probe = await ProbeAsync(
            Connection(true, "https://tracker.example.com"),
            new RecordingSource(() => Unreached(reason)));

        Assert.False(probe!.Reached);
        Assert.Equal(expected, probe.Reason);
        Assert.Empty(probe.Freshness);
    }

    [Fact]
    public async Task ProbeThatThrows_IsReportedRatherThanPropagated()
    {
        // The client contracts never to throw for a remote failure. If it does, the operator gets
        // a red result rather than a 500 — and the reason names the fault as ours, not a refusal
        // the producer issued.
        var probe = await ProbeAsync(Connection(true, "https://tracker.example.com"), new ThrowingSource());

        Assert.False(probe!.Reached);
        Assert.Equal("exception", probe.Reason);
    }

    // ── The health-row boundary ───────────────────────────────────────────────

    [Fact]
    public async Task Probe_IsLoggedAsAProbe()
    {
        await ProbeAsync(Connection(true, "https://tracker.example.com"), new RecordingSource(Reached));

        var row = Assert.Single(await Health().ListRecentFetchesAsync(10));
        Assert.Equal("probe", row.Kind);
        Assert.Equal("ok", row.Outcome);
        Assert.Equal(1, row.PurlCount);
    }

    [Fact]
    public async Task PassingProbe_DoesNotClearAFailingScanPath()
    {
        // The reason a probe is a fetch-log row and not a health write. The scan path is broken;
        // the operator presses Test; the tracker happens to answer. Enrichment is still not
        // working, and the panel must keep saying so.
        await Health().RecordScanFetchAsync(
            new VulnTrackerFetchOutcome(false, "serverError", 4, 0, 10, _clock.GetUtcNow()));
        await Health().RecordScanFetchAsync(
            new VulnTrackerFetchOutcome(false, "serverError", 4, 0, 10, _clock.GetUtcNow()));

        _clock.Advance(TimeSpan.FromMinutes(5));
        var probe = await ProbeAsync(Connection(true, "https://tracker.example.com"), new RecordingSource(Reached));

        Assert.True(probe!.Reached);

        var health = await Health().GetHealthAsync();
        Assert.Equal("failed", health!.LastStatus);
        Assert.Equal(2, health.ConsecutiveFailures);
        Assert.Null(health.LastSuccessAt);
    }

    [Fact]
    public async Task FailingProbe_DoesNotReportAWorkingScanPathAsBroken()
    {
        // The mirror image, and the one that bites during setup: an operator testing a URL they
        // are still editing must not mark a scan path that is working as failing.
        await Health().RecordScanFetchAsync(
            new VulnTrackerFetchOutcome(true, "none", 9, 20, 30, _clock.GetUtcNow()));

        _clock.Advance(TimeSpan.FromMinutes(5));
        await ProbeAsync(
            Connection(true, "https://tracker.example.com"),
            new RecordingSource(() => Unreached(EnrichmentUnreachedReason.Transport)));

        var health = await Health().GetHealthAsync();
        Assert.Equal("ok", health!.LastStatus);
        Assert.Equal(0, health.ConsecutiveFailures);
        Assert.Equal(9, health.LastPurlCount);
    }
}
