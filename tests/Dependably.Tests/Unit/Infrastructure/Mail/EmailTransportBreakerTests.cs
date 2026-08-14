using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// <see cref="EmailTransportBreaker"/> in isolation: what trips it, what deliberately does not, the
/// half-open probe protocol, and self-service recovery. No database, no SMTP — every clock instant is
/// asserted exactly against a frozen <see cref="FakeTimeProvider"/>, per this repo's determinism gate.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailTransportBreakerTests
{
    private static EmailTransportBreaker Build(
        FakeTimeProvider clock, params (string Key, string Value)[] overrides) =>
        new(
            new ConfigurationBuilder()
                .AddInMemoryCollection(overrides.ToDictionary(o => o.Key, o => (string?)o.Value))
                .Build(),
            clock,
            NullLogger<EmailTransportBreaker>.Instance);

    // ── Closed: normal operation ────────────────────────────────────────────

    [Fact]
    public void Closed_GrantsTheFullBatchBudget()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock);

        Assert.Equal(50, breaker.BeginPassBudget(50));
        Assert.Equal(EmailTransportState.Closed, breaker.Snapshot().State);
    }

    [Fact]
    public void RecordTransportFailure_BelowThreshold_StaysClosed()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock, ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "3"));

        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();

        var snapshot = breaker.Snapshot();
        Assert.Equal(EmailTransportState.Closed, snapshot.State);
        Assert.Equal(2, snapshot.ConsecutiveTransportFailures);
        Assert.Equal(50, breaker.BeginPassBudget(50));
    }

    // ── What trips it, and what deliberately does not ──────────────────────

    [Fact]
    public void RecordTransportFailure_AtThreshold_OpensTheBreaker()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock, ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "3"));

        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();

        var snapshot = breaker.Snapshot();
        Assert.Equal(EmailTransportState.Open, snapshot.State);
        Assert.Equal(3, snapshot.ConsecutiveTransportFailures);
        Assert.Equal(clock.GetUtcNow(), snapshot.OpenedAt);
        Assert.Equal(0, breaker.BeginPassBudget(50));
    }

    /// <summary>
    /// A single bad recipient is not a relay outage: a permanent failure never counts toward the
    /// trip threshold, no matter how many pile up.
    /// </summary>
    [Fact]
    public void RecordPermanentFailure_NeverOpensTheBreaker_RegardlessOfCount()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock, ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "3"));

        for (int i = 0; i < 50; i++)
        {
            breaker.RecordPermanentFailure();
        }

        Assert.Equal(EmailTransportState.Closed, breaker.Snapshot().State);
        Assert.Equal(50, breaker.BeginPassBudget(50));
    }

    /// <summary>
    /// A permanent failure is evidence the relay is reachable: it resets a streak of transport
    /// failures that had not yet reached the trip threshold, rather than letting them accumulate
    /// across an unrelated, message-specific rejection.
    /// </summary>
    [Fact]
    public void RecordPermanentFailure_ResetsAnInProgressTransportFailureStreak()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock, ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "3"));

        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();
        breaker.RecordPermanentFailure();
        Assert.Equal(0, breaker.Snapshot().ConsecutiveTransportFailures);

        // Two more transport failures alone must not trip a threshold of 3 — the streak restarted.
        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();
        Assert.Equal(EmailTransportState.Closed, breaker.Snapshot().State);
    }

    // ── Half-open / probe protocol ───────────────────────────────────────────

    private static EmailTransportBreaker OpenedBreaker(
        FakeTimeProvider clock, int threshold = 3, int initialCooldownSeconds = 30)
    {
        var breaker = Build(
            clock,
            ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", threshold.ToString()),
            ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", initialCooldownSeconds.ToString()));
        for (int i = 0; i < threshold; i++)
        {
            breaker.RecordTransportFailure();
        }

        Assert.Equal(EmailTransportState.Open, breaker.Snapshot().State);
        return breaker;
    }

    [Fact]
    public void Open_BeforeCooldownElapses_GrantsNoBudget()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);

        clock.Advance(TimeSpan.FromSeconds(29));

        Assert.Equal(0, breaker.BeginPassBudget(50));
        Assert.Equal(EmailTransportState.Open, breaker.Snapshot().State);
    }

    /// <summary>
    /// Once the cooldown elapses the breaker admits exactly one message — a probe — never the full
    /// batch. This is what keeps a recovering relay from being stampeded by the whole backlog.
    /// </summary>
    [Fact]
    public void Open_AfterCooldownElapses_GrantsExactlyOneProbeBudget_AndEntersHalfOpen()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);

        clock.Advance(TimeSpan.FromSeconds(30));

        Assert.Equal(1, breaker.BeginPassBudget(50));
        Assert.Equal(EmailTransportState.HalfOpen, breaker.Snapshot().State);
    }

    /// <summary>
    /// While a probe is in flight, no further pass — on this replica — is granted any budget at all,
    /// even after further time passes. Never more than one message in flight against anything but a
    /// closed breaker.
    /// </summary>
    [Fact]
    public void HalfOpen_ProbeInFlight_FurtherPassesGetNoBudget()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, breaker.BeginPassBudget(50));

        clock.Advance(TimeSpan.FromMinutes(10));

        Assert.Equal(0, breaker.BeginPassBudget(50));
        Assert.Equal(EmailTransportState.HalfOpen, breaker.Snapshot().State);
    }

    [Fact]
    public void Probe_Delivered_ClosesTheBreaker()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, breaker.BeginPassBudget(50));

        breaker.RecordDelivered();

        var snapshot = breaker.Snapshot();
        Assert.Equal(EmailTransportState.Closed, snapshot.State);
        Assert.Equal(0, snapshot.ConsecutiveTransportFailures);
        Assert.Null(snapshot.OpenedAt);
        Assert.Equal(50, breaker.BeginPassBudget(50));
    }

    /// <summary>
    /// A permanent failure on the probe still proves the relay reachable — the protocol answered
    /// with a definitive verdict about the message, not silence. Closes the breaker exactly like a
    /// delivered probe.
    /// </summary>
    [Fact]
    public void Probe_PermanentFailure_StillClosesTheBreaker()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, breaker.BeginPassBudget(50));

        breaker.RecordPermanentFailure();

        Assert.Equal(EmailTransportState.Closed, breaker.Snapshot().State);
        Assert.Equal(50, breaker.BeginPassBudget(50));
    }

    /// <summary>
    /// A transport failure on the probe reopens the breaker with a doubled cooldown, capped — so a
    /// relay that is still down settles into a slow, steady poll instead of a tight retry loop.
    /// </summary>
    [Fact]
    public void Probe_TransportFailure_ReopensWithDoubledCooldown()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, breaker.BeginPassBudget(50));
        var probeAt = clock.GetUtcNow();

        breaker.RecordTransportFailure();

        var snapshot = breaker.Snapshot();
        Assert.Equal(EmailTransportState.Open, snapshot.State);
        Assert.Equal(probeAt.AddSeconds(60), snapshot.NextProbeAt);

        // Still nothing before the doubled cooldown elapses...
        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal(0, breaker.BeginPassBudget(50));

        // ...exactly one probe once it does.
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, breaker.BeginPassBudget(50));
    }

    [Fact]
    public void Probe_TransportFailure_CooldownDoublingIsCappedAtTheConfiguredMaximum()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(
            clock,
            ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "1"),
            ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", "300"),
            ("EMAIL_TRANSPORT_BREAKER_MAX_COOLDOWN_MINUTES", "10"));

        breaker.RecordTransportFailure(); // opens at 300s cooldown
        Assert.Equal(EmailTransportState.Open, breaker.Snapshot().State);

        clock.Advance(TimeSpan.FromSeconds(300));
        Assert.Equal(1, breaker.BeginPassBudget(50)); // probes
        var probeAt = clock.GetUtcNow();

        breaker.RecordTransportFailure(); // doubling 300s -> 600s would exceed the 10-minute cap

        Assert.Equal(probeAt.AddMinutes(10), breaker.Snapshot().NextProbeAt);
    }

    /// <summary>
    /// A probe budget granted but never used — every row's own message-level backoff was still in
    /// the future — proves nothing about the relay. It must not count as a failed probe (no doubled
    /// cooldown) or a successful one (no close): the next pass gets to try again at the ORIGINAL
    /// cooldown deadline, unchanged.
    /// </summary>
    [Fact]
    public void AbandonUnusedProbe_ReleasesTheProbe_WithoutChangingTheCooldownClock()
    {
        var clock = TestTime.Frozen();
        var breaker = OpenedBreaker(clock, initialCooldownSeconds: 30);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, breaker.BeginPassBudget(50));

        breaker.AbandonUnusedProbe();

        var snapshot = breaker.Snapshot();
        Assert.Equal(EmailTransportState.Open, snapshot.State);
        Assert.Equal(3, snapshot.ConsecutiveTransportFailures); // untouched

        // The original cooldown deadline already passed, so the very next pass probes again.
        Assert.Equal(1, breaker.BeginPassBudget(50));
    }

    /// <summary>Calling it outside a half-open probe is a no-op — nothing to abandon.</summary>
    [Fact]
    public void AbandonUnusedProbe_WhileClosed_IsANoOp()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock);

        breaker.AbandonUnusedProbe();

        Assert.Equal(EmailTransportState.Closed, breaker.Snapshot().State);
        Assert.Equal(50, breaker.BeginPassBudget(50));
    }

    // ── Self-service recovery: no operator action closes the breaker ────────

    [Fact]
    public void RecordDelivered_WhileClosed_KeepsTheBreakerClosedAndResetsAnyPartialStreak()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(clock, ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "3"));

        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();
        breaker.RecordDelivered();

        var snapshot = breaker.Snapshot();
        Assert.Equal(EmailTransportState.Closed, snapshot.State);
        Assert.Equal(0, snapshot.ConsecutiveTransportFailures);
    }

    /// <summary>
    /// Recovery happens by the breaker probing itself on its own schedule — nothing external ever
    /// calls a "close" method. This test drives that full self-service cycle end to end: open, wait
    /// out the cooldown, probe, succeed, and the breaker is back to admitting full batches.
    /// </summary>
    [Fact]
    public void FullCycle_OpensProbesAndRecoversWithoutAnyExternalIntervention()
    {
        var clock = TestTime.Frozen();
        var breaker = Build(
            clock,
            ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "3"),
            ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", "30"));

        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();
        breaker.RecordTransportFailure();
        Assert.Equal(EmailTransportState.Open, breaker.Snapshot().State);
        Assert.Equal(0, breaker.BeginPassBudget(50));

        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(1, breaker.BeginPassBudget(50));
        Assert.Equal(EmailTransportState.HalfOpen, breaker.Snapshot().State);

        breaker.RecordDelivered();

        Assert.Equal(EmailTransportState.Closed, breaker.Snapshot().State);
        Assert.Equal(50, breaker.BeginPassBudget(50));
    }
}
