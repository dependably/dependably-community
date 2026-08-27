using System.Net.Sockets;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// A suspended/archived/deleting org's durable outbox message is never delivered (see
/// TenantLifecycle) — the recipients are tenant-configured, exactly the third-party egress the
/// suspension is meant to stop. Every mixed-pass assertion pairs the negative probe with the
/// adversarial twin (an active org's message in the SAME pass is still delivered).
///
/// <para>
/// The headline regression this file exists to pin: adversarial review found that suppressing a
/// suspended org's message with a bare <c>continue</c> — never calling any
/// <see cref="EmailTransportBreaker"/> method — leaves a probe (<see cref="EmailTransportBreaker.BeginPassBudget"/>
/// granting exactly 1 while <see cref="EmailTransportState.HalfOpen"/>) unresolved whenever that
/// suspended org's row is the one row claimed. <see cref="EmailTransportBreaker.BeginPassBudget"/>
/// then returns 0 for every subsequent pass, forever — freezing delivery for EVERY org, including
/// operator-scope mail, until a process restart. The fix has two independent halves, pinned by two
/// separate tests: resolving the probe (<see cref="EmailTransportBreaker.AbandonUnusedProbe"/>),
/// pinned below by <see cref="SuspendedOrgsMessageAsTheProbe_DoesNotFreezeDeliveryForEveryOtherOrgForever"/>,
/// and deferring the suspended row's own <c>next_attempt_at</c> so it stops perpetually re-winning
/// the single probe slot, pinned separately by
/// <see cref="SuspendedOrgsMessage_DefersByMaxBackoff_AndIsNotReclaimedAtTheNaturalLeaseLapsePoint"/>.
/// A negative control proved the two are genuinely independent: removing ONLY the deferral (leaving
/// <c>AbandonUnusedProbe</c> in place) left every assertion in the headline test passing, because
/// <see cref="EmailOutboxPolicy.LeaseDuration"/> (2 min) already rotates a claimed-but-skipped row
/// out of <c>sending</c>'s reclaim window on its own — the healthy org's message still gets its turn
/// within the headline test's 5-pass/25-second budget regardless of whether the suspended row's own
/// backoff was ever stretched. The deferral's actual, narrower job — stretching that natural 2-minute
/// re-claim cycle out to <see cref="EmailOutboxPolicy.MaxBackoff"/> (30 min) so a long-suspended org
/// does not burn an attempt (and a probe slot) every 2 minutes forever — needed its own test.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailOutboxSuspensionBreakerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── doubles / helpers, mirroring EmailOutboxDeliveryServiceTests ───────────

    private sealed class ToggleMailSender : SmtpMailSender
    {
        public ToggleMailSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false))
        {
        }

        public Func<Exception>? Failure { get; set; }
        public int Calls { get; private set; }

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default)
        {
            Calls++;
            return Failure is null ? Task.CompletedTask : Task.FromException(Failure());
        }
    }

    private static EnvelopeProtector MakeProtector()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(key)
            })
            .Build();
        return new EnvelopeProtector(new EnvFileMasterKeyProvider(config));
    }

    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    private InstanceSmtpConfig ConfiguredInstance()
    {
        var rows = new Dictionary<string, string?>
        {
            ["smtp_enabled"] = "1",
            ["smtp_host"] = "relay.example.com",
            ["smtp_from_address"] = "alerts@example.com",
            ["smtp_security"] = "none",
        };
        return new InstanceSmtpConfig(
            (key, _) => Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null), _clock);
    }

    private static EmailOutboxPolicy Policy(params (string Key, string Value)[] overrides) =>
        new(new ConfigurationBuilder()
            .AddInMemoryCollection(overrides.ToDictionary(o => o.Key, o => (string?)o.Value))
            .Build());

    private EmailTransportBreaker Breaker(params (string Key, string Value)[] overrides) =>
        new(
            new ConfigurationBuilder()
                .AddInMemoryCollection(overrides.ToDictionary(o => o.Key, o => (string?)o.Value))
                .Build(),
            _clock,
            NullLogger<EmailTransportBreaker>.Instance);

    private sealed record Harness(
        AlertEmailQueue Writer,
        EmailOutboxRepository Outbox,
        ToggleMailSender Sender,
        AlertRepository Alerts,
        AlertSettingsRepository Settings,
        EmailOutboxPolicy Policy,
        InstanceSmtpConfig Instance,
        EmailTransportBreaker Breaker,
        OrgRepository Orgs)
    {
        public EmailOutboxDeliveryService NewWorker(TimeProvider clock) => new(
            new EmailOutboxDeliveryServices(
                Outbox, Policy, Breaker, Instance, Sender, Alerts, Settings, Orgs, clock,
                NullLogger<EmailOutboxDeliveryService>.Instance));
    }

    private Harness BuildHarness(EnvelopeProtector protector, EmailTransportBreaker breaker)
    {
        var settings = new AlertSettingsRepository(_db, protector, _clock);
        var alerts = new AlertRepository(_db, _clock);
        var sender = new ToggleMailSender();
        var outbox = new EmailOutboxRepository(_db, _clock);
        var policy = Policy();
        var instance = ConfiguredInstance();
        var orgs = new OrgRepository(_db);

        var worker = new EmailOutboxDeliveryService(
                         new EmailOutboxDeliveryServices(
                         outbox, policy, breaker, instance, sender, alerts, settings, orgs, _clock, NullLogger<EmailOutboxDeliveryService>.Instance));

        var writer = new AlertEmailQueue(
            outbox, policy, worker, settings, alerts, RealLocalizer(),
            NullLogger<AlertEmailQueue>.Instance);

        return new Harness(writer, outbox, sender, alerts, settings, policy, instance, breaker, orgs);
    }

    private async Task SeedOrgAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)", new { orgId, status });
    }

    private static async Task<AlertRecord> QueueOneAsync(Harness h, string orgId, string purl)
    {
        await h.Settings.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: $"ops-{orgId}@example.com"));

        var alert = await h.Alerts.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: purl, Title: $"New quarantine item: {purl}", Detail: "Held pending review."));

        await h.Writer.NotifyAsync(alert!);
        return alert!;
    }

    private async Task<string?> StateAsync(string correlationId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT state FROM email_outbox WHERE correlation_id = @correlationId", new { correlationId });
    }

    private async Task<(long Attempts, string State, string? NextAttemptAt)> AttemptRowAsync(string correlationId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(long, string, string?)>(
            """
            SELECT attempts, state, next_attempt_at
            FROM email_outbox WHERE correlation_id = @correlationId
            """,
            new { correlationId });
    }

    // ── the headline regression ─────────────────────────────────────────────

    /// <summary>
    /// Reproduces the exact sequence the adversarial review's HIGH finding walked through:
    /// (1) a suspended org's message sits in the outbox; (2) a transient relay failure trips the
    /// breaker; (3) once the cooldown elapses, the suspended org's long-idle message — never
    /// touched by the suppression, so it still sorts first by <c>(next_attempt_at, created_at)</c>
    /// — is the exact row the single-probe budget claims. Without a fix, the breaker freezes in
    /// <c>HalfOpen</c> forever right there, and the healthy org's own message — queued AFTER the
    /// trip and due to retry moments later — is never attempted again, no matter how many further
    /// passes run or how much time passes. This test proves it eventually IS attempted and
    /// delivered, which only holds if the suppression both resolves the probe and stops
    /// perpetually re-winning it.
    /// </summary>
    [Fact]
    public async Task SuspendedOrgsMessageAsTheProbe_DoesNotFreezeDeliveryForEveryOtherOrgForever()
    {
        using var ep = MakeProtector();
        var breaker = Breaker(
            ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "1"),
            ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", "5"));
        var h = BuildHarness(ep, breaker);

        await SeedOrgAsync("locked", "suspended");
        await SeedOrgAsync("live", "active");

        // Step 1: trip the breaker using ONLY the active org's message — the transient failure
        // makes this exactly what a real outage looks like, independent of suspension.
        var liveAlert = await QueueOneAsync(h, "live", "pkg:npm/breaker-live@1.0.0");
        h.Sender.Failure = () => new SocketException((int)SocketError.ConnectionRefused);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(1, h.Sender.Calls);
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State);
        // The failed attempt backs off ~30s (EmailOutboxPolicy.FirstBackoff) from here.
        Assert.Equal(EmailOutboxStates.Pending, await StateAsync(liveAlert.Id));

        // Step 2: NOW queue the suspended org's message. It is due immediately (next_attempt_at =
        // now), strictly earlier than the active org's message (due at +~30s) — exactly the
        // ordering that makes it win the single probe slot below.
        var lockedAlert = await QueueOneAsync(h, "locked", "pkg:npm/breaker-locked@1.0.0");

        // Step 3: advance past the breaker's cooldown (5s) but NOT past the active org's own
        // backoff (~30s) — the suspended org's message is the only one due, so it IS the probe.
        h.Sender.Failure = null; // the relay is actually fine now; nothing should reach it this pass
        _clock.Advance(TimeSpan.FromSeconds(5));
        await worker.RunPassAsync(CancellationToken.None);

        // The probe claimed the suspended org's row and skipped it — no send happened.
        Assert.Equal(1, h.Sender.Calls);

        // Step 4: advance well past the active org's due time. Every later pass must still be
        // ABLE to claim and attempt it — the breaker must not be frozen at budget=0 forever.
        _clock.Advance(TimeSpan.FromMinutes(2));
        for (int i = 0; i < 5 && (await StateAsync(liveAlert.Id)) != EmailOutboxStates.Delivered; i++)
        {
            await worker.RunPassAsync(CancellationToken.None);
            _clock.Advance(TimeSpan.FromSeconds(5));
        }

        Assert.Equal(EmailOutboxStates.Delivered, await StateAsync(liveAlert.Id));
        Assert.Equal(EmailTransportState.Closed, h.Breaker.Snapshot().State);

        // The suspended org's message was never delivered throughout.
        Assert.NotEqual(EmailOutboxStates.Delivered, await StateAsync(lockedAlert.Id));
    }

    /// <summary>
    /// Isolates the deferral half of the HIGH fix from the probe-resolution half above. Without the
    /// deferral, a claimed-then-skipped suspended row is left exactly where <see cref="EmailOutboxRepository.ClaimDueAsync"/>
    /// put it — <c>sending</c>, under a plain <see cref="EmailOutboxPolicy.LeaseDuration"/> (2 min)
    /// lease, never reset to <c>pending</c>. Once that lease naturally lapses, <c>ClaimDueAsync</c>'s
    /// own <c>WHERE</c> clause reclaims it again (attempts increments a second time) even though
    /// suspension has not changed — a suspended org's row would then burn an attempt, and win the
    /// single probe slot, every 2 minutes forever. This asserts the deferral's actual effect directly:
    /// <c>next_attempt_at</c> advances to <c>MaxBackoff</c> (30 min) on the first skip, and the row is
    /// NOT reclaimed at the natural 2-minute lease-lapse point a second time.
    /// </summary>
    [Fact]
    public async Task SuspendedOrgsMessage_DefersByMaxBackoff_AndIsNotReclaimedAtTheNaturalLeaseLapsePoint()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Breaker());

        await SeedOrgAsync("locked", "suspended");
        var lockedAlert = await QueueOneAsync(h, "locked", "pkg:npm/deferral-pin@1.0.0");

        var worker = h.NewWorker(_clock);
        var beforeFirstPass = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        var (attemptsAfterFirst, stateAfterFirst, nextAttemptAtAfterFirst) = await AttemptRowAsync(lockedAlert.Id);
        Assert.Equal(1, attemptsAfterFirst);
        Assert.Equal(EmailOutboxStates.Pending, stateAfterFirst);
        Assert.Equal((beforeFirstPass + EmailOutboxPolicy.MaxBackoff).ToUtcIso(), nextAttemptAtAfterFirst);

        // Advance past the natural lease-lapse point (2 min) but nowhere near MaxBackoff (30 min).
        // Without the deferral, the row would still read state='sending' with a lease that expired
        // one second ago, so ClaimDueAsync's WHERE clause would treat it as claimable again right
        // here and reclaim it — bumping attempts to 2 even though the org is still suspended.
        _clock.Advance(EmailOutboxPolicy.LeaseDuration + TimeSpan.FromSeconds(1));
        await worker.RunPassAsync(CancellationToken.None);

        var (attemptsAfterSecond, stateAfterSecond, _) = await AttemptRowAsync(lockedAlert.Id);
        Assert.Equal(1, attemptsAfterSecond); // unchanged — the deferred next_attempt_at is not due yet
        Assert.Equal(EmailOutboxStates.Pending, stateAfterSecond);
    }

    // ── standalone suppression, no breaker involvement — the adversarial twin ──

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task RunPass_NeverDeliversTo_ANonActiveOrg_ButStillDeliversAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Breaker());

        await SeedOrgAsync("locked", nonActiveStatus);
        await SeedOrgAsync("live", "active");

        var lockedAlert = await QueueOneAsync(h, "locked", "pkg:npm/plain-locked@1.0.0");
        var liveAlert = await QueueOneAsync(h, "live", "pkg:npm/plain-live@1.0.0");

        await h.NewWorker(_clock).RunPassAsync(CancellationToken.None);

        Assert.NotEqual(EmailOutboxStates.Delivered, await StateAsync(lockedAlert.Id));
        Assert.Equal(EmailOutboxStates.Delivered, await StateAsync(liveAlert.Id));
    }

    /// <summary>
    /// A soft-deleted org (<c>orgs.deleted_at</c> set) is not active even though its <c>status</c>
    /// column is untouched at <c>'active'</c> — see <see cref="TenantLifecycle.IsActive(Org?)"/>.
    /// </summary>
    [Fact]
    public async Task RunPass_NeverDeliversTo_ASoftDeletedOrg_EvenThoughStatusIsStillActive()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Breaker());

        await SeedOrgAsync("softdeleted", "active");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @now WHERE id = 'softdeleted'",
                new { now = _clock.GetUtcNow().ToUtcIso() });
        }

        var alert = await QueueOneAsync(h, "softdeleted", "pkg:npm/softdeleted@1.0.0");
        await h.NewWorker(_clock).RunPassAsync(CancellationToken.None);

        Assert.NotEqual(EmailOutboxStates.Delivered, await StateAsync(alert.Id));
    }
}
