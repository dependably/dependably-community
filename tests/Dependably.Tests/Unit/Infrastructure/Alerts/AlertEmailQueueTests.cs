using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// Unit tests for alert email delivery over a recording <see cref="FakeMailSender"/>: success,
/// terminal failure, resolver-null no-op, auto-disable, mixed partial-failure fan-out, and the
/// overflow drop path. <see cref="AlertEmailQueue"/> is now a thin <c>IAlertNotifier</c> adapter
/// over the shared <see cref="EmailDeliveryQueue"/> (the generic worker/retry/drain core extracted
/// so every outbound-email channel shares one delivery engine), so these tests drive the shared
/// queue's background service directly (<c>StartAsync</c>/<c>StopAsync</c>/counters) while using
/// <see cref="AlertEmailQueue.Notify"/> (or a directly-constructed <see cref="AlertEmailJob"/> for
/// the tests that used to call the old <c>DeliverAsync(AlertRecord, ct)</c> overload) to exercise
/// the alert-specific wrapping. Mirrors <c>AlertSlackQueueTests</c>'s construction style (real
/// repositories over an in-memory SQLite store, a fake send seam routed by transport host substring).
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertEmailQueueTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── helpers ───────────────────────────────────────────────────────────────

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

    /// <summary>Not inheriting the instance transport in any of these tests — the reader never
    /// resolves any key, so an all-null stub is a faithful "instance not configured" double.</summary>
    private static InstanceSmtpConfig BuildUnconfiguredInstance() =>
        new((_, _) => Task.FromResult<string?>(null), Clock);

    private static async Task<AlertRecord> SeedActiveAlertAsync(AlertRepository alerts, string orgId, string sourceRef)
    {
        var alert = await alerts.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: sourceRef,
            Ecosystem: "npm", Purl: "pkg:npm/email-test@1.0.0",
            Title: "New quarantine item: pkg:npm/email-test@1.0.0", Detail: "Held pending review."));
        return alert!;
    }

    private static async Task EnableEmailAsync(
        AlertSettingsRepository settings, string orgId, string host, string[] recipients)
    {
        // The delivery gate (email_enabled + recipients) lives on the gates upsert; the
        // transport columns on the email upsert.
        await settings.UpdateGatesAsync(orgId, new UpdateAlertGates(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            EmailEnabled: true, EmailRecipients: string.Join(",", recipients)));
        await settings.UpdateEmailAsync(orgId, new UpdateAlertEmail(
            EmailInheritInstance: false,
            EmailSmtpHost: host,
            EmailSmtpPort: 587,
            EmailSmtpSecurity: "none",
            EmailSmtpUsername: null,
            EmailSmtpPassword: null,
            EmailSmtpFrom: "alerts@example.com"));
    }

    /// <summary>
    /// Polls the DURABLE end state (the persisted alert/settings row) rather than the queue's
    /// in-memory counters — see <c>AlertSlackQueueTests.WaitAsync</c> for why that distinction
    /// matters (the queue bumps its counters before the DB writes land).
    /// </summary>
    private static async Task WaitAsync(Func<Task<bool>> condition, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting real async completion of the durable write path
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (!await condition() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        if (!await condition())
        {
            throw new TimeoutException("Condition never satisfied.");
        }
    }

    /// <summary>Drives a queue's retry backoff deterministically — see
    /// <c>AlertSlackQueueTests.PumpUntilAsync</c> for the full rationale.</summary>
    private static async Task PumpUntilAsync(
        FakeTimeProvider clock, Func<Task<bool>> condition, TimeSpan step, int maxIterations = 1000)
    {
        for (int i = 0; i < maxIterations && !await condition(); i++)
        {
            clock.Advance(step);
            await Task.Delay(20);
        }

        if (!await condition())
        {
            throw new TimeoutException("Condition never satisfied while pumping the fake clock.");
        }
    }

    /// <summary>Records every send and routes success/failure by a "good"/"bad" substring in the
    /// transport host — the SMTP-send analog of <c>AlertSlackQueueTests.RoutingHandler</c>. Since
    /// the queue's channel has a single reader, alerts are delivered one at a time, so the shared
    /// Last* fields are never written concurrently.</summary>
    private sealed class FakeMailSender : SmtpMailSender
    {
        // The connect guard is never exercised — SendAsync is fully overridden below — so a
        // permissive predicate is enough to satisfy the base constructor.
        public FakeMailSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false))
        {
        }

        public int Calls { get; private set; }
        public IReadOnlyList<string>? LastTo { get; private set; }
        public string? LastSubject { get; private set; }
        public string? LastBody { get; private set; }

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default)
        {
            Calls++;
            LastTo = to;
            LastSubject = subject;
            LastBody = body;

            return transport.Host?.Contains("bad", StringComparison.Ordinal) == true
                ? Task.FromException(new InvalidOperationException("simulated SMTP failure"))
                : Task.CompletedTask;
        }
    }

    private static (EmailDeliveryQueue Queue, AlertEmailQueue Alerts) BuildQueue(
        AlertSettingsRepository settings, AlertRepository alerts, SmtpMailSender sender,
        FakeTimeProvider clock, int? capacity = null)
    {
        var deliveryQueue = capacity is int c
            ? new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance, c)
            : new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var alertQueue = new AlertEmailQueue(
            deliveryQueue, new EffectiveEmailConfigResolver(settings, BuildUnconfiguredInstance()),
            settings, alerts, RealLocalizer(), NullLogger<AlertEmailQueue>.Instance);
        return (deliveryQueue, alertQueue);
    }

    // ── Success path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Notify_EmailConfigured_DeliversAndRecordsSuccess()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();

        await EnableEmailAsync(settings, "org1", "good.example.com", ["a@example.com", "b@example.com"]);
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var (deliveryQueue, alertQueue) = BuildQueue(settings, alerts, sender, Clock);
        using var cts = new CancellationTokenSource();
        _ = deliveryQueue.StartAsync(cts.Token);

        alertQueue.Notify(alert);
        await WaitAsync(async () => (await alerts.GetByIdAsync("org1", alert.Id))?.EmailStatus is not null);

        try { await deliveryQueue.StopAsync(CancellationToken.None); } catch { }

        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", reread!.EmailStatus);
        Assert.Null(reread.EmailError);

        var orgSettings = await settings.GetAsync("org1");
        Assert.Equal("ok", orgSettings.EmailLastStatus);
        Assert.Equal(0, orgSettings.EmailConsecutiveFailures);

        // All recipients land on the one message.
        Assert.Equal(1, sender.Calls);
        Assert.NotNull(sender.LastTo);
        Assert.Equal(["a@example.com", "b@example.com"], sender.LastTo);
        Assert.Contains(alert.Title, sender.LastSubject);
    }

    // ── Terminal failure + mixed partial-failure fan-out ────────────────────────

    /// <summary>
    /// End-to-end through the running queue: one org's transport always succeeds, another's
    /// always throws. The failing org goes through the full 1s/5s/30s backoff before the terminal
    /// failure is recorded — outcomes are independent per org (mixed partial-failure).
    /// </summary>
    [Fact]
    public async Task Notify_MixedOrgs_OneSucceedsOneFails_IndependentOutcomes()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();
        var emailClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableEmailAsync(settings, "org1", "good.example.com", ["a@example.com"]);
        await EnableEmailAsync(settings, "org2", "bad.example.com", ["b@example.com"]);
        var goodAlert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));
        var badAlert = await SeedActiveAlertAsync(alerts, "org2", Guid.NewGuid().ToString("N"));

        var (deliveryQueue, alertQueue) = BuildQueue(settings, alerts, sender, emailClock);
        using var cts = new CancellationTokenSource();
        _ = deliveryQueue.StartAsync(cts.Token);

        alertQueue.Notify(goodAlert);
        alertQueue.Notify(badAlert);

        await PumpUntilAsync(emailClock, async () =>
        {
            var good = await alerts.GetByIdAsync("org1", goodAlert.Id);
            var bad = await alerts.GetByIdAsync("org2", badAlert.Id);
            return good?.EmailStatus is not null && bad?.EmailStatus is not null;
        }, TimeSpan.FromSeconds(1));

        try { await deliveryQueue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, deliveryQueue.DeliveredCount);
        Assert.Equal(1, deliveryQueue.FailedCount);

        var goodReread = await alerts.GetByIdAsync("org1", goodAlert.Id);
        var badReread = await alerts.GetByIdAsync("org2", badAlert.Id);
        Assert.Equal("sent", goodReread!.EmailStatus);
        Assert.Equal("failed", badReread!.EmailStatus);
        Assert.NotNull(badReread.EmailError);

        var goodSettings = await settings.GetAsync("org1");
        var badSettings = await settings.GetAsync("org2");
        Assert.Equal(0, goodSettings.EmailConsecutiveFailures);
        Assert.Equal(1, badSettings.EmailConsecutiveFailures);
        // A single failure does not yet auto-disable (threshold is 20).
        Assert.True(badSettings.EmailEnabled);
    }

    // ── Cross-tenant non-delivery ────────────────────────────────────────────

    /// <summary>
    /// Both orgs configure email recipients and enable delivery, each with its own recipient
    /// list. Notifying an alert whose <c>OrgId</c> is org1 must never reach org2's recipients —
    /// <see cref="Notify_MixedOrgs_OneSucceedsOneFails_IndependentOutcomes"/> proves independent
    /// per-org *outcomes* but never asserts that the wrong tenant's recipients never appear in
    /// any send. This is the "must-NOT" twin: the mail sender is invoked with org1's recipients
    /// only, and the one rendered body carries only org1's alert content.
    /// </summary>
    [Fact]
    public async Task Notify_AlertForOrg1_NeverDeliveredToOrg2Recipients()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();

        await EnableEmailAsync(settings, "org1", "good.example.com", ["org1-a@example.com", "org1-b@example.com"]);
        await EnableEmailAsync(settings, "org2", "good.example.com", ["org2-a@example.com"]);

        var org1Alert = await alerts.TryInsertAsync(new NewAlert(
            "org1", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/org1-secret@1.0.0",
            Title: "ORG1-ONLY quarantine item", Detail: "org1 detail payload"));

        var org2Alert = await alerts.TryInsertAsync(new NewAlert(
            "org2", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/org2-secret@1.0.0",
            Title: "ORG2-ONLY quarantine item", Detail: "org2 detail payload"));

        var (deliveryQueue, alertQueue) = BuildQueue(settings, alerts, sender, Clock);
        using var cts = new CancellationTokenSource();
        _ = deliveryQueue.StartAsync(cts.Token);

        alertQueue.Notify(org1Alert!);
        await WaitAsync(async () => (await alerts.GetByIdAsync("org1", org1Alert!.Id))?.EmailStatus is not null);

        try { await deliveryQueue.StopAsync(CancellationToken.None); } catch { }

        // The mail sender was invoked exactly once, and only with org1's recipients — org2's
        // recipients never appear in any send.
        Assert.Equal(1, sender.Calls);
        Assert.NotNull(sender.LastTo);
        Assert.Equal(["org1-a@example.com", "org1-b@example.com"], sender.LastTo);
        Assert.DoesNotContain("org2-a@example.com", sender.LastTo!);

        // The rendered body carries org1's alert content and no trace of org2's.
        Assert.Contains("ORG1-ONLY", sender.LastBody);
        Assert.DoesNotContain("ORG2-ONLY", sender.LastBody);

        // org2's alert was never touched: no email delivery attempted, no outcome recorded.
        var org2Reread = await alerts.GetByIdAsync("org2", org2Alert!.Id);
        Assert.NotNull(org2Reread);
        Assert.Null(org2Reread!.EmailStatus);
        Assert.Null(org2Reread.EmailError);
    }

    /// <summary>Drives the retry path directly (no queue loop) against a directly-constructed
    /// <see cref="AlertEmailJob"/> and asserts the exact backoff schedule: 1 initial attempt at
    /// t=0, then retries at +1s, +5s, +30s (4 attempts total) before the terminal failure is
    /// recorded.</summary>
    [Fact]
    public async Task DeliverAsync_TransientFailure_RetriesAtExactBackoffThenRecordsTerminalFailure()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();
        var emailClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableEmailAsync(settings, "org1", "bad.example.com", ["a@example.com"]);
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var (deliveryQueue, _) = BuildQueue(settings, alerts, sender, emailClock);
        var job = new AlertEmailJob(
            alert, new EffectiveEmailConfigResolver(settings, BuildUnconfiguredInstance()),
            alerts, settings, RealLocalizer(), NullLogger<AlertEmailQueue>.Instance);

        var deliverTask = deliveryQueue.DeliverAsync(job, CancellationToken.None);

        // 1 initial attempt fires immediately.
        await WaitAsync(() => Task.FromResult(sender.Calls >= 1));
        Assert.Equal(1, sender.Calls);

        // +1s → attempt 2.
        emailClock.Advance(TimeSpan.FromSeconds(1));
        await WaitAsync(() => Task.FromResult(sender.Calls >= 2));
        Assert.Equal(2, sender.Calls);

        // +5s → attempt 3.
        emailClock.Advance(TimeSpan.FromSeconds(5));
        await WaitAsync(() => Task.FromResult(sender.Calls >= 3));
        Assert.Equal(3, sender.Calls);

        // +30s → attempt 4 (final).
        emailClock.Advance(TimeSpan.FromSeconds(30));
        await WaitAsync(() => Task.FromResult(sender.Calls >= 4));
        Assert.Equal(4, sender.Calls);

        await deliverTask;

        Assert.Equal(1, deliveryQueue.FailedCount);
        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("failed", reread!.EmailStatus);
        Assert.Contains("simulated SMTP failure", reread.EmailError);

        var orgSettings = await settings.GetAsync("org1");
        Assert.Equal("failed", orgSettings.EmailLastStatus);
        Assert.Equal(1, orgSettings.EmailConsecutiveFailures);
    }

    // ── Shutdown drain (channel still buffered when the stopping token is cancelled) ──

    /// <summary>
    /// Reproduces the shutdown-drop defect deterministically by invoking <c>ExecuteAsync</c>
    /// directly (via the <see cref="EmailDeliveryQueue.ExecuteAsyncForTests"/> test hook) with an
    /// already-cancelled token — <see cref="BackgroundService.StartAsync"/> itself short-circuits
    /// and never calls <c>ExecuteAsync</c> at all in that case, so it cannot exercise the real
    /// race being tested (a stopping token cancelled while the read loop is genuinely running,
    /// mid-shutdown, with a job still buffered). Two alerts are buffered before the drain runs,
    /// one routed to a succeeding transport and one to a failing one — the drain must deliver the
    /// first and durably record the second's failure, independently.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_DrainsMixedSuccessAndFailure()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();
        var emailClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableEmailAsync(settings, "org1", "good.example.com", ["a@example.com"]);
        await EnableEmailAsync(settings, "org2", "bad.example.com", ["b@example.com"]);
        var goodAlert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));
        var badAlert = await SeedActiveAlertAsync(alerts, "org2", Guid.NewGuid().ToString("N"));

        var (deliveryQueue, alertQueue) = BuildQueue(settings, alerts, sender, emailClock);

        // Buffer both alerts before the worker ever starts reading.
        alertQueue.Notify(goodAlert);
        alertQueue.Notify(badAlert);

        // Drives ExecuteAsync directly with an already-cancelled token — the exact state the
        // stopping token is in by the time BackgroundService.StopAsync signals cancellation.
        var executeTask = deliveryQueue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // The failing alert burns through the 1s/5s/30s backoff inside the drain itself; pump
        // the fake clock so that finishes in virtual time instead of real time.
        await PumpUntilAsync(emailClock, async () =>
        {
            var good = await alerts.GetByIdAsync("org1", goodAlert.Id);
            var bad = await alerts.GetByIdAsync("org2", badAlert.Id);
            return good?.EmailStatus is not null && bad?.EmailStatus is not null;
        }, TimeSpan.FromSeconds(1));

        await executeTask;

        Assert.Equal(1, deliveryQueue.DeliveredCount);
        Assert.Equal(1, deliveryQueue.FailedCount);

        var goodReread = await alerts.GetByIdAsync("org1", goodAlert.Id);
        var badReread = await alerts.GetByIdAsync("org2", badAlert.Id);
        Assert.Equal("sent", goodReread!.EmailStatus);
        Assert.Equal("failed", badReread!.EmailStatus);
    }

    // ── Resolver-null: silent no-op ─────────────────────────────────────────────

    [Fact]
    public async Task Notify_ResolverNull_NoSendAttempted_NothingRecorded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();

        // No EnableEmailAsync call — org1 has no settings row at all (email off by default).
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var (deliveryQueue, alertQueue) = BuildQueue(settings, alerts, sender, Clock);
        using var cts = new CancellationTokenSource();
        _ = deliveryQueue.StartAsync(cts.Token);

        alertQueue.Notify(alert);
        // Give the consumer a moment to process the (no-op) item.
        await Task.Delay(200);

        await cts.CancelAsync();
        try { await deliveryQueue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(0, sender.Calls);
        Assert.Equal(0, deliveryQueue.DeliveredCount);
        Assert.Equal(0, deliveryQueue.FailedCount);
        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Null(reread!.EmailStatus);

        var orgSettings = await settings.GetAsync("org1");
        Assert.Null(orgSettings.EmailLastStatus);
        Assert.Equal(0, orgSettings.EmailConsecutiveFailures);
    }

    /// <summary>Enabled but with no usable transport at all (no recipients) is the "channel
    /// effectively disabled" case the resolver treats identically to fully-off.</summary>
    [Fact]
    public async Task Notify_EnabledButNoRecipients_NoSendAttempted_NothingRecorded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();

        await settings.UpdateGatesAsync("org1", new UpdateAlertGates(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            EmailEnabled: true, EmailRecipients: null));
        await settings.UpdateEmailAsync("org1", new UpdateAlertEmail(
            EmailInheritInstance: false,
            EmailSmtpHost: "good.example.com", EmailSmtpPort: 587, EmailSmtpSecurity: "none",
            EmailSmtpUsername: null, EmailSmtpPassword: null, EmailSmtpFrom: "alerts@example.com"));
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var (deliveryQueue, _) = BuildQueue(settings, alerts, sender, Clock);
        var job = new AlertEmailJob(
            alert, new EffectiveEmailConfigResolver(settings, BuildUnconfiguredInstance()),
            alerts, settings, RealLocalizer(), NullLogger<AlertEmailQueue>.Instance);
        await deliveryQueue.DeliverAsync(job, CancellationToken.None);

        Assert.Equal(0, sender.Calls);
        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Null(reread!.EmailStatus);
    }

    // ── Auto-disable (exercised directly against the repository, same as the Slack suite) ──────

    [Fact]
    public async Task RecordEmailFailure_AutoDisablesWhenDurationWindowExceeded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings, "org1", "bad.example.com", ["a@example.com"]);

        string staleFailingSince = Clock.GetUtcNow().AddHours(-49).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE alert_settings SET email_failing_since = @s WHERE org_id = @id",
            new { s = staleFailingSince, id = "org1" });

        bool disabled = await settings.RecordEmailFailureAsync(
            "org1", "timeout", AlertDeliveryPolicy.AutoDisableAfterFailures, AlertDeliveryPolicy.AutoDisableAfterDuration);
        Assert.True(disabled);

        var updated = await settings.GetAsync("org1");
        Assert.False(updated.EmailEnabled);
    }

    // ── Overflow / drop path ──────────────────────────────────────────────────

    [Fact]
    public async Task Notify_WhenChannelFull_DropsAndIncrementsCounter()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var sender = new FakeMailSender();

        await EnableEmailAsync(settings, "org1", "good.example.com", ["a@example.com"]);
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        // Never started — nothing is dequeued, so the channel fills and drops.
        var (deliveryQueue, alertQueue) = BuildQueue(settings, alerts, sender, Clock, capacity: 1);

        for (int i = 0; i < 5; i++)
        {
            alertQueue.Notify(alert);
        }

        Assert.Equal(4, deliveryQueue.DroppedCount);
    }

    // ── Subject/body rendering ───────────────────────────────────────────────

    [Fact]
    public void BuildMessage_StripsCrlfFromTitle_AndFormatsSubjectAndBody()
    {
        var alert = new AlertRecord(
            Id: "id1", OrgId: "org1", Type: AlertTypes.QuarantineNew, Severity: null, SourceRef: "ref",
            Ecosystem: "npm", Purl: "pkg:npm/x@1.0.0", Title: "Bad title\r\nInjected-Header: evil",
            Detail: "Held pending manual review.", State: "active",
            DismissedBy: null, DismissedAt: null, SlackStatus: null, SlackError: null,
            EmailStatus: null, EmailError: null,
            CreatedAt: Clock.GetUtcNow(), UpdatedAt: Clock.GetUtcNow());

        (string subject, string body) = AlertEmailQueue.BuildMessage(RealLocalizer(), alert);

        Assert.DoesNotContain('\r', subject);
        Assert.DoesNotContain('\n', subject);
        Assert.Contains("Bad title", subject);
        Assert.Contains("Injected-Header: evil", subject);
        Assert.Contains("Held pending manual review.", body);
    }
}
