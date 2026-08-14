using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using MailKit.Net.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies the production DI wiring, not just the queue in isolation: <see cref="IAlertNotifier"/>
/// resolves to <see cref="CompositeAlertNotifier"/> (never a bare queue), and a real
/// <c>AlertService.RaiseQuarantineAlertAsync</c> call travels
/// <c>AlertService</c> → <c>CompositeAlertNotifier</c> → <see cref="AlertEmailQueue"/> →
/// <c>email_outbox</c> → <see cref="EmailOutboxDeliveryService"/> → <see cref="SmtpMailSender"/>
/// through the actual composition root. Nothing is constructed by hand here, unlike the
/// <c>AlertEmailQueueTests</c> / <c>EmailOutboxDeliveryServiceTests</c> unit suites.
///
/// <para>
/// Two properties are asserted separately on purpose, because they have different determinism
/// requirements. That the message is <em>persisted and attempted</em> through the real wiring is
/// checked on its own; <em>how a given failure is classified</em> is checked against a failure the
/// test injects, so the transient/permanent split — the substance of the retry policy — is pinned by
/// the exception rather than by whatever a socket happens to do on the host the suite runs on.
/// Coupling the two is what let an earlier form of this file assert a class it never produced.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class AlertNotifierWiringTests : IAsyncLifetime
{
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task IAlertNotifier_ResolvesToCompositeAlertNotifier_FanningToBothIndependentlyResolvableQueues()
    {
        await using var factory = new DependablyFactory();

        var notifier = factory.Services.GetRequiredService<IAlertNotifier>();
        Assert.IsType<CompositeAlertNotifier>(notifier);

        // CompositeAlertNotifier fans out to these — it doesn't replace them, so each queue is
        // still independently resolvable (and is the same hosted-service instance).
        Assert.NotNull(factory.Services.GetRequiredService<AlertSlackQueue>());
        Assert.NotNull(factory.Services.GetRequiredService<AlertEmailQueue>());
    }

    private sealed record Arranged(
        string OrgId,
        AlertRepository Alerts,
        AlertService Service,
        System.Data.Common.DbConnection Conn);

    /// <summary>
    /// Seeds the one instance-level SMTP transport and the org's alert-email channel through the real
    /// repositories. The transport host is a parameter because one test wants the real SSRF-guarded
    /// connect to run and the others want it bypassed by an injected sender.
    /// </summary>
    private static async Task<Arranged> ArrangeAsync(DependablyFactory factory, string smtpHost)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        var conn = await store.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        var settings = factory.Services.GetRequiredService<AlertSettingsRepository>();
        await settings.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "ops@example.com"));

        // SMTP is instance-level, so the transport is seeded on instance_settings, not on the org.
        var orgs = factory.Services.GetRequiredService<OrgRepository>();
        await orgs.SetInstanceSettingAsync("smtp_enabled", "1");
        await orgs.SetInstanceSettingAsync("smtp_host", smtpHost);
        await orgs.SetInstanceSettingAsync("smtp_port", "2525");
        await orgs.SetInstanceSettingAsync("smtp_security", "none");
        await orgs.SetInstanceSettingAsync("smtp_from_address", "alerts@example.com");
        factory.Services.GetRequiredService<InstanceSmtpConfig>().Invalidate();

        return new Arranged(
            orgId,
            factory.Services.GetRequiredService<AlertRepository>(),
            factory.Services.GetRequiredService<AlertService>(),
            conn);
    }

    // Attempts is long, not int: SQLite materialises INTEGER as Int64 and Dapper's positional-record
    // constructor match is exact.
    private sealed record OutboxRow(long Attempts, string? LastError, string? FailureClass, string State);

    private static Task<OutboxRow> ReadOutboxRowAsync(System.Data.Common.DbConnection conn, string correlationId) =>
        conn.QuerySingleAsync<OutboxRow>(
            """
            SELECT attempts AS Attempts, last_error AS LastError,
                   failure_class AS FailureClass, state AS State
            FROM email_outbox WHERE correlation_id = @id
            """,
            new { id = correlationId });

    /// <summary>
    /// Pumps the frozen clock until the delivery worker has recorded a delivery <em>outcome</em> on
    /// the row. The clock (not a real-time sleep) drives the worker's own poll interval and backoff;
    /// the wall-clock read only bounds how long the test waits for a genuinely asynchronous
    /// background pass to be scheduled.
    ///
    /// <para>
    /// The wait condition is <c>failure_class</c> becoming non-null, not <c>attempts</c> becoming
    /// non-zero. The attempt counter is incremented when the row is <em>claimed</em>, before the send
    /// is even tried, so waiting on it returns while the outcome columns are still empty and every
    /// assertion after it reads a half-written row.
    /// </para>
    /// </summary>
    private static async Task<OutboxRow> WaitForOutcomeAsync(
        System.Data.Common.DbConnection conn, string correlationId, FakeTimeProvider clock)
    {
        // now-ok: polling deadline awaiting the background delivery worker's real async pass.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        var row = await ReadOutboxRowAsync(conn, correlationId);
        // now-ok: same deadline read.
        while (row.FailureClass is null && DateTimeOffset.UtcNow < deadline)
        {
            clock.Advance(TimeSpan.FromSeconds(5));
            await Task.Delay(50);
            row = await ReadOutboxRowAsync(conn, correlationId);
        }

        Assert.True(row.FailureClass is not null,
            $"the delivery worker never recorded an outcome (state {row.State}, attempts {row.Attempts}).");
        return row;
    }

    /// <summary>
    /// The persistence half, which is where the durability guarantee starts: by the time the raise
    /// call returns, the outbox row exists and carries everything a later delivery needs — the
    /// recipient snapshot, the rendered message, the message kind, and the coalescing key.
    ///
    /// <para>
    /// Deliberately no state or attempt-count assertion. The worker is a live hosted service nudged on
    /// enqueue, so it may legitimately have claimed the row already; asserting <c>pending</c> here
    /// would pin scheduling luck rather than behaviour. That the row is persisted <em>before</em> any
    /// attempt is pinned deterministically instead by
    /// <c>AlertEmailQueueTests.NotifyAsync_PersistsTheMessageBeforeAnyDeliveryAttempt</c>, where no
    /// worker is running at all.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RaiseQuarantineAlert_PersistsToTheOutboxThroughRealDIWiring_CarryingEverythingDeliveryNeeds()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var sender = new CapturingMailSender();
        await using var factory = new DependablyFactory { FrozenClock = clock, MailSenderOverride = sender };

        var arranged = await ArrangeAsync(factory, "relay.example.test");
        await using (arranged.Conn)
        {
            string sourceRef = Guid.NewGuid().ToString("N");
            await arranged.Service.RaiseQuarantineAlertAsync(
                arranged.OrgId, sourceRef, "npm", "pkg:npm/wiring-test@1.0.0", "quarantine",
                "Held pending review.");

            var alert = (await arranged.Alerts.ListAsync(arranged.OrgId, null, 50, 0)).Items
                .FirstOrDefault(a => a.SourceRef == sourceRef);
            Assert.NotNull(alert);

            // The write side is synchronous with the raise, so the row is already durable here.
            (string messageKind, string coalesceKey, string recipients, string subject, string body) =
                await arranged.Conn.QuerySingleAsync<(string, string, string, string, string)>(
                    """
                    SELECT message_kind, coalesce_key, recipients, subject, body
                    FROM email_outbox WHERE correlation_id = @id
                    """,
                    new { id = alert!.Id });

            Assert.Equal(EmailOutboxMessageKinds.Alert, messageKind);
            Assert.Equal("ops@example.com", recipients);
            Assert.Equal($"{AlertTypes.QuarantineNew}:pkg:npm/wiring-test@1.0.0", coalesceKey);
            Assert.Contains(alert.Title, subject);
            Assert.Contains("Held pending review.", body);

            // Queued is not delivered: the raise itself records no outcome on the alert row.
            Assert.Null(alert.EmailStatus);

            // Slack was never configured for this org — its outcome column stays untouched,
            // confirming the two channels record independently.
            Assert.Null(alert.SlackStatus);
        }
    }

    /// <summary>
    /// The classification half, driven by an <em>injected</em> SMTP failure so the expected class is a
    /// property of the exception rather than of the host's network. An SMTP 4xx is "not now" and stays
    /// queued for a retry; an SMTP 5xx is "not ever, as sent" and dead-letters on the first attempt.
    /// Both travel the real composition root, so the wiring and the split are covered at once without
    /// either assertion depending on ambient behaviour.
    /// </summary>
    [Theory]
    [InlineData(SmtpStatusCode.ServiceNotAvailable, EmailOutboxFailureClasses.Transient, EmailOutboxStates.Pending, null)]
    [InlineData(SmtpStatusCode.MailboxUnavailable, EmailOutboxFailureClasses.Permanent, EmailOutboxStates.DeadLetter, "failed")]
    public async Task RaiseQuarantineAlert_InjectedSmtpFailure_IsClassifiedAndTransitionedThroughRealDIWiring(
        SmtpStatusCode status, string expectedClass, string expectedState, string? expectedAlertEmailStatus)
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var sender = new CapturingMailSender
        {
            Failure = () => new SmtpCommandException(
                SmtpErrorCode.MessageNotAccepted, status, $"{(int)status} injected"),
        };
        await using var factory = new DependablyFactory { FrozenClock = clock, MailSenderOverride = sender };

        var arranged = await ArrangeAsync(factory, "relay.example.test");
        await using (arranged.Conn)
        {
            string sourceRef = Guid.NewGuid().ToString("N");
            await arranged.Service.RaiseQuarantineAlertAsync(
                arranged.OrgId, sourceRef, "npm", "pkg:npm/wiring-test@1.0.0", "quarantine",
                "Held pending review.");

            var alert = (await arranged.Alerts.ListAsync(arranged.OrgId, null, 50, 0)).Items
                .First(a => a.SourceRef == sourceRef);
            var row = await WaitForOutcomeAsync(arranged.Conn, alert.Id, clock);

            Assert.Equal(expectedClass, row.FailureClass);
            Assert.Equal(expectedState, row.State);
            Assert.Contains("injected", row.LastError);

            // The attempt really went through the real SmtpMailSender seam, carrying the org's
            // recipient list.
            Assert.NotEmpty(sender.Sent);
            Assert.Equal(["ops@example.com"], sender.Sent[0].Recipients);

            // A terminal outcome is stamped on the alert row; a retryable one deliberately is not.
            var reread = (await arranged.Alerts.ListAsync(arranged.OrgId, null, 50, 0)).Items
                .First(a => a.SourceRef == sourceRef);
            Assert.Equal(expectedAlertEmailStatus, reread.EmailStatus);
        }
    }

    /// <summary>
    /// The one case that keeps a real connect in the loop, and it is deterministic without a network:
    /// a loopback relay host is refused by <see cref="SmtpMailSender"/>'s own connect-time SSRF guard
    /// before a socket is opened, and the guard's verdict on <c>127.0.0.1</c> is a pure function of a
    /// static range list. That refusal is a configuration error rather than an outage, so it must
    /// dead-letter rather than spend the retry budget on a host that will be refused identically every
    /// time.
    ///
    /// <para>
    /// The factory's permissive <c>SsrfConnectCallback</c> registration does not reach this path:
    /// <c>AddDependablyMail</c> hands <see cref="SmtpMailSender"/> its own guard instance, because
    /// MailKit has no <c>SocketsHttpHandler</c> to hang a shared callback off. So this also pins that
    /// the production guard is genuinely live on the outbox delivery path.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RaiseQuarantineAlert_LoopbackRelayHost_IsRefusedByTheSsrfGuardAndDeadLetters()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        await using var factory = new DependablyFactory { FrozenClock = clock };

        var arranged = await ArrangeAsync(factory, "127.0.0.1");
        await using (arranged.Conn)
        {
            string sourceRef = Guid.NewGuid().ToString("N");
            await arranged.Service.RaiseQuarantineAlertAsync(
                arranged.OrgId, sourceRef, "npm", "pkg:npm/wiring-test@1.0.0", "quarantine",
                "Held pending review.");

            var alert = (await arranged.Alerts.ListAsync(arranged.OrgId, null, 50, 0)).Items
                .First(a => a.SourceRef == sourceRef);
            var row = await WaitForOutcomeAsync(arranged.Conn, alert.Id, clock);

            Assert.Equal(EmailOutboxFailureClasses.Permanent, row.FailureClass);
            Assert.Equal(EmailOutboxStates.DeadLetter, row.State);
            Assert.Contains(nameof(Dependably.Protocol.SsrfBlockedException), row.LastError);

            // Permanent means no second attempt was spent on it.
            Assert.Equal(1L, row.Attempts);

            var reread = (await arranged.Alerts.ListAsync(arranged.OrgId, null, 50, 0)).Items
                .First(a => a.SourceRef == sourceRef);
            Assert.Equal("failed", reread.EmailStatus);
        }
    }
}
