using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using MimeKit;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// The durable outbox's delivery semantics: the lifecycle, the failure classification, and all four
/// bounds. Every test drives the real <see cref="EmailOutboxDeliveryService"/> over a real
/// <see cref="EmailOutboxRepository"/> against an in-memory SQLite store, with a frozen clock, so
/// backoff instants and ceiling crossings are asserted exactly rather than within a tolerance.
///
/// <para>
/// The two facts these tests exist to pin, neither of which the previous in-memory delivery path
/// could satisfy: a message survives the process that queued it, and an outage longer than the old
/// 1s/5s/30s retry budget does not lose it.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailOutboxDeliveryServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── doubles ──────────────────────────────────────────────────────────────

    /// <summary>
    /// A send seam whose outcome is switchable mid-test, so a relay outage and its recovery are both
    /// expressible against one worker instance.
    /// </summary>
    private sealed class ToggleMailSender : SmtpMailSender
    {
        public ToggleMailSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false))
        {
        }

        /// <summary>When non-null, every send throws this instead of succeeding.</summary>
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

    private InstanceSmtpConfig UnconfiguredInstance() =>
        new((_, _) => Task.FromResult<string?>(null), _clock);

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
        EnvelopeProtector Protector,
        OrgRepository Orgs)
    {
        /// <summary>
        /// A fresh worker over the same store — which is exactly what a process restart looks like
        /// from the outbox's point of view. Building a second one mid-test is how the restart cases
        /// prove the queue lives in the database and not in the worker. The breaker instance is
        /// deliberately the Harness-level one (not a fresh one per call) so tests can drive several
        /// passes and inspect one continuous breaker history.
        /// </summary>
        public EmailOutboxDeliveryService NewWorker(TimeProvider clock) => new(
            new EmailOutboxDeliveryServices(
                Outbox, Policy, Breaker, Instance, Sender, Alerts, Settings, Orgs, clock,
                NullLogger<EmailOutboxDeliveryService>.Instance));
    }

    private Harness BuildHarness(
        EnvelopeProtector protector,
        InstanceSmtpConfig? instance = null,
        EmailOutboxPolicy? policy = null,
        EmailTransportBreaker? breaker = null)
    {
        var settings = new AlertSettingsRepository(_db, protector, _clock);
        var alerts = new AlertRepository(_db, _clock);
        var sender = new ToggleMailSender();
        var outbox = new EmailOutboxRepository(_db, _clock);
        var resolvedPolicy = policy ?? Policy();
        var resolvedInstance = instance ?? ConfiguredInstance();
        var resolvedBreaker = breaker ?? Breaker();

        var worker = new EmailOutboxDeliveryService(
                         new EmailOutboxDeliveryServices(
                         outbox, resolvedPolicy, resolvedBreaker, resolvedInstance, sender, alerts, settings, new OrgRepository(_db), _clock, NullLogger<EmailOutboxDeliveryService>.Instance));

        var writer = new AlertEmailQueue(
            outbox, resolvedPolicy, worker, settings, alerts, RealLocalizer(),
            NullLogger<AlertEmailQueue>.Instance);

        return new Harness(
            writer, outbox, sender, alerts, settings, resolvedPolicy, resolvedInstance, resolvedBreaker,
            protector, new OrgRepository(_db));
    }

    private static async Task<AlertRecord> QueueOneAsync(Harness h, string purl = "pkg:npm/outbox-test@1.0.0")
    {
        await h.Settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "ops@example.com"));

        var alert = await h.Alerts.TryInsertAsync(new NewAlert(
            "org1", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: purl,
            Title: "New quarantine item: pkg:npm/outbox-test@1.0.0", Detail: "Held pending review."));

        await h.Writer.NotifyAsync(alert!);
        return alert!;
    }

    // Attempts is long, not int: SQLite materialises INTEGER as Int64 and Dapper's
    // positional-record constructor match is exact.
    private sealed record Row(
        string State, long Attempts, string? FailureClass, string? LastError,
        string NextAttemptAt, string? CompletedAt);

    private async Task<Row> ReadRowAsync(string correlationId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<Row>(
            """
            SELECT state AS State, attempts AS Attempts, failure_class AS FailureClass,
                   last_error AS LastError, next_attempt_at AS NextAttemptAt,
                   completed_at AS CompletedAt
            FROM email_outbox WHERE correlation_id = @correlationId
            """,
            new { correlationId });
    }

    private async Task<int> CountAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM email_outbox");
    }

    /// <summary>
    /// Seeds an extra org and turns its alert-email channel on. The class fixture only creates
    /// org1; the reconciliation cases need several tenants in one batch.
    /// </summary>
    private async Task SeedOrgAsync(Harness h, string orgId, string slug)
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@orgId, @slug)", new { orgId, slug });
        }

        await h.Settings.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "ops@example.com"));
    }

    /// <summary>Raises an alert for <paramref name="orgId"/> and persists its mail to the outbox.</summary>
    private static async Task<AlertRecord> QueueForOrgAsync(Harness h, string orgId, string purl)
    {
        var alert = await h.Alerts.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: purl,
            Title: $"New quarantine item: {purl}", Detail: "Held pending review."));

        await h.Writer.NotifyAsync(alert!);
        return alert!;
    }

    /// <summary>
    /// Reproduces the divergence the reconciliation sweep exists for: the outbox row keeps its
    /// authoritative terminal state, and the projection onto the alert is gone — exactly the
    /// residue of a <c>RecordEmailOutcomeAsync</c> that threw, or of a process that died between
    /// the two non-transactional writes. <c>updated_at</c> is deliberately left as it was, because
    /// the write being simulated never happened.
    /// </summary>
    private async Task LoseTheProjectionAsync(string alertId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE alert SET email_status = NULL, email_error = NULL WHERE id = @id",
            new { id = alertId });
    }

    private async Task SetOrgStatusAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE orgs SET status = @status WHERE id = @orgId", new { orgId, status });
    }

    // ── Durability: the message outlives the process that queued it ───────────

    /// <summary>
    /// The message is queued, and the worker that queued it never runs a single pass. A brand-new
    /// worker — the post-restart process — picks the message up and delivers it. Under the in-memory
    /// channel the message existed only inside the worker, so this is the case that was simply
    /// unrecoverable.
    /// </summary>
    [Fact]
    public async Task Restart_MessageQueuedByOneWorker_IsDeliveredByAFreshWorker()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        // The queueing worker is discarded without ever running. Everything below is the new process.
        var afterRestart = h.NewWorker(_clock);
        await afterRestart.RunPassAsync(CancellationToken.None);

        Assert.Equal(1, h.Sender.Calls);
        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(alert.Id)).State);
        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    /// <summary>
    /// A restart that lands mid-attempt: the row is left in <c>sending</c> under a lease no process
    /// holds any more. Once the lease lapses the row re-enters the drain set rather than being stuck
    /// in a non-terminal state forever — and the attempt it already consumed is not rewound, so the
    /// retry ceiling still holds across the crash.
    /// </summary>
    [Fact]
    public async Task Restart_MidAttempt_LapsedLeaseReturnsTheRowToTheDrainSet()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        // Claim the row and abandon it, exactly as a killed replica would.
        var claimed = await h.Outbox.ClaimDueAsync(10);
        Assert.Single(claimed);
        Assert.Equal(1, claimed[0].Attempts);
        Assert.Equal(EmailOutboxStates.Sending, (await ReadRowAsync(alert.Id)).State);

        // Before the lease lapses the row is invisible to any other worker — no double send.
        Assert.Empty(await h.Outbox.ClaimDueAsync(10));

        _clock.Advance(EmailOutboxPolicy.LeaseDuration + TimeSpan.FromSeconds(1));
        var reclaimed = await h.Outbox.ClaimDueAsync(10);
        Assert.Single(reclaimed);
        Assert.Equal(2, reclaimed[0].Attempts);
    }

    /// <summary>
    /// The headline case. The relay is down for well over the old delivery path's entire budget
    /// (1 s + 5 s + 30 s ≈ 36 s, after which it recorded a terminal failure and discarded the
    /// message), then recovers. The message is still queued and is delivered.
    /// </summary>
    [Fact]
    public async Task Outage_LongerThanTheOldRetryBudget_StillDeliversOnRecovery()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);
        var queuedAt = _clock.GetUtcNow();

        h.Sender.Failure = () => new SocketException((int)SocketError.ConnectionRefused);
        var worker = h.NewWorker(_clock);

        // Attempt 1 at t0 fails; the next attempt is scheduled 30s out.
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailOutboxStates.Pending, (await ReadRowAsync(alert.Id)).State);

        // Burn well past the 36-second window the old path gave up at.
        _clock.Advance(TimeSpan.FromMinutes(1));
        await worker.RunPassAsync(CancellationToken.None);
        _clock.Advance(TimeSpan.FromMinutes(2));
        await worker.RunPassAsync(CancellationToken.None);

        var stillQueued = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Pending, stillQueued.State);
        Assert.Equal(3L, stillQueued.Attempts);
        // No terminal outcome has been stamped on the alert: it has not failed, it is waiting.
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);

        // The relay comes back, ten minutes after the message was raised.
        h.Sender.Failure = null;
        _clock.Advance(TimeSpan.FromMinutes(7));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.True(_clock.GetUtcNow() - queuedAt > TimeSpan.FromSeconds(36));
        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(alert.Id)).State);
        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    // ── Retry classification ─────────────────────────────────────────────────

    /// <summary>
    /// An SMTP 5xx is the protocol saying "not ever, as sent". It dead-letters on the first attempt:
    /// no retries, a terminal state distinct from <c>expired</c>, and the failure recorded on the
    /// alert so an operator can see which message is bad.
    /// </summary>
    [Fact]
    public async Task PermanentFailure_SmtpFiveXx_DeadLettersWithoutRetrying()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        h.Sender.Failure = () => new SmtpCommandException(
            SmtpErrorCode.RecipientNotAccepted, SmtpStatusCode.MailboxUnavailable, "550 no such mailbox");

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        // A second pass must not pick the row back up — terminal means terminal.
        _clock.Advance(TimeSpan.FromHours(1));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(1, h.Sender.Calls);
        var row = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.DeadLetter, row.State);
        Assert.Equal(EmailOutboxFailureClasses.Permanent, row.FailureClass);
        Assert.Equal(1L, row.Attempts);
        Assert.NotNull(row.CompletedAt);

        Assert.Equal(1, worker.DeadLetteredCount);
        Assert.Equal("failed", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    /// <summary>
    /// A relay host the SSRF guard refuses dead-letters on the first attempt, with no retry. The
    /// state-level counterpart to the classifier case: the guard resolves and vets the host, so every
    /// retry reaches the identical verdict and spending the retry budget on it buys nothing. This is
    /// the shape an operator produces by pointing the instance relay at a loopback or private address,
    /// and it must read as a configuration error rather than as an outage.
    /// </summary>
    [Fact]
    public async Task PermanentFailure_SsrfBlockedRelayHost_DeadLettersWithoutRetrying()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        h.Sender.Failure = () => new SsrfBlockedException("smtp://127.0.0.1:25");

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        // Well past any backoff: a terminal row is never picked back up.
        _clock.Advance(TimeSpan.FromHours(1));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(1, h.Sender.Calls);
        var row = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.DeadLetter, row.State);
        Assert.Equal(EmailOutboxFailureClasses.Permanent, row.FailureClass);
        Assert.Equal(1L, row.Attempts);
        Assert.Equal(1, worker.DeadLetteredCount);
        Assert.Equal("failed", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    /// <summary>
    /// An unrecognised failure is not thrown away on the first attempt. It is retried like a transient
    /// one and retired by the retry ceiling — <c>expired</c>, not <c>dead_letter</c>, because nothing
    /// established that the message itself is bad. That is the fail-safe direction: a novel failure
    /// degrades into "gives up eventually" rather than "dropped immediately".
    /// </summary>
    [Fact]
    public async Task UnrecognisedFailure_RetriesUpToTheCeilingThenExpires()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, policy: Policy(("EMAIL_OUTBOX_MAX_ATTEMPTS", "2")));
        var alert = await QueueOneAsync(h);

        h.Sender.Failure = () => new NotSupportedException("a failure mode nobody has classified");

        var worker = h.NewWorker(_clock);

        await worker.RunPassAsync(CancellationToken.None);
        var afterFirst = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Pending, afterFirst.State);
        Assert.Equal(EmailOutboxFailureClasses.Unknown, afterFirst.FailureClass);

        _clock.Advance(EmailOutboxPolicy.FirstBackoff);
        await worker.RunPassAsync(CancellationToken.None);

        var afterSecond = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Expired, afterSecond.State);
        Assert.Equal(EmailOutboxFailureClasses.Unknown, afterSecond.FailureClass);
        Assert.Equal(2L, afterSecond.Attempts);
        Assert.Equal(2, h.Sender.Calls);
        Assert.Equal(1, worker.ExpiredCount);
        Assert.Equal("failed", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    /// <summary>Exact backoff instants: 30 s, then 60 s, then 120 s from each failed attempt.</summary>
    [Fact]
    public async Task TransientFailure_SchedulesTheNextAttemptAtTheExactBackoffInstant()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);
        h.Sender.Failure = () => new SmtpProtocolException("connection reset");

        var worker = h.NewWorker(_clock);
        var t0 = _clock.GetUtcNow();

        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(t0.AddSeconds(30).ToUtcIso(), (await ReadRowAsync(alert.Id)).NextAttemptAt);

        _clock.Advance(TimeSpan.FromSeconds(30));
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(t0.AddSeconds(30 + 60).ToUtcIso(), (await ReadRowAsync(alert.Id)).NextAttemptAt);

        _clock.Advance(TimeSpan.FromSeconds(60));
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(t0.AddSeconds(90 + 120).ToUtcIso(), (await ReadRowAsync(alert.Id)).NextAttemptAt);
    }

    /// <summary>The backoff doubles from 30 s and is capped at 30 minutes, so a long outage settles
    /// into a steady, cheap poll rather than an ever-growing gap.</summary>
    [Theory]
    [InlineData(1, 30)]
    [InlineData(2, 60)]
    [InlineData(3, 120)]
    [InlineData(6, 960)]
    [InlineData(7, 1800)]
    [InlineData(40, 1800)]
    public void BackoffAfter_DoublesFromThirtySecondsAndCapsAtThirtyMinutes(int attempts, int expectedSeconds) =>
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), EmailOutboxPolicy.BackoffAfter(attempts));

    /// <summary>
    /// The classification table, asserted against the exception types the transport actually raises.
    /// The unmatched arm is the load-bearing one: unknown means "retry, bounded", never "discard".
    /// </summary>
    [Theory]
    [MemberData(nameof(ClassificationCases))]
    [SuppressMessage("Usage", "xUnit1045:Avoid using TheoryData type arguments that might not be serializable",
        Justification = "The subject under test classifies exceptions; the exception instance is the test data.")]
    public void Classifier_MapsEachFailureToItsClass(Exception ex, string expected) =>
        Assert.Equal(expected, EmailOutboxFailureClassifier.Classify(ex));

    // The classifier's input is an exception, so the table's first column is one by construction.
    // A non-serializable row costs only individual-row re-run in Test Explorer; substituting a
    // discriminator string plus a factory would hide which exception each verdict is about, which is
    // the whole content of this table.
    [SuppressMessage("Usage", "xUnit1045:Avoid using TheoryData type arguments that might not be serializable",
        Justification = "The subject under test classifies exceptions; the exception instance is the test data.")]
    public static TheoryData<Exception, string> ClassificationCases() => new()
    {
        // Permanent: the protocol or the message says so.
        {
            new SmtpCommandException(
                SmtpErrorCode.RecipientNotAccepted, SmtpStatusCode.MailboxUnavailable, "550"),
            EmailOutboxFailureClasses.Permanent
        },
        { new AuthenticationException("535 authentication failed"), EmailOutboxFailureClasses.Permanent },
        { new ParseException("not an address", 0, 0), EmailOutboxFailureClasses.Permanent },
        // A configuration error, not an outage: the guard reaches the identical verdict every retry.
        { new SsrfBlockedException("smtp://169.254.169.254"), EmailOutboxFailureClasses.Permanent },

        // Transient: the relay could not take it right now.
        {
            new SmtpCommandException(
                SmtpErrorCode.MessageNotAccepted, SmtpStatusCode.ServiceNotAvailable, "421"),
            EmailOutboxFailureClasses.Transient
        },
        { new SmtpProtocolException("unexpected end of stream"), EmailOutboxFailureClasses.Transient },
        { new SocketException((int)SocketError.ConnectionRefused), EmailOutboxFailureClasses.Transient },
        { new TimeoutException("relay did not answer"), EmailOutboxFailureClasses.Transient },
        { new IOException("broken pipe"), EmailOutboxFailureClasses.Transient },

        // Unrecognised: retried, bounded by the ceiling, never dead-lettered on sight.
        { new NotSupportedException("novel"), EmailOutboxFailureClasses.Unknown },
        { new InvalidOperationException("novel"), EmailOutboxFailureClasses.Unknown },
        // A TLS handshake failure is deliberately here and not permanent: an expired relay
        // certificate is an outage a renewal fixes, with no change to the message.
        { new SslHandshakeException("certificate expired"), EmailOutboxFailureClasses.Unknown },
    };

    // ── The four bounds ──────────────────────────────────────────────────────

    /// <summary>
    /// The retention ceiling retires a message nothing ever tried to send. This is the bound the
    /// retry ceiling cannot cover: an unconfigured relay consumes no attempts, so without a
    /// retention ceiling the row would sit in <c>pending</c> forever, holding recipient addresses.
    /// </summary>
    [Fact]
    public async Task RetentionCeiling_ExpiresAMessageThatWasNeverAttempted()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(
            ep,
            instance: UnconfiguredInstance(),
            policy: Policy(("EMAIL_OUTBOX_RETENTION_HOURS", "1")));
        var alert = await QueueOneAsync(h);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailOutboxStates.Pending, (await ReadRowAsync(alert.Id)).State);

        _clock.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));
        await worker.RunPassAsync(CancellationToken.None);

        var row = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Expired, row.State);
        Assert.Equal(0L, row.Attempts);
        Assert.Equal(0, h.Sender.Calls);
        Assert.NotNull(row.CompletedAt);
    }

    /// <summary>
    /// The maximum-retry-duration ceiling retires a message before scheduling an attempt that would
    /// fall beyond it, independently of the attempt count — the configured ceiling here is 100
    /// attempts, which is never reached.
    /// </summary>
    [Fact]
    public async Task MaxRetryDuration_ExpiresTheMessageIndependentlyOfTheAttemptCeiling()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, policy: Policy(
            ("EMAIL_OUTBOX_MAX_RETRY_HOURS", "1"),
            ("EMAIL_OUTBOX_MAX_ATTEMPTS", "100"),
            ("EMAIL_OUTBOX_RETENTION_HOURS", "72")));
        var alert = await QueueOneAsync(h);
        h.Sender.Failure = () => new SocketException((int)SocketError.TimedOut);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailOutboxStates.Pending, (await ReadRowAsync(alert.Id)).State);

        // 15 seconds short of the retry deadline: the attempt runs, but its 30-second backoff would
        // land past the deadline, so the message expires instead of being scheduled again.
        _clock.Advance(TimeSpan.FromMinutes(59) + TimeSpan.FromSeconds(45));
        await worker.RunPassAsync(CancellationToken.None);

        var row = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Expired, row.State);
        Assert.Equal(2L, row.Attempts);
        Assert.Equal(EmailOutboxFailureClasses.Transient, row.FailureClass);
    }

    /// <summary>
    /// Terminal rows are never removed by the delivery path — a dead letter an operator cannot
    /// inspect is no better than a dropped message. The retention sweep is the only delete path, and
    /// it only reaches rows whose terminal state is older than the configured window.
    /// </summary>
    [Fact]
    public async Task TerminalRows_SurviveTheDeliveryPath_AndArePrunedOnlyByRetention()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        await QueueOneAsync(h);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);

        // Many more passes over a delivered row change nothing: it stays, inspectable.
        for (int i = 0; i < 3; i++)
        {
            _clock.Advance(TimeSpan.FromDays(10));
            await worker.RunPassAsync(CancellationToken.None);
        }

        Assert.Equal(1, await CountAsync());

        // A cutoff before the row completed leaves it alone; one after it removes it.
        var completedAt = _clock.GetUtcNow().AddDays(-30);
        Assert.Equal(0, await h.Outbox.PruneTerminalAsync(completedAt.AddDays(-1)));
        Assert.Equal(1, await CountAsync());

        Assert.Equal(1, await h.Outbox.PruneTerminalAsync(_clock.GetUtcNow()));
        Assert.Equal(0, await CountAsync());
    }

    /// <summary>The backlog gauge the worker reports on, and what #533's operator surface will read.</summary>
    [Fact]
    public async Task Backlog_ReportsDepthOldestAndTerminalCounts()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var queued = await QueueOneAsync(h);
        var queuedAt = _clock.GetUtcNow();

        var backlog = await h.Outbox.GetBacklogAsync();
        Assert.Equal(1, backlog.Depth);
        Assert.Equal(queuedAt.ToUtcIso(), backlog.OldestCreatedAt);
        Assert.Equal(0, backlog.DeadLettered);
        Assert.Equal(0, backlog.Expired);

        h.Sender.Failure = () => new SmtpCommandException(
            SmtpErrorCode.RecipientNotAccepted, SmtpStatusCode.MailboxUnavailable, "550");
        await h.NewWorker(_clock).RunPassAsync(CancellationToken.None);

        var after = await h.Outbox.GetBacklogAsync();
        Assert.Equal(0, after.Depth);
        Assert.Null(after.OldestCreatedAt);
        Assert.Equal(1, after.DeadLettered);
        Assert.Equal(EmailOutboxStates.DeadLetter, (await ReadRowAsync(queued.Id)).State);
    }

    // ── Transport circuit breaker, driven through the real delivery pass ─────

    /// <summary>
    /// A run of transport-scope (transient) failures across passes stops the worker from claiming
    /// further rows — a message raised while the breaker is open is left untouched, at zero attempts,
    /// until the breaker probes again.
    /// </summary>
    [Fact]
    public async Task Breaker_OpensAfterConsecutiveTransientFailures_AndStopsClaimingNewRows()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, breaker: Breaker(("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "2")));

        var first = await QueueOneAsync(h, purl: "pkg:npm/breaker-first@1.0.0");
        var second = await QueueOneAsync(h, purl: "pkg:npm/breaker-second@1.0.0");
        h.Sender.Failure = () => new SocketException((int)SocketError.ConnectionRefused);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(2, h.Sender.Calls);
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State);

        // A third message raised while the breaker is open is queued but never attempted.
        var third = await QueueOneAsync(h, purl: "pkg:npm/breaker-third@1.0.0");
        _clock.Advance(TimeSpan.FromSeconds(1));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(2, h.Sender.Calls); // unchanged
        var thirdRow = await ReadRowAsync(third.Id);
        Assert.Equal(EmailOutboxStates.Pending, thirdRow.State);
        Assert.Equal(0L, thirdRow.Attempts);
    }

    /// <summary>
    /// A relay that only ever rejects individual recipients (SMTP 5xx) never trips the breaker, no
    /// matter how many pile up — the breaker is a fact about the transport, and a permanent failure
    /// is proof the transport is answering, not evidence it is down.
    /// </summary>
    [Fact]
    public async Task Breaker_DoesNotOpen_OnPermanentFailuresOnly()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, breaker: Breaker(("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "2")));

        await QueueOneAsync(h, purl: "pkg:npm/permanent-a@1.0.0");
        await QueueOneAsync(h, purl: "pkg:npm/permanent-b@1.0.0");
        await QueueOneAsync(h, purl: "pkg:npm/permanent-c@1.0.0");
        h.Sender.Failure = () => new SmtpCommandException(
            SmtpErrorCode.RecipientNotAccepted, SmtpStatusCode.MailboxUnavailable, "550 no such mailbox");

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(3, h.Sender.Calls);
        Assert.Equal(EmailTransportState.Closed, h.Breaker.Snapshot().State);

        // A fresh message right after is still attempted normally — nothing was ever gated.
        h.Sender.Failure = null;
        var fresh = await QueueOneAsync(h, purl: "pkg:npm/permanent-fresh@1.0.0");
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(fresh.Id)).State);
    }

    /// <summary>
    /// The headline recovery case. The breaker opens, then — once its cooldown elapses — admits
    /// exactly one message as a probe rather than the whole backlog landing on the just-recovered
    /// relay at once. The probe succeeding closes the breaker, and the rest of the backlog is
    /// delivered normally from the next pass.
    /// </summary>
    [Fact]
    public async Task Breaker_RecoversViaASingleProbe_NeverTheWholeBacklogAtOnce()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(
            ep,
            breaker: Breaker(
                ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "1"),
                ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", "30")));

        var messages = new List<AlertRecord>();
        for (int i = 0; i < 5; i++)
        {
            messages.Add(await QueueOneAsync(h, purl: $"pkg:npm/burst-{i}@1.0.0"));
        }

        h.Sender.Failure = () => new SocketException((int)SocketError.ConnectionRefused);
        var worker = h.NewWorker(_clock);

        // Every already-claimed message in this pass is still attempted — the breaker opening
        // mid-batch does not abandon work already claimed under lease — but claiming for the NEXT
        // pass is gated from here on.
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(5, h.Sender.Calls);
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State);

        // The relay recovers. The cooldown elapses, but recovery is still exactly one probe.
        h.Sender.Failure = null;
        _clock.Advance(TimeSpan.FromSeconds(30));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(6, h.Sender.Calls); // exactly one more send, not five
        Assert.Equal(EmailTransportState.Closed, h.Breaker.Snapshot().State);

        int delivered = 0;
        foreach (var message in messages)
        {
            if ((await ReadRowAsync(message.Id)).State == EmailOutboxStates.Delivered)
            {
                delivered++;
            }
        }

        Assert.Equal(1, delivered); // only the probe message landed so far

        // The breaker is closed again: the remaining backlog (each already past its own
        // message-level backoff by now) delivers normally on the next pass.
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(10, h.Sender.Calls);
        foreach (var message in messages)
        {
            Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(message.Id)).State);
        }
    }

    /// <summary>
    /// The breaker only ever narrows what gets CLAIMED. <see cref="EmailOutboxDeliveryService.RunPassAsync"/>
    /// always retires overdue rows before it ever looks at the breaker, so a message that ages past
    /// its retention ceiling still reaches <c>expired</c> even though the breaker has been open — and
    /// has never once been probed — for its entire lifetime.
    /// </summary>
    [Fact]
    public async Task Breaker_Open_DoesNotStarveRetentionExpiry()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(
            ep,
            policy: Policy(("EMAIL_OUTBOX_RETENTION_HOURS", "1")),
            // A cooldown far longer than the retention window: the breaker never once probes
            // before the message must have expired, so expiry cannot be riding a probe's coattails.
            breaker: Breaker(
                ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "1"),
                ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", "36000")));

        // Trip the breaker before the message under test even exists.
        h.Breaker.RecordTransportFailure();
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State);

        var alert = await QueueOneAsync(h);
        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailOutboxStates.Pending, (await ReadRowAsync(alert.Id)).State);

        _clock.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));
        await worker.RunPassAsync(CancellationToken.None);

        var row = await ReadRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Expired, row.State);
        Assert.Equal(0, h.Sender.Calls); // never attempted — the breaker was open the whole time
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State); // still open, still unprobed
    }

    /// <summary>
    /// The invariant !932 established for failure recording holds identically for the breaker's
    /// failure path: sustained transport failures accumulate breaker state and terminal outbox rows,
    /// never a tenant configuration mutation. <c>email_enabled</c> stays exactly as the tenant set it
    /// through an open breaker, a probe, and a close.
    /// </summary>
    [Fact]
    public async Task Breaker_SustainedTransportFailures_NeverMutatesEmailEnabled()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(
            ep,
            breaker: Breaker(
                ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "1"),
                ("EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", "30")));

        var alert = await QueueOneAsync(h);
        h.Sender.Failure = () => new SocketException((int)SocketError.ConnectionRefused);
        var worker = h.NewWorker(_clock);

        // The first attempt fails and trips the breaker outright (threshold 1).
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State);
        Assert.True((await h.Settings.GetAsync("org1")).EmailEnabled);

        // Passes before the cooldown elapses claim nothing — the breaker stays open and untouched,
        // and tenant intent is still untouched.
        for (int i = 0; i < 3; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(5));
            await worker.RunPassAsync(CancellationToken.None);
            Assert.True((await h.Settings.GetAsync("org1")).EmailEnabled);
        }

        Assert.Equal(1, h.Sender.Calls); // only the original attempt — nothing claimed while gated

        // The cooldown elapses: the probe still fails (the relay is still down), reopening the
        // breaker with a longer cooldown. Tenant intent is still untouched.
        _clock.Advance(TimeSpan.FromSeconds(30));
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(2, h.Sender.Calls);
        Assert.Equal(EmailTransportState.Open, h.Breaker.Snapshot().State);
        Assert.True((await h.Settings.GetAsync("org1")).EmailEnabled);

        // The relay recovers, and the next probe — once its (now doubled) cooldown elapses —
        // succeeds. Tenant intent has been untouched through the whole open→probe→open→probe→close
        // history.
        h.Sender.Failure = null;
        _clock.Advance(TimeSpan.FromSeconds(60));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(alert.Id)).State);
        Assert.True((await h.Settings.GetAsync("org1")).EmailEnabled);
    }

    // ── Reconciliation of the alert-side projection ──────────────────────────

    /// <summary>
    /// The headline case. The message is delivered and the outbox row is terminal, but the second,
    /// non-transactional write — the projection onto the alert — did not land. Nothing else in the
    /// system would ever repair that: <c>ClaimDueAsync</c> never returns a terminal row, so the
    /// alert would read as NULL forever, indistinguishable from mail that was never attempted. A
    /// later pass re-derives the outcome from the outbox row, which is still authoritative.
    /// </summary>
    [Fact]
    public async Task Reconcile_TerminalRowWhoseAlertDisagrees_ReProjectsTheOutcome()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(alert.Id)).State);
        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);

        await LoseTheProjectionAsync(alert.Id);
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);

        _clock.Advance(TimeSpan.FromMinutes(10));
        var repairedAt = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        var reread = await h.Alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", reread!.EmailStatus);
        Assert.Equal(repairedAt, reread.UpdatedAt);
        Assert.Equal(1, worker.ReconciledCount);

        // The outbox row itself is untouched by the repair — it was already correct.
        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(alert.Id)).State);
        Assert.Equal(1, h.Sender.Calls);
    }

    /// <summary>
    /// The adversarial twin of the case above, and the one a sweep that re-projects unconditionally
    /// fails. An alert that already agrees with its terminal outbox row must be left completely
    /// alone: not re-written with the same value, not counted as reconciled, and — the observable
    /// that discriminates the mutant — not given a fresh <c>updated_at</c>. The clock is advanced
    /// between the delivery and the later passes precisely so an unconditional re-write would move
    /// that column to a different, exactly-asserted instant.
    /// </summary>
    [Fact]
    public async Task Reconcile_TerminalRowWhoseAlertAgrees_IsLeftUntouched()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        var worker = h.NewWorker(_clock);
        var deliveredAt = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        var afterDelivery = await h.Alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", afterDelivery!.EmailStatus);
        Assert.Equal(deliveredAt, afterDelivery.UpdatedAt);

        for (int i = 0; i < 3; i++)
        {
            _clock.Advance(TimeSpan.FromHours(1));
            await worker.RunPassAsync(CancellationToken.None);
        }

        var reread = await h.Alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", reread!.EmailStatus);
        // Still the delivery instant, three hours later: nothing re-wrote this row.
        Assert.Equal(deliveredAt, reread.UpdatedAt);
        Assert.Equal(0, worker.ReconciledCount);
    }

    /// <summary>
    /// The design distinction the sweep turns on. <c>alert.email_status</c> is a state and is
    /// re-projected; the <c>alert_settings</c> delivery-health columns are accumulative
    /// (<c>email_consecutive_failures</c> is a counter, <c>email_failing_since</c> a first-seen
    /// instant) and are deliberately NOT replayed. Replaying them would invent failures that never
    /// happened and could cross an operator's threshold on repair — and, because the repair itself
    /// is retried on the next pass, it would double-count by construction.
    ///
    /// <para>
    /// Every health column is asserted at its exact original instant/value after the repair, with
    /// the clock advanced well past it, so a sweep that replays <c>RecordEmailFailureAsync</c> fails
    /// on the counter, on the first-seen instant, and on the last-delivery instant alike.
    /// </para>
    /// </summary>
    [Fact]
    public async Task Reconcile_DoesNotReplayTheAccumulativeHealthCounters()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var alert = await QueueOneAsync(h);

        h.Sender.Failure = () => new SmtpCommandException(
            SmtpErrorCode.RecipientNotAccepted, SmtpStatusCode.MailboxUnavailable, "550 no such mailbox");

        var worker = h.NewWorker(_clock);
        var failedAt = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        var health = await h.Settings.GetAsync("org1");
        Assert.Equal("failed", health.EmailLastStatus);
        Assert.Equal(1, health.EmailConsecutiveFailures);
        Assert.Equal(failedAt.ToUtcIso(), health.EmailFailingSince);
        Assert.Equal(failedAt.ToUtcIso(), health.EmailLastDeliveryAt);

        await LoseTheProjectionAsync(alert.Id);

        _clock.Advance(TimeSpan.FromHours(6));
        var repairedAt = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        // The state is repaired…
        var reread = await h.Alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("failed", reread!.EmailStatus);
        Assert.Contains("550 no such mailbox", reread.EmailError);
        Assert.Equal(repairedAt, reread.UpdatedAt);
        Assert.Equal(1, worker.ReconciledCount);

        // …and the accumulative health record is exactly as the one real failure left it.
        var afterRepair = await h.Settings.GetAsync("org1");
        Assert.Equal(1, afterRepair.EmailConsecutiveFailures);
        Assert.Equal(failedAt.ToUtcIso(), afterRepair.EmailFailingSince);
        Assert.Equal(failedAt.ToUtcIso(), afterRepair.EmailLastDeliveryAt);
        Assert.Equal("failed", afterRepair.EmailLastStatus);

        // Tenant configuration is untouched, the same posture the failure path itself holds.
        Assert.True(afterRepair.EmailEnabled);
    }

    /// <summary>
    /// A message retired at a ceiling has never had ANY projection written to its alert:
    /// <see cref="EmailOutboxRepository.ExpireOverdueAsync"/> retires rows in one set-based sweep
    /// with no per-row bookkeeping. Nothing is manipulated in this test — the divergence arises on
    /// its own — and the reconciliation in the same pass is what stops a never-delivered alert from
    /// reading as never-attempted.
    /// </summary>
    [Fact]
    public async Task Reconcile_CeilingExpiredRow_ProjectsFailedOntoItsAlert()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(
            ep,
            instance: UnconfiguredInstance(),
            policy: Policy(("EMAIL_OUTBOX_RETENTION_HOURS", "1")));
        var alert = await QueueOneAsync(h);

        var worker = h.NewWorker(_clock);
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(EmailOutboxStates.Pending, (await ReadRowAsync(alert.Id)).State);
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);

        _clock.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));
        var expiredAt = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(EmailOutboxStates.Expired, (await ReadRowAsync(alert.Id)).State);
        var reread = await h.Alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("failed", reread!.EmailStatus);
        Assert.Equal(expiredAt, reread.UpdatedAt);
        Assert.Equal(0, h.Sender.Calls);
        Assert.Equal(1, worker.ReconciledCount);
    }

    /// <summary>
    /// Mixed partial failure across tenants in one pass, with the twin folded in. org1's row is
    /// delivered, org2's dead-lettered, org3's delivered — all three projections then lost — and
    /// org3 is suspended. The two active tenants are repaired to their own, different statuses; the
    /// suspended tenant's is not touched, because a suspended org admits no per-tenant background
    /// work. Reinstating org3 resumes its repair on the next pass, so the exclusion is a deferral
    /// rather than a permanent loss.
    ///
    /// <para>
    /// The suspension exclusion lives in the selection SQL, not in a caller-side skip, so an
    /// excluded tenant's rows never occupy the pass's batch and cannot starve the tenants that are
    /// active. A mutant dropping the <c>o.status = 'active'</c> join predicate repairs org3 in the
    /// first pass and fails here.
    /// </para>
    /// </summary>
    [Fact]
    public async Task Reconcile_MixedTenants_RepairsActiveOnes_DefersTheSuspendedOne()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        await SeedOrgAsync(h, "org2", "beta");
        await SeedOrgAsync(h, "org3", "gamma");

        var org1Alert = await QueueOneAsync(h, purl: "pkg:npm/recon-one@1.0.0");
        var org2Alert = await QueueForOrgAsync(h, "org2", "pkg:npm/recon-two@1.0.0");
        var org3Alert = await QueueForOrgAsync(h, "org3", "pkg:npm/recon-three@1.0.0");

        var worker = h.NewWorker(_clock);

        // org2's row is dead-lettered directly, so exactly one of the three ends in a failed
        // terminal state while the other two deliver over the same shared transport.
        await h.Outbox.MarkDeadLetterAsync(
            (await OutboxIdForAsync(org2Alert.Id))!, EmailOutboxFailureClasses.Permanent, "550 rejected");
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(org1Alert.Id)).State);
        Assert.Equal(EmailOutboxStates.DeadLetter, (await ReadRowAsync(org2Alert.Id)).State);
        Assert.Equal(EmailOutboxStates.Delivered, (await ReadRowAsync(org3Alert.Id)).State);

        // org2's row was dead-lettered before this worker ever saw it, so that pass's own
        // reconciliation already projected its outcome once. The repairs under test are counted
        // from here, as a delta, rather than from zero.
        long reconciledBefore = worker.ReconciledCount;

        await LoseTheProjectionAsync(org1Alert.Id);
        await LoseTheProjectionAsync(org2Alert.Id);
        await LoseTheProjectionAsync(org3Alert.Id);
        await SetOrgStatusAsync("org3", "suspended");

        _clock.Advance(TimeSpan.FromMinutes(30));
        await worker.RunPassAsync(CancellationToken.None);

        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", org1Alert.Id))!.EmailStatus);
        var org2Reread = await h.Alerts.GetByIdAsync("org2", org2Alert.Id);
        Assert.Equal("failed", org2Reread!.EmailStatus);
        Assert.Contains("550 rejected", org2Reread.EmailError);
        // The must-NOT half: a suspended tenant's read model is not written by a background pass.
        Assert.Null((await h.Alerts.GetByIdAsync("org3", org3Alert.Id))!.EmailStatus);
        Assert.Equal(2, worker.ReconciledCount - reconciledBefore);

        // Deferred, not lost: reinstating the tenant resumes the repair.
        await SetOrgStatusAsync("org3", "active");
        _clock.Advance(TimeSpan.FromMinutes(5));
        var org3RepairedAt = _clock.GetUtcNow();
        await worker.RunPassAsync(CancellationToken.None);

        var org3Reread = await h.Alerts.GetByIdAsync("org3", org3Alert.Id);
        Assert.Equal("sent", org3Reread!.EmailStatus);
        Assert.Equal(org3RepairedAt, org3Reread.UpdatedAt);
        Assert.Equal(3, worker.ReconciledCount - reconciledBefore);
    }

    /// <summary>
    /// The bound. A divergent backlog larger than the batch is never materialised in one go: the
    /// selection returns exactly <c>batchSize</c> rows, oldest terminal first, and successive calls
    /// walk the backlog as earlier rows are repaired out of the predicate rather than re-reading its
    /// head. A mutant dropping the <c>LIMIT</c> returns all five and fails the first assertion; one
    /// ordering newest-first fails the identity assertions.
    /// </summary>
    [Fact]
    public async Task Reconcile_DivergentBacklogLargerThanTheBatch_IsBoundedAndWalksForward()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);
        var worker = h.NewWorker(_clock);

        // Five alerts, each delivered a minute apart so completed_at is a strict order, then every
        // projection lost.
        var alerts = new List<AlertRecord>();
        for (int i = 0; i < 5; i++)
        {
            alerts.Add(await QueueOneAsync(h, purl: $"pkg:npm/bounded-{i}@1.0.0"));
            await worker.RunPassAsync(CancellationToken.None);
            _clock.Advance(TimeSpan.FromMinutes(1));
        }

        foreach (var alert in alerts)
        {
            await LoseTheProjectionAsync(alert.Id);
        }

        var firstBatch = await h.Outbox.FindDivergentAlertProjectionsAsync(2);
        Assert.Equal(2, firstBatch.Count);
        Assert.Equal(
            new[] { alerts[0].Id, alerts[1].Id },
            firstBatch.Select(r => r.CorrelationId).ToArray());

        // Repairing the head removes it from the predicate, so the next read is the next two —
        // progress, not a stuck head.
        foreach (var row in firstBatch)
        {
            await h.Alerts.RecordEmailOutcomeAsync(row.OrgId, row.CorrelationId, "sent", null);
        }

        var secondBatch = await h.Outbox.FindDivergentAlertProjectionsAsync(2);
        Assert.Equal(
            new[] { alerts[2].Id, alerts[3].Id },
            secondBatch.Select(r => r.CorrelationId).ToArray());

        // A whole pass drains what is left, because the pass's own batch is far larger than five.
        _clock.Advance(TimeSpan.FromMinutes(1));
        await worker.RunPassAsync(CancellationToken.None);
        Assert.Empty(
            await h.Outbox.FindDivergentAlertProjectionsAsync(EmailOutboxPolicy.ReconcileBatchSize));
        foreach (var alert in alerts)
        {
            Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
        }
    }

    /// <summary>
    /// A coalesced alert carries no outbox row of its own — its occurrence was folded into another
    /// alert's digest — so it must never be selected for repair, however long its <c>coalesced</c>
    /// status sits there. The sweep keys on the outbox row, and the correct answer for an alert that
    /// has none is to leave it alone rather than invent an outcome for it.
    /// </summary>
    [Fact]
    public async Task Reconcile_CoalescedAlertWithNoOutboxRowOfItsOwn_IsNeverRepaired()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep);

        var opener = await QueueOneAsync(h, purl: "pkg:npm/coalesce-recon@1.0.0");
        var folded = await h.Alerts.TryInsertAsync(new NewAlert(
            "org1", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/coalesce-recon@1.0.0",
            Title: "New quarantine item: pkg:npm/coalesce-recon@1.0.0", Detail: "Held pending review."));
        await h.Writer.NotifyAsync(folded!);

        var foldedAt = _clock.GetUtcNow();
        Assert.Equal(1, await CountAsync());
        Assert.Equal("coalesced", (await h.Alerts.GetByIdAsync("org1", folded!.Id))!.EmailStatus);

        var worker = h.NewWorker(_clock);
        _clock.Advance(TimeSpan.FromMinutes(1));
        await worker.RunPassAsync(CancellationToken.None);
        _clock.Advance(TimeSpan.FromHours(1));
        await worker.RunPassAsync(CancellationToken.None);

        // The digest's own outcome landed on the alert that opened it, and the folded alert kept
        // its coalesced status at the exact instant it was written.
        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", opener.Id))!.EmailStatus);
        var foldedReread = await h.Alerts.GetByIdAsync("org1", folded.Id);
        Assert.Equal("coalesced", foldedReread!.EmailStatus);
        Assert.Equal(foldedAt, foldedReread.UpdatedAt);
        Assert.Equal(0, worker.ReconciledCount);
    }

    /// <summary>The outbox row id currently carrying <paramref name="correlationId"/>.</summary>
    private async Task<string?> OutboxIdForAsync(string correlationId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM email_outbox WHERE correlation_id = @correlationId",
            new { correlationId });
    }
}
