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
/// <see cref="AlertEmailQueue"/> is the write side of the durable email outbox: it resolves the
/// org's channel, renders the message, and persists it to <c>email_outbox</c> before returning.
/// These tests cover that write side and the seam it hands to
/// <see cref="EmailOutboxDeliveryService"/> — what gets persisted, what deliberately does not, the
/// cross-tenant recipient guarantee, the depth-cap shed policy, and mixed per-org outcomes.
///
/// <para>
/// The lifecycle, retry classification, and the four bounds are driven separately, against the real
/// delivery worker, in <c>EmailOutboxDeliveryServiceTests</c>.
/// </para>
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

    /// <summary>The reader never resolves any key, so an all-null stub is a faithful
    /// "instance not configured" double.</summary>
    private static InstanceSmtpConfig BuildUnconfiguredInstance() =>
        new((_, _) => Task.FromResult<string?>(null), Clock);

    /// <summary>The one transport every org sends over. <paramref name="host"/> containing "bad"
    /// simulates an instance-wide relay outage.</summary>
    private static InstanceSmtpConfig BuildInstance(string host = "instance.example.com")
    {
        var rows = new Dictionary<string, string?>
        {
            ["smtp_enabled"] = "1",
            ["smtp_host"] = host,
            ["smtp_from_address"] = "alerts@example.com",
            ["smtp_security"] = "none",
        };
        return new InstanceSmtpConfig(
            (key, _) => Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null), Clock);
    }

    private static EmailOutboxPolicy BuildPolicy(params (string Key, string Value)[] overrides) =>
        new(new ConfigurationBuilder()
            .AddInMemoryCollection(overrides.ToDictionary(o => o.Key, o => (string?)o.Value))
            .Build());

    private static EmailTransportBreaker BuildBreaker(
        FakeTimeProvider clock, params (string Key, string Value)[] overrides) =>
        new(
            new ConfigurationBuilder()
                .AddInMemoryCollection(overrides.ToDictionary(o => o.Key, o => (string?)o.Value))
                .Build(),
            clock,
            NullLogger<EmailTransportBreaker>.Instance);

    private static async Task<AlertRecord> SeedActiveAlertAsync(
        AlertRepository alerts, string orgId, string sourceRef, string purl = "pkg:npm/email-test@1.0.0")
    {
        var alert = await alerts.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: sourceRef,
            Ecosystem: "npm", Purl: purl,
            Title: "New quarantine item: pkg:npm/email-test@1.0.0", Detail: "Held pending review."));
        return alert!;
    }

    /// <summary>An org owns only the delivery gate and its recipient list.</summary>
    private static Task EnableEmailAsync(
        AlertSettingsRepository settings, string orgId, string[] recipients) =>
        settings.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: string.Join(",", recipients)));

    /// <summary>Records every send and routes success/failure by a "bad" substring in the transport
    /// host or in any recipient.</summary>
    private sealed class FakeMailSender : SmtpMailSender
    {
        // The connect guard is never exercised — SendAsync is fully overridden below — so a
        // permissive predicate is enough to satisfy the base constructor.
        public FakeMailSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false))
        {
        }

        private readonly List<SentMessage> _sent = [];

        public sealed record SentMessage(IReadOnlyList<string> To, string Subject, string Body);

        public IReadOnlyList<SentMessage> Sent => _sent;
        public int Calls => _sent.Count;
        public IReadOnlyList<string>? LastTo => _sent.Count == 0 ? null : _sent[^1].To;
        public string? LastSubject => _sent.Count == 0 ? null : _sent[^1].Subject;
        public string? LastBody => _sent.Count == 0 ? null : _sent[^1].Body;

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default)
        {
            _sent.Add(new SentMessage(to, subject, body));

            // The transport is instance-level and identical for every org, so a per-org outcome can
            // only come from the recipient — a relay that accepts one address and rejects another.
            // Host is still honoured so an instance-wide outage stays expressible.
            bool fails = transport.Host?.Contains("bad", StringComparison.Ordinal) == true
                || to.Any(r => r.Contains("bad", StringComparison.Ordinal));
            return fails
                ? Task.FromException(new InvalidOperationException("simulated SMTP failure"))
                : Task.CompletedTask;
        }
    }

    private sealed record Harness(
        AlertEmailQueue Writer,
        EmailOutboxDeliveryService Worker,
        EmailOutboxRepository Outbox,
        FakeMailSender Sender,
        AlertRepository Alerts,
        AlertSettingsRepository Settings);

    private Harness BuildHarness(
        EnvelopeProtector protector,
        FakeTimeProvider clock,
        InstanceSmtpConfig? instance = null,
        EmailOutboxPolicy? policy = null,
        EmailTransportBreaker? breaker = null)
    {
        var settings = new AlertSettingsRepository(_db, protector, clock);
        var alerts = new AlertRepository(_db, clock);
        var sender = new FakeMailSender();
        var outbox = new EmailOutboxRepository(_db, clock);
        var resolvedPolicy = policy ?? BuildPolicy();
        var resolvedInstance = instance ?? BuildInstance();
        var resolvedBreaker = breaker ?? BuildBreaker(clock);

        var worker = new EmailOutboxDeliveryService(
            outbox, resolvedPolicy, resolvedBreaker, resolvedInstance, sender, alerts, settings, clock,
            NullLogger<EmailOutboxDeliveryService>.Instance);

        var writer = new AlertEmailQueue(
            outbox, resolvedPolicy, worker, settings, alerts, RealLocalizer(),
            NullLogger<AlertEmailQueue>.Instance);

        return new Harness(writer, worker, outbox, sender, alerts, settings);
    }

    // Attempts/OccurrenceCount are long, not int: SQLite materialises INTEGER as Int64 and Dapper's
    // positional-record constructor match is exact.
    private sealed record OutboxRow(
        string State, long Attempts, string? LastError, string? FailureClass,
        string? CoalesceKey, string? Recipients, string? MessageKind, string? OrgId,
        long OccurrenceCount, string Subject, string Body);

    private async Task<OutboxRow> ReadOutboxRowAsync(string correlationId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<OutboxRow>(
            """
            SELECT state AS State, attempts AS Attempts, last_error AS LastError,
                   failure_class AS FailureClass, coalesce_key AS CoalesceKey,
                   recipients AS Recipients, message_kind AS MessageKind, org_id AS OrgId,
                   occurrence_count AS OccurrenceCount, subject AS Subject, body AS Body
            FROM email_outbox WHERE correlation_id = @correlationId
            """,
            new { correlationId });
    }

    private async Task<int> CountOutboxAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM email_outbox");
    }

    // ── The write side persists before anything is attempted ─────────────────

    /// <summary>
    /// The durability guarantee starts here: the row exists, complete and deliverable, before any
    /// relay is dialed. This is the assertion the old in-memory channel could not make at all.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_PersistsTheMessageBeforeAnyDeliveryAttempt()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com", "b@example.com"]);
        var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(alert);

        // Nothing was sent — no delivery pass has run yet — but the message is already durable.
        Assert.Equal(0, h.Sender.Calls);

        var row = await ReadOutboxRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Pending, row.State);
        Assert.Equal(0L, row.Attempts);
        Assert.Equal("a@example.com,b@example.com", row.Recipients);
        Assert.Equal(EmailOutboxMessageKinds.Alert, row.MessageKind);
        Assert.Equal("org1", row.OrgId);

        // The alert row carries no outcome yet: queued is not delivered.
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    /// <summary>
    /// The coalescing key is written from the first release, keyed on the alert kind plus the package
    /// coordinate, so a later burst-coalescing pass needs a query rather than a backfill.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_RecordsTheCoalescingKeyFromTheAlertKindAndCoordinate()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com"]);
        var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(alert);

        var row = await ReadOutboxRowAsync(alert.Id);
        Assert.Equal($"{AlertTypes.QuarantineNew}:pkg:npm/email-test@1.0.0", row.CoalesceKey);
    }

    /// <summary>A coordinate-less alert still gets a non-empty key, from its dedup source ref.</summary>
    [Fact]
    public void CoalescingKey_WithNoPurl_FallsBackToTheSourceRef()
    {
        Assert.Equal(
            "quarantine_new:quarantine-row-7",
            EmailOutboxCoalescing.ForAlert(AlertTypes.QuarantineNew, null, "quarantine-row-7"));
    }

    // ── Burst coalescing: N identical alerts collapse to one digest ──────────

    /// <summary>
    /// The headline coalescing case. 50 identical alerts (same org, same alert kind, same package
    /// coordinate) raised while nothing has been delivered yet collapse into exactly one outbox row
    /// whose <c>occurrence_count</c> is 50 — not 50 rows, and not 49 silently discarded. Every
    /// occurrence is accounted for: the first alert owns the surviving digest row, and every other
    /// one is stamped <c>"coalesced"</c> on its own row rather than left with no outcome at all.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_BurstOfIdenticalAlerts_CollapsesToOneDigest_AccountingForEveryOccurrence()
    {
        const int burstSize = 50;
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);
        await EnableEmailAsync(h.Settings, "org1", ["ops@example.com"]);

        var alerts = new List<AlertRecord>();
        for (int i = 0; i < burstSize; i++)
        {
            var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));
            alerts.Add(alert);
            await h.Writer.NotifyAsync(alert);
        }

        // Exactly one row, not fifty.
        Assert.Equal(1, await CountOutboxAsync());

        var digestRow = await ReadOutboxRowAsync(alerts[0].Id);
        Assert.Equal(burstSize, digestRow.OccurrenceCount);
        Assert.Contains(burstSize.ToString(), digestRow.Subject);

        // The alert that opened the burst is still awaiting delivery; every other one already
        // carries its own "coalesced" accounting — each recording the running occurrence count at
        // the moment it was folded in — rather than sitting at no outcome at all.
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alerts[0].Id))!.EmailStatus);
        for (int i = 1; i < burstSize; i++)
        {
            var reread = await h.Alerts.GetByIdAsync("org1", alerts[i].Id);
            Assert.Equal("coalesced", reread!.EmailStatus);
            Assert.Contains((i + 1).ToString(), reread.EmailError);
        }

        // On recovery, exactly one email goes out for the whole burst — never fifty.
        await h.Worker.RunPassAsync(CancellationToken.None);
        Assert.Equal(1, h.Sender.Calls);
        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", alerts[0].Id))!.EmailStatus);
    }

    /// <summary>The must-NOT twin of the burst test: the same alert kind and package coordinate for
    /// two different orgs must never collapse into one email — the coalescing key is always grouped
    /// with org_id.</summary>
    [Fact]
    public async Task NotifyAsync_SameAlertAcrossTwoOrgs_NeverCoalescesAcrossTheTenantBoundary()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);
        await EnableEmailAsync(h.Settings, "org1", ["org1-ops@example.com"]);
        await EnableEmailAsync(h.Settings, "org2", ["org2-ops@example.com"]);

        var org1Alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));
        var org2Alert = await SeedActiveAlertAsync(h.Alerts, "org2", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(org1Alert);
        await h.Writer.NotifyAsync(org2Alert);

        Assert.Equal(2, await CountOutboxAsync());
        var org1Row = await ReadOutboxRowAsync(org1Alert.Id);
        var org2Row = await ReadOutboxRowAsync(org2Alert.Id);
        Assert.Equal(1, org1Row.OccurrenceCount);
        Assert.Equal(1, org2Row.OccurrenceCount);

        // Neither alert's own status was touched by the other org's burst — there was no burst.
        Assert.Null((await h.Alerts.GetByIdAsync("org1", org1Alert.Id))!.EmailStatus);
        Assert.Null((await h.Alerts.GetByIdAsync("org2", org2Alert.Id))!.EmailStatus);
    }

    /// <summary>
    /// A digest already claimed for delivery is not a valid coalesce target: the race is resolved
    /// toward never losing the occurrence, by falling through to a fresh row rather than the alert
    /// vanishing.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_BurstArrivingAfterTheDigestWasClaimed_EnqueuesAFreshRowInstead()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);
        await EnableEmailAsync(h.Settings, "org1", ["ops@example.com"]);

        var first = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));
        await h.Writer.NotifyAsync(first);

        // The delivery worker claims the row — it is no longer a valid coalesce target.
        var claimed = await h.Outbox.ClaimDueAsync(batchSize: 10);
        Assert.Single(claimed);

        var second = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));
        await h.Writer.NotifyAsync(second);

        // Two rows: the claimed one, untouched, and a fresh one for the second occurrence — never a
        // silently dropped alert.
        Assert.Equal(2, await CountOutboxAsync());
        var secondRow = await ReadOutboxRowAsync(second.Id);
        Assert.Equal(1, secondRow.OccurrenceCount);
        Assert.Equal(EmailOutboxStates.Pending, secondRow.State);
    }

    // ── Success path through the real worker ─────────────────────────────────

    [Fact]
    public async Task Pass_EmailConfigured_DeliversAndRecordsSuccess()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com", "b@example.com"]);
        var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(alert);
        await h.Worker.RunPassAsync(CancellationToken.None);

        var reread = await h.Alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", reread!.EmailStatus);
        Assert.Null(reread.EmailError);

        var orgSettings = await h.Settings.GetAsync("org1");
        Assert.Equal("ok", orgSettings.EmailLastStatus);
        Assert.Equal(0, orgSettings.EmailConsecutiveFailures);

        // All recipients land on the one message.
        Assert.Equal(1, h.Sender.Calls);
        Assert.Equal(["a@example.com", "b@example.com"], h.Sender.LastTo);
        Assert.Contains(alert.Title, h.Sender.LastSubject);

        var row = await ReadOutboxRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Delivered, row.State);
        Assert.Equal(1L, row.Attempts);
    }

    // ── Mixed partial failure across orgs ────────────────────────────────────

    /// <summary>
    /// One org's recipient always succeeds, another's always fails, in the same pass over the same
    /// shared transport. The outcomes are independent: one row terminal-delivered, the other back in
    /// <c>pending</c> with a scheduled retry — and no <c>failed</c> stamp on the alert, because a
    /// transient failure is no longer terminal.
    /// </summary>
    [Fact]
    public async Task Pass_MixedOrgs_OneSucceedsOneFails_IndependentOutcomes()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com"]);
        await EnableEmailAsync(h.Settings, "org2", ["bad-b@example.com"]);
        var goodAlert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));
        var badAlert = await SeedActiveAlertAsync(h.Alerts, "org2", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(goodAlert);
        await h.Writer.NotifyAsync(badAlert);
        await h.Worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(2, h.Sender.Calls);
        Assert.Equal(1, h.Worker.DeliveredCount);
        Assert.Equal(1, h.Worker.RetriedCount);

        var good = await ReadOutboxRowAsync(goodAlert.Id);
        var bad = await ReadOutboxRowAsync(badAlert.Id);
        Assert.Equal(EmailOutboxStates.Delivered, good.State);
        Assert.Equal(EmailOutboxStates.Pending, bad.State);
        Assert.Equal(1L, bad.Attempts);
        Assert.Contains("simulated SMTP failure", bad.LastError);

        // org1's alert is terminal; org2's is still in flight, so no outcome is stamped on it.
        Assert.Equal("sent", (await h.Alerts.GetByIdAsync("org1", goodAlert.Id))!.EmailStatus);
        Assert.Null((await h.Alerts.GetByIdAsync("org2", badAlert.Id))!.EmailStatus);

        var goodSettings = await h.Settings.GetAsync("org1");
        var badSettings = await h.Settings.GetAsync("org2");
        Assert.Equal(0, goodSettings.EmailConsecutiveFailures);
        // Health records terminal outcomes only — a retryable failure has not failed yet.
        Assert.Equal(0, badSettings.EmailConsecutiveFailures);
        Assert.True(badSettings.EmailEnabled);
    }

    // ── Cross-tenant non-delivery ────────────────────────────────────────────

    /// <summary>
    /// Both orgs enable delivery with their own recipient lists. An alert whose <c>OrgId</c> is org1
    /// must never reach org2's recipients, and the one rendered body must carry only org1's content.
    /// The "must-NOT" twin of the mixed-outcome test above, which proves independence but never that
    /// the wrong tenant's addresses stay out of every send.
    /// </summary>
    [Fact]
    public async Task Pass_AlertForOrg1_NeverDeliveredToOrg2Recipients()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        await EnableEmailAsync(h.Settings, "org1", ["org1-a@example.com", "org1-b@example.com"]);
        await EnableEmailAsync(h.Settings, "org2", ["org2-a@example.com"]);

        var org1Alert = await h.Alerts.TryInsertAsync(new NewAlert(
            "org1", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/org1-secret@1.0.0",
            Title: "ORG1-ONLY quarantine item", Detail: "org1 detail payload"));

        var org2Alert = await h.Alerts.TryInsertAsync(new NewAlert(
            "org2", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/org2-secret@1.0.0",
            Title: "ORG2-ONLY quarantine item", Detail: "org2 detail payload"));

        await h.Writer.NotifyAsync(org1Alert!);
        await h.Worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(1, h.Sender.Calls);
        Assert.Equal(["org1-a@example.com", "org1-b@example.com"], h.Sender.LastTo);
        Assert.DoesNotContain("org2-a@example.com", h.Sender.LastTo!);

        Assert.Contains("ORG1-ONLY", h.Sender.LastBody);
        Assert.DoesNotContain("ORG2-ONLY", h.Sender.LastBody);

        // Only org1's message was ever persisted, and org2's alert was never touched.
        Assert.Equal(1, await CountOutboxAsync());
        var org2Reread = await h.Alerts.GetByIdAsync("org2", org2Alert!.Id);
        Assert.Null(org2Reread!.EmailStatus);
        Assert.Null(org2Reread.EmailError);
    }

    // ── Nothing to send: no row, no record ───────────────────────────────────

    [Fact]
    public async Task NotifyAsync_ChannelDisabled_PersistsNothing()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        // No EnableEmailAsync call — org1 has no settings row at all (email off by default).
        var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(alert);
        await h.Worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(0, await CountOutboxAsync());
        Assert.Equal(0, h.Sender.Calls);
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);

        var orgSettings = await h.Settings.GetAsync("org1");
        Assert.Null(orgSettings.EmailLastStatus);
        Assert.Equal(0, orgSettings.EmailConsecutiveFailures);
    }

    /// <summary>Gate on but no recipients: the channel resolves to nothing, identically to off.</summary>
    [Fact]
    public async Task NotifyAsync_EnabledButNoRecipients_PersistsNothing()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock);

        await h.Settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: null));
        var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(alert);

        Assert.Equal(0, await CountOutboxAsync());
        Assert.Null((await h.Alerts.GetByIdAsync("org1", alert.Id))!.EmailStatus);
    }

    // ── The behaviour change: an unconfigured relay no longer loses the mail ──

    /// <summary>
    /// The org's channel is on; the operator's relay is not configured. The message is still
    /// persisted, no attempt is charged against it, and it waits — which is the whole point. Under
    /// the in-memory path this combination sent nothing and recorded nothing, and the message was
    /// gone the instant the worker dequeued it.
    /// </summary>
    [Fact]
    public async Task Pass_InstanceTransportUnconfigured_MessageStaysQueuedAndUnattempted()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock, instance: BuildUnconfiguredInstance());

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com"]);
        var alert = await SeedActiveAlertAsync(h.Alerts, "org1", Guid.NewGuid().ToString("N"));

        await h.Writer.NotifyAsync(alert);
        await h.Worker.RunPassAsync(CancellationToken.None);
        await h.Worker.RunPassAsync(CancellationToken.None);

        Assert.Equal(0, h.Sender.Calls);

        var row = await ReadOutboxRowAsync(alert.Id);
        Assert.Equal(EmailOutboxStates.Pending, row.State);
        // No attempt was consumed: an unresolvable transport is not a failed delivery.
        Assert.Equal(0L, row.Attempts);

        // Tenant intent is untouched and no failure is recorded — the relay is the operator's.
        var orgSettings = await h.Settings.GetAsync("org1");
        Assert.True(orgSettings.EmailEnabled);
        Assert.Null(orgSettings.EmailLastStatus);
    }

    // ── Depth cap: shed the newest, and record the shed ──────────────────────

    /// <summary>
    /// At the depth cap the newest message is refused. The refusal is recorded where it is visible —
    /// the alert row and the org's delivery health — and the already-queued message is untouched,
    /// which is what makes "persisted until delivered or expired" true of every row that got in.
    /// The two alerts carry different purls (and so different coalesce keys) so the cap is exercised
    /// on two genuinely distinct messages rather than being absorbed by coalescing.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_AtDepthCap_RefusesTheNewestAndRecordsTheDrop()
    {
        using var ep = MakeProtector();
        var h = BuildHarness(ep, Clock, policy: BuildPolicy(("EMAIL_OUTBOX_MAX_DEPTH", "1")));

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com"]);
        var first = await SeedActiveAlertAsync(
            h.Alerts, "org1", Guid.NewGuid().ToString("N"), purl: "pkg:npm/depth-cap-first@1.0.0");
        var second = await SeedActiveAlertAsync(
            h.Alerts, "org1", Guid.NewGuid().ToString("N"), purl: "pkg:npm/depth-cap-second@1.0.0");

        await h.Writer.NotifyAsync(first);
        await h.Writer.NotifyAsync(second);

        // Exactly one row got in, and it is the first — the cap sheds the newest, never evicts.
        Assert.Equal(1, await CountOutboxAsync());
        var firstRow = await ReadOutboxRowAsync(first.Id);
        Assert.Equal(EmailOutboxStates.Pending, firstRow.State);

        // The shed message is recorded on its own alert row and on the org's delivery health, so the
        // drop is visible to the tenant rather than living only in a log line.
        var secondReread = await h.Alerts.GetByIdAsync("org1", second.Id);
        Assert.Equal("failed", secondReread!.EmailStatus);
        Assert.Contains("depth cap", secondReread.EmailError);

        var orgSettings = await h.Settings.GetAsync("org1");
        Assert.Equal("failed", orgSettings.EmailLastStatus);
        Assert.Equal(1, orgSettings.EmailConsecutiveFailures);
        // A full shared queue is an operator condition; the tenant's channel stays enabled.
        Assert.True(orgSettings.EmailEnabled);
    }

    /// <summary>
    /// The depth cap is enforced at enqueue time, in <see cref="EmailOutboxRepository.TryEnqueueAsync"/>
    /// — it has nothing to do with the transport breaker, which only ever gates what the delivery
    /// worker CLAIMS. An open breaker changes nothing about the shed policy: the cap still sheds the
    /// newest message exactly as it does with the breaker closed.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_AtDepthCap_StillShedsTheNewest_EvenWithTheBreakerOpen()
    {
        using var ep = MakeProtector();
        var breaker = BuildBreaker(Clock, ("EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", "1"));
        breaker.RecordTransportFailure(); // opens it before any message exists
        Assert.Equal(EmailTransportState.Open, breaker.Snapshot().State);

        var h = BuildHarness(
            ep, Clock, policy: BuildPolicy(("EMAIL_OUTBOX_MAX_DEPTH", "1")), breaker: breaker);

        await EnableEmailAsync(h.Settings, "org1", ["a@example.com"]);
        var first = await SeedActiveAlertAsync(
            h.Alerts, "org1", Guid.NewGuid().ToString("N"), purl: "pkg:npm/breaker-depth-first@1.0.0");
        var second = await SeedActiveAlertAsync(
            h.Alerts, "org1", Guid.NewGuid().ToString("N"), purl: "pkg:npm/breaker-depth-second@1.0.0");

        await h.Writer.NotifyAsync(first);
        await h.Writer.NotifyAsync(second);

        Assert.Equal(1, await CountOutboxAsync());
        var secondReread = await h.Alerts.GetByIdAsync("org1", second.Id);
        Assert.Equal("failed", secondReread!.EmailStatus);
        Assert.Contains("depth cap", secondReread.EmailError);
    }

    // ── Failure health never rewrites tenant intent ───────────────────────────

    /// <summary>The Slack arm auto-disables after a sustained failure window; the email arm
    /// deliberately does not, because the failing component is the operator's shared relay.</summary>
    [Fact]
    public async Task RecordEmailFailure_SustainedWindow_StillDoesNotDisableTheChannel()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings, "org1", ["bad-a@example.com"]);

        string staleFailingSince = Clock.GetUtcNow().AddHours(-49).ToUtcIso();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE alert_settings SET email_failing_since = @s WHERE org_id = @id",
            new { s = staleFailingSince, id = "org1" });

        await settings.RecordEmailFailureAsync("org1", "timeout");

        var updated = await settings.GetAsync("org1");
        Assert.True(updated.EmailEnabled);
        Assert.Equal("failed", updated.EmailLastStatus);
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
