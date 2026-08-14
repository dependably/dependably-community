using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// Unit tests for the Slack delivery queue over a stubbed <see cref="HttpMessageHandler"/>:
/// success, terminal failure, auto-disable, payload shape, mixed partial-failure fan-out, and
/// the overflow drop path. Mirrors <c>WebhookDeliveryTests</c>'s construction style
/// (real repositories over an in-memory SQLite store, a fake handler routed by URL substring).
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertSlackQueueTests : IAsyncLifetime
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

    private static IConfiguration BuildCfg(int capacity = 1024) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ALERT_SLACK_QUEUE_CAPACITY"] = capacity.ToString()
            })
            .Build();

    private static async Task<AlertRecord> SeedActiveAlertAsync(AlertRepository alerts, string orgId, string sourceRef)
    {
        var alert = await alerts.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: sourceRef,
            Ecosystem: "npm", Purl: "pkg:npm/slack-test@1.0.0",
            Title: "New quarantine item: pkg:npm/slack-test@1.0.0", Detail: null));
        return alert!;
    }

    private static async Task EnableSlackAsync(AlertSettingsRepository settings, string orgId, string webhookUrl) =>
        await settings.UpdateSlackAsync(orgId, new UpdateAlertSlack(SlackEnabled: true, SlackWebhookUrl: webhookUrl));

    /// <summary>
    /// Polls the DURABLE end state (the persisted alert/settings row) rather than the queue's
    /// in-memory counters. <see cref="AlertSlackQueue"/> increments <c>DeliveredCount</c>/
    /// <c>FailedCount</c> BEFORE its two DB writes complete — waiting on the counter and then
    /// immediately cancelling the token races those writes and can leave the row's
    /// <c>SlackStatus</c>/<c>SlackLastStatus</c> unset even though the counter says "delivered".
    /// Waiting on the row itself only returns once the write has actually landed.
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

    /// <summary>Routes by URL substring: "good" → 200, "bad" → 502. Captures the last request body,
    /// and every (url, body) pair — the latter lets cross-tenant tests assert exactly which
    /// destination(s) were called, not just an aggregate count.</summary>
    private sealed class RoutingHandler : DelegatingHandler
    {
        public string? LastBody { get; private set; }
        public int Calls { get; private set; }
        public List<(string Url, string Body)> Requests { get; } = [];

        public RoutingHandler() : base(new HttpClientHandler()) { }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            string url = request.RequestUri?.ToString() ?? "";
            Requests.Add((url, LastBody ?? ""));
            return url.Contains("good")
                ? new HttpResponseMessage(HttpStatusCode.OK)
                : new HttpResponseMessage(HttpStatusCode.BadGateway);
        }
    }

    private static SlackWebhookClient BuildClient(RoutingHandler handler) =>
        new(new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) });

    private static SlackWebhookClient BuildClient(HttpMessageHandler handler) =>
        new(new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) });

    // ── Success path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Notify_SlackConfigured_DeliversAndRecordsSuccess()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);

        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var queue = new AlertSlackQueue(settings, alerts, client, Clock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        await queue.NotifyAsync(alert);
        // Waits on the DURABLE end state (the persisted alert row), not the queue's in-memory
        // DeliveredCount — the queue increments that counter BEFORE its DB writes complete, so
        // waiting on the counter and then cancelling races the write.
        await WaitAsync(async () => (await alerts.GetByIdAsync("org1", alert.Id))?.SlackStatus is not null);

        // Graceful drain — StopAsync signals ExecuteAsync's stopping token itself, but by the
        // time we get here the durable write has already landed, so there is nothing in-flight
        // left for a cancellation to interrupt.
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", reread!.SlackStatus);
        Assert.Null(reread.SlackError);

        var orgSettings = await settings.GetAsync("org1");
        Assert.Equal("ok", orgSettings.SlackLastStatus);
        Assert.Equal(0, orgSettings.SlackConsecutiveFailures);
    }

    /// <summary>Payload is a bare {"text": "..."} body carrying the alert title.</summary>
    [Fact]
    public async Task Notify_PayloadShape_IsBareTextObject()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);

        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var queue = new AlertSlackQueue(settings, alerts, client, Clock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        await queue.NotifyAsync(alert);
        // Waits on the DURABLE end state (the persisted alert row), not the queue's in-memory
        // DeliveredCount — the queue increments that counter BEFORE its DB writes complete, so
        // waiting on the counter and then cancelling races the write.
        await WaitAsync(async () => (await alerts.GetByIdAsync("org1", alert.Id))?.SlackStatus is not null);

        // Graceful drain — StopAsync signals ExecuteAsync's stopping token itself, but by the
        // time we get here the durable write has already landed, so there is nothing in-flight
        // left for a cancellation to interrupt.
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.NotNull(handler.LastBody);
        using var doc = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        string text = doc.RootElement.GetProperty("text").GetString()!;
        Assert.Contains(alert.Title, text);
        // Exactly one top-level property — the bare {"text": ...} contract, not the HMAC envelope.
        Assert.Single(doc.RootElement.EnumerateObject());
    }

    // ── Shutdown mid-bookkeeping (host-stopping token cancelled after send succeeds) ──

    /// <summary>
    /// Simulates host shutdown landing in the window between the Slack POST succeeding and the
    /// durable outcome write: the fake handler cancels the stopping token synchronously, before
    /// returning the 200 response, so <see cref="AlertSlackQueue.DeliverAsync"/> resumes with an
    /// already-cancelled token. The delivery must still be recorded as durable state (not lost
    /// to a swallowed <see cref="OperationCanceledException"/>), and
    /// <see cref="AlertSlackQueue.DeliveredCount"/> must only report 1 once that write has
    /// actually landed.
    /// </summary>
    [Fact]
    public async Task DeliverAsync_ShutdownCancelsTokenRightAfterSendSucceeds_OutcomeStillRecorded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);

        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        using var cts = new CancellationTokenSource();
        var handler = new CancelOnSendHandler(cts);
        var client = BuildClient(handler);
        var queue = new AlertSlackQueue(settings, alerts, client, Clock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);

        // Drives the delivery path directly (no queue/BackgroundService loop needed) with a
        // token that gets cancelled synchronously the instant the POST "lands" — the exact
        // window the shutdown bug races.
        await queue.DeliverAsync(alert, cts.Token);

        Assert.True(cts.IsCancellationRequested);
        Assert.Equal(1, queue.DeliveredCount);

        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("sent", reread!.SlackStatus);
        Assert.Null(reread.SlackError);

        var orgSettings = await settings.GetAsync("org1");
        Assert.Equal("ok", orgSettings.SlackLastStatus);
    }

    /// <summary>
    /// Same shutdown-window scenario on the terminal-failure path: once retries are exhausted,
    /// the failure bookkeeping (which drives auto-disable) must also survive a stopping token
    /// cancelled the instant the last attempt finishes. A dedicated <see cref="FakeTimeProvider"/>
    /// drives the retry backoff so the test doesn't wait out the real 1s/5s/30s schedule.
    /// </summary>
    [Fact]
    public async Task DeliverAsync_ShutdownCancelsTokenRightAfterFinalAttemptFails_FailureStillRecorded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableSlackAsync(settings, "org1", "https://bad.example.com/hook");
        // One failure short of the auto-disable threshold, so this delivery's failure crosses
        // it — proving the auto-disable-driving count itself survived the cancelled token.
        for (int i = 0; i < AlertSlackQueue.AutoDisableAfterFailures - 1; i++)
        {
            await settings.RecordSlackFailureAsync(
                "org1", "seed", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);
        }

        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        using var cts = new CancellationTokenSource();
        var handler = new CancelOnFinalFailureHandler(cts);
        var client = BuildClient(handler);
        var queue = new AlertSlackQueue(settings, alerts, client, slackClock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);

        var deliverTask = queue.DeliverAsync(alert, cts.Token);
        await ClockPump.UntilAsync(
            slackClock, () => Task.FromResult(cts.IsCancellationRequested), TimeSpan.FromSeconds(1),
            maxAdvances: 1000);
        await deliverTask;

        Assert.Equal(1, queue.FailedCount);

        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Equal("failed", reread!.SlackStatus);

        var orgSettings = await settings.GetAsync("org1");
        Assert.False(orgSettings.SlackEnabled, "Auto-disable must still fire from the durably-recorded failure count.");
    }

    /// <summary>Cancels the given token synchronously right before returning a 200 response.</summary>
    private sealed class CancelOnSendHandler : DelegatingHandler
    {
        private readonly CancellationTokenSource _cancelOnSend;
        public CancelOnSendHandler(CancellationTokenSource cancelOnSend) : base(new HttpClientHandler())
        {
            _cancelOnSend = cancelOnSend;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _cancelOnSend.Cancel();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    /// <summary>
    /// Fails every attempt with 502; on the last attempt of the retry budget (1 initial + 3
    /// retries = 4 total), cancels the given token synchronously right before returning —
    /// simulating shutdown landing exactly as the retry budget is exhausted.
    /// </summary>
    private sealed class CancelOnFinalFailureHandler : DelegatingHandler
    {
        private readonly CancellationTokenSource _cancelOnFinal;
        private int _attempts;

        public CancelOnFinalFailureHandler(CancellationTokenSource cancelOnFinal)
            : base(new HttpClientHandler())
        {
            _cancelOnFinal = cancelOnFinal;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int attempt = Interlocked.Increment(ref _attempts);
            if (attempt >= 4)
            {
                _cancelOnFinal.Cancel();
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway));
        }
    }

    // ── Shutdown drain (channel still buffered when the stopping token is cancelled) ──

    /// <summary>
    /// Reproduces the shutdown-drop defect deterministically by invoking <c>ExecuteAsync</c>
    /// directly (via the <see cref="AlertSlackQueue.ExecuteAsyncForTests"/> test hook) with an
    /// already-cancelled token — <see cref="BackgroundService.StartAsync"/> itself short-circuits
    /// and never calls <c>ExecuteAsync</c> at all in that case, so it cannot exercise the real
    /// race being tested (a stopping token cancelled while the read loop is genuinely running,
    /// mid-shutdown, with an alert still buffered). Two alerts are buffered before the drain runs,
    /// one routed to a reachable webhook and one to an unreachable one — the drain must deliver
    /// the first and durably record the second's failure, independently.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_DrainsMixedSuccessAndFailure()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");
        await EnableSlackAsync(settings, "org2", "https://bad.example.com/hook");
        var goodAlert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));
        var badAlert = await SeedActiveAlertAsync(alerts, "org2", Guid.NewGuid().ToString("N"));

        var queue = new AlertSlackQueue(settings, alerts, client, slackClock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);

        // Buffer both alerts before the worker ever starts reading.
        await queue.NotifyAsync(goodAlert);
        await queue.NotifyAsync(badAlert);

        // Drives ExecuteAsync directly with an already-cancelled token — the exact state the
        // stopping token is in by the time BackgroundService.StopAsync signals cancellation.
        var executeTask = queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // The failing alert burns through the 1s/5s/30s backoff inside the drain itself; pump
        // the fake clock so that finishes in virtual time instead of real time.
        await ClockPump.UntilAsync(slackClock, async () =>
        {
            var good = await alerts.GetByIdAsync("org1", goodAlert.Id);
            var bad = await alerts.GetByIdAsync("org2", badAlert.Id);
            return good?.SlackStatus is not null && bad?.SlackStatus is not null;
        }, TimeSpan.FromSeconds(1), maxAdvances: 1000);

        await executeTask;

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);

        var goodReread = await alerts.GetByIdAsync("org1", goodAlert.Id);
        var badReread = await alerts.GetByIdAsync("org2", badAlert.Id);
        Assert.Equal("sent", goodReread!.SlackStatus);
        Assert.Equal("failed", badReread!.SlackStatus);
    }

    // ── Disabled / unconfigured: silent no-op ───────────────────────────────────

    [Fact]
    public async Task Notify_SlackDisabled_NoHttpCall_NoOutcomeRecorded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);

        // No EnableSlackAsync call — org1 has no settings row at all (Slack off by default).
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var queue = new AlertSlackQueue(settings, alerts, client, Clock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        await queue.NotifyAsync(alert);
        // Give the consumer a moment to process the (no-op) item.
        await Task.Delay(200);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(0, handler.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
        var reread = await alerts.GetByIdAsync("org1", alert.Id);
        Assert.Null(reread!.SlackStatus);
    }

    // ── Terminal failure + mixed partial-failure fan-out ────────────────────────

    /// <summary>
    /// End-to-end through the running queue: one org's webhook is reachable ("good"), another's
    /// always 502s ("bad"). The bad org goes through the full 1s/5s/30s backoff before the
    /// terminal failure is recorded — outcomes are independent per org (mixed partial-failure).
    /// A dedicated <see cref="FakeTimeProvider"/> drives the queue's retry backoff so the test
    /// advances virtual time instead of waiting out the real 36-second schedule.
    /// </summary>
    [Fact]
    public async Task Notify_MixedOrgs_OneSucceedsOneFails_IndependentOutcomes()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");
        await EnableSlackAsync(settings, "org2", "https://bad.example.com/hook");
        var goodAlert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));
        var badAlert = await SeedActiveAlertAsync(alerts, "org2", Guid.NewGuid().ToString("N"));

        var queue = new AlertSlackQueue(settings, alerts, client, slackClock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        await queue.NotifyAsync(goodAlert);
        await queue.NotifyAsync(badAlert);

        // Advance the fake clock through the 1s + 5s + 30s backoff schedule; each iteration only
        // yields a few real milliseconds so the background delivery loop can observe the fired
        // timer, keeping the test fast and deterministic instead of waiting out real backoff.
        // Pumps until the DURABLE end state (both persisted rows) lands, not the queue's
        // in-memory DeliveredCount/FailedCount — the queue increments those counters BEFORE its
        // DB writes complete, so pumping only until the counter changes and then cancelling
        // races the write.
        await ClockPump.UntilAsync(slackClock, async () =>
        {
            var good = await alerts.GetByIdAsync("org1", goodAlert.Id);
            var bad = await alerts.GetByIdAsync("org2", badAlert.Id);
            return good?.SlackStatus is not null && bad?.SlackStatus is not null;
        }, TimeSpan.FromSeconds(1), maxAdvances: 1000);

        // Graceful drain — StopAsync signals ExecuteAsync's stopping token itself, but by the
        // time we get here both durable writes have already landed, so there is nothing
        // in-flight left for a cancellation to interrupt.
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);

        var goodReread = await alerts.GetByIdAsync("org1", goodAlert.Id);
        var badReread = await alerts.GetByIdAsync("org2", badAlert.Id);
        Assert.Equal("sent", goodReread!.SlackStatus);
        Assert.Equal("failed", badReread!.SlackStatus);
        Assert.NotNull(badReread.SlackError);

        var goodSettings = await settings.GetAsync("org1");
        var badSettings = await settings.GetAsync("org2");
        Assert.Equal(0, goodSettings.SlackConsecutiveFailures);
        Assert.Equal(1, badSettings.SlackConsecutiveFailures);
        // A single failure does not yet auto-disable (threshold is 20).
        Assert.True(badSettings.SlackEnabled);
    }

    // ── Cross-tenant fairness ────────────────────────────────────────────────

    /// <summary>
    /// The cross-tenant property, on the alerting path where it matters most: org1's Slack webhook
    /// URL points at an endpoint that accepts the connection and never answers, and org2's
    /// security alert must still be delivered while org1's delivery is still hanging. Alerts are
    /// raised by supply-chain blocks and vuln findings, so a shared single-reader queue lets one
    /// tenant's unreachable endpoint delay every other tenant's security notifications.
    ///
    /// The wait is gated on a <see cref="TaskCompletionSource"/> the test controls, and no clock
    /// is advanced, so the pass means org2 was served concurrently rather than eventually.
    /// </summary>
    [Fact]
    public async Task Notify_OneOrgsWebhookHangs_AnotherOrgsAlertIsStillDelivered()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new HangingHandler();
        var client = BuildClient(handler);

        await EnableSlackAsync(settings, "org1", "https://hang.example.com/hook");
        await EnableSlackAsync(settings, "org2", "https://good.example.com/hook");
        var hangingAlert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));
        var otherAlert = await SeedActiveAlertAsync(alerts, "org2", Guid.NewGuid().ToString("N"));

        var queue = new AlertSlackQueue(
            settings, alerts, client, Clock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        await queue.NotifyAsync(hangingAlert);
        await handler.HangEntered.Task;

        await queue.NotifyAsync(otherAlert);
        await WaitAsync(async () => (await alerts.GetByIdAsync("org2", otherAlert.Id))?.SlackStatus is not null);

        Assert.Equal("sent", (await alerts.GetByIdAsync("org2", otherAlert.Id))!.SlackStatus);
        Assert.False(handler.HangReleased.Task.IsCompleted,
            "org1's delivery must still be in flight — otherwise the test proved nothing.");

        handler.HangReleased.TrySetResult();
        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }
    }

    /// <summary>
    /// The fairness bound holds on the stopping path too. The shutdown drain has a bounded window,
    /// and an org whose Slack endpoint accepts the connection and never answers would otherwise
    /// hold that whole window — abandoning every other org's queued security alerts on every
    /// deploy and restart. Each drained alert runs under the same per-alert budget as normal
    /// service, so org1's hung endpoint costs its own budget and org2's alert still goes out.
    /// </summary>
    [Fact]
    public async Task Drain_OneOrgsHungWebhook_DoesNotConsumeAnotherOrgsShareOfTheWindow()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new HangingHandler();
        var client = BuildClient(handler);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());

        await EnableSlackAsync(settings, "org1", "https://hang.example.com/hook");
        await EnableSlackAsync(settings, "org2", "https://good.example.com/hook");
        var hangingAlert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));
        var otherAlert = await SeedActiveAlertAsync(alerts, "org2", Guid.NewGuid().ToString("N"));

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ALERT_SLACK_QUEUE_CAPACITY"] = "1024",
                ["ALERT_SLACK_BUDGET_SECONDS"] = "30"
            })
            .Build();

        var queue = new AlertSlackQueue(
            settings, alerts, client, slackClock, cfg, NullLogger<AlertSlackQueue>.Instance);

        // Both alerts are queued before any worker runs, so both go through the drain.
        await queue.NotifyAsync(hangingAlert);
        await queue.NotifyAsync(otherAlert);

        var executeTask = queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        await ClockPump.UntilAsync(slackClock, async () =>
            (await alerts.GetByIdAsync("org2", otherAlert.Id))?.SlackStatus is not null,
            TimeSpan.FromSeconds(5), maxAdvances: 60);

        handler.HangReleased.TrySetResult();
        await executeTask;

        Assert.Equal("sent", (await alerts.GetByIdAsync("org2", otherAlert.Id))!.SlackStatus);
        Assert.Equal(1, queue.DeliveredCount);

        // org1's alert was abandoned on its own budget, so nothing terminal was recorded for it.
        Assert.Null((await alerts.GetByIdAsync("org1", hangingAlert.Id))!.SlackStatus);
    }

    /// <summary>Parks any request whose URL contains "hang" until the test releases it; 200
    /// otherwise. The gate makes the fairness assertion deterministic — the hung delivery is
    /// provably still in flight when the other org's outcome is asserted.</summary>
    private sealed class HangingHandler : DelegatingHandler
    {
        public TaskCompletionSource HangEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource HangReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public HangingHandler() : base(new HttpClientHandler()) { }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if ((request.RequestUri?.ToString() ?? "").Contains("hang"))
            {
                HangEntered.TrySetResult();
                await HangReleased.Task.WaitAsync(cancellationToken);
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    // ── Cross-tenant non-delivery ────────────────────────────────────────────

    /// <summary>
    /// Both orgs configure and enable Slack, each with its own webhook URL. Notifying an alert
    /// whose <c>OrgId</c> is org1 must never reach org2's webhook — <see cref="Notify_MixedOrgs_OneSucceedsOneFails_IndependentOutcomes"/>
    /// proves independent per-org *outcomes* but never asserts that the wrong tenant's webhook
    /// received zero requests. This is the "must-NOT" twin: org2's URL gets no POST at all, and
    /// the one delivered text carries only org1's alert content.
    /// </summary>
    [Fact]
    public async Task Notify_AlertForOrg1_NeverDeliveredToOrg2Webhook()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);

        await EnableSlackAsync(settings, "org1", "https://good.example.com/org1-hook");
        await EnableSlackAsync(settings, "org2", "https://good.example.com/org2-hook");

        var org1Alert = await alerts.TryInsertAsync(new NewAlert(
            "org1", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/org1-secret@1.0.0",
            Title: "ORG1-ONLY quarantine item", Detail: "org1 detail payload"));

        var org2Alert = await alerts.TryInsertAsync(new NewAlert(
            "org2", AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/org2-secret@1.0.0",
            Title: "ORG2-ONLY quarantine item", Detail: "org2 detail payload"));

        var queue = new AlertSlackQueue(settings, alerts, client, Clock, BuildCfg(), NullLogger<AlertSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        await queue.NotifyAsync(org1Alert!);
        // Waits on the DURABLE end state (the persisted alert row), not the queue's in-memory
        // DeliveredCount — the queue increments that counter BEFORE its DB writes complete, so
        // waiting on the counter and then cancelling races the write.
        await WaitAsync(async () => (await alerts.GetByIdAsync("org1", org1Alert!.Id))?.SlackStatus is not null);

        // Graceful drain — StopAsync signals ExecuteAsync's stopping token itself, but by the
        // time we get here the durable write has already landed, so there is nothing in-flight
        // left for a cancellation to interrupt.
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        // Exactly one POST was ever sent, and it went to org1's webhook — org2's webhook
        // received nothing at all.
        Assert.Single(handler.Requests);
        var (url, body) = handler.Requests[0];
        Assert.Equal("https://good.example.com/org1-hook", url);
        Assert.DoesNotContain(handler.Requests, r => r.Url == "https://good.example.com/org2-hook");

        // The delivered text carries org1's alert content and no trace of org2's.
        Assert.Contains("ORG1-ONLY", body);
        Assert.DoesNotContain("ORG2-ONLY", body);

        // org2's alert was never touched: no Slack delivery attempted, no outcome recorded.
        var org2Reread = await alerts.GetByIdAsync("org2", org2Alert!.Id);
        Assert.NotNull(org2Reread);
        Assert.Null(org2Reread!.SlackStatus);
        Assert.Null(org2Reread.SlackError);
    }

    // ── Auto-disable (exercised directly against the repository, same as the webhook suite) ────

    [Fact]
    public async Task RecordSlackFailure_AutoDisablesAfterConsecutiveThreshold()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableSlackAsync(settings, "org1", "https://bad.example.com/hook");

        for (int i = 0; i < AlertSlackQueue.AutoDisableAfterFailures - 1; i++)
        {
            bool disabled = await settings.RecordSlackFailureAsync(
                "org1", "err", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);
            Assert.False(disabled, $"Should not disable at failure {i + 1}");
        }

        bool finalDisabled = await settings.RecordSlackFailureAsync(
            "org1", "err", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);
        Assert.True(finalDisabled);

        var updated = await settings.GetAsync("org1");
        Assert.False(updated.SlackEnabled);
    }

    [Fact]
    public async Task RecordSlackFailure_AutoDisablesWhenDurationWindowExceeded()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableSlackAsync(settings, "org1", "https://bad.example.com/hook");

        string staleFailingSince = Clock.GetUtcNow().AddHours(-49).ToUtcIso();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE alert_settings SET slack_failing_since = @s WHERE org_id = @id",
            new { s = staleFailingSince, id = "org1" });

        bool disabled = await settings.RecordSlackFailureAsync(
            "org1", "timeout", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);
        Assert.True(disabled);

        var updated = await settings.GetAsync("org1");
        Assert.False(updated.SlackEnabled);
    }

    /// <summary>
    /// The Slack counter's lost-update, made deterministic. A competing writer lands its own
    /// failures in the window a read-then-write leaves open — the window a second replica occupies
    /// in production — and the counter must still hold every failure that happened.
    ///
    /// The interleave is driven from the injected clock rather than from real threads because
    /// <c>Microsoft.Data.Sqlite</c> executes its async API synchronously: parallel tasks against
    /// this store cannot interleave, so a thread-race test would pass over a broken counter. The
    /// repository reads the clock once for the timestamp and once for the auto-disable window, so
    /// firing the competing write on the second read lands it exactly in the gap a read-then-write
    /// has and an atomic increment does not.
    /// </summary>
    [Fact]
    public async Task RecordSlackFailure_CompetingWriterLandsMidCall_NoFailureIsLost()
    {
        using var ep = MakeProtector();
        await EnableSlackAsync(new AlertSettingsRepository(_db, ep, Clock), "org1", "https://bad.example.com/hook");

        var racingClock = new HookOnSecondReadTimeProvider(() =>
        {
            using var conn = _db.OpenAsync().GetAwaiter().GetResult();
            conn.Execute(
                """
                UPDATE alert_settings
                SET slack_consecutive_failures = slack_consecutive_failures + 7
                WHERE org_id = @orgId
                """,
                new { orgId = "org1" });
        });

        var raced = new AlertSettingsRepository(_db, ep, racingClock);
        await raced.RecordSlackFailureAsync(
            "org1", "err", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);

        var settings = new AlertSettingsRepository(_db, ep, Clock);
        Assert.Equal(8, (await settings.GetAsync("org1")).SlackConsecutiveFailures);

        await settings.RecordSlackFailureAsync(
            "org1", "err", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);
        Assert.Equal(9, (await settings.GetAsync("org1")).SlackConsecutiveFailures);
    }

    /// <summary>
    /// A <see cref="TimeProvider"/> that runs a callback on its second <c>GetUtcNow</c>, used to
    /// land a competing write in the middle of a repository call deterministically.
    /// </summary>
    private sealed class HookOnSecondReadTimeProvider : TimeProvider
    {
        private readonly Action _onSecondRead;
        private int _reads;

        public HookOnSecondReadTimeProvider(Action onSecondRead) => _onSecondRead = onSecondRead;

        public override DateTimeOffset GetUtcNow()
        {
            if (Interlocked.Increment(ref _reads) == 2)
            {
                _onSecondRead();
            }

            return TestTime.KnownNow;
        }
    }

    /// <summary>
    /// The email arm has no second clock read, so the interleaving technique the Slack and webhook
    /// counters are pinned with cannot reach it. This distinguishes the two implementations a
    /// different way: from a stored count above <see cref="int.MaxValue"/>, a counter that reloads
    /// the value and recomputes it in C# — <c>(int)stored + 1</c> — wraps to a negative number,
    /// while one the database increments in place does not. The seeded value is synthetic; what it
    /// demonstrates is not, and it is the same property the other two counters need: the new value
    /// is derived from the stored one by the database, never from a copy the caller read earlier.
    /// </summary>
    [Fact]
    public async Task RecordEmailFailure_CountIsDerivedFromTheStoredValueByTheDatabase()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "ops@example.com"));

        const long seeded = (long)int.MaxValue + 10;
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE alert_settings SET email_consecutive_failures = @n WHERE org_id = @orgId",
                new { n = seeded, orgId = "org1" });
        }

        await settings.RecordEmailFailureAsync("org1", "relay refused");

        await using (var conn = await _db.OpenAsync())
        {
            long stored = await conn.ExecuteScalarAsync<long>(
                "SELECT email_consecutive_failures FROM alert_settings WHERE org_id = @orgId",
                new { orgId = "org1" });
            Assert.Equal(seeded + 1, stored);
        }
    }

    /// <summary>
    /// The email counter is incremented in SQL for the same reason — and stays health-only. Alert email rides
    /// the operator's shared instance relay, so a delivery failure is an infrastructure fact, not
    /// a fault in this tenant's configuration: the count and the failure timestamps move,
    /// <c>email_enabled</c> never does. The asymmetry with the Slack arm above is deliberate, and
    /// making the increment atomic must not quietly acquire an auto-disable along the way.
    /// </summary>
    [Fact]
    public async Task RecordEmailFailure_RepeatedFailures_CountUp_AndEmailStaysEnabled()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "ops@example.com"));

        const int failures = 12;
        for (int i = 0; i < failures; i++)
        {
            await settings.RecordEmailFailureAsync("org1", "relay refused");
        }

        var updated = await settings.GetAsync("org1");
        Assert.Equal(failures, updated.EmailConsecutiveFailures);
        Assert.Equal("failed", updated.EmailLastStatus);
        Assert.NotNull(updated.EmailFailingSince);
        Assert.True(updated.EmailEnabled, "A shared-relay outage must never disable a tenant's channel.");
    }

    [Fact]
    public async Task RecordSlackSuccess_ResetsFailureCounters()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");

        await settings.RecordSlackFailureAsync(
            "org1", "err", AlertSlackQueue.AutoDisableAfterFailures, AlertSlackQueue.AutoDisableAfterDuration);
        await settings.RecordSlackSuccessAsync("org1");

        var updated = await settings.GetAsync("org1");
        Assert.Equal(0, updated.SlackConsecutiveFailures);
        Assert.Null(updated.SlackFailingSince);
        Assert.Null(updated.SlackLastError);
        Assert.Equal("ok", updated.SlackLastStatus);
    }

    // ── Overflow / drop path ──────────────────────────────────────────────────

    [Fact]
    public async Task Notify_WhenChannelFull_DropsAndIncrementsCounter()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var handler = new RoutingHandler();
        var client = BuildClient(handler);

        await EnableSlackAsync(settings, "org1", "https://good.example.com/hook");
        var alert = await SeedActiveAlertAsync(alerts, "org1", Guid.NewGuid().ToString("N"));

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ALERT_SLACK_QUEUE_CAPACITY"] = "1" })
            .Build();
        // Never started — nothing is dequeued, so the channel fills and drops.
        var queue = new AlertSlackQueue(settings, alerts, client, Clock, cfg, NullLogger<AlertSlackQueue>.Instance);

        for (int i = 0; i < 5; i++)
        {
            await queue.NotifyAsync(alert);
        }

        Assert.Equal(4, queue.DroppedCount);
    }
}
