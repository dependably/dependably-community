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
        await settings.UpdateAsync(orgId, new UpdateAlertSettings(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            SlackEnabled: true, SlackWebhookUrl: webhookUrl));

    private static async Task WaitAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting real async completion of the queue's consumer loop
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(3));
        while (!condition() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        if (!condition())
        {
            throw new TimeoutException("Condition never satisfied.");
        }
    }

    /// <summary>
    /// Drives a queue's retry backoff deterministically: advances <paramref name="clock"/> by
    /// <paramref name="step"/> and yields briefly so the background delivery loop observes each
    /// fired timer, repeating until <paramref name="condition"/> is met. The tiny real-time yield
    /// only gives the scheduler a turn — it does not wait out the backoff itself, which is driven
    /// entirely by the advancing fake clock.
    /// </summary>
    private static async Task PumpUntilAsync(
        FakeTimeProvider clock, Func<bool> condition, TimeSpan step, int maxIterations = 200)
    {
        for (int i = 0; i < maxIterations && !condition(); i++)
        {
            clock.Advance(step);
            await Task.Delay(5);
        }

        if (!condition())
        {
            throw new TimeoutException("Condition never satisfied while pumping the fake clock.");
        }
    }

    /// <summary>Routes by URL substring: "good" → 200, "bad" → 502. Captures the last request body.</summary>
    private sealed class RoutingHandler : DelegatingHandler
    {
        public string? LastBody { get; private set; }
        public int Calls { get; private set; }

        public RoutingHandler() : base(new HttpClientHandler()) { }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            string url = request.RequestUri?.ToString() ?? "";
            return url.Contains("good")
                ? new HttpResponseMessage(HttpStatusCode.OK)
                : new HttpResponseMessage(HttpStatusCode.BadGateway);
        }
    }

    private static SlackWebhookClient BuildClient(RoutingHandler handler) =>
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

        queue.Notify(alert);
        await WaitAsync(() => queue.DeliveredCount == 1);

        await cts.CancelAsync();
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

        queue.Notify(alert);
        await WaitAsync(() => queue.DeliveredCount == 1);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.NotNull(handler.LastBody);
        using var doc = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        string text = doc.RootElement.GetProperty("text").GetString()!;
        Assert.Contains(alert.Title, text);
        // Exactly one top-level property — the bare {"text": ...} contract, not the HMAC envelope.
        Assert.Single(doc.RootElement.EnumerateObject());
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

        queue.Notify(alert);
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

        queue.Notify(goodAlert);
        queue.Notify(badAlert);

        // Advance the fake clock through the 1s + 5s + 30s backoff schedule; each iteration only
        // yields a few real milliseconds so the background delivery loop can observe the fired
        // timer, keeping the test fast and deterministic instead of waiting out real backoff.
        await PumpUntilAsync(slackClock, () => queue.DeliveredCount + queue.FailedCount >= 2, TimeSpan.FromSeconds(1));

        await cts.CancelAsync();
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

        string staleFailingSince = Clock.GetUtcNow().AddHours(-49).ToString("yyyy-MM-ddTHH:mm:ssZ");
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
            queue.Notify(alert);
        }

        Assert.Equal(4, queue.DroppedCount);
    }
}
