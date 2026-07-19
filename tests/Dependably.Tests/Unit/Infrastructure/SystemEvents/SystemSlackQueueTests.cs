using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.SystemEvents;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.SystemEvents;

/// <summary>
/// Unit tests for the operator-realm Slack queue over a stubbed <see cref="HttpMessageHandler"/>.
/// Structural sibling of <c>AlertSlackQueueTests</c>: success, no-op when disabled/unset,
/// terminal-failure retry arithmetic driven by a <see cref="FakeTimeProvider"/>, and the overflow
/// drop path. Unlike the per-org queue there is no auto-disable to cover.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemSlackQueueTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    private static IConfiguration BuildCfg(int capacity = 256) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SYSTEM_SLACK_QUEUE_CAPACITY"] = capacity.ToString()
            })
            .Build();

    private async Task EnableSlackAsync(string webhookUrl)
    {
        var orgs = new OrgRepository(_db);
        await orgs.SetInstanceSettingAsync("system_slack_enabled", "1");
        await orgs.SetInstanceSettingAsync("system_slack_webhook_url", webhookUrl);
    }

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

    private OrgRepository Orgs => new(_db);

    // ── Success path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Notify_SlackConfigured_DeliversAndRecordsSuccess()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        await EnableSlackAsync("https://good.example.com/hook");

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), NullLogger<SystemSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        await WaitAsync(() => queue.DeliveredCount == 1);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        var orgs = new OrgRepository(_db);
        Assert.Equal("sent", await orgs.GetInstanceSettingAsync("system_slack_last_status"));
        Assert.Equal("", await orgs.GetInstanceSettingAsync("system_slack_last_error"));
        Assert.NotNull(await orgs.GetInstanceSettingAsync("system_slack_last_delivery_at"));
    }

    /// <summary>Payload is a bare {"text": "..."} body carrying the rendered message.</summary>
    [Fact]
    public async Task Notify_PayloadShape_IsBareTextObject_WithRenderedMessage()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        await EnableSlackAsync("https://good.example.com/hook");

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), NullLogger<SystemSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        await WaitAsync(() => queue.DeliveredCount == 1);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.NotNull(handler.LastBody);
        using var doc = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        string text = doc.RootElement.GetProperty("text").GetString()!;
        Assert.Contains("acme", text);
        Assert.Contains("ops@example.com", text);
        Assert.Single(doc.RootElement.EnumerateObject());
    }

    // ── Disabled / unconfigured: silent no-op ───────────────────────────────────

    [Fact]
    public async Task Notify_SlackDisabled_NoHttpCall_NoOutcomeRecorded()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        // No EnableSlackAsync call — instance has no system_slack_* rows (off by default).

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), NullLogger<SystemSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        await Task.Delay(200);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(0, handler.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
        var orgs = new OrgRepository(_db);
        Assert.Null(await orgs.GetInstanceSettingAsync("system_slack_last_status"));
    }

    [Fact]
    public async Task Notify_SlackEnabledButNoWebhookUrl_NoHttpCall()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var orgs = new OrgRepository(_db);
        await orgs.SetInstanceSettingAsync("system_slack_enabled", "1");
        // No webhook URL row at all.

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), NullLogger<SystemSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        await Task.Delay(200);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(0, handler.Calls);
    }

    // ── Terminal failure + mixed partial-failure fan-out ────────────────────────

    /// <summary>
    /// Two events go through the same queue in sequence: one delivers ("good"), the other 502s
    /// through the full 1s/5s/30s backoff before the terminal failure is recorded — a mixed
    /// partial-failure scenario across sequential deliveries on the single-reader queue.
    /// </summary>
    [Fact]
    public async Task Notify_SequentialEvents_OneSucceedsOneFails_IndependentOutcomes()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());
        await EnableSlackAsync("https://good.example.com/hook");

        var queue = new SystemSlackQueue(Orgs, client, slackClock, RealLocalizer(), BuildCfg(), NullLogger<SystemSlackQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        await WaitAsync(() => queue.DeliveredCount == 1);

        var orgs = new OrgRepository(_db);
        await orgs.SetInstanceSettingAsync("system_slack_webhook_url", "https://bad.example.com/hook");
        queue.Notify(new SystemEventRecord("tenant.deleted", "acme", null, "ops@example.com"));

        await PumpUntilAsync(slackClock, () => queue.FailedCount == 1, TimeSpan.FromSeconds(1));

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);
        Assert.Equal("failed", await orgs.GetInstanceSettingAsync("system_slack_last_status"));
        Assert.NotNull(await orgs.GetInstanceSettingAsync("system_slack_last_error"));
    }

    // ── Shutdown drain (channel still buffered when the stopping token is cancelled) ──

    /// <summary>
    /// Fails the first <paramref name="failFirstNCalls"/> HTTP calls with 502, then succeeds.
    /// Used to force a deterministic mixed outcome across two sequentially-drained events that
    /// share the same (single, instance-wide) webhook URL: the first event exhausts its full
    /// 1s/5s/30s retry budget failing (4 calls), and the second event's first attempt then lands
    /// on a call past that budget and succeeds.
    /// </summary>
    private sealed class SequencedHandler : DelegatingHandler
    {
        private readonly int _failFirstNCalls;
        private int _calls;
        public SequencedHandler(int failFirstNCalls) : base(new HttpClientHandler()) => _failFirstNCalls = failFirstNCalls;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int call = Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(
                call <= _failFirstNCalls ? HttpStatusCode.BadGateway : HttpStatusCode.OK));
        }
    }

    /// <summary>
    /// Reproduces the shutdown-drop defect deterministically by invoking <c>ExecuteAsync</c>
    /// directly (via the <see cref="SystemSlackQueue.ExecuteAsyncForTests"/> test hook) with an
    /// already-cancelled token — <see cref="BackgroundService.StartAsync"/> itself short-circuits
    /// and never calls <c>ExecuteAsync</c> at all in that case, so it cannot exercise the real
    /// race being tested (a stopping token cancelled while the read loop is genuinely running,
    /// mid-shutdown, with an event still buffered). Two events are buffered before the drain runs;
    /// a <see cref="SequencedHandler"/> forces the first event to exhaust its retry budget failing
    /// and the second to succeed on its first attempt — the drain must record both outcomes
    /// independently instead of losing either to the pre-cancelled token.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_DrainsMixedSuccessAndFailure()
    {
        var handler = new SequencedHandler(failFirstNCalls: 4);
        var client = new SlackWebhookClient(new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) });
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());
        var orgs = new OrgRepository(_db);
        await EnableSlackAsync("https://hook.example.com/hook");

        var queue = new SystemSlackQueue(Orgs, client, slackClock, RealLocalizer(), BuildCfg(), NullLogger<SystemSlackQueue>.Instance);

        // Buffer both events before the worker ever starts reading.
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        queue.Notify(new SystemEventRecord("tenant.deleted", "acme", null, "ops@example.com"));

        // Drives ExecuteAsync directly with an already-cancelled token — the exact state the
        // stopping token is in by the time BackgroundService.StopAsync signals cancellation.
        var executeTask = queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // The first event burns through the 1s/5s/30s backoff inside the drain itself; pump the
        // fake clock so that finishes in virtual time instead of real time.
        await PumpUntilAsync(slackClock, () => queue.DeliveredCount == 1 && queue.FailedCount == 1, TimeSpan.FromSeconds(1));

        await executeTask;

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);
        // The single instance-wide outcome columns reflect whichever event was recorded last —
        // the second, successfully-delivered one — while the per-event counters above already
        // prove both outcomes were independently reached.
        Assert.Equal("sent", await orgs.GetInstanceSettingAsync("system_slack_last_status"));
    }

    // ── Overflow / drop path ──────────────────────────────────────────────────

    [Fact]
    public async Task Notify_WhenChannelFull_DropsAndIncrementsCounter()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        await EnableSlackAsync("https://good.example.com/hook");

        // Never started — nothing is dequeued, so the channel fills and drops.
        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(1), NullLogger<SystemSlackQueue>.Instance);

        for (int i = 0; i < 5; i++)
        {
            queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        }

        Assert.Equal(4, queue.DroppedCount);
    }
}
