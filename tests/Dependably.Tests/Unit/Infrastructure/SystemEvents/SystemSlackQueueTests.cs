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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.SystemEvents;

/// <summary>
/// Unit tests for the operator-realm Slack queue over a stubbed <see cref="HttpMessageHandler"/>.
/// Structural sibling of <c>AlertSlackQueueTests</c>: success, no-op when disabled/unset,
/// terminal-failure retry arithmetic driven by a <see cref="FakeTimeProvider"/>, and the overflow
/// drop path. Unlike the per-org queue there is no auto-disable to cover.
///
/// Every test that runs the consumer loop buffers its events first and then drives the loop with
/// <see cref="RunConsumerInline"/> rather than <see cref="Microsoft.Extensions.Hosting.BackgroundService.StartAsync"/>
/// followed by <see cref="SystemSlackQueue.Notify"/>. Both of the latter resume the consumer on a
/// thread-pool thread — <c>StartAsync</c> schedules <c>ExecuteAsync</c> there, and a reader parked
/// on an empty channel is woken there — while xUnit runs the test's own polling on its dedicated
/// threads. When sibling test classes block pool threads the consumer simply does not run, the
/// poll's real-time ceiling keeps counting, and the test fails with nothing wrong in the queue.
/// Buffered events are instead processed on the test's own thread before the loop first yields,
/// so the outcome no longer depends on a pool thread being free.
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

    /// <summary>
    /// Production's retry schedule with the intervals removed, for the tests whose subject is the
    /// terminal outcome of the retry chain rather than its pacing. The same four attempts run and
    /// the durable bookkeeping is identical; what disappears is the need to drive a clock from the
    /// test to let the chain proceed, which is a race the test cannot win reliably on a loaded
    /// machine — every advance spent before the loop registers its next timer is lost, and when
    /// the advance budget runs out the clock freezes with the chain still parked on it. The
    /// intervals themselves are pinned where they belong, in the tests that assert on backoff,
    /// which keep the real schedule.
    /// </summary>
    private static readonly TimeSpan[] NoBackoff =
        [TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero];

    /// <summary>
    /// Runs the queue's live consumer loop (not the shutdown drain: the token is not cancelled) on
    /// the calling thread. Call it after <see cref="SystemSlackQueue.Notify"/> has buffered every
    /// event the test needs: the loop then reads and delivers them before its first real yield.
    /// The returned task completes once <paramref name="stoppingToken"/> is cancelled and the loop
    /// has drained; see <see cref="StopAsync"/>.
    /// </summary>
    private static Task RunConsumerInline(SystemSlackQueue queue, CancellationToken stoppingToken) =>
        queue.ExecuteAsyncForTests(stoppingToken);

    /// <summary>
    /// Stops a loop started by <see cref="RunConsumerInline"/> and awaits its exit, so nothing the
    /// loop does can land after the test's assertions.
    /// </summary>
    private static async Task StopAsync(CancellationTokenSource cts, Task consumer)
    {
        await cts.CancelAsync();
        await consumer;
    }

    /// <summary>
    /// Waits until <paramref name="expected"/> events have reached a terminal outcome.
    /// <see cref="SystemSlackQueue.ProcessedCount"/> is the one counter every outcome advances — sent,
    /// failed, skipped, or disabled — and only after the outcome columns are written, so a delivery
    /// that went wrong ends the wait at once instead of leaving it to run out. The test then asserts
    /// on which outcome it was. A skipped delivery or a consumer loop that has exited fails here
    /// with its cause; the real-time ceiling is a backstop for a hang, never the expected way out.
    /// </summary>
    private static async Task WaitForProcessedAsync(
        SystemSlackQueue queue, long expected, Task consumer, CapturingLogger<SystemSlackQueue> queueLog)
    {
        // now-ok: polling deadline backstopping a hung consumer loop; the expected path never reaches it
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(3);
        while (queue.ProcessedCount < expected)
        {
            if (queueLog.SkippedDeliveries() is { Count: > 0 } skipped)
            {
                throw new InvalidOperationException(
                    "The queue skipped a delivery: " + string.Join(" | ", skipped));
            }

            if (consumer.IsCompleted)
            {
                throw new InvalidOperationException(
                    $"The consumer loop exited ({consumer.Status}) after {queue.ProcessedCount} of {expected} events.",
                    consumer.Exception);
            }

            // now-ok: polling deadline backstopping a hung consumer loop
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    $"Processed {queue.ProcessedCount} of {expected} events (delivered {queue.DeliveredCount}, " +
                    $"failed {queue.FailedCount}). Queue warnings: {string.Join(" | ", queueLog.Warnings())}");
            }

            await Task.Delay(20);
        }
    }

    /// <summary>
    /// Records what the queue logs at warning level and above, exception included.
    /// <see cref="NullLogger{T}"/> would discard the one line that explains a delivery the queue
    /// decided not to make.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _warnings = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                _warnings.Enqueue(exception is null
                    ? formatter(state, exception)
                    : $"{formatter(state, exception)} ({exception.GetType().Name}: {exception.Message})");
            }
        }

        public IReadOnlyList<string> Warnings() => [.. _warnings];

        /// <summary>The queue's "could not load the Slack settings" warnings.</summary>
        public IReadOnlyList<string> SkippedDeliveries() =>
            [.. _warnings.Where(w => w.Contains("skipping delivery", StringComparison.Ordinal))];
    }

    /// <summary>
    /// Returns 200 when the URL contains "good" and the body does not contain
    /// <c>failWhenBodyContains</c>, and 502 otherwise. Records every (url, body) pair in call order.
    /// The handler runs on the consumer's thread while the test reads it from its own, so the
    /// recording is locked, and the body is read synchronously so the stub never yields.
    /// </summary>
    private sealed class RoutingHandler : DelegatingHandler
    {
        private readonly string? _failWhenBodyContains;
        private readonly Lock _gate = new();
        private readonly List<(string Url, string Body)> _requests = [];

        public RoutingHandler(string? failWhenBodyContains = null) : base(new HttpClientHandler()) =>
            _failWhenBodyContains = failWhenBodyContains;

        public int Calls { get { lock (_gate) { return _requests.Count; } } }
        public string? LastBody { get { lock (_gate) { return _requests.Count == 0 ? null : _requests[^1].Body; } } }
        public IReadOnlyList<(string Url, string Body)> Requests { get { lock (_gate) { return [.. _requests]; } } }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = "";
            if (request.Content is not null)
            {
                using var reader = new StreamReader(request.Content.ReadAsStream(cancellationToken));
                body = reader.ReadToEnd();
            }

            string url = request.RequestUri?.ToString() ?? "";
            lock (_gate)
            {
                _requests.Add((url, body));
            }

            bool succeeds = url.Contains("good", StringComparison.Ordinal)
                && (_failWhenBodyContains is null || !body.Contains(_failWhenBodyContains, StringComparison.Ordinal));
            return Task.FromResult(new HttpResponseMessage(succeeds ? HttpStatusCode.OK : HttpStatusCode.BadGateway));
        }
    }

    private static SlackWebhookClient BuildClient(HttpMessageHandler handler) =>
        new(new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) });

    private OrgRepository Orgs => new(_db);

    // ── Success path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Notify_SlackConfigured_DeliversAndRecordsSuccess()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var queueLog = new CapturingLogger<SystemSlackQueue>();
        await EnableSlackAsync("https://good.example.com/hook");

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), queueLog);
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));

        using var cts = new CancellationTokenSource();
        var consumer = RunConsumerInline(queue, cts.Token);
        await WaitForProcessedAsync(queue, 1, consumer, queueLog);
        await StopAsync(cts, consumer);

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Empty(queueLog.Warnings());
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
        var queueLog = new CapturingLogger<SystemSlackQueue>();
        await EnableSlackAsync("https://good.example.com/hook");

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), queueLog);
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));

        using var cts = new CancellationTokenSource();
        var consumer = RunConsumerInline(queue, cts.Token);
        await WaitForProcessedAsync(queue, 1, consumer, queueLog);
        await StopAsync(cts, consumer);

        Assert.Equal(1, queue.DeliveredCount);
        Assert.NotNull(handler.LastBody);
        using var doc = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        string text = doc.RootElement.GetProperty("text").GetString()!;
        Assert.Contains("acme", text);
        Assert.Contains("ops@example.com", text);
        Assert.Single(doc.RootElement.EnumerateObject());
    }

    // ── Disabled / unconfigured: silent no-op ───────────────────────────────────

    /// <summary>
    /// Waits for the event to be processed rather than for a fixed interval: a fixed interval
    /// passes whether the queue declined the event or simply had not reached it yet.
    /// </summary>
    [Fact]
    public async Task Notify_SlackDisabled_NoHttpCall_NoOutcomeRecorded()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var queueLog = new CapturingLogger<SystemSlackQueue>();
        // No EnableSlackAsync call — instance has no system_slack_* rows (off by default).

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), queueLog);
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));

        using var cts = new CancellationTokenSource();
        var consumer = RunConsumerInline(queue, cts.Token);
        await WaitForProcessedAsync(queue, 1, consumer, queueLog);
        await StopAsync(cts, consumer);

        Assert.Equal(0, handler.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
        Assert.Empty(queueLog.Warnings());
        var orgs = new OrgRepository(_db);
        Assert.Null(await orgs.GetInstanceSettingAsync("system_slack_last_status"));
    }

    [Fact]
    public async Task Notify_SlackEnabledButNoWebhookUrl_NoHttpCall()
    {
        var handler = new RoutingHandler();
        var client = BuildClient(handler);
        var queueLog = new CapturingLogger<SystemSlackQueue>();
        var orgs = new OrgRepository(_db);
        await orgs.SetInstanceSettingAsync("system_slack_enabled", "1");
        // No webhook URL row at all.

        var queue = new SystemSlackQueue(Orgs, client, Clock, RealLocalizer(), BuildCfg(), queueLog);
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));

        using var cts = new CancellationTokenSource();
        var consumer = RunConsumerInline(queue, cts.Token);
        await WaitForProcessedAsync(queue, 1, consumer, queueLog);
        await StopAsync(cts, consumer);

        Assert.Equal(0, handler.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
        Assert.Empty(queueLog.Warnings());
    }

    // ── Terminal failure + mixed partial-failure fan-out ────────────────────────

    /// <summary>
    /// Two events go through the same queue in sequence: one delivers, the other exhausts its
    /// retry budget 502ing before the terminal failure is recorded — a mixed partial-failure
    /// scenario across sequential deliveries on the single-reader queue. Which event fails is a
    /// property of the event (the handler 502s any message naming the doomed tenant), not of the
    /// moment the instance webhook setting is changed, so both events are buffered up front and
    /// nothing has to wait for the first to finish before the second is sent. The chain runs on
    /// <see cref="NoBackoff"/>: the subject is which outcome each event reaches, not the pacing
    /// between attempts.
    /// </summary>
    [Fact]
    public async Task Notify_SequentialEvents_OneSucceedsOneFails_IndependentOutcomes()
    {
        var handler = new RoutingHandler(failWhenBodyContains: "doomed");
        var client = BuildClient(handler);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());
        var queueLog = new CapturingLogger<SystemSlackQueue>();
        await EnableSlackAsync("https://good.example.com/hook");

        var queue = new SystemSlackQueue(
            Orgs, client, slackClock, RealLocalizer(), BuildCfg(), queueLog, NoBackoff);
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        queue.Notify(new SystemEventRecord("tenant.deleted", "doomed", null, "ops@example.com"));

        using var cts = new CancellationTokenSource();
        var consumer = RunConsumerInline(queue, cts.Token);
        await WaitForProcessedAsync(queue, 2, consumer, queueLog);
        await StopAsync(cts, consumer);

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);

        // In order: the first event's single successful attempt, then the second event's four
        // failing attempts — its failure did not touch the first, and the first did not stop the
        // second from running its whole retry budget.
        var requests = handler.Requests;
        Assert.Equal(5, requests.Count);
        Assert.Contains("acme", requests[0].Body);
        Assert.All(requests.Skip(1), r => Assert.Contains("doomed", r.Body));

        var orgs = new OrgRepository(_db);
        Assert.Equal("failed", await orgs.GetInstanceSettingAsync("system_slack_last_status"));
        Assert.Contains("502", await orgs.GetInstanceSettingAsync("system_slack_last_error"));

        // The only warning is the second event's own terminal failure; nothing about the first
        // delivery, or about either settings read, was swallowed along the way.
        string onlyWarning = Assert.Single(queueLog.Warnings());
        Assert.StartsWith("System Slack delivery failed after 4 attempts", onlyWarning);
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
    /// already-cancelled token — <see cref="Microsoft.Extensions.Hosting.BackgroundService.StartAsync"/>
    /// itself short-circuits and never calls <c>ExecuteAsync</c> at all in that case, so it cannot
    /// exercise the real race being tested (a stopping token cancelled while the read loop is
    /// genuinely running, mid-shutdown, with an event still buffered). Two events are buffered
    /// before the drain runs; a <see cref="SequencedHandler"/> forces the first event to exhaust
    /// its retry budget failing and the second to succeed on its first attempt — the drain must
    /// record both outcomes independently instead of losing either to the pre-cancelled token.
    /// The chain runs on <see cref="NoBackoff"/>; <see cref="SequencedHandler"/>'s call ordering,
    /// not the intervals between attempts, is what makes the mixed outcome deterministic.
    /// Awaiting the drain itself is the completion signal: it returns only once both buffered
    /// events have been delivered, so nothing is polled against a clock.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_DrainsMixedSuccessAndFailure()
    {
        var handler = new SequencedHandler(failFirstNCalls: 4);
        var client = BuildClient(handler);
        var slackClock = new FakeTimeProvider(Clock.GetUtcNow());
        var queueLog = new CapturingLogger<SystemSlackQueue>();
        var orgs = new OrgRepository(_db);
        await EnableSlackAsync("https://hook.example.com/hook");

        var queue = new SystemSlackQueue(
            Orgs, client, slackClock, RealLocalizer(), BuildCfg(), queueLog, NoBackoff);

        // Buffer both events before the worker ever starts reading.
        queue.Notify(new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"));
        queue.Notify(new SystemEventRecord("tenant.deleted", "acme", null, "ops@example.com"));

        // Drives ExecuteAsync directly with an already-cancelled token — the exact state the
        // stopping token is in by the time BackgroundService.StopAsync signals cancellation. The
        // first event exhausts its retry budget inside the drain itself; on NoBackoff that costs
        // no time at all, real or virtual, so nothing has to drive the clock through it.
        await queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        Assert.Equal(2, queue.ProcessedCount);
        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);
        Assert.DoesNotContain(queueLog.Warnings(), w => w.Contains("skipping delivery", StringComparison.Ordinal));
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
