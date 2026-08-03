using System.Net;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for HealthcheckPinger.
/// Most tests configure the smallest interval the pinger accepts so the first iteration comes
/// round quickly; a CancellationTokenSource stops the background task once its ping has landed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HealthcheckPingerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private ReadinessAggregator _readiness = null!;

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
        var blobs = new InMemoryBlobStore();
        var sp = new ServiceCollection().BuildServiceProvider();
        _readiness = new ReadinessAggregator(_db, blobs, sp);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static IConfiguration BuildConfig(params (string Key, string Value)[] pairs)
    {
        var dict = pairs.ToDictionary(p => p.Key, p => p.Value);
        return new ConfigurationBuilder()
            .AddInMemoryCollection(dict!)
            .Build();
    }

    private HealthcheckPinger BuildPinger(IConfiguration config, IHttpClientFactory factory)
        => BuildPinger(config, factory, NullLogger<HealthcheckPinger>.Instance);

    private HealthcheckPinger BuildPinger(
        IConfiguration config, IHttpClientFactory factory, ILogger<HealthcheckPinger> logger)
        => new(
            factory,
            new InProcessDistributedLock(TimeProvider.System),
            _readiness,
            new AirGapMode(config),
            config,
            logger,
            TimeProvider.System);

    /// <summary>
    /// Deterministically awaits the pinger's background loop having made its HTTP call, bounded
    /// by a generous safety timeout — replaces a fixed <see cref="Task.Delay(int)"/> guess with
    /// a real completion signal from the handler (<see cref="CapturingHttpHandler.RequestReceived"/>,
    /// passed by its base <see cref="Task"/> since the concrete handler type is file-local),
    /// since the loop involves genuine async work (a readiness check plus the send itself) that
    /// a short fixed wait can miss under load.
    /// </summary>
    private static async Task WaitForPingAsync(Task requestReceived)
    {
        // now-ok: bounds a genuine async completion on another thread. Nothing here asserts how
        // *fast* the ping is, only that one happens, so the bound must be generous rather than
        // tight. The loop is thread-pool scheduled and does real work before sending, so the gap
        // between StartAsync returning and the request landing is governed by scheduling on a
        // loaded runner, not by the code under test. This exists only so a genuine hang fails
        // instead of blocking forever.
        var finished = await Task.WhenAny(requestReceived, Task.Delay(TimeSpan.FromSeconds(60)));
        Assert.True(finished == requestReceived,
            "HealthcheckPinger did not send a ping within the safety timeout.");
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// When HEALTHCHECK_PING_URL is absent the pinger must return immediately
    /// without making any HTTP calls.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_NoPingUrl_ReturnsWithoutHttpCall()
    {
        var config = BuildConfig(); // no HEALTHCHECK_PING_URL
        var trackingFactory = new TrackingHttpClientFactory();
        var pinger = BuildPinger(config, trackingFactory);

        using var cts = new CancellationTokenSource();
        // ExecuteAsync returns synchronously (returns early) when no URL is set.
        await pinger.StartAsync(cts.Token);
        await pinger.StopAsync(default);

        Assert.Equal(0, trackingFactory.CreateClientCallCount);
    }

    /// <summary>
    /// Default method is GET.  With interval=0 the first iteration fires immediately
    /// after the Task.Delay resolves; we let it run then cancel.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_DefaultGetMethod_SendsGetRequest()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"));

        var handler = new CapturingHttpHandler();
        var factory = new SingleClientFactory(handler);
        var pinger = BuildPinger(config, factory);

        using var cts = new CancellationTokenSource();
        // Start pinger in background; wait for its real ping to land, then cancel.
        var task = pinger.StartAsync(cts.Token);
        await WaitForPingAsync(handler.RequestReceived);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.NotNull(handler.LastRequest);
        Assert.Equal(HttpMethod.Get, handler.LastRequest!.Method);
    }

    /// <summary>
    /// When HEALTHCHECK_PING_METHOD=POST the request must use POST.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_PostMethod_SendsPostRequest()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"),
            ("HEALTHCHECK_PING_METHOD", "POST"));

        var handler = new CapturingHttpHandler();
        var factory = new SingleClientFactory(handler);
        var pinger = BuildPinger(config, factory);

        using var cts = new CancellationTokenSource();
        var task = pinger.StartAsync(cts.Token);
        await WaitForPingAsync(handler.RequestReceived);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.NotNull(handler.LastRequest);
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
    }

    /// <summary>
    /// HEALTHCHECK_PING_PAYLOAD=status (with method left as default GET) forces a
    /// POST request carrying the JSON status body — exercises the `_sendPayload`
    /// half of the `_usePost || _sendPayload` short-circuit.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_PayloadStatusWithDefaultMethod_SendsPostWithJsonBody()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"),
            ("HEALTHCHECK_PING_PAYLOAD", "status"));

        var handler = new CapturingHttpHandler();
        var factory = new SingleClientFactory(handler);
        var pinger = BuildPinger(config, factory);

        using var cts = new CancellationTokenSource();
        var task = pinger.StartAsync(cts.Token);
        await WaitForPingAsync(handler.RequestReceived);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.NotNull(handler.LastRequest);
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.NotNull(handler.LastRequest.Content);
        string body = await handler.LastRequest.Content!.ReadAsStringAsync();
        Assert.Contains("\"status\":", body);
        Assert.Contains("\"instance_id\":", body);
    }

    /// <summary>
    /// A non-2xx response from the upstream must not surface as an exception —
    /// the pinger swallows transport/HTTP errors and continues looping.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_NonSuccessResponse_DoesNotThrow()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"));

        var handler = new CapturingHttpHandler(statusCode: HttpStatusCode.ServiceUnavailable);
        var factory = new SingleClientFactory(handler);
        var pinger = BuildPinger(config, factory);

        using var cts = new CancellationTokenSource();
        var task = pinger.StartAsync(cts.Token);
        await WaitForPingAsync(handler.RequestReceived);
        cts.Cancel();
        await pinger.StopAsync(default);

        // Must complete without throwing.
        var ex = await Record.ExceptionAsync(() => task);
        Assert.True(ex is null or OperationCanceledException,
            $"Unexpected exception: {ex?.GetType().Name}: {ex?.Message}");
    }

    /// <summary>
    /// With a ping URL configured but AIR_GAPPED=true, the pinger must not emit the outbound
    /// heartbeat — it never creates an HTTP client. Closes the air-gap gap for this job.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_AirGapped_SuppressesOutboundPing()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"),
            ("AIR_GAPPED", "true"));

        var trackingFactory = new TrackingHttpClientFactory();
        var pinger = BuildPinger(config, trackingFactory);

        using var cts = new CancellationTokenSource();
        var task = pinger.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.Equal(0, trackingFactory.CreateClientCallCount);
    }

    /// <summary>
    /// DISABLE_BACKGROUND_JOBS=healthcheck-pinger suppresses the heartbeat even when the
    /// instance is not fully air-gapped — the granular per-job opt-out.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_JobDisabledByName_SuppressesOutboundPing()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"),
            ("DISABLE_BACKGROUND_JOBS", "healthcheck-pinger"));

        var trackingFactory = new TrackingHttpClientFactory();
        var pinger = BuildPinger(config, trackingFactory);

        using var cts = new CancellationTokenSource();
        var task = pinger.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.Equal(0, trackingFactory.CreateClientCallCount);
    }

    // ── Interval and timeout floors ───────────────────────────────────────────

    /// <summary>
    /// A non-positive interval is coerced to the floor rather than left to spin the loop as fast
    /// as the pool allows, and the coercion is logged rather than applied silently.
    /// </summary>
    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    public void Constructor_NonPositiveInterval_ClampsAndWarns(string configured)
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", configured));

        var logger = new CapturingLogger();
        _ = BuildPinger(config, new TrackingHttpClientFactory(), logger);

        string warning = Assert.Single(logger.Warnings,
            w => w.Contains("HEALTHCHECK_PING_INTERVAL_SECONDS", StringComparison.Ordinal));
        Assert.Contains(configured, warning, StringComparison.Ordinal);
    }

    /// <summary>
    /// Same floor on the request timeout: <see cref="HttpClient.Timeout"/> rejects a non-positive
    /// value, so an unclamped one would throw on the first send rather than at configuration time.
    /// </summary>
    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    public void Constructor_NonPositiveTimeout_ClampsAndWarns(string configured)
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_TIMEOUT_SECONDS", configured));

        var logger = new CapturingLogger();
        _ = BuildPinger(config, new TrackingHttpClientFactory(), logger);

        Assert.Single(logger.Warnings,
            w => w.Contains("HEALTHCHECK_PING_TIMEOUT_SECONDS", StringComparison.Ordinal));
    }

    /// <summary>A valid interval is left alone and logs nothing.</summary>
    [Fact]
    public void Constructor_ValidIntervalAndTimeout_DoNotWarn()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "30"),
            ("HEALTHCHECK_PING_TIMEOUT_SECONDS", "5"));

        var logger = new CapturingLogger();
        _ = BuildPinger(config, new TrackingHttpClientFactory(), logger);

        Assert.Empty(logger.Warnings);
    }

    /// <summary>
    /// A clamped interval must still ping: the floor changes how often the loop runs, not whether
    /// it runs at all.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_ClampedInterval_StillSendsPing()
    {
        var config = BuildConfig(
            ("HEALTHCHECK_PING_URL", "http://example.com/ping"),
            ("HEALTHCHECK_PING_INTERVAL_SECONDS", "0"));

        var handler = new CapturingHttpHandler();
        var factory = new SingleClientFactory(handler);
        var pinger = BuildPinger(config, factory);

        using var cts = new CancellationTokenSource();
        var task = pinger.StartAsync(cts.Token);
        await WaitForPingAsync(handler.RequestReceived);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.NotNull(handler.LastRequest);
    }
}

// ── Test doubles ──────────────────────────────────────────────────────────────

/// <summary>
/// Tracks how many times CreateClient was called — used to verify the pinger
/// never touches HTTP when no URL is configured.
/// </summary>
file sealed class TrackingHttpClientFactory : IHttpClientFactory
{
    public int CreateClientCallCount { get; private set; }

    public HttpClient CreateClient(string name)
    {
        CreateClientCallCount++;
        return new HttpClient(new CapturingHttpHandler());
    }
}

/// <summary>
/// Captures the most recent outgoing request and returns a configurable response. Signals
/// <see cref="RequestReceived"/> the moment a request lands, so tests can await the pinger's
/// background loop having actually made its call instead of guessing at how long that takes
/// with a fixed <see cref="Task.Delay(int)"/> — the loop involves real async work (a readiness
/// check plus the HTTP send itself), so a short fixed wait flakes under load.
/// </summary>
file sealed class CapturingHttpHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly TaskCompletionSource<HttpRequestMessage> _received =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public CapturingHttpHandler(HttpStatusCode statusCode = HttpStatusCode.OK)
        => _statusCode = statusCode;

    public HttpRequestMessage? LastRequest { get; private set; }

    /// <summary>Completes with the first captured request once the handler has been invoked.</summary>
    public Task<HttpRequestMessage> RequestReceived => _received.Task;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        _received.TrySetResult(request);
        return Task.FromResult(new HttpResponseMessage(_statusCode));
    }
}

/// <summary>
/// IHttpClientFactory that always returns a single HttpClient backed by a given handler.
/// </summary>
file sealed class SingleClientFactory : IHttpClientFactory
{
    private readonly HttpClient _client;

    public SingleClientFactory(HttpMessageHandler handler)
        => _client = new HttpClient(handler);

    public HttpClient CreateClient(string name) => _client;
}

/// <summary>Collects warning-level messages so a coercion can be asserted on.</summary>
file sealed class CapturingLogger : ILogger<HealthcheckPinger>
{
    private readonly List<string> _warnings = [];

    public IReadOnlyList<string> Warnings => _warnings;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (logLevel == LogLevel.Warning)
        {
            _warnings.Add(formatter(state, exception));
        }
    }
}
