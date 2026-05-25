using System.Net;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for HealthcheckPinger.
/// Uses a zero-interval so each loop iteration resolves immediately; a short
/// CancellationTokenSource stops the background task after one iteration.
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
        => new(
            factory,
            new InProcessDistributedLock(),
            _readiness,
            config,
            NullLogger<HealthcheckPinger>.Instance);

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
        // Start pinger in background; cancel after short delay to allow one iteration.
        var task = pinger.StartAsync(cts.Token);
        await Task.Delay(200);
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
        await Task.Delay(200);
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
        await Task.Delay(200);
        cts.Cancel();
        await pinger.StopAsync(default);
        try { await task; } catch (OperationCanceledException) { }

        Assert.NotNull(handler.LastRequest);
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.NotNull(handler.LastRequest.Content);
        var body = await handler.LastRequest.Content!.ReadAsStringAsync();
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
        await Task.Delay(200);
        cts.Cancel();
        await pinger.StopAsync(default);

        // Must complete without throwing.
        var ex = await Record.ExceptionAsync(() => task);
        Assert.True(ex is null or OperationCanceledException,
            $"Unexpected exception: {ex?.GetType().Name}: {ex?.Message}");
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
/// Captures the most recent outgoing request and returns a configurable response.
/// </summary>
file sealed class CapturingHttpHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;

    public CapturingHttpHandler(HttpStatusCode statusCode = HttpStatusCode.OK)
        => _statusCode = statusCode;

    public HttpRequestMessage? LastRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
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
