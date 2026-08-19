using System.Net;
using System.Reflection;
using Dependably.Api;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Coverage for the single-flight dedup guarding <see cref="GoController"/>'s <c>@latest</c>
/// upstream fetch (<see cref="GoLatestFetchCoordinator.InFlight"/>).
/// </summary>
[Trait("Category", "Unit")]
public sealed class GoControllerSingleFlightTests
{
    private const string OrgId = "test-org";
    private const string Module = "example.com/foo";
    private const string UpstreamBase = "https://proxy.golang.org";

    [Fact]
    public async Task FetchLatestFromUpstreamAsync_CallerCancelsWhileFetchStillRunning_DoesNotStartDuplicateUpstreamFetch()
    {
        // ABA regression: caller A's own wait detaches (client disconnect/timeout) while the
        // shared upstream @latest fetch it registered is still running. Caller B then joins the
        // same coordinate before the shared fetch resolves. The single-flight in-flight entry
        // must survive A's early detach so B joins the live fetch instead of starting a
        // duplicate one.
        var handler = new GatedHandler();
        var coordinator = new GoLatestFetchCoordinator();
        var svc = new GoControllerServices(
            Packages: null!,
            Tokens: null!,
            Audit: null!,
            Orgs: null!,
            Blobs: null!,
            Upstream: null!,
            Registries: null!,
            HttpClientFactory: new StaticHttpClientFactory(new HttpClient(handler)),
            Db: null!,
            CacheRecorder: null!,
            CacheArtifacts: null!,
            TenantAccess: null!,
            Vulns: null!,
            Time: TimeProvider.System,
            Configuration: null!,
            Logger: NullLogger<GoController>.Instance,
            LatestCoordinator: coordinator,
            Reserved: null!,
            BlockGate: null!,
            Licenses: null!);

        var controller = new GoController(svc);

        // FetchLatestFromUpstreamAsync is intentionally private (an internal collapsing step
        // between the public @latest route and the shared upstream fetch); reflection reaches it
        // directly so the test exercises the real single-flight registration/removal logic
        // instead of re-implementing it.
        var method = typeof(GoController).GetMethod(
            "FetchLatestFromUpstreamAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

        Task<string?> Invoke(CancellationToken ct) =>
            (Task<string?>)method.Invoke(controller, [OrgId, Module, Module, UpstreamBase, ct, null])!;

        using var ctsA = new CancellationTokenSource();
        var taskA = Invoke(ctsA.Token);

        await handler.FirstCallStarted;

        ctsA.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => taskA);

        // Caller B joins for the identical coordinate while the shared fetch is still blocked on
        // the gate. On the buggy unconditional-TryRemove finally, A's cancellation already evicted
        // the in-flight entry, so B would start a second (un-gated, immediately-completing) fetch
        // here instead of joining the still-running one.
        var taskB = Invoke(default);

        var winner = await Task.WhenAny(taskB, Task.Delay(TimeSpan.FromMilliseconds(300)));
        Assert.NotSame(taskB, winner); // B must still be waiting on the shared (gated) fetch
        Assert.Equal(1, handler.CallCount);

        handler.ReleaseFirstCall();
        string? resultB = await taskB;

        Assert.NotNull(resultB);
        Assert.Equal(1, handler.CallCount); // still exactly one upstream round-trip
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>
    /// Blocks the first request on a gate the test controls explicitly, so the single-flight
    /// in-flight entry is deterministically still "running" when a second caller joins. Every
    /// subsequent request completes immediately, so a duplicate (un-gated) fetch is observable
    /// as an immediate second completion rather than needing a wall-clock race.
    /// </summary>
    private sealed class GatedHandler : HttpMessageHandler
    {
        private int _callCount;
        private readonly TaskCompletionSource _firstCallStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseFirstCall = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CallCount => _callCount;
        public Task FirstCallStarted => _firstCallStarted.Task;
        public void ReleaseFirstCall() => _releaseFirstCall.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _callCount) == 1)
            {
                _firstCallStarted.SetResult();
                await _releaseFirstCall.Task;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z"}"""),
            };
        }
    }
}
