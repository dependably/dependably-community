using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance tests for the artifact-blob single-flight coordinator in
/// <see cref="UpstreamClient"/>. Verifies that:
/// - Concurrent cache-misses for the same blob key collapse to one upstream fetch.
/// - Concurrent misses for distinct blobs each fetch independently.
/// - A mixed workload (same-blob collapse + distinct-blob parallel) satisfies both rules
///   simultaneously (house-rule: mixed partial-failure scenario).
/// - The UpstreamQueueThrottleHandler rejects requests when the semaphore is full and
///   releases slots so subsequent callers succeed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamBlobSingleFlightTests
{
    // ── Single-flight on GetOrFetchStreamAsync (blob-key path) ────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_ConcurrentSameKey_ProducesOneUpstreamRequest()
    {
        // GateHandler parks every request until Release() is called, giving us a
        // deterministic window where all concurrent callers are queued behind the gate.
        var gate = new GateHandler(HttpStatusCode.OK, RandomBytes(64));
        var (client, _) = BuildClient(gate);

        string blobKey = BlobKeys.Proxy(Sha256Hex(gate.ResponseBody));
        const string url = "http://upstream.invalid/pkg.whl";
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(gate.ResponseBody));

        // Start 6 callers on the same key by invoking them directly (not via Task.Run), one after
        // another, without awaiting in between. GetOrFetchStreamAsync's synchronous prologue —
        // including the in-flight map registration — runs to completion on THIS thread before
        // its first real suspension point (InMemoryBlobStore.GetAsync completes synchronously,
        // so the await over it never yields), so by the time each call returns a pending Task,
        // it has already registered. This is deterministic by construction: no thread pool
        // scheduling, no signal, no margin — all 6 are guaranteed registered before the gate is
        // released.
        var tasks = new Task<(Stream Body, bool IsHit)>[6];
        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = client.GetOrFetchStreamAsync(blobKey, url, spec, "pypi", ct: default);
        }

        gate.Release();
        var results = await Task.WhenAll(tasks);

        // Exactly one upstream HTTP call for 6 concurrent callers.
        Assert.Equal(1, gate.CallCount);
        // Every caller received a stream (the cache re-open after the single fetch).
        foreach (var (stream, _) in results)
        {
            await stream.DisposeAsync();
        }
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_ConcurrentDistinctKeys_EachFetchesIndependently()
    {
        byte[] blobsA = RandomBytes(32);
        byte[] blobsB = RandomBytes(32);
        byte[] blobsC = RandomBytes(32);

        var gateA = new GateHandler(HttpStatusCode.OK, blobsA);
        var gateB = new GateHandler(HttpStatusCode.OK, blobsB);
        var gateC = new GateHandler(HttpStatusCode.OK, blobsC);

        // Multi-gate factory: routes by URL path to the correct gate.
        var (client, _) = BuildClient(new RoutingHandler(
            ("http://upstream.invalid/a.whl", gateA),
            ("http://upstream.invalid/b.whl", gateB),
            ("http://upstream.invalid/c.whl", gateC)));

        var tasks = new[]
        {
            Task.Run(() => client.GetOrFetchStreamAsync(
                BlobKeys.Proxy(Sha256Hex(blobsA)), "http://upstream.invalid/a.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(blobsA)), "pypi", ct: default)),
            Task.Run(() => client.GetOrFetchStreamAsync(
                BlobKeys.Proxy(Sha256Hex(blobsB)), "http://upstream.invalid/b.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(blobsB)), "pypi", ct: default)),
            Task.Run(() => client.GetOrFetchStreamAsync(
                BlobKeys.Proxy(Sha256Hex(blobsC)), "http://upstream.invalid/c.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(blobsC)), "pypi", ct: default)),
        };

        // Distinct keys never collapse, so there is no registration race to wait out here —
        // each gate simply unblocks its own caller whenever that caller reaches it.
        gateA.Release();
        gateB.Release();
        gateC.Release();
        var results = await Task.WhenAll(tasks);

        // Three distinct blobs → three independent upstream requests.
        Assert.Equal(1, gateA.CallCount);
        Assert.Equal(1, gateB.CallCount);
        Assert.Equal(1, gateC.CallCount);
        foreach (var (stream, _) in results)
        {
            await stream.DisposeAsync();
        }
    }

    /// <summary>
    /// Mixed scenario (house rule: tests must cover the mixed partial-failure case).
    /// Two groups: blobs A share one key (should collapse to 1 fetch); blobs B and C
    /// each have distinct keys (should each fetch independently). All four concurrent
    /// callers are racing simultaneously.
    /// </summary>
    [Fact]
    public async Task GetOrFetchStreamAsync_Mixed_CollapsesSameKey_AndFetchesDistinctKeysIndependently()
    {
        byte[] sharedBody = RandomBytes(32);
        byte[] bodyB = RandomBytes(32);
        byte[] bodyC = RandomBytes(32);

        var gateShared = new GateHandler(HttpStatusCode.OK, sharedBody);
        var gateB = new GateHandler(HttpStatusCode.OK, bodyB);
        var gateC = new GateHandler(HttpStatusCode.OK, bodyC);

        var (client, _) = BuildClient(new RoutingHandler(
            ("http://upstream.invalid/shared.whl", gateShared),
            ("http://upstream.invalid/b.whl", gateB),
            ("http://upstream.invalid/c.whl", gateC)));

        string sharedKey = BlobKeys.Proxy(Sha256Hex(sharedBody));
        string keyB = BlobKeys.Proxy(Sha256Hex(bodyB));
        string keyC = BlobKeys.Proxy(Sha256Hex(bodyC));

        // Two callers for the shared key, one each for B and C — four total, invoked directly
        // (not via Task.Run) one after another without awaiting in between. As in the same-key
        // test above, GetOrFetchStreamAsync's registration is synchronous, so each call has
        // already registered by the time it returns a pending Task — deterministic, no barrier
        // or margin needed.
        var tasks = new[]
        {
            client.GetOrFetchStreamAsync(
                sharedKey, "http://upstream.invalid/shared.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(sharedBody)), "pypi", ct: default),
            client.GetOrFetchStreamAsync(
                sharedKey, "http://upstream.invalid/shared.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(sharedBody)), "pypi", ct: default),
            client.GetOrFetchStreamAsync(
                keyB, "http://upstream.invalid/b.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(bodyB)), "pypi", ct: default),
            client.GetOrFetchStreamAsync(
                keyC, "http://upstream.invalid/c.whl",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(bodyC)), "pypi", ct: default),
        };

        gateShared.Release();
        gateB.Release();
        gateC.Release();
        var results = await Task.WhenAll(tasks);

        // Shared key → 1 upstream call (two callers collapsed).
        Assert.Equal(1, gateShared.CallCount);
        // Distinct keys → 1 call each.
        Assert.Equal(1, gateB.CallCount);
        Assert.Equal(1, gateC.CallCount);

        foreach (var (stream, _) in results)
        {
            await stream.DisposeAsync();
        }
    }

    // ── Cancelled waiter must not collapse the in-flight entry (dedup under cancellation) ──

    [Fact]
    public async Task GetOrFetchStreamAsync_FirstWaiterCancels_SecondJoinerDoesNotTriggerSecondFetch()
    {
        // The first caller's WaitAsync(ct) detaches early (its own token cancels) while the
        // shared upstream fetch is still running. A second, uncancelled caller for the SAME key
        // must join the SAME shared fetch rather than triggering a brand-new upstream call —
        // exactly the stampede+cancellation scenario the in-flight map exists to collapse.
        var gate = new GateHandler(HttpStatusCode.OK, RandomBytes(64));
        var (client, _) = BuildClient(gate);

        string blobKey = BlobKeys.Proxy(Sha256Hex(gate.ResponseBody));
        const string url = "http://upstream.invalid/pkg-cancel.whl";
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(gate.ResponseBody));

        using var cts = new CancellationTokenSource();
        var firstTask = client.GetOrFetchStreamAsync(blobKey, url, spec, "pypi", ct: cts.Token);

        // Wait until the first caller has actually registered in the in-flight map and reached
        // the gate (parked on the shared upstream call) before cancelling it — a deterministic
        // replacement for guessing how long that takes with a fixed Task.Delay.
        await gate.WaitForCallCountAsync(1);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstTask);

        // A second caller for the same key must join the still-running shared fetch, not start
        // a fresh one. Calling it directly (not via Task.Run) is deterministic, not just
        // best-effort: GetOrFetchStreamAsync's synchronous prologue — including the in-flight
        // map registration — runs to completion on THIS thread before the method's first real
        // suspension point, and that happens-before relationship holds regardless of scheduler
        // contention (unlike a cross-thread "has it started yet" signal, which a sufficiently
        // loaded box can still lose the race against). Only after that registration has
        // definitely landed do we release the gate.
        var secondTask = client.GetOrFetchStreamAsync(blobKey, url, spec, "pypi", ct: default);
        gate.Release();
        var (stream, _) = await secondTask;
        await stream.DisposeAsync();

        Assert.Equal(1, gate.CallCount);
    }

    // ── UpstreamQueueThrottleHandler ──────────────────────────────────────────

    [Fact]
    public async Task QueueThrottle_FullQueue_ShedsImmediately()
    {
        // Semaphore with capacity 2; third concurrent request must be shed immediately.
        var semaphore = new SemaphoreSlim(2, 2);
        var gate = new GateHandler(HttpStatusCode.OK, RandomBytes(16));
        var logger = NullLogger<UpstreamQueueThrottleHandler>.Instance;

        // DelegatingHandler chain: throttle → gate
        var throttle = new UpstreamQueueThrottleHandler(semaphore, TimeSpan.FromMilliseconds(10), logger)
        {
            InnerHandler = gate
        };
        using var httpClient = new HttpClient(throttle);

        // Acquire both slots manually so the third caller finds the semaphore empty.
        await semaphore.WaitAsync();
        await semaphore.WaitAsync();

        // Third request must be shed (503) without invoking the inner handler.
        using var req = new HttpRequestMessage(HttpMethod.Get, "http://upstream.invalid/x");
        using var response = await httpClient.SendAsync(req, default);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, gate.CallCount); // inner handler never called

        // Release slots so semaphore returns to clean state.
        semaphore.Release(2);
    }

    [Fact]
    public async Task QueueThrottle_SlotReleasedAfterRequest_NextCallerSucceeds()
    {
        // Capacity 1: the first request holds the slot until the gate releases,
        // then the second request acquires the freed slot and succeeds.
        var semaphore = new SemaphoreSlim(1, 1);
        var gate = new GateHandler(HttpStatusCode.OK, RandomBytes(8));
        var logger = NullLogger<UpstreamQueueThrottleHandler>.Instance;

        var throttle = new UpstreamQueueThrottleHandler(semaphore, TimeSpan.FromSeconds(5), logger)
        {
            InnerHandler = gate
        };
        using var httpClient = new HttpClient(throttle);

        // First request occupies the single slot; release only after it has actually parked
        // on the gate — a deterministic replacement for guessing how long that takes.
        var first = httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "http://upstream.invalid/a"), default);
        await gate.WaitForCallCountAsync(1);
        gate.Release();
        using var r1 = await first;

        // Gate resets for the second request — CallCount is cumulative across Reset(), so the
        // second arrival is the 2nd call overall.
        gate.Reset(HttpStatusCode.OK, RandomBytes(8));
        var second = httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "http://upstream.invalid/b"), default);
        await gate.WaitForCallCountAsync(2);
        gate.Release();
        using var r2 = await second;

        Assert.Equal(HttpStatusCode.OK, r1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, r2.StatusCode);
        Assert.Equal(2, gate.CallCount);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, InMemoryBlobStore Blobs) BuildClient(HttpMessageHandler handler)
    {
        var factory = new FactoryFor(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-singleflight-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory,
            tiered,
            new AuditRepository(new NullMetadataStore()),
            new AllowAllValidator(),
            new DisabledAirGap(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        return (client, blobs);
    }

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Test doubles ─────────────────────────────────────────────────────────

    private sealed class GateHandler : HttpMessageHandler
    {
        private readonly object _arrivalLock = new();
        private TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource? _arrival;
        private int _arrivalTarget;
        private HttpStatusCode _status;
        private int _callCount;

        public GateHandler(HttpStatusCode status, byte[] body)
        {
            _status = status;
            ResponseBody = body;
        }

        public byte[] ResponseBody { get; private set; }
        public int CallCount => _callCount;

        public void Release() => _gate.TrySetResult();

        public void Reset(HttpStatusCode status, byte[] body)
        {
            _status = status;
            ResponseBody = body;
            _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        /// <summary>
        /// Completes once the gate has been hit by at least <paramref name="count"/> requests —
        /// a deterministic replacement for guessing how long a caller takes to reach the HTTP
        /// layer with a fixed <see cref="Task.Delay(int)"/>, which flakes under load.
        /// </summary>
        public Task WaitForCallCountAsync(int count, CancellationToken ct = default)
        {
            lock (_arrivalLock)
            {
                if (_callCount >= count)
                {
                    return Task.CompletedTask;
                }

                _arrivalTarget = count;
                _arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                return _arrival.Task.WaitAsync(ct);
            }
        }

        // Public forwarder so RoutingHandler can delegate to this gate without needing
        // to subclass it or cast to the protected SendAsync.
        public Task<HttpResponseMessage> ForwardAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => SendAsync(request, cancellationToken);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int count = Interlocked.Increment(ref _callCount);
            lock (_arrivalLock)
            {
                if (_arrival is not null && count >= _arrivalTarget)
                {
                    _arrival.TrySetResult();
                }
            }

            await _gate.Task.WaitAsync(cancellationToken);
            return new HttpResponseMessage(_status)
            {
                Content = new ByteArrayContent(ResponseBody)
            };
        }
    }

    /// <summary>
    /// Routes each request to the gate whose URL prefix matches the request URI.
    /// Supports the distinct-blob tests where different URLs go to different handlers.
    /// </summary>
    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly (string Prefix, GateHandler Gate)[] _routes;

        public RoutingHandler(params (string Prefix, GateHandler Gate)[] routes)
            => _routes = routes;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri?.ToString() ?? string.Empty;
            foreach (var (prefix, gate) in _routes)
            {
                if (url.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return gate.ForwardAsync(request, cancellationToken);
                }
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler handler) => _client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class NullMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, action TEXT, target TEXT,
                    detail TEXT, actor_email TEXT, created_at TEXT, source_ip TEXT);
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY, org_id TEXT, package_version_id TEXT, action TEXT,
                    user_id TEXT, purl TEXT, detail TEXT, source_ip TEXT, created_at TEXT);
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }
}
