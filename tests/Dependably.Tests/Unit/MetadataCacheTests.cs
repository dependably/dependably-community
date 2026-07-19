using System.Net;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// TTL-cache behaviours layered into <see cref="UpstreamClient.GetOrFetchMetadataAsync(string, string, CancellationToken)"/>:
/// positive TTL (fresh hit, no upstream call), serve-stale-on-transient-failure (network,
/// timeout, 5xx) within a bounded max-stale window, negative (404) caching, the memory bound,
/// and the mixed partial-failure fan-out. Time is frozen with <see cref="FakeTimeProvider"/>
/// and advanced to exact expiry instants — no wall-clock tolerances.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetadataCacheTests
{
    private const string Url = "http://master.invalid/npm/left-pad";

    [Fact]
    public async Task FreshHit_WithinTtl_MakesNoUpstreamCall()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("v1"));
        var clock = TestTime.Frozen();
        var (client, cache) = Build(handler, clock, ttlSeconds: 120);

        var first = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("v1", first.BodyAsString());
        Assert.Equal(1, handler.CallCount);

        // Still inside the 120s TTL: a second call must be served from cache, not upstream.
        clock.Advance(TimeSpan.FromSeconds(119));
        var second = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("v1", second.BodyAsString());
        Assert.Equal(1, handler.CallCount);
        Assert.True(cache.Enabled);
    }

    [Fact]
    public async Task Expired_UpstreamHealthy_RefetchesOnce_ConcurrentCallsCoalesce()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("v1"));
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 60);

        _ = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(1, handler.CallCount);

        // Past the 60s TTL. Line up N concurrent callers behind a gated refresh; single-flight
        // must collapse them into ONE upstream request.
        clock.Advance(TimeSpan.FromSeconds(61));
        handler.Enqueue(Reply.Ok("v2").Gated());

        // Invoke all 6 callers directly (not via Task.Run), one after another, without awaiting
        // in between. GetOrFetchMetadataAsync's synchronous prologue — the stale-cache check, the
        // (synchronously-completing fake) validator check, and the in-flight map registration
        // inside SingleFlightMetadataAsync — runs to completion on THIS thread before its first
        // real suspension point, so each call has already registered by the time it returns a
        // pending Task. Deterministic by construction: no thread pool scheduling, no signal, no
        // margin.
        var tasks = new Task<UpstreamMetadataResponse>[6];
        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = client.GetOrFetchMetadataAsync(Url);
        }

        handler.ReleaseGate();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(2, handler.CallCount);
        Assert.All(results, r => Assert.Equal("v2", r.BodyAsString()));
    }

    [Fact]
    public async Task Expired_Upstream5xx_ServesStale_WithinMaxStale_ThenFailsBeyond()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("cached"));
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 60, maxStaleSeconds: 3600);

        _ = await client.GetOrFetchMetadataAsync(Url);

        // Expired; refresh returns 503 → stale served (never the 5xx).
        clock.Advance(TimeSpan.FromSeconds(61));
        handler.Enqueue(Reply.WithStatus(HttpStatusCode.ServiceUnavailable, "err"));
        var stale = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("cached", stale.BodyAsString());
        Assert.True(stale.IsSuccessStatusCode);

        // Beyond max-stale (ttl 60 + stale 3600 = 3660): the entry is gone, the 503 propagates.
        clock.Advance(TimeSpan.FromSeconds(3601));
        handler.Enqueue(Reply.WithStatus(HttpStatusCode.ServiceUnavailable, "err"));
        var propagated = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(503, propagated.StatusCode);
        Assert.False(propagated.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Expired_UpstreamNetworkError_ServesStale()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("cached"));
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 60, maxStaleSeconds: 3600);

        _ = await client.GetOrFetchMetadataAsync(Url);

        clock.Advance(TimeSpan.FromSeconds(61));
        handler.Enqueue(Reply.Throw(new HttpRequestException("connection refused")));
        var stale = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("cached", stale.BodyAsString());
    }

    [Fact]
    public async Task NotFound_IsNegativeCached_ThenReFetched_ThenReplacedByOk()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.WithStatus(HttpStatusCode.NotFound, "missing"));
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 120, negativeTtlSeconds: 30);

        var miss = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(404, miss.StatusCode);
        Assert.Equal(1, handler.CallCount);

        // Within negative TTL → served from cache, no upstream call.
        clock.Advance(TimeSpan.FromSeconds(29));
        var missAgain = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(404, missAgain.StatusCode);
        Assert.Equal(1, handler.CallCount);

        // After negative TTL → re-fetched; the package now exists (200) and replaces the entry.
        clock.Advance(TimeSpan.FromSeconds(2));
        handler.Enqueue(Reply.Ok("now-here"));
        var found = await client.GetOrFetchMetadataAsync(Url);
        Assert.True(found.IsSuccessStatusCode);
        Assert.Equal("now-here", found.BodyAsString());
        Assert.Equal(2, handler.CallCount);

        // The 200 is now positively cached — a follow-up within TTL makes no call.
        clock.Advance(TimeSpan.FromSeconds(10));
        var warm = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("now-here", warm.BodyAsString());
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task NegativeEntry_IsNeverServedStale()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.WithStatus(HttpStatusCode.NotFound, "missing"));
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 120, negativeTtlSeconds: 30, maxStaleSeconds: 3600);

        _ = await client.GetOrFetchMetadataAsync(Url);

        // Negative entry expired; refresh fails transiently. A 404 is never resurrected as
        // stale — the transient failure must surface, not a stale "not found".
        clock.Advance(TimeSpan.FromSeconds(31));
        handler.Enqueue(Reply.Throw(new HttpRequestException("connection refused")));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetOrFetchMetadataAsync(Url));
    }

    [Fact]
    public async Task ColdMiss_DeadUpstream_Fails_NoPhantomStale()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Throw(new HttpRequestException("connection refused")));
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 120, maxStaleSeconds: 3600);

        // Nothing was ever cached: a dead upstream on the very first request must fail.
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetOrFetchMetadataAsync(Url));
    }

    [Fact]
    public async Task MemoryBound_EvictsEarlyEntriesOnOverflow()
    {
        var handler = new ScriptedHandler();
        var clock = TestTime.Frozen();
        // ~4KB budget with ~1KB bodies (+512 overhead each) holds only a handful of entries;
        // inserting many distinct URLs must drive size-based eviction.
        var (client, cache) = Build(handler, clock, ttlSeconds: 3600, maxBytes: 4096);

        string body = new('x', 1024);
        const int inserted = 40;
        for (int i = 0; i < inserted; i++)
        {
            handler.Enqueue(Reply.Ok(body));
            _ = await client.GetOrFetchMetadataAsync($"{Url}/{i}");
        }

        // MemoryCache compacts over-capacity entries on a background schedule; wait (bounded)
        // for the entry count to settle below the number inserted — proof the byte bound evicted.
        var deadline = DateTime.UtcNow.AddSeconds(5); // now-ok: bounded test poll awaiting async compaction, not domain time
        while (cache.Count >= inserted && DateTime.UtcNow < deadline) // now-ok: same bounded poll deadline
        {
            await Task.Delay(20);
        }

        Assert.True(cache.Count < inserted, $"expected eviction to bring count below {inserted}, was {cache.Count}");

        // The early entries are among those evicted under the byte bound: with a ~4KB budget and
        // ~1.5KB/entry, only a couple survive, so the first ten inserted are (nearly) all gone.
        int earlySurvivors = Enumerable.Range(0, 10).Count(i => cache.TryGet($"{Url}/{i}") is not null);
        Assert.True(earlySurvivors < 10, $"expected early entries to be evicted, but all 10 survived (count {cache.Count})");
    }

    [Fact]
    public async Task MixedPartialFailure_SomeRefreshSomeServeStale_InSameWindow()
    {
        var handler = new ScriptedHandler();
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 60, maxStaleSeconds: 3600);

        const string urlA = "http://master.invalid/npm/a";
        const string urlB = "http://master.invalid/npm/b";

        // Warm both.
        handler.EnqueueFor(urlA, Reply.Ok("a-v1"));
        handler.EnqueueFor(urlB, Reply.Ok("b-v1"));
        _ = await client.GetOrFetchMetadataAsync(urlA);
        _ = await client.GetOrFetchMetadataAsync(urlB);

        // Expire both. In the SAME window: A refreshes cleanly to a new version; B's upstream
        // is down and serves stale.
        clock.Advance(TimeSpan.FromSeconds(61));
        handler.EnqueueFor(urlA, Reply.Ok("a-v2"));
        handler.EnqueueFor(urlB, Reply.Throw(new HttpRequestException("down")));

        var a = await client.GetOrFetchMetadataAsync(urlA);
        var b = await client.GetOrFetchMetadataAsync(urlB);

        Assert.Equal("a-v2", a.BodyAsString());   // refreshed
        Assert.Equal("b-v1", b.BodyAsString());   // served stale
    }

    [Fact]
    public async Task DifferentAuthHeaders_SameUrl_DoNotShareCachedBody()
    {
        var handler = new ScriptedHandler();
        var clock = TestTime.Frozen();
        var (client, _) = Build(handler, clock, ttlSeconds: 3600);

        // Two orgs configure a Settings->Proxy upstream at the same private-registry URL. Org A
        // holds valid credentials; org B has none (or different creds). Org A's authenticated body
        // must never satisfy org B's request off the shared-singleton TTL cache.
        handler.Enqueue(Reply.Ok("org-a-private"));
        var a = await client.GetOrFetchMetadataAsync(Url, authorizationHeader: "Bearer org-a-token");
        Assert.Equal("org-a-private", a.BodyAsString());
        Assert.Equal(1, handler.CallCount);

        // Well within the 3600s TTL: a URL-only cache key would serve org A's cached body here
        // with no upstream call. Keying on the credential hash forces a fresh fetch for org B.
        handler.Enqueue(Reply.Ok("org-b-public"));
        var b = await client.GetOrFetchMetadataAsync(Url, authorizationHeader: null);
        Assert.Equal("org-b-public", b.BodyAsString());
        Assert.Equal(2, handler.CallCount);

        // A third caller reusing org A's exact credentials still shares A's cached entry — the
        // isolation is per-credential, not per-request.
        var aWarm = await client.GetOrFetchMetadataAsync(Url, authorizationHeader: "Bearer org-a-token");
        Assert.Equal("org-a-private", aWarm.BodyAsString());
        Assert.Equal(2, handler.CallCount);
    }

    // ── Edge master-reachability recording ──────────────────────────────────────

    [Fact]
    public async Task StaleServe_On5xx_RecordsMasterUnreachable_ThenRecoveryFlipsBackToOk()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("cached"));
        var clock = TestTime.Frozen();
        var edge = new EdgeStatusTracker(clock);
        var (client, _) = Build(handler, clock, ttlSeconds: 60, maxStaleSeconds: 3600, edgeStatus: edge);

        // Warm the cache with a genuine 2xx from the master: reachability is ok.
        _ = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(EdgeReachabilityState.Ok, edge.State);

        // Expired; the master refresh returns 503 → the cache serves the stale 2xx. The response
        // the caller sees is a healthy 200, but the master is DOWN — the tracker must record a
        // failure and report degraded with a fresh lastFailedPullAt.
        clock.Advance(TimeSpan.FromSeconds(61));
        handler.Enqueue(Reply.WithStatus(HttpStatusCode.ServiceUnavailable, "err"));
        var stale = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("cached", stale.BodyAsString());   // serve-stale still works
        Assert.True(stale.IsSuccessStatusCode);
        Assert.Equal(EdgeReachabilityState.Degraded, edge.State);
        Assert.Equal(clock.GetUtcNow().UtcTicks, edge.LastFailureAtTicks);

        // A later successful refresh flips the state back to ok.
        clock.Advance(TimeSpan.FromSeconds(30));
        handler.Enqueue(Reply.Ok("fresh"));
        var recovered = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("fresh", recovered.BodyAsString());
        Assert.Equal(EdgeReachabilityState.Ok, edge.State);
        Assert.Equal(clock.GetUtcNow().UtcTicks, edge.LastSuccessAtTicks);
    }

    [Fact]
    public async Task StaleServe_OnNetworkError_RecordsMasterUnreachable()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("cached"));
        var clock = TestTime.Frozen();
        var edge = new EdgeStatusTracker(clock);
        var (client, _) = Build(handler, clock, ttlSeconds: 60, maxStaleSeconds: 3600, edgeStatus: edge);

        _ = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(EdgeReachabilityState.Ok, edge.State);

        // Expired; the master connection is refused → stale served, but the master is unreachable.
        clock.Advance(TimeSpan.FromSeconds(61));
        handler.Enqueue(Reply.Throw(new HttpRequestException("connection refused")));
        var stale = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("cached", stale.BodyAsString());
        Assert.Equal(EdgeReachabilityState.Degraded, edge.State);
        Assert.Equal(clock.GetUtcNow().UtcTicks, edge.LastFailureAtTicks);
    }

    [Fact]
    public async Task FreshCacheHit_RecordsNothing_NoUpstreamContact()
    {
        var handler = new ScriptedHandler();
        handler.Enqueue(Reply.Ok("v1"));
        var clock = TestTime.Frozen();
        var edge = new EdgeStatusTracker(clock);
        var (client, _) = Build(handler, clock, ttlSeconds: 120, edgeStatus: edge);

        _ = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(EdgeReachabilityState.Ok, edge.State);
        long successTicksAfterFetch = edge.LastSuccessAtTicks;

        // A fresh cache hit never touches the master, so it must not stamp a new outcome.
        clock.Advance(TimeSpan.FromSeconds(60));
        var second = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("v1", second.BodyAsString());
        Assert.Equal(1, handler.CallCount);
        Assert.Equal(successTicksAfterFetch, edge.LastSuccessAtTicks);
        Assert.Equal(0, edge.LastFailureAtTicks);
    }

    // ── Config matrix ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Disabled_ByDefault_NonEdge_EveryCallForwardsUpstream()
    {
        var handler = new ScriptedHandler();
        var clock = TestTime.Frozen();
        // No Proxy:MetadataCacheTtlSeconds, not edge → disabled → pure pass-through.
        var (client, cache) = Build(handler, clock, ttlSeconds: null, edge: false);
        Assert.False(cache.Enabled);

        handler.Enqueue(Reply.Ok("v1"));
        _ = await client.GetOrFetchMetadataAsync(Url);
        handler.Enqueue(Reply.Ok("v1"));
        _ = await client.GetOrFetchMetadataAsync(Url);

        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task EnabledByDefault_InEdgeMode()
    {
        var handler = new ScriptedHandler();
        var clock = TestTime.Frozen();
        var (client, cache) = Build(handler, clock, ttlSeconds: null, edge: true);
        Assert.True(cache.Enabled);

        handler.Enqueue(Reply.Ok("v1"));
        _ = await client.GetOrFetchMetadataAsync(Url);
        // Second call within the 120s edge default TTL → cached.
        clock.Advance(TimeSpan.FromSeconds(60));
        var second = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal("v1", second.BodyAsString());
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task ExplicitZeroTtl_OverridesEdgeDefault_Disables()
    {
        var handler = new ScriptedHandler();
        var clock = TestTime.Frozen();
        var (client, cache) = Build(handler, clock, ttlSeconds: 0, edge: true);
        Assert.False(cache.Enabled);

        handler.Enqueue(Reply.Ok("v1"));
        _ = await client.GetOrFetchMetadataAsync(Url);
        handler.Enqueue(Reply.Ok("v1"));
        _ = await client.GetOrFetchMetadataAsync(Url);
        Assert.Equal(2, handler.CallCount);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, MetadataResponseCache Cache) Build(
        ScriptedHandler handler,
        FakeTimeProvider clock,
        int? ttlSeconds = 120,
        int maxStaleSeconds = MetadataCacheOptions.DefaultMaxStaleSeconds,
        int negativeTtlSeconds = MetadataCacheOptions.DefaultNegativeTtlSeconds,
        long maxBytes = MetadataCacheOptions.DefaultMaxBytes,
        bool edge = false,
        EdgeStatusTracker? edgeStatus = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}"),
            ["DEPLOYMENT_MODE"] = edge ? "edge" : "single",
            ["Proxy:MetadataCacheMaxStaleSeconds"] = maxStaleSeconds.ToString(),
            ["Proxy:MetadataCacheNegativeTtlSeconds"] = negativeTtlSeconds.ToString(),
            ["Proxy:MetadataCacheMaxBytes"] = maxBytes.ToString(),
        };
        if (ttlSeconds is int t)
        {
            settings["Proxy:MetadataCacheTtlSeconds"] = t.ToString();
        }
        if (edge)
        {
            settings["EDGE_MASTER_URL"] = "http://master.invalid";
            settings["EDGE_MASTER_TOKEN"] = "edge-token";
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var edgeMode = new EdgeMode(config);
        var cacheOptions = MetadataCacheOptions.Resolve(config, edgeMode);
        var cache = new MetadataResponseCache(cacheOptions, clock);

        var factory = new FactoryFor(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        var audit = new AuditRepository(new DiscardMetadataStore());
        var client = new UpstreamClient(
            factory,
            tiered,
            audit,
            new AllowEverythingValidator(),
            new NotAirGapped(),
            new DriveInfoStagingDiskInfo(settings["PROXY_STAGING_PATH"]!),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance,
            lifetime: null,
            metadataCache: cache,
            edgeStatus: edgeStatus);
        return (client, cache);
    }

    // A scripted upstream: per-URL FIFO queues of replies (status/body or a thrown exception).
    // Falls back to a shared default queue for tests using a single URL.
    private sealed class ScriptedHandler : HttpMessageHandler
    {
        private readonly Queue<Reply> _default = new();
        private readonly Dictionary<string, Queue<Reply>> _byUrl = new();
        private TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int CallCount;

        public void Enqueue(Reply reply) => _default.Enqueue(reply);

        public void EnqueueFor(string url, Reply reply)
        {
            if (!_byUrl.TryGetValue(url, out var q))
            {
                q = new Queue<Reply>();
                _byUrl[url] = q;
            }
            q.Enqueue(reply);
        }

        public void ReleaseGate() => _gate.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            string url = request.RequestUri!.ToString();
            var reply = _byUrl.TryGetValue(url, out var q) && q.Count > 0 ? q.Dequeue() : _default.Dequeue();

            if (reply.IsGated)
            {
                await _gate.Task.WaitAsync(cancellationToken);
                _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }

            return reply.Exception is not null
                ? throw reply.Exception
                : new HttpResponseMessage(reply.Status)
                {
                    Content = new StringContent(reply.Body!, System.Text.Encoding.UTF8, "application/json"),
                };
        }
    }

    private sealed record Reply(HttpStatusCode Status, string? Body, Exception? Exception, bool IsGated)
    {
        public static Reply Ok(string body) => new(HttpStatusCode.OK, body, null, false);
        public static Reply WithStatus(HttpStatusCode status, string body) => new(status, body, null, false);
        public static Reply Throw(Exception ex) => new(HttpStatusCode.OK, null, ex, false);
        public Reply Gated() => this with { IsGated = true };
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class NotAirGapped : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowEverythingValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class DiscardMetadataStore : IMetadataStore
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
