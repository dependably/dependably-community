using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression tests for two state-lifecycle defects in <see cref="NpmPackumentHandler"/>:
///
///  1. The passthrough single-flight rebuild must NOT read the initiating request's
///     <see cref="HttpContext"/> — it outlives that request (runs under
///     <see cref="CancellationToken.None"/> while callers detach), so a recycled/pooled context's
///     Request.Host could be baked into cached tarball URLs. The fix resolves the tarball base URL
///     before entering the rebuild and closes over the string. The test drives the real detach
///     race: the initiating caller cancels mid-upstream-fetch, its context host is then mutated,
///     and a second caller riding the same shared rebuild must still receive tarball URLs built
///     from the initiating caller's ORIGINAL host.
///
///  2. The local-only path must not re-cache a stale render after a concurrent Evict. A publish
///     that commits and evicts between the version read and the Set is otherwise invisible for up
///     to the local TTL. The fix captures the cache's invalidation generation before the read and
///     only Sets when it is unchanged. The test injects an Evict into the read window and asserts
///     the stale bytes are never cached.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmPackumentHandlerReviewTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = "npm-review-org" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Finding 1: passthrough rebuild must not read a recycled HttpContext ───────

    [Fact]
    public async Task Passthrough_RebuildOutlivingInitiatingRequest_UsesCapturedHostNotRecycledContext()
    {
        // Passthrough on (default), anonymous reads allowed, one npm upstream configured.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, anonymous_pull, proxy_passthrough_enabled) VALUES (@id, 1, 1)",
                new { id = _orgId });
            await conn.ExecuteAsync("""
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type)
                VALUES (@id, @o, 'npm', 'http://upstream.invalid', 0, 'anonymous')
                """,
                new { id = Guid.NewGuid().ToString("N"), o = _orgId });
        }

        // Upstream packument whose sole version carries an absolute tarball URL — the handler
        // rewrites its host segment to the request host, which is exactly the value the rebuild
        // must source from the INITIATING request, not a later mutation of that context.
        var gate = new GateHandler(HttpStatusCode.OK, """
            {
              "name": "lodash",
              "dist-tags": { "latest": "4.17.21" },
              "versions": {
                "4.17.21": {
                  "name": "lodash",
                  "version": "4.17.21",
                  "dist": { "tarball": "http://upstream.invalid/lodash/-/lodash-4.17.21.tgz" }
                }
              },
              "time": { "4.17.21": "2020-01-01T00:00:00Z" }
            }
            """);

        var cache = new RenderedResponseCache<NpmPackumentKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NpmPackument);
        var handler = BuildHandler(cache, gate);

        // Caller 1 initiates on host "good.example.test" and blocks inside the upstream fetch.
        var http1 = BuildContext("good.example.test");
        using var cts = new CancellationTokenSource();
        var task1 = handler.GetPackageAsync(http1, _orgId, "lodash", cts.Token);

        // The rebuild has started and reached the (blocked) upstream call — on the fixed code the
        // tarball base URL is already captured from host "good.example.test".
        await gate.WaitForCallCountAsync(1);

        // Caller 1 detaches (client abort). Its request completes and its context is recycled —
        // model that by flipping the host on the very same HttpContext instance.
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task1);
        http1.Request.Host = new HostString("evil.example.test");

        // Caller 2 (different host again) joins the SAME in-flight rebuild via single-flight.
        var http2 = BuildContext("second.example.test");
        var task2 = handler.GetPackageAsync(http2, _orgId, "lodash", CancellationToken.None);

        // Release upstream so the shared rebuild completes and caches its bytes.
        gate.Release();
        var served = Assert.IsType<FileContentResult>(await task2);

        string tarball = ExtractTarball(served.FileContents, "4.17.21");
        Assert.Contains("good.example.test", tarball);
        Assert.DoesNotContain("evil.example.test", tarball);
        Assert.DoesNotContain("second.example.test", tarball);
    }

    // ── Finding 2: local render must not re-cache after a concurrent Evict ────────

    [Fact]
    public async Task LocalOnly_ConcurrentEvictDuringRead_StaleRenderIsNotCached()
    {
        // Passthrough OFF → local-only path. Anonymous reads allowed. One hosted version.
        await SeedLocalPackageAsync();

        var cacheKey = new NpmPackumentKey(_orgId, "hosted-pkg");
        var cache = new EvictDuringReadCache(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NpmPackument,
            cacheKey);
        var handler = BuildHandler(cache);

        // The first read misses; the seam Evicts the key in that read window (a publish that
        // commits + evicts between the version read and the Set). The render must be served but
        // NOT cached, because its snapshot predates the eviction.
        var http = BuildContext("host.example.test");
        var result = await handler.GetPackageAsync(http, _orgId, "hosted-pkg", CancellationToken.None);
        Assert.IsType<FileContentResult>(result);

        // Old code (unconditional cache.Set) would have cached the pre-eviction bytes here; the
        // fix discards the Set because the invalidation generation advanced during the read.
        Assert.False(cache.TryGet(cacheKey, out _),
            "a render whose snapshot predates a concurrent Evict must not be cached");
    }

    [Fact]
    public async Task LocalOnly_NoConcurrentEvict_RenderIsCached()
    {
        // Control: with no intervening Evict the generation is unchanged and the Set is kept, so
        // the second read is a genuine cache hit.
        await SeedLocalPackageAsync();

        var cacheKey = new NpmPackumentKey(_orgId, "hosted-pkg");
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NpmPackument);
        var handler = BuildHandler(cache);

        var http = BuildContext("host.example.test");
        Assert.IsType<FileContentResult>(
            await handler.GetPackageAsync(http, _orgId, "hosted-pkg", CancellationToken.None));

        Assert.True(cache.TryGet(cacheKey, out byte[]? cached) && cached is not null,
            "with no intervening Evict the render must be cached");
    }

    // ── Finding 3: local render must not survive a racing proxy-settings invalidate ──

    [Fact]
    public async Task LocalOnly_ConcurrentProxySettingsInvalidateDuringRead_StaleRenderIsNotCached()
    {
        // Passthrough OFF → local-only path. Anonymous reads allowed. One hosted version.
        await SeedLocalPackageAsync();

        var epochStore = new OrgCacheEpochStore();
        var cacheKey = new NpmPackumentKey(_orgId, "hosted-pkg");
        var cache = new InvalidateEpochDuringReadCache(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NpmPackument, epochStore, cacheKey, _orgId);
        var handler = BuildHandler(cache);

        // The first read misses; the seam invalidates the org's policy epoch in that read
        // window (a proxy-settings PUT that commits + invalidates between the version read and
        // the Set). The render must be served but NOT cached, because its snapshot predates the
        // policy flip.
        var http = BuildContext("host.example.test");
        var result = await handler.GetPackageAsync(http, _orgId, "hosted-pkg", CancellationToken.None);
        Assert.IsType<FileContentResult>(result);

        // Old code (SetIfGenerationUnchanged with no epoch token — the underlying Set would
        // have captured the epoch fresh at write time, i.e. AFTER the Invalidate already ran)
        // would bind to the NEW live epoch and survive the flip. The fix captures the token
        // before the read, so the write binds to the already-retired token and is dropped/
        // immediately evicted.
        Assert.False(cache.TryGet(cacheKey, out _),
            "a render whose snapshot predates a concurrent proxy-settings invalidate must not be cached");
    }

    [Fact]
    public async Task LocalOnly_NoConcurrentInvalidate_RenderIsCached()
    {
        // Control: with no intervening Invalidate the epoch token is unchanged and the Set is
        // kept, so the second read is a genuine cache hit.
        await SeedLocalPackageAsync();

        var epochStore = new OrgCacheEpochStore();
        var cacheKey = new NpmPackumentKey(_orgId, "hosted-pkg");
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NpmPackument, epochStore);
        var handler = BuildHandler(cache);

        var http = BuildContext("host.example.test");
        Assert.IsType<FileContentResult>(
            await handler.GetPackageAsync(http, _orgId, "hosted-pkg", CancellationToken.None));

        Assert.True(cache.TryGet(cacheKey, out byte[]? cached) && cached is not null,
            "with no intervening Invalidate the render must be cached");
    }

    // ── Cache mechanism: the generation gate in isolation ────────────────────────

    [Fact]
    public void SetIfGenerationUnchanged_DiscardsAfterEvict_KeepsWhenGenerationCurrent()
    {
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 1024 }),
            MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey("org", "pkg");

        // Capture the generation, then a concurrent Evict lands — the stale-snapshot Set is dropped.
        long stale = cache.GetGeneration(key);
        cache.Evict(key);
        Assert.False(cache.SetIfGenerationUnchanged(key, [1, 2, 3], TimeSpan.FromMinutes(5), stale));
        Assert.False(cache.TryGet(key, out _));

        // Re-capture after the Evict and the Set is kept (mixed outcome: one discarded, one kept).
        long fresh = cache.GetGeneration(key);
        Assert.True(cache.SetIfGenerationUnchanged(key, [4, 5, 6], TimeSpan.FromMinutes(5), fresh));
        Assert.True(cache.TryGet(key, out byte[]? kept));
        Assert.Equal(new byte[] { 4, 5, 6 }, kept);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private async Task SeedLocalPackageAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, anonymous_pull, proxy_passthrough_enabled) VALUES (@id, 1, 0)",
            new { id = _orgId });
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @o, 'npm', 'hosted-pkg', 'hosted-pkg', 0)
            """,
            new { id = "pkg-local", o = _orgId });
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, filename, created_at)
            VALUES (@id, 'pkg-local', '1.0.0', 'pkg:npm/hosted-pkg@1.0.0', @bk, 'uploaded', 'hosted-pkg-1.0.0.tgz', @ts)
            """,
            new
            {
                id = "ver-local",
                bk = "registry/hosted-pkg-1.0.0.tgz",
                ts = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    private NpmPackumentHandler BuildHandler(RenderedResponseCache<NpmPackumentKey> cache, GateHandler? gate = null)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}"),
            })
            .Build();

        var orgs = new OrgRepository(_db);
        var packages = new PackageRepository(_db);
        var tokens = new TokenRepository(_db, _clock);
        var vulns = new VulnerabilityRepository(_db, _clock);
        var cacheArtifacts = new CacheArtifactRepository(_db);
        var inventory = new ArtifactInventoryRepository(_db, packages, cacheArtifacts, vulns);
        var urls = new RequestPublicUrlBuilder(config);
        var claims = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(config));
        var reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), _clock);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        var distTags = new NpmDistTagRepository(_db, _clock);
        var upstream = BuildUpstreamClient(gate ?? new GateHandler(HttpStatusCode.NotFound, ""), config);

        return new NpmPackumentHandler(
            orgs, packages, tokens, vulns, inventory, urls, claims, reserved,
            upstream, registries, distTags, cache,
            new RenderedMetadataCacheOptions(TimeSpan.FromSeconds(600), TimeSpan.FromSeconds(300)),
            _clock, NullLogger<NpmPackumentHandler>.Instance);
    }

    private UpstreamClient BuildUpstreamClient(GateHandler gate, IConfiguration config)
    {
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var audit = new AuditRepository(_db);
        string stagingDir = config["PROXY_STAGING_PATH"]!;
        return new UpstreamClient(
            new FactoryFor(gate),
            tiered,
            audit,
            new AllowEverythingValidator(),
            new AirGapMode(config),
            new DriveInfoStagingDiskInfo(stagingDir),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
    }

    private DefaultHttpContext BuildContext(string host)
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "npm-review-org");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString(host);
        return http;
    }

    private static string ExtractTarball(byte[] packumentBytes, string version)
    {
        var obj = JsonNode.Parse(packumentBytes)!.AsObject();
        return obj["versions"]![version]!["dist"]!["tarball"]!.GetValue<string>();
    }

    // Cache subclass that simulates a publish committing + evicting the key exactly inside the
    // local-render read window: on the first miss for the target key it Evicts (bumping the
    // invalidation generation), which the fixed handler observes when it tries to Set.
    private sealed class EvictDuringReadCache : RenderedResponseCache<NpmPackumentKey>
    {
        private readonly NpmPackumentKey _target;
        private bool _fired;

        public EvictDuringReadCache(IMemoryCache cache, Func<NpmPackumentKey, string> keyFormatter, NpmPackumentKey target)
            : base(cache, keyFormatter) => _target = target;

        public override bool TryGet(NpmPackumentKey key, out byte[]? value)
        {
            bool hit = base.TryGet(key, out value);
            if (!hit && !_fired && key.Equals(_target))
            {
                _fired = true;
                Evict(_target);
            }

            return hit;
        }
    }

    // Cache subclass that simulates a proxy-settings PUT committing + invalidating the org's
    // rendered-cache epoch exactly inside the local-render read window: on the first miss for
    // the target key it calls OrgCacheEpochStore.Invalidate, which the fixed handler's
    // pre-captured epoch token observes when it tries to Set.
    private sealed class InvalidateEpochDuringReadCache : RenderedResponseCache<NpmPackumentKey>
    {
        private readonly NpmPackumentKey _target;
        private readonly OrgCacheEpochStore _epochStore;
        private readonly string _orgId;
        private bool _fired;

        public InvalidateEpochDuringReadCache(
            IMemoryCache cache, Func<NpmPackumentKey, string> keyFormatter,
            OrgCacheEpochStore epochStore, NpmPackumentKey target, string orgId)
            : base(cache, keyFormatter, epochStore)
        {
            _epochStore = epochStore;
            _target = target;
            _orgId = orgId;
        }

        public override bool TryGet(NpmPackumentKey key, out byte[]? value)
        {
            bool hit = base.TryGet(key, out value);
            if (!hit && !_fired && key.Equals(_target))
            {
                _fired = true;
                _epochStore.Invalidate(_orgId);
            }

            return hit;
        }
    }

    // ── Upstream test doubles (blocking HTTP gate + permissive policy) ────────────

    private sealed class GateHandler : HttpMessageHandler
    {
        private readonly object _arrivalLock = new();
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource? _arrival;
        private int _arrivalTarget;
        private readonly HttpStatusCode _status;
        private readonly string _body;
        public int CallCount;

        public GateHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        public void Release() => _gate.TrySetResult();

        public Task WaitForCallCountAsync(int count, CancellationToken ct = default)
        {
            lock (_arrivalLock)
            {
                if (CallCount >= count)
                {
                    return Task.CompletedTask;
                }

                _arrivalTarget = count;
                _arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                return _arrival.Task.WaitAsync(ct);
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int count = Interlocked.Increment(ref CallCount);
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
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowEverythingValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }
}
