using System.Net;
using System.Text;
using Dapper;
using Dependably.Api.NuGetProtocol;
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
/// Regression coverage for <see cref="NuGetRegistrationHandler"/>'s local-only render path: a
/// proxy-settings PUT that commits its policy write and invalidates the org's rendered-cache
/// epoch (<see cref="OrgCacheEpochStore.Invalidate"/>) between this handler's policy-dependent
/// read and its eventual cache write must not have that invalidation lost. The fix captures the
/// epoch token before the read (mirroring <see cref="RenderedResponseCache{TKey}.GetOrRebuildAsync"/>)
/// and threads it into the write, so a write whose snapshot predates the flip expires immediately
/// on insert instead of surviving to <c>RegistrationLocalTtl</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetRegistrationHandlerReviewTests : IAsyncLifetime
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
            new { id = _orgId, slug = "nuget-review-org" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task LocalOnly_ConcurrentProxySettingsInvalidateDuringRead_StaleRenderIsNotCached()
    {
        // Passthrough OFF → local-only path. Anonymous reads allowed. One hosted version.
        await SeedLocalPackageAsync();

        var epochStore = new OrgCacheEpochStore();
        var cacheKey = new NuGetRegistrationKey(_orgId, "hosted-pkg", SemVer2: true);
        var cache = new InvalidateEpochDuringReadCache(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NuGetRegistration, epochStore, cacheKey, _orgId);
        var handler = BuildHandler(cache);

        // The first read misses; the seam invalidates the org's policy epoch in that read
        // window (a proxy-settings PUT that commits + invalidates between the version read and
        // the Set). The render must be served but NOT cached, because its snapshot predates the
        // policy flip.
        var http = BuildContext("host.example.test");
        var result = await handler.RegistrationIndexAsync(http, _orgId, "hosted-pkg", semVer2: true, CancellationToken.None);
        Assert.IsType<FileContentResult>(result);

        // Old code (cache.Set with no epoch token — captured fresh at write time, i.e. AFTER the
        // Invalidate already ran) would bind to the NEW live epoch and survive the flip. The fix
        // captures the token before the read, so the write binds to the already-retired token
        // and is dropped/immediately evicted.
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
        var cacheKey = new NuGetRegistrationKey(_orgId, "hosted-pkg", SemVer2: true);
        var cache = new RenderedResponseCache<NuGetRegistrationKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NuGetRegistration, epochStore);
        var handler = BuildHandler(cache);

        var http = BuildContext("host.example.test");
        Assert.IsType<FileContentResult>(
            await handler.RegistrationIndexAsync(http, _orgId, "hosted-pkg", semVer2: true, CancellationToken.None));

        Assert.True(cache.TryGet(cacheKey, out byte[]? cached) && cached is not null,
            "with no intervening Invalidate the render must be cached");
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
            VALUES (@id, @o, 'nuget', 'hosted-pkg', 'hosted-pkg', 0)
            """,
            new { id = "pkg-local", o = _orgId });
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, filename, created_at)
            VALUES (@id, 'pkg-local', '1.0.0', 'pkg:nuget/hosted-pkg@1.0.0', @bk, 'uploaded', 'hosted-pkg.1.0.0.nupkg', @ts)
            """,
            new
            {
                id = "ver-local",
                bk = "registry/hosted-pkg.1.0.0.nupkg",
                ts = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    private NuGetRegistrationHandler BuildHandler(RenderedResponseCache<NuGetRegistrationKey> cache)
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
        var claims = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(config));
        var reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), _clock);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        var urls = new RequestPublicUrlBuilder(config);
        // The local-only path under test never calls upstream (passthrough is off), so a
        // gate that would block forever if hit is a deliberate trip-wire against regressions
        // that accidentally route this scenario through the proxy path.
        var upstream = BuildUpstreamClient(new GateHandler(HttpStatusCode.NotFound, ""), config);

        return new NuGetRegistrationHandler(
            orgs, packages, tokens, vulns, inventory,
            upstream, registries, claims, reserved, cache,
            new RenderedMetadataCacheOptions(TimeSpan.FromSeconds(600), TimeSpan.FromSeconds(300)),
            urls, _clock, NullLogger<NuGetRegistrationHandler>.Instance);
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
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "nuget-review-org");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString(host);
        return http;
    }

    // Cache subclass that simulates a proxy-settings PUT committing + invalidating the org's
    // rendered-cache epoch exactly inside the local-render read window: on the first miss for
    // the target key it calls OrgCacheEpochStore.Invalidate, which the fixed handler's
    // pre-captured epoch token observes when it tries to Set.
    private sealed class InvalidateEpochDuringReadCache : RenderedResponseCache<NuGetRegistrationKey>
    {
        private readonly NuGetRegistrationKey _target;
        private readonly OrgCacheEpochStore _epochStore;
        private readonly string _orgId;
        private bool _fired;

        public InvalidateEpochDuringReadCache(
            IMemoryCache cache, Func<NuGetRegistrationKey, string> keyFormatter,
            OrgCacheEpochStore epochStore, NuGetRegistrationKey target, string orgId)
            : base(cache, keyFormatter, epochStore)
        {
            _epochStore = epochStore;
            _target = target;
            _orgId = orgId;
        }

        public override bool TryGet(NuGetRegistrationKey key, out byte[]? value)
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

    // ── Upstream test doubles (never expected to be invoked in this scenario) ────

    private sealed class GateHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public GateHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            });
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
