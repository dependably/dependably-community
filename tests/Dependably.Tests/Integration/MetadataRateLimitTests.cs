using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that the <c>metadata</c> rate-limiter policy and the process-wide
/// <see cref="MetadataConcurrencyGate"/> work correctly on npm packument, PyPI simple
/// index, and NuGet registration GET endpoints.
///
/// Scenarios:
///   1. A burst past the configured rate returns 429 with Retry-After (per ecosystem).
///   2. The metadata limiter is partitioned per source IP.
///   3. The <see cref="MetadataConcurrencyGate"/> bounds simultaneous cache-MISS rebuilds.
///   4. Cache-HIT requests return immediately without acquiring the gate (ungated).
///   5. Mixed: cache-HIT (fast, ungated) + cache-MISS (gated) co-existing under load.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MetadataRateLimitTests
{
    // ── 1. Burst past policy limit returns 429 ────────────────────────────────

    [Fact]
    public async Task NpmPackument_BurstPastLimit_Returns429WithRetryAfter()
    {
        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "2",
            ["METADATA_RATE_LIMIT_QUEUE"] = "0",
        });
        await factory.InitializeAsync();
        await factory.PushNpmPackage("rate-limit-npm", "1.0.0");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        // Exhaust the 2-permit window.
        for (int i = 0; i < 2; i++)
        {
            var ok = await GetWithIpAsync(client, "/npm/rate-limit-npm", "198.51.100.40");
            Assert.NotEqual(HttpStatusCode.TooManyRequests, ok.StatusCode);
        }

        var blocked = await GetWithIpAsync(client, "/npm/rate-limit-npm", "198.51.100.40");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(blocked.Headers.Contains("Retry-After"),
            "429 from the metadata limiter must carry a Retry-After header");
    }

    [Fact]
    public async Task PyPiSimpleIndex_BurstPastLimit_Returns429()
    {
        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "2",
            ["METADATA_RATE_LIMIT_QUEUE"] = "0",
        });
        await factory.InitializeAsync();
        await factory.PushPyPiPackage("rate-limit-pypi", "1.0.0");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBasic(token);

        for (int i = 0; i < 2; i++)
        {
            var ok = await GetWithIpAsync(client, "/simple/rate-limit-pypi/", "198.51.100.42");
            Assert.NotEqual(HttpStatusCode.TooManyRequests, ok.StatusCode);
        }

        var blocked = await GetWithIpAsync(client, "/simple/rate-limit-pypi/", "198.51.100.42");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(blocked.Headers.Contains("Retry-After"),
            "429 from the metadata limiter must carry a Retry-After header");
    }

    [Fact]
    public async Task NuGetRegistration_BurstPastLimit_Returns429()
    {
        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "2",
            ["METADATA_RATE_LIMIT_QUEUE"] = "0",
        });
        await factory.InitializeAsync();
        string pkg = $"ratelimit-nuget-{Guid.NewGuid():N}"[..28];
        await factory.PushNuGetPackage(pkg, "1.0.0");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBasic(token);

        for (int i = 0; i < 2; i++)
        {
            var ok = await GetWithIpAsync(client, $"/nuget/registration/{pkg}/index.json", "198.51.100.44");
            Assert.NotEqual(HttpStatusCode.TooManyRequests, ok.StatusCode);
        }

        var blocked = await GetWithIpAsync(client, $"/nuget/registration/{pkg}/index.json", "198.51.100.44");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(blocked.Headers.Contains("Retry-After"),
            "429 from the metadata limiter must carry a Retry-After header");
    }

    // ── 2. Metadata limiter is partitioned per source IP ─────────────────────

    [Fact]
    public async Task MetadataRateLimit_IsPartitionedPerSourceIp()
    {
        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "2",
            ["METADATA_RATE_LIMIT_QUEUE"] = "0",
        });
        await factory.InitializeAsync();
        await factory.PushNpmPackage("rate-limit-partition-npm", "1.0.0");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        // IP-A exhausts its 2-permit window.
        for (int i = 0; i < 2; i++)
        {
            await GetWithIpAsync(client, "/npm/rate-limit-partition-npm", "198.51.100.50");
        }
        var blockedA = await GetWithIpAsync(client, "/npm/rate-limit-partition-npm", "198.51.100.50");
        Assert.Equal(HttpStatusCode.TooManyRequests, blockedA.StatusCode);

        // IP-B still has a full window — one IP cannot block another.
        var okB = await GetWithIpAsync(client, "/npm/rate-limit-partition-npm", "198.51.100.51");
        Assert.NotEqual(HttpStatusCode.TooManyRequests, okB.StatusCode);
    }

    // ── 3. Semaphore gate does not deadlock local-path requests ──────────────

    [Fact]
    public async Task MetadataConcurrencyGate_LocalPath_DoesNotDeadlock()
    {
        // Gate set to 1 slot. Fan out 8 simultaneous packument requests for distinct packages
        // pushed locally (no upstream proxy). The local rebuild path calls _cache.Set directly
        // without going through GetOrRebuildAsync, so the gate semaphore is never acquired.
        // All requests must complete without deadlocking regardless of gate slot count.
        const int packages = 8;

        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "100000",
            ["METADATA_REBUILD_CONCURRENCY"] = "1",
        });
        await factory.InitializeAsync();

        for (int i = 0; i < packages; i++)
        {
            await factory.PushNpmPackage($"local-gate-pkg-{i}", "1.0.0");
        }

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        var tasks = Enumerable.Range(0, packages).Select(i =>
            GetWithIpAsync(client, $"/npm/local-gate-pkg-{i}", "198.51.100.60")).ToList();

        var statuses = await Task.WhenAll(tasks.Select(async t => (await t).StatusCode));

        // All requests must succeed; the gate must not have caused any deadlock.
        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.OK, s));
    }

    // ── 4. Cache-HIT path is ungated ─────────────────────────────────────────

    [Fact]
    public async Task MetadataConcurrencyGate_CacheHit_DoesNotAcquireGate()
    {
        // Gate set to 1 slot. After pre-warming the cache, we hold the sole semaphore slot
        // manually. A subsequent cache-HIT request must return immediately without blocking
        // on the gate — if it incorrectly tries to acquire, WaitAsync(5s) times out.
        //
        // Mixed-scenario: cache-HIT (fast, ungated) concurrent with a slot holder (MISS
        // simulation) — the two must not interfere.
        const int gateSlots = 1;

        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "100000",
            ["METADATA_REBUILD_CONCURRENCY"] = gateSlots.ToString(),
        });
        await factory.InitializeAsync();
        await factory.PushNpmPackage("hit-pkg", "1.0.0");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        // Pre-warm the cache for hit-pkg.
        var warmup = await GetWithIpAsync(client, "/npm/hit-pkg", "198.51.100.70");
        Assert.Equal(HttpStatusCode.OK, warmup.StatusCode);

        var gate = factory.Services.GetRequiredService<MetadataConcurrencyGate>();

        // Occupy the single gate slot to simulate a concurrent cold rebuild.
        await gate.Semaphore.WaitAsync();
        try
        {
            // Cache-HIT must return before the 5-second cancellation fires — the HIT path
            // reads from the in-process MemoryCache without touching the gate semaphore.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var hitTask = GetWithIpAsync(client, "/npm/hit-pkg", "198.51.100.70");
            var hitResp = await hitTask.WaitAsync(cts.Token);

            Assert.Equal(HttpStatusCode.OK, hitResp.StatusCode);
            // Slot must still be exhausted — the HIT did not release and re-acquire it.
            Assert.Equal(0, gate.Semaphore.CurrentCount);
        }
        finally
        {
            gate.Semaphore.Release();
        }
    }

    // ── 5. Mixed: cache-HIT + cache-MISS under load ───────────────────────────

    [Fact]
    public async Task MetadataGate_Mixed_HitAndMiss_AllSucceed()
    {
        // 4 packages: 2 pre-warmed (cache HITs) + 2 cold (cache MISSes). Fan out all 4
        // requests simultaneously. The gate is set to 2 slots — enough to rebuild both cold
        // packages in parallel. All 4 requests must return 200, including the HITs which
        // must not be delayed by the gated MISS rebuilds.
        const int gateSlots = 2;

        await using var factory = new MetadataRateLimitFactory(new Dictionary<string, string>
        {
            ["METADATA_RATE_LIMIT_PERMITS"] = "100000",
            ["METADATA_REBUILD_CONCURRENCY"] = gateSlots.ToString(),
        });
        await factory.InitializeAsync();

        for (int i = 0; i < 4; i++)
        {
            await factory.PushNpmPackage($"mixed-pkg-{i}", "1.0.0");
        }

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        // Pre-warm packages 0 and 1 (these become HIT requests in the burst below).
        for (int i = 0; i < 2; i++)
        {
            var warm = await GetWithIpAsync(client, $"/npm/mixed-pkg-{i}", "198.51.100.80");
            Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        }

        // Concurrent burst: 2 cached HITs (packages 0 and 1) + 2 cold MISSes (packages 2 and 3).
        var hitTasks = Enumerable.Range(0, 2).Select(i =>
            GetWithIpAsync(client, $"/npm/mixed-pkg-{i}", "198.51.100.80"));
        var missTasks = Enumerable.Range(2, 2).Select(i =>
            GetWithIpAsync(client, $"/npm/mixed-pkg-{i}", "198.51.100.80"));

        var allResponses = await Task.WhenAll(hitTasks.Concat(missTasks));

        Assert.All(allResponses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static async Task<HttpResponseMessage> GetWithIpAsync(HttpClient client, string path, string sourceIp)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, sourceIp);
        return await client.SendAsync(req);
    }

    // ── Private factory ───────────────────────────────────────────────────────

    /// <summary>
    /// Dedicated factory for metadata rate-limit tests. Uses a startup filter that sets
    /// <c>Connection.RemoteIpAddress</c> from the <c>X-Test-Remote-Ip</c> header so the
    /// metadata limiter's per-IP partitioning resolves correctly in TestServer.
    /// </summary>
    private sealed class MetadataRateLimitFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();
        private readonly InMemoryBlobStore _blobStore = new();

        public MetadataRateLimitFactory(Dictionary<string, string> settings) => _settings = settings;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blobStore);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blobStore, _blobStore));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);
            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();
            builder.Services.RemoveAll<SsrfConnectCallback>();
            builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

            // HeaderRemoteIpFilter drives the rate-limit partition key per-IP. The inline
            // LoopbackStartupFilter sets a loopback default so IP-gated internal probe paths
            // (/health etc.) are satisfied without configuration; HeaderRemoteIpFilter overrides
            // that default when an explicit X-Test-Remote-Ip header is present.
            builder.Services.AddSingleton<IStartupFilter, LoopbackStartupFilter>();
            builder.Services.AddSingleton<IStartupFilter, HeaderRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            // Keep unrelated limiters out of the way.
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            foreach (var (key, value) in _settings)
            {
                builder.WebHost.UseSetting(key, value);
            }

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync()
        {
            _ = CreateClient();
            return Task.CompletedTask;
        }

        public new async Task DisposeAsync()
        {
            await _metadataStore.DisposeAsync();
            await base.DisposeAsync();
        }

        // ── Token helpers ─────────────────────────────────────────────────────

        public async Task<string> CreateToken(string kind)
        {
            var tokens = Services.GetRequiredService<TokenRepository>();
            var orgs = Services.GetRequiredService<OrgRepository>();
            var org = await orgs.GetBySlugAsync("default")
                ?? throw new InvalidOperationException("Default org not found.");
            string caps = kind switch
            {
                "pull" => """["read:artifact","read:metadata"]""",
                "push" => """["publish:*","read:artifact","read:metadata","yank:*"]""",
                _ => throw new ArgumentException($"Unknown token kind '{kind}'.", nameof(kind)),
            };
            var (raw, _) = await tokens.CreateServiceTokenAsync(
                org.Id, $"test-{kind}-{Guid.NewGuid():N}", caps, expiresAt: null);
            return raw;
        }

        public HttpClient CreateClientWithBearer(string token)
        {
            var client = CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }

        public HttpClient CreateClientWithBasic(string token)
        {
            var client = CreateClient();
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("test:" + token));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", encoded);
            return client;
        }

        // ── Package push helpers (mirrors DependablyFactory's API) ────────────

        public async Task PushNpmPackage(string name, string version)
        {
            string token = await CreateToken("push");
            string body = NpmFixtures.BuildPublishBody(name, version);
            using var client = CreateClientWithBearer(token);
            var resp = await client.PutAsync($"/npm/{name}",
                new StringContent(body, Encoding.UTF8, "application/json"));
            resp.EnsureSuccessStatusCode();
        }

        public async Task PushPyPiPackage(string name, string version)
        {
            string token = await CreateToken("push");
            var (bytes, sha256) = PyPiFixtures.BuildWheel(name, version);
            string filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";

            using var client = CreateClientWithBasic(token);
            var content = new MultipartFormDataContent
            {
                { new StringContent("file_upload"), ":action" },
                { new StringContent("2.1"), "metadata_version" },
                { new StringContent(name), "name" },
                { new StringContent(version), "version" },
                { new StringContent(sha256), "sha256_digest" },
            };
            var fileContent = new ByteArrayContent(bytes);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(fileContent, "content", filename);

            var resp = await client.PostAsync("/pypi/legacy/", content);
            resp.EnsureSuccessStatusCode();
        }

        public async Task PushNuGetPackage(string id, string version)
        {
            string token = await CreateToken("push");
            var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
            string filename = $"{id}.{version}.nupkg";

            using var client = CreateClient();
            client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

            var content = new MultipartFormDataContent();
            var fileContent = new ByteArrayContent(bytes);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(fileContent, "package", filename);

            var resp = await client.PutAsync("/nuget/publish", content);
            resp.EnsureSuccessStatusCode();
        }
    }

    /// <summary>
    /// Sets <c>Connection.RemoteIpAddress</c> to loopback for every TestServer request.
    /// TestServer leaves it null; loopback matches the default allowlist (127.0.0.1/::1)
    /// so IP-gated paths (/health, /metrics) are reachable without extra configuration.
    /// </summary>
    private sealed class LoopbackStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    await n();
                });
                next(app);
            };
    }

    /// <summary>
    /// Startup filter that reads <c>X-Test-Remote-Ip</c> and sets
    /// <c>Connection.RemoteIpAddress</c> before the production pipeline runs.
    /// Required so the metadata limiter's per-IP partitioning resolves correctly
    /// in TestServer (which otherwise has no remote IP).
    /// </summary>
    private sealed class HeaderRemoteIpFilter : IStartupFilter
    {
        public const string HeaderName = "X-Test-Remote-Ip";

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    if (ctx.Request.Headers.TryGetValue(HeaderName, out var raw)
                        && IPAddress.TryParse(raw.ToString(), out var ip))
                    {
                        ctx.Connection.RemoteIpAddress = ip;
                    }
                    await n();
                });
                next(app);
            };
    }
}
