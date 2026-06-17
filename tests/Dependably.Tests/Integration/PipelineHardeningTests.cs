using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Infrastructure;
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
/// Pipeline-order and unauthenticated-surface hardening:
///   * ForwardedHeadersMiddleware runs before the /metrics IP allowlist, so
///     X-Forwarded-For from a TRUSTED_PROXIES source resolves the real client IP
///     (and is ignored from anything else).
///   * /version sits behind the same allowlist.
///   * The in-process login limiter and the anonymous-probe limiter partition per
///     client IP — one abusive source cannot exhaust the instance-wide budget.
///   * /ready reports per-check ok/error without raw exception detail.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PipelineHardeningTests
{
    private const string TrustedProxyIp = "10.9.9.9";
    private const string AllowlistedClientIp = "198.51.100.7";

    // ── Forwarded headers vs /metrics + /version allowlist ───────────────────

    [Fact]
    public async Task Metrics_XForwardedFor_FromTrustedProxy_ResolvesRealClientIp()
    {
        await using var factory = NewForwardedHeadersFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, TrustedProxyIp);
        req.Headers.Add("X-Forwarded-For", AllowlistedClientIp);

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Metrics_XForwardedFor_FromUntrustedSource_IsIgnored()
    {
        await using var factory = NewForwardedHeadersFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, "203.0.113.50");
        req.Headers.Add("X-Forwarded-For", AllowlistedClientIp);

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Metrics_TrustedProxyWithoutForwardedFor_IsNotItselfAllowlisted()
    {
        await using var factory = NewForwardedHeadersFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, TrustedProxyIp);

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Version_AllowlistedClientIp_ReturnsVersion()
    {
        await using var factory = NewForwardedHeadersFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/version");
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, AllowlistedClientIp);

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("version").GetString()));
    }

    [Fact]
    public async Task Version_NonAllowlistedClientIp_Returns403()
    {
        await using var factory = NewForwardedHeadersFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/version");
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, "203.0.113.51");

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    private static PipelineFactory NewForwardedHeadersFactory() => new(new Dictionary<string, string>
    {
        ["TRUSTED_PROXIES"] = TrustedProxyIp,
        ["METRICS_ALLOWED_IPS"] = AllowlistedClientIp,
    });

    // ── Per-IP rate limiting (in-process, no Redis) ───────────────────────────

    [Fact]
    public async Task LoginRateLimit_IsPartitionedPerClientIp()
    {
        // X-Test-Remote-Ip drives Connection.RemoteIpAddress directly via HeaderRemoteIpFilter
        // (runs before all production middleware). TRUSTED_PROXIES is not set, so X-Forwarded-For
        // is ignored (fail-closed) — rate-limit partitioning relies on the real socket peer.
        await using var factory = new PipelineFactory(new Dictionary<string, string>
        {
            ["LOGIN_RATE_LIMIT_PERMITS"] = "2",
        });
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        // First client exhausts its own window…
        for (int i = 0; i < 2; i++)
        {
            var resp = await PostLoginAsync(client, sourceIp: "198.51.100.10", attempt: i);
            Assert.NotEqual(HttpStatusCode.TooManyRequests, resp.StatusCode);
        }
        var blocked = await PostLoginAsync(client, sourceIp: "198.51.100.10", attempt: 99);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);

        // …while a different client IP still has a full window.
        var other = await PostLoginAsync(client, sourceIp: "198.51.100.11", attempt: 0);
        Assert.NotEqual(HttpStatusCode.TooManyRequests, other.StatusCode);
    }

    [Fact]
    public async Task AnonymousProbeRateLimit_IsPartitionedPerClientIp()
    {
        await using var factory = new PipelineFactory(new Dictionary<string, string>
        {
            ["ANON_RATE_LIMIT_PERMITS"] = "3",
        });
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        for (int i = 0; i < 3; i++)
        {
            var resp = await GetWithSocketIpAsync(client, "/health", "198.51.100.20");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        var blocked = await GetWithSocketIpAsync(client, "/health", "198.51.100.20");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);

        var other = await GetWithSocketIpAsync(client, "/health", "198.51.100.21");
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task ManagementApiRateLimit_ExhaustedBudget_Returns429WithRetryAfter()
    {
        // ANON_RATE_LIMIT_PERMITS is set well above MANAGEMENT_RATE_LIMIT_PERMITS so the
        // GlobalLimiter is the one that fires, not the endpoint-specific "anon" policy.
        await using var factory = new PipelineFactory(new Dictionary<string, string>
        {
            ["MANAGEMENT_RATE_LIMIT_PERMITS"] = "3",
            ["ANON_RATE_LIMIT_PERMITS"] = "100000",
        });
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        // Three requests from the same IP exhaust the configured budget.
        for (int i = 0; i < 3; i++)
        {
            var resp = await GetWithSocketIpAsync(client, "/api/v1/bootstrap", "198.51.100.30");
            Assert.NotEqual(HttpStatusCode.TooManyRequests, resp.StatusCode);
        }

        // The fourth request must be rejected by the management GlobalLimiter.
        var blocked = await GetWithSocketIpAsync(client, "/api/v1/bootstrap", "198.51.100.30");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(blocked.Headers.Contains("Retry-After"),
            "429 responses from the management limiter must carry a Retry-After header");

        // A different source IP still has a full window (limiter partitions per principal).
        var other = await GetWithSocketIpAsync(client, "/api/v1/bootstrap", "198.51.100.31");
        Assert.NotEqual(HttpStatusCode.TooManyRequests, other.StatusCode);
    }

    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string sourceIp, int attempt)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login")
        {
            // Unique email per attempt keeps the per-account lockout out of the picture;
            // this test exercises only the per-IP limiter window.
            Content = JsonContent.Create(new { email = $"nobody{attempt}@example.test", password = "wrong-password" }),
        };
        // Use the test socket-peer header so HeaderRemoteIpFilter sets RemoteIpAddress
        // directly. X-Forwarded-For is ignored without TRUSTED_PROXIES (fail-closed).
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, sourceIp);
        return await client.SendAsync(req);
    }

    private static async Task<HttpResponseMessage> GetWithSocketIpAsync(HttpClient client, string path, string sourceIp)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        // Drive RemoteIpAddress through the test socket-peer header, not X-Forwarded-For,
        // since forwarded-header processing is disabled when TRUSTED_PROXIES is unset.
        req.Headers.Add(HeaderRemoteIpFilter.HeaderName, sourceIp);
        return await client.SendAsync(req);
    }

    // ── /ready response shape ─────────────────────────────────────────────────

    [Fact]
    public async Task Ready_DegradedCheck_DoesNotLeakExceptionDetail()
    {
        await using var factory = new PipelineFactory(
            new Dictionary<string, string>(),
            blobStore: new FailingExistsBlobStore());
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);

        string raw = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain(FailingExistsBlobStore.SecretDetail, raw);

        using var body = JsonDocument.Parse(raw);
        Assert.Equal("degraded", body.RootElement.GetProperty("status").GetString());
        Assert.Equal("error", body.RootElement.GetProperty("checks").GetProperty("blob_store").GetString());
        Assert.Equal("ok", body.RootElement.GetProperty("checks").GetProperty("db").GetString());
        Assert.False(body.RootElement.TryGetProperty("errors", out _),
            "the /ready body must not carry a raw per-check error map");
    }

    // ── Test scaffolding ──────────────────────────────────────────────────────

    /// <summary>
    /// App factory with per-test settings and a startup filter that sets
    /// <c>Connection.RemoteIpAddress</c> from the <c>X-Test-Remote-Ip</c> request
    /// header before the production pipeline runs — TestServer connections
    /// otherwise have no remote IP, which both the forwarded-headers trust check
    /// and the rate-limit partitioning need.
    /// </summary>
    private sealed class PipelineFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly IBlobStore _blobStore;
        private readonly TestMetadataStore _metadataStore = new();

        public PipelineFactory(Dictionary<string, string> settings, IBlobStore? blobStore = null)
        {
            _settings = settings;
            _blobStore = blobStore ?? new InMemoryBlobStore();
        }

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton(_blobStore);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blobStore, _blobStore));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);
            builder.Services.AddSingleton<IStartupFilter, HeaderRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
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
    }

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

    /// <summary>
    /// Blob store whose existence probe fails with a message that must never
    /// surface in the anonymous /ready body (it carries path/endpoint detail).
    /// </summary>
    private sealed class FailingExistsBlobStore : IBlobStore
    {
        public const string SecretDetail = "/var/secret-internal/blobs: simulated disk failure";

        private readonly InMemoryBlobStore _inner = new();

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => _inner.PutAsync(key, data, ct);

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) => _inner.GetRangeAsync(key, from, to, ct);

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => throw new IOException(SecretDetail);

        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => _inner.ListAsync(prefix, ct);
    }
}
