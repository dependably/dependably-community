using System.Net;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end proof that <c>POST /api/v1/auth/forgot-password</c> bounds reset mail per TARGET
/// account, not merely per source IP.
///
/// <para>
/// Every request in these tests arrives from a different source address (a header-driven
/// <c>RemoteIpAddress</c>, one /64 apart), and the per-IP permit budget is pinned high enough that
/// it cannot be what stops anything. So when the reset tokens stop being issued, the per-account
/// budget is the only control that could have stopped them — which is exactly the property the
/// per-IP limiter cannot provide against a distributed attacker.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PerAccountResetThrottleTests
{
    private const string ClientIpHeader = "X-Test-Client-Ip";

    /// <summary>Distinct /64s, so the IPv6 partition collapse gives each request its own bucket.</summary>
    private static string SourceAddressFor(int i) => $"2001:db8:{i:x}::1";

    [Fact]
    public async Task ManyDistinctSourceIps_TargetingOneAccount_StopAtThePerAccountCap()
    {
        await using var factory = new ThrottleFactory(new Dictionary<string, string>
        {
            ["ACCOUNT_SEND_MAX_PER_WINDOW"] = "3",
            // Far above the request count below: the per-IP limiter must not be what stops this.
            ["INVITE_RATE_LIMIT_PERMITS"] = "100000",
        });
        await factory.InitializeAsync();
        const string email = "throttled-target@example.com";
        string userId = await factory.CreateUser(email, "originalPassword123");

        using var client = factory.CreateClient();

        var statuses = new List<HttpStatusCode>();
        var bodies = new List<string>();
        for (int i = 0; i < 10; i++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/forgot-password")
            {
                Content = JsonContent.Create(new { email }),
            };
            req.Headers.Add(ClientIpHeader, SourceAddressFor(i));
            var resp = await client.SendAsync(req);
            statuses.Add(resp.StatusCode);
            bodies.Add(await resp.Content.ReadAsStringAsync());
        }

        // No caller can tell a throttled request from an accepted one: same status, same body.
        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.Accepted, s));
        Assert.Single(bodies.Distinct());

        // IssueAsync voids the previous outstanding link on each send, so the surviving row count
        // does not measure how many were sent. link_issued does: it is stamped inside the branch
        // that mints and mails the link, so it counts sends, not intentions.
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        int sent = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE action = 'user.password_reset_requested' AND detail LIKE '%"link_issued":true%'
            """);
        Assert.Equal(3, sent);

        int throttled = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE action = 'user.password_reset_requested' AND detail LIKE '%"throttled":true%'
            """);
        Assert.Equal(7, throttled);

        // The budget row is keyed by the pseudonym, and the address never appears in it.
        int rows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM account_send_throttle WHERE purpose = 'password_reset'");
        Assert.Equal(1, rows);
        int leaked = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM account_send_throttle WHERE email_hash LIKE '%throttled-target%'");
        Assert.Equal(0, leaked);

        Assert.NotEmpty(userId);
    }

    /// <summary>
    /// Adversarial twin: one account hitting its cap must not stop a different account from getting
    /// its reset link. If the budget were keyed on anything coarser than the account, this would
    /// fail — and the control would be an anonymous denial-of-service against every user at once.
    /// </summary>
    [Fact]
    public async Task OneAccountAtItsCap_DoesNotBlockAnotherAccount()
    {
        await using var factory = new ThrottleFactory(new Dictionary<string, string>
        {
            ["ACCOUNT_SEND_MAX_PER_WINDOW"] = "2",
            ["INVITE_RATE_LIMIT_PERMITS"] = "100000",
        });
        await factory.InitializeAsync();
        const string victim = "twin-victim@example.com";
        const string bystander = "twin-bystander@example.com";
        await factory.CreateUser(victim, "originalPassword123");
        string bystanderId = await factory.CreateUser(bystander, "originalPassword123");

        using var client = factory.CreateClient();

        for (int i = 0; i < 6; i++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/forgot-password")
            {
                Content = JsonContent.Create(new { email = victim }),
            };
            req.Headers.Add(ClientIpHeader, SourceAddressFor(i));
            using var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        }

        using var bystanderReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/forgot-password")
        {
            Content = JsonContent.Create(new { email = bystander }),
        };
        bystanderReq.Headers.Add(ClientIpHeader, SourceAddressFor(99));
        using var bystanderResp = await client.SendAsync(bystanderReq);
        Assert.Equal(HttpStatusCode.Accepted, bystanderResp.StatusCode);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        // The bystander's link was actually issued — their budget was never touched.
        int bystanderTokens = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = @id AND consumed_at IS NULL",
            new { id = bystanderId });
        Assert.Equal(1, bystanderTokens);

        // Two independent budget rows, one per account.
        int rows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM account_send_throttle WHERE purpose = 'password_reset'");
        Assert.Equal(2, rows);
    }

    /// <summary>
    /// An unknown address consumes budget too, so the write path is identical whether or not the
    /// address resolves to an account. If the throttle only ran on the matched branch, the presence
    /// of a budget row would itself answer "does this account exist?" for anyone who could read the
    /// database — and the differing work would be a timing signal on an enumeration-sensitive flow.
    /// </summary>
    [Fact]
    public async Task UnknownAddress_ConsumesBudgetToo_SoTheWritePathDoesNotRevealExistence()
    {
        await using var factory = new ThrottleFactory(new Dictionary<string, string>
        {
            ["ACCOUNT_SEND_MAX_PER_WINDOW"] = "5",
            ["INVITE_RATE_LIMIT_PERMITS"] = "100000",
        });
        await factory.InitializeAsync();
        await factory.CreateUser("known-shape@example.com", "originalPassword123");

        using var client = factory.CreateClient();
        foreach (string address in new[] { "known-shape@example.com", "no-such-account@example.com" })
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/forgot-password")
            {
                Content = JsonContent.Create(new { email = address }),
            };
            req.Headers.Add(ClientIpHeader, SourceAddressFor(1));
            using var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        }

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        int rows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM account_send_throttle WHERE purpose = 'password_reset'");
        Assert.Equal(2, rows);
    }

    // ── Private factory ───────────────────────────────────────────────────────

    /// <summary>
    /// Minimal auth-surface factory whose remote address is driven by a request header, so a single
    /// in-process client can present itself as many distinct sources.
    /// </summary>
    private sealed class ThrottleFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();
        private readonly InMemoryBlobStore _blobStore = new();

        public ThrottleFactory(Dictionary<string, string> settings) => _settings = settings;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            // Pin single mode before ConfigureBuilder so it overrides any ambient DEPLOYMENT_MODE
            // OS environment variable — the tenant-resolver strategy is selected at registration
            // time. Mirrors DependablyFactory.
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "single",
            });

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

            builder.Services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter, ClientIpStartupFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            foreach ((string key, string value) in _settings)
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

        public async Task<string> CreateUser(string email, string password)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4);
            string userId = Guid.NewGuid().ToString("N");

            await using var conn = await _metadataStore.OpenAsync();
            string orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");

            await conn.ExecuteAsync(
                """
                INSERT INTO users (id, tenant_id, email, password_hash, role)
                VALUES (@id, @tenantId, @email, @hash, 'member')
                """,
                new { id = userId, tenantId = orgId, email, hash = passwordHash });

            return userId;
        }

        public new HttpClient CreateClient() => base.CreateClient();
    }

    /// <summary>
    /// Sets <c>Connection.RemoteIpAddress</c> from the test header before anything else in the
    /// pipeline sees the request, so the rate-limit partitioner and the audit trail both observe
    /// the address the test intends. Falls back to loopback when the header is absent.
    /// </summary>
    private sealed class ClientIpStartupFilter : Microsoft.AspNetCore.Hosting.IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress =
                        ctx.Request.Headers.TryGetValue(ClientIpHeader, out var value)
                        && IPAddress.TryParse(value.ToString(), out var parsed)
                            ? parsed
                            : IPAddress.Loopback;
                    await n();
                });
                next(app);
            };
    }
}
