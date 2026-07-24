using System.Net;
using System.Net.Http.Json;
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
/// Verifies the two rate-limit policies guarding the self-serve reset flow trip at their
/// configured permit count. Uses a dedicated factory per test (not the shared
/// <see cref="DependablyFactory"/>, which pins <c>LOGIN_RATE_LIMIT_PERMITS</c> /
/// <c>INVITE_RATE_LIMIT_PERMITS</c> high so unrelated test classes sharing that fixture don't
/// self-throttle) so a tight budget can be asserted deterministically.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PasswordResetRateLimitTests
{
    [Fact]
    public async Task ForgotPassword_BurstPastInviteLimit_Returns429()
    {
        await using var factory = new AuthRateLimitFactory(new Dictionary<string, string>
        {
            ["INVITE_RATE_LIMIT_PERMITS"] = "2",
        });
        await factory.InitializeAsync();
        await factory.CreateUser("rl-forgot@example.com", "originalPassword123");

        using var client = factory.CreateClient();

        for (int i = 0; i < 2; i++)
        {
            var ok = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = "rl-forgot@example.com" });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, ok.StatusCode);
        }

        var blocked = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = "rl-forgot@example.com" });
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_BurstPastLoginLimit_Returns429()
    {
        await using var factory = new AuthRateLimitFactory(new Dictionary<string, string>
        {
            ["LOGIN_RATE_LIMIT_PERMITS"] = "2",
        });
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        for (int i = 0; i < 2; i++)
        {
            var ok = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
                new { token = "irrelevant-token", newPassword = "irrelevantPassword123!" });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, ok.StatusCode);
        }

        var blocked = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = "irrelevant-token", newPassword = "irrelevantPassword123!" });
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
    }

    // ── Private factory ───────────────────────────────────────────────────────

    /// <summary>Minimal factory for auth-surface rate-limit tests — no upstream/blob
    /// scaffolding needed, just an in-memory metadata store and the settings under test.</summary>
    private sealed class AuthRateLimitFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();
        private readonly InMemoryBlobStore _blobStore = new();

        public AuthRateLimitFactory(Dictionary<string, string> settings) => _settings = settings;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            // Pin single mode before ConfigureBuilder so it overrides any ambient DEPLOYMENT_MODE
            // OS environment variable (e.g. one exported for a local debug instance) — the
            // tenant-resolver strategy is selected from this at registration time, so setting it
            // any later leaves the resolver bound to the wrong mode. Mirrors DependablyFactory.
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

            builder.Services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter, LoopbackStartupFilter>();

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill");
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
            string orgId = await Dapper.SqlMapper.ExecuteScalarAsync<string>(conn,
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");

            await Dapper.SqlMapper.ExecuteAsync(conn,
                """
                INSERT INTO users (id, tenant_id, email, password_hash, role)
                VALUES (@id, @tenantId, @email, @hash, 'member')
                """,
                new { id = userId, tenantId = orgId, email, hash = passwordHash });

            return userId;
        }

        public new HttpClient CreateClient() => base.CreateClient();
    }

    /// <summary>Sets <c>Connection.RemoteIpAddress</c> to loopback for every TestServer
    /// request — matches the default allowlist so IP-gated internal probe paths stay
    /// reachable; the "invite"/"login" limiters here partition per-IP, so every request in a
    /// single test shares one bucket regardless.</summary>
    private sealed class LoopbackStartupFilter : Microsoft.AspNetCore.Hosting.IStartupFilter
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
}
