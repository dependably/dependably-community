using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
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
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves that a <c>/metrics</c> allowlist change is reflected on the very next
/// <c>GET /metrics</c> request (no perceptible delay) for both the apex
/// (<c>PUT /api/v1/system/metrics-access</c>) and single-mode instance
/// (<c>PUT /api/v1/instance/metrics-access</c>) save endpoints. A third scenario
/// pins the 5-second TTL ceiling when <c>Invalidate()</c> is bypassed.
///
/// <para><b>Conclusion:</b> all three propagation assertions pass — there is no
/// staleness bug in this code path. <see cref="MetricsAccessConfig.Invalidate"/>
/// is called by both PUT handlers immediately after the DB write, and the
/// middleware receives the same singleton instance registered once in
/// <c>Program.cs</c>. <see cref="MetricsAccessConfig.ResolveAsync"/> re-reads
/// when <c>_cached</c> is null regardless of <c>_expiry</c>, so a save is
/// visible in the very next request without any clock advance.</para>
///
/// <para>The observed multi-minute "delay" in production was not a propagation
/// delay. Behind Docker Desktop's published-port NAT the real peer is
/// <c>192.168.65.1</c>; earlier attempts used LAN/bridge IPs
/// (<c>192.168.2.x</c>, <c>172.18.0.1</c>) that never matched, keeping
/// <c>/metrics</c> at 403 until the correct IP was added. The denied IP is
/// already collected in <c>scrapeDiagnostics.recent[].remoteIp</c> and exposed on
/// the Observability page. The deferred UX improvement is to surface that value
/// on the allowlist editor (<c>web/src/lib/settings/SettingsMetrics.svelte</c>)
/// so operators do not need to guess.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class MetricsAccessPropagationTests
{
    // A non-loopback IP that the default allowlist (127.0.0.1, ::1) does not include,
    // so we can assert it is denied before the PUT and allowed immediately after.
    private static readonly IPAddress ProbeIp = IPAddress.Parse("10.20.30.40");

    // ── Multi-mode / apex path ──────────────────────────────────────────────

    /// <summary>
    /// Apex path: <c>PUT /api/v1/system/metrics-access</c> followed immediately
    /// by <c>GET /metrics</c> from the newly-added IP returns 200 without any
    /// clock advance. This proves <c>Invalidate()</c> makes the save visible in
    /// the next request.
    /// </summary>
    [Fact]
    public async Task SystemPath_PutMetricsAccess_IsVisibleOnNextMetricsRequest()
    {
        var clock = TestTime.Frozen();
        await using var factory = new ProbeIpMultiFactory(clock);
        await factory.InitializeAsync();

        using var sysClient = await factory.CreateSystemAdminClientAsync();

        // Establish a known baseline: only loopback in the allowlist.
        var baseline = await sysClient.PutAsJsonAsync(
            "/api/v1/system/metrics-access",
            new { enabled = true, allowedIps = new[] { "127.0.0.1", "::1" } });
        Assert.Equal(HttpStatusCode.OK, baseline.StatusCode);

        // Advance the clock beyond the 5s TTL so the baseline entry is cached
        // and the probe IP is definitely blocked.
        clock.Advance(TimeSpan.FromSeconds(10));

        factory.RemoteIp = ProbeIp;
        var beforePut = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, beforePut.StatusCode);

        // Add the probe IP via the apex endpoint — Invalidate() is called inside.
        var put = await sysClient.PutAsJsonAsync(
            "/api/v1/system/metrics-access",
            new { enabled = true, allowedIps = new[] { "127.0.0.1", "::1", ProbeIp.ToString() } });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        // KEY ASSERTION: next GET /metrics from the probe IP — no clock advance — must be 200.
        factory.RemoteIp = ProbeIp;
        var afterPut = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.OK, afterPut.StatusCode);
    }

    // ── Single-mode / instance path ─────────────────────────────────────────

    /// <summary>
    /// Instance (single-mode) path: <c>PUT /api/v1/instance/metrics-access</c>
    /// followed immediately by <c>GET /metrics</c> from the newly-added IP
    /// returns 200 without any clock advance.
    /// </summary>
    [Fact]
    public async Task InstancePath_PutMetricsAccess_IsVisibleOnNextMetricsRequest()
    {
        var clock = TestTime.Frozen();
        await using var factory = new ProbeIpSingleFactory(clock);
        await factory.InitializeAsync();

        // Warm a baseline allowlist and advance past the TTL so the probe IP is cached
        // as blocked (not just a cold-start default hit).
        string jwt = await factory.CreateAdminJwtAsync();
        using var adminClient = factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", jwt);

        var baseline = await adminClient.PutAsJsonAsync(
            "/api/v1/instance/metrics-access",
            new { enabled = true, allowedIps = new[] { "127.0.0.1", "::1" } });
        Assert.Equal(HttpStatusCode.OK, baseline.StatusCode);

        clock.Advance(TimeSpan.FromSeconds(10));

        factory.RemoteIp = ProbeIp;
        var beforePut = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, beforePut.StatusCode);

        // Add the probe IP via the instance endpoint — Invalidate() is called inside.
        var put = await adminClient.PutAsJsonAsync(
            "/api/v1/instance/metrics-access",
            new { enabled = true, allowedIps = new[] { "127.0.0.1", "::1", ProbeIp.ToString() } });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        // KEY ASSERTION: next GET /metrics from probe IP — no clock advance — must be 200.
        factory.RemoteIp = ProbeIp;
        var afterPut = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.OK, afterPut.StatusCode);
    }

    // ── TTL ceiling documentation ───────────────────────────────────────────

    /// <summary>
    /// Documents the 5-second TTL ceiling: a write that bypasses the save endpoint
    /// (so <c>Invalidate()</c> is never called) is not visible before the TTL expires
    /// but is visible once the frozen clock advances past the 5-second expiry.
    /// This pins the maximum staleness guarantee even without an explicit invalidation.
    /// </summary>
    [Fact]
    public async Task TtlCeiling_DirectDbWrite_NotVisibleBeforeTtl_VisibleAfter()
    {
        var clock = TestTime.Frozen();
        await using var factory = new ProbeIpMultiFactory(clock);
        await factory.InitializeAsync();

        using var sysClient = await factory.CreateSystemAdminClientAsync();

        // Seed an allowlist that excludes the probe IP and let the cache warm.
        var seed = await sysClient.PutAsJsonAsync(
            "/api/v1/system/metrics-access",
            new { enabled = true, allowedIps = new[] { "127.0.0.1", "::1" } });
        Assert.Equal(HttpStatusCode.OK, seed.StatusCode);

        // Trigger a ResolveAsync to fill the cache; probe IP must be forbidden.
        factory.RemoteIp = ProbeIp;
        var blocked = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

        // Write the new IP directly to instance_settings, bypassing the PUT endpoint.
        // Invalidate() is NOT called — the cache is stale by design.
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT OR REPLACE INTO instance_settings (key, value) VALUES (@key, @value)",
                new
                {
                    key = "metrics_allowed_ips",
                    value = System.Text.Json.JsonSerializer.Serialize(
                        new[] { "127.0.0.1", "::1", ProbeIp.ToString() }),
                });
        }

        // Before TTL expiry: cache still serves the stale result — probe IP blocked.
        factory.RemoteIp = ProbeIp;
        var stillBlocked = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, stillBlocked.StatusCode);

        // Advance the fake clock past the 5-second TTL (well clear of the boundary).
        clock.Advance(TimeSpan.FromSeconds(7));

        // After TTL expiry: ResolveAsync re-reads from DB; probe IP is now allowed.
        factory.RemoteIp = ProbeIp;
        var nowAllowed = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.OK, nowAllowed.StatusCode);
    }

    // ── Private factory helpers ─────────────────────────────────────────────

    /// <summary>
    /// A <c>ConfigurableRemoteIpFilter</c> that injects a mutable
    /// <c>IPAddress</c> into <c>Connection.RemoteIpAddress</c> on each
    /// incoming request. The factory exposes a <c>RemoteIp</c> property;
    /// tests change it between requests to simulate different callers.
    /// </summary>
    private sealed class ConfigurableRemoteIpFilter : IStartupFilter
    {
        private readonly Func<IPAddress> _getIp;

        public ConfigurableRemoteIpFilter(Func<IPAddress> getIp) => _getIp = getIp;

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress = _getIp();
                    await n();
                });
                next(app);
            };
    }

    /// <summary>
    /// Multi-mode (DEPLOYMENT_MODE=multi) factory with a frozen clock and a
    /// per-request IP that can be changed between requests.
    /// </summary>
    private sealed class ProbeIpMultiFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly FakeTimeProvider _clock;
        private readonly TestMetadataStore _store = new();
        private readonly InMemoryBlobStore _blob = new();

        public IPAddress RemoteIp { get; set; } = IPAddress.Loopback;

        public ProbeIpMultiFactory(FakeTimeProvider clock) => _clock = clock;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            builder.Configuration["DEPLOYMENT_MODE"] = "multi";
            builder.Configuration["APEX_HOST"] = DependablyMultiFactory.ApexHost;
            builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] =
                DependablyMultiFactory.SystemAdminEmail;
            builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"] =
                DependablyMultiFactory.SystemAdminPassword;

            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<TimeProvider>();
            builder.Services.AddSingleton<TimeProvider>(_clock);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_store);

            // Replace the SSRF validator so tests that use MockUpstream can run;
            // no-op here since these tests don't fetch upstream packages.
            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();
            builder.Services.RemoveAll<SsrfConnectCallback>();
            builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

            // Inject the caller IP for every /metrics request.
            builder.Services.AddSingleton<IStartupFilter>(
                new ConfigurableRemoteIpFilter(() => RemoteIp));

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }

        public new async Task DisposeAsync()
        {
            await _store.DisposeAsync();
            await base.DisposeAsync();
        }

        public async Task<HttpClient> CreateSystemAdminClientAsync()
        {
            await using var conn = await _store.OpenAsync();
            string sysId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM system_admins LIMIT 1")
                ?? throw new InvalidOperationException("system_admin not found.");
            await conn.ExecuteAsync(
                "UPDATE system_admins SET must_change_password = 0 WHERE id = @sysId",
                new { sysId });
            string jwtSecret = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
                ?? throw new InvalidOperationException("jwt_secret missing.");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // now-ok: mints a JWT the host validates against its real clock.
            var now = DateTime.UtcNow;
            var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                claims:
                [
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, sysId),
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti,
                        Guid.NewGuid().ToString("N")),
                    new Claim("role", "system_admin"),
                    new Claim("scope", "system"),
                ],
                notBefore: now,
                expires: now.AddHours(1),
                signingCredentials: creds);
            string jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler()
                .WriteToken(token);

            var client = CreateClient();
            client.DefaultRequestHeaders.Host = DependablyMultiFactory.ApexHost;
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", jwt);
            return client;
        }
    }

    /// <summary>
    /// Single-mode factory (DEPLOYMENT_MODE defaults to single) with a frozen
    /// clock and a mutable per-request IP.
    /// </summary>
    private sealed class ProbeIpSingleFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly FakeTimeProvider _clock;
        private readonly TestMetadataStore _store = new();
        private readonly InMemoryBlobStore _blob = new();

        public IPAddress RemoteIp { get; set; } = IPAddress.Loopback;

        public ProbeIpSingleFactory(FakeTimeProvider clock) => _clock = clock;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<TimeProvider>();
            builder.Services.AddSingleton<TimeProvider>(_clock);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_store);

            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();
            builder.Services.RemoveAll<SsrfConnectCallback>();
            builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

            builder.Services.AddSingleton<IStartupFilter>(
                new ConfigurableRemoteIpFilter(() => RemoteIp));

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }

        public new async Task DisposeAsync()
        {
            await _store.DisposeAsync();
            await base.DisposeAsync();
        }

        public async Task<string> CreateAdminJwtAsync()
        {
            await using var conn = await _store.OpenAsync();
            string orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
            string adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @adminId",
                new { adminId });
            string jwtSecret = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
                ?? throw new InvalidOperationException("JWT secret not found.");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // now-ok: mints a JWT the host validates against its real clock.
            var now = DateTime.UtcNow;
            var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                claims:
                [
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, adminId),
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti,
                        Guid.NewGuid().ToString("N")),
                    new Claim("org_id", orgId),
                    new Claim("tid", orgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                ],
                notBefore: now,
                expires: now.AddHours(8),
                signingCredentials: creds);
            return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler()
                .WriteToken(token);
        }
    }
}
