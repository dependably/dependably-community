using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Integration;

/// <summary>
/// Asserts that IP-denied requests to <c>/metrics</c> and <c>/version</c> write
/// exactly one audit row per 10-minute cooldown window (coalesced), and that
/// <c>GET .../metrics-access</c> surfaces the denied IP in <c>recentDeniedIps</c>.
///
/// <para>Two factory variants exercise the two scope paths:</para>
/// <list type="bullet">
///   <item><see cref="SystemScopeAuditFactory"/> — multi-mode, apex host → scope='system', org_id=NULL.</item>
///   <item><see cref="TenantScopeAuditFactory"/> — single-mode → scope='tenant', org_id set.</item>
/// </list>
/// </summary>
[Trait("Category", "Integration")]
public sealed class MetricsScrapeDeniedAuditSystemScopeTests : IAsyncLifetime
{
    private readonly SystemScopeAuditFactory _factory = new();

    public Task InitializeAsync() => _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── Coalescing: system scope ─────────────────────────────────────────────

    [Fact]
    public async Task DeniedMetrics_WritesOneAuditRow_SystemScope()
    {
        // Apex host → TenantContext.Apex → scope='system'.
        using var client = _factory.CreateBlockedApexClient();

        var resp = await client.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);

        await using var conn = await _factory.Db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND scope = 'system'");
        Assert.Equal(1L, count);
    }

    [Fact]
    public async Task DeniedMetrics_Burst_WritesOnlyOneAuditRow_SystemScope()
    {
        // Several denials from the same IP on the apex surface within the cooldown
        // window must produce exactly one audit row — the burst is coalesced.
        using var client = _factory.CreateBlockedApexClient();

        for (int i = 0; i < 5; i++)
        {
            var r = await client.GetAsync("/metrics");
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }

        await using var conn = await _factory.Db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND scope = 'system'");
        Assert.Equal(1L, count);
    }

    [Fact]
    public async Task DeniedMetrics_WritesCorrectFields_SystemScope()
    {
        using var client = _factory.CreateBlockedApexClient();

        await client.GetAsync("/metrics");

        await using var conn = await _factory.Db.OpenAsync();
        var (action, scope, orgId, sourceIp, detail) = await conn.QuerySingleOrDefaultAsync<(string Action, string Scope, string? OrgId, string? SourceIp, string? Detail)>(
            """
            SELECT action, scope, org_id, source_ip, detail
            FROM audit_log
            WHERE action = 'metrics.scrape_denied' AND scope = 'system'
            LIMIT 1
            """);

        Assert.Equal("metrics.scrape_denied", action);
        Assert.Equal("system", scope);
        Assert.Null(orgId);
        // IP from LoopbackRemoteIpFilter, normalized to dotted-quad.
        Assert.Equal("127.0.0.1", sourceIp);
        // Detail JSON must carry endpoint and reason.
        Assert.NotNull(detail);
        var detailDoc = JsonDocument.Parse(detail!).RootElement;
        Assert.Equal("/metrics", detailDoc.GetProperty("endpoint").GetString());
        Assert.Equal("denied_ip", detailDoc.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task DeniedVersion_WritesOneAuditRow_SystemScope()
    {
        using var client = _factory.CreateBlockedApexClient();

        var resp = await client.GetAsync("/version");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);

        await using var conn = await _factory.Db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND scope = 'system'");
        Assert.Equal(1L, count);
    }

    [Fact]
    public async Task DeniedMetricsAndVersion_WriteDistinctAuditRows_BecauseEndpointDiffers()
    {
        // /metrics and /version have distinct cooldown keys (endpoint is part of the key).
        // A denial on each produces two audit rows — one per endpoint.
        using var client = _factory.CreateBlockedApexClient();

        await client.GetAsync("/metrics");
        await client.GetAsync("/version");

        await using var conn = await _factory.Db.OpenAsync();
        long metricsCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND detail LIKE '%/metrics%'");
        long versionCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND detail LIKE '%/version%'");
        Assert.Equal(1L, metricsCount);
        Assert.Equal(1L, versionCount);
    }

    // ── recentDeniedIps surface ───────────────────────────────────────────────

    [Fact]
    public async Task GetSystemMetricsAccess_ReturnsRecentDeniedIp_AfterDenial()
    {
        using var blockedClient = _factory.CreateBlockedApexClient();
        var denyResp = await blockedClient.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, denyResp.StatusCode);

        // GET /api/v1/system/metrics-access as the system_admin.
        using var adminClient = await _factory.CreateSystemAdminClientAsync();
        var resp = await adminClient.GetAsync("/api/v1/system/metrics-access");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(json.TryGetProperty("recentDeniedIps", out var denied));
        var ips = denied.EnumerateArray().Select(e => e.GetProperty("ip").GetString()).ToList();
        Assert.Contains("127.0.0.1", ips);
    }

    // ── Mixed partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task MixedRequests_AllowedAndDenied_RingBufferRecordsAllDenialsAuditCoalesces()
    {
        // Mix of denials. The allowed IPs are 10.0.0.0/8; loopback 127.0.0.1 is always
        // denied. Several denials within the cooldown window → exactly 1 audit row but
        // all entries recorded in the ring buffer's lifetime counter.
        using var blockedClient = _factory.CreateBlockedApexClient();

        for (int i = 0; i < 3; i++)
        {
            var r = await blockedClient.GetAsync("/metrics");
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }

        await using var conn = await _factory.Db.OpenAsync();
        long auditRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied'");
        // Exactly 1 audit row — the burst is coalesced.
        Assert.Equal(1L, auditRows);

        // ScrapeDiagnostics ring buffer records all 3 attempts (not coalesced at this layer).
        var diag = _factory.Services.GetRequiredService<ScrapeDiagnostics>();
        var (_, deniedIpTotal, _) = diag.LifetimeCounts();
        Assert.True(deniedIpTotal >= 3,
            $"Expected at least 3 DeniedIp entries in ring buffer; got {deniedIpTotal}");
    }
}

/// <summary>
/// Tenant-scope variant: single-mode factory where all requests land on the one
/// default tenant (<see cref="SingleTenantResolver"/> returns <c>TenantContext.ForTenant</c>)
/// so denials are audited with scope='tenant' and the tenant's org_id.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MetricsScrapeDeniedAuditTenantScopeTests : IAsyncLifetime
{
    private readonly TenantScopeAuditFactory _factory = new();

    public Task InitializeAsync() => _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task DeniedMetrics_WritesTenantScopeAuditRow()
    {
        // Single-mode: every request is resolved to the single default tenant.
        // scope='tenant', org_id = default tenant's id.
        using var client = _factory.CreateBlockedClient();
        var resp = await client.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);

        await using var conn = await _factory.Db.OpenAsync();
        var (scope, orgId, sourceIp) = await conn.QuerySingleOrDefaultAsync<(string Scope, string? OrgId, string? SourceIp)>(
            """
            SELECT scope, org_id, source_ip
            FROM audit_log
            WHERE action = 'metrics.scrape_denied'
            LIMIT 1
            """);

        Assert.Equal("tenant", scope);
        // org_id must be the default tenant, not null.
        Assert.NotNull(orgId);
        Assert.Equal("127.0.0.1", sourceIp);
    }

    [Fact]
    public async Task DeniedMetrics_TenantBurst_WritesOnlyOneAuditRow()
    {
        // Multiple denials within the cooldown window produce exactly one audit row.
        using var client = _factory.CreateBlockedClient();

        for (int i = 0; i < 4; i++)
        {
            var r = await client.GetAsync("/metrics");
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }

        await using var conn = await _factory.Db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND scope = 'tenant'");
        Assert.Equal(1L, count);
    }

    [Fact]
    public async Task GetInstanceMetricsAccess_ReturnsRecentDeniedIp_AfterDenial()
    {
        using var blockedClient = _factory.CreateBlockedClient();
        var denyResp = await blockedClient.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, denyResp.StatusCode);

        using var adminClient = await _factory.CreateAdminClientAsync();
        var resp = await adminClient.GetAsync("/api/v1/instance/metrics-access");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(json.TryGetProperty("recentDeniedIps", out var denied));
        var ips = denied.EnumerateArray().Select(e => e.GetProperty("ip").GetString()).ToList();
        Assert.Contains("127.0.0.1", ips);
    }

    [Fact]
    public async Task MixedRequests_TenantDenials_AuditCoalesced_RingBufferFull()
    {
        // Mixed partial-failure scenario: some requests from a blocked IP (loopback),
        // verify audit coalescing while ring buffer records all.
        using var blockedClient = _factory.CreateBlockedClient();

        // Three denied requests.
        for (int i = 0; i < 3; i++)
        {
            var r = await blockedClient.GetAsync("/metrics");
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }

        await using var conn = await _factory.Db.OpenAsync();
        long denied = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'metrics.scrape_denied' AND scope = 'tenant'");
        // Exactly 1 audit row — burst coalesced.
        Assert.Equal(1L, denied);

        var diag = _factory.Services.GetRequiredService<ScrapeDiagnostics>();
        var (_, deniedIpTotal, _) = diag.LifetimeCounts();
        Assert.True(deniedIpTotal >= 3,
            $"Ring buffer expected >= 3 DeniedIp; got {deniedIpTotal}");
    }
}

// ── Factories ─────────────────────────────────────────────────────────────────

/// <summary>
/// Multi-mode factory: DEPLOYMENT_MODE=multi, BASE_URL=http://localhost (apex=localhost),
/// loopback IP injected, allowlist set to 10.0.0.0/8 (excludes loopback). Requests via
/// the apex host produce scope='system' audit rows. Exposes a <see cref="FakeTimeProvider"/>
/// so the cooldown window can be advanced in tests that need to reset it.
/// </summary>
internal sealed class SystemScopeAuditFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly InMemoryBlobStore _blob = new();
    private readonly TestMetadataStore _metadataStore = new();
    public readonly FakeTimeProvider Clock = new(new DateTimeOffset(2026, 6, 15, 10, 0, 0, TimeSpan.Zero));

    public const string ApexHost = "localhost";
    public const string SystemAdminEmail = "sysadmin@scrapeaudit.local";
    // deepcode ignore NoHardcodedCredentials: static test-fixture password for a WebApplicationFactory seed, not a real secret
    public const string SystemAdminPassword = "TestPassword12345!";

    public IMetadataStore Db => _metadataStore;

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();

        builder.Configuration["DEPLOYMENT_MODE"] = "multi";
        builder.Configuration["BASE_URL"] = $"http://{ApexHost}";
        builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] = SystemAdminEmail;
        builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"] = SystemAdminPassword;

        Program.ConfigureBuilder(builder);

        builder.Services.RemoveAll<IBlobStore>();
        builder.Services.AddSingleton<IBlobStore>(_blob);
        builder.Services.RemoveAll<TieredBlobStorage>();
        builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
        builder.Services.RemoveAll<IMetadataStore>();
        builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

        // Freeze time so the cooldown gate is deterministic.
        builder.Services.RemoveAll<TimeProvider>();
        builder.Services.AddSingleton<TimeProvider>(Clock);

        builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

        builder.WebHost.UseTestServer();
        builder.WebHost.UseSetting("METRICS_ALLOWED_IPS", "10.0.0.0/8");
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
        await _metadataStore.DisposeAsync();
        await base.DisposeAsync();
    }

    /// <summary>
    /// Returns a client with loopback IP (127.0.0.1) and the apex Host header.
    /// Loopback is outside 10.0.0.0/8, so requests are denied (403).
    /// Apex host → TenantContext.Apex → scope='system'.
    /// </summary>
    public HttpClient CreateBlockedApexClient()
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Host = ApexHost;
        return client;
    }

    /// <summary>Returns an authenticated HttpClient for the system_admin.</summary>
    public async Task<HttpClient> CreateSystemAdminClientAsync()
    {
        string jwt = await IssueSystemAdminJwtAsync();
        var client = CreateClient();
        client.DefaultRequestHeaders.Host = ApexHost;
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private async Task<string> IssueSystemAdminJwtAsync()
    {
        await using var conn = await _metadataStore.OpenAsync();
        string sysId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM system_admins LIMIT 1")
            ?? throw new InvalidOperationException("system_admin not seeded.");
        await conn.ExecuteAsync(
            "UPDATE system_admins SET must_change_password = 0 WHERE id = @sysId", new { sysId });
        string jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing");

        var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its real clock.
        var now = DateTime.UtcNow;
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: new[]
            {
                new System.Security.Claims.Claim(
                    System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, sysId),
                new System.Security.Claims.Claim(
                    System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new System.Security.Claims.Claim("role", "system_admin"),
                new System.Security.Claims.Claim("scope", "system"),
            },
            notBefore: now,
            expires: now.AddHours(1),
            signingCredentials: creds);
        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
    }

    private sealed class LoopbackRemoteIpFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress = IPAddress.Loopback;
                    await n();
                });
                next(app);
            };
    }
}

/// <summary>
/// Single-mode factory with METRICS_ALLOWED_IPS=10.0.0.0/8 and loopback IP injected.
/// In single-mode, <see cref="SingleTenantResolver"/> resolves every request to the
/// one default tenant, so denials are audited with scope='tenant'.
/// </summary>
internal sealed class TenantScopeAuditFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly InMemoryBlobStore _blob = new();
    private readonly TestMetadataStore _metadataStore = new();
    public readonly FakeTimeProvider Clock = new(new DateTimeOffset(2026, 6, 15, 10, 0, 0, TimeSpan.Zero));

    public IMetadataStore Db => _metadataStore;

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();
        Program.ConfigureBuilder(builder);

        builder.Services.RemoveAll<IBlobStore>();
        builder.Services.AddSingleton<IBlobStore>(_blob);
        builder.Services.RemoveAll<TieredBlobStorage>();
        builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
        builder.Services.RemoveAll<IMetadataStore>();
        builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

        builder.Services.RemoveAll<TimeProvider>();
        builder.Services.AddSingleton<TimeProvider>(Clock);

        builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

        builder.WebHost.UseTestServer();
        builder.WebHost.UseSetting("METRICS_ALLOWED_IPS", "10.0.0.0/8");
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
        await _metadataStore.DisposeAsync();
        await base.DisposeAsync();
    }

    /// <summary>Returns a client with loopback IP — outside the 10.0.0.0/8 allowlist → denied.</summary>
    public HttpClient CreateBlockedClient() => CreateClient();

    /// <summary>Returns a JWT-authenticated HttpClient for the seeded bootstrap admin.</summary>
    public async Task<HttpClient> CreateAdminClientAsync()
    {
        await using var conn = await _metadataStore.OpenAsync();

        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        string adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found.");
        await conn.ExecuteAsync(
            "UPDATE users SET must_change_password = 0 WHERE id = @adminId", new { adminId });
        string jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
            ?? throw new InvalidOperationException("JWT secret not found.");

        var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its real clock.
        var now = DateTime.UtcNow;
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: new[]
            {
                new System.Security.Claims.Claim(
                    System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, adminId),
                new System.Security.Claims.Claim(
                    System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new System.Security.Claims.Claim("org_id", orgId),
                new System.Security.Claims.Claim("tid", orgId),
                new System.Security.Claims.Claim("role", "owner"),
                new System.Security.Claims.Claim("scope", "tenant"),
            },
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);
        string jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);

        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private sealed class LoopbackRemoteIpFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress = IPAddress.Loopback;
                    await n();
                });
                next(app);
            };
    }
}
