using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Dapper;
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
using Microsoft.IdentityModel.Tokens;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Integration.OpenApi;

/// <summary>
/// Verifies that the management OpenAPI document (<c>/openapi/management.json</c>)
/// and the management Swagger UI shell (<c>/api/v1/docs/</c>) and its static
/// assets are gated behind the metrics IP allowlist AND an authenticated
/// management session, while the protocol document (<c>/openapi/protocol.json</c>)
/// and protocol UI (<c>/docs/</c>) remain public.
///
/// The mixed scenarios — management gated while protocol stays public under the
/// same restrictive allowlist, and an allowlisted-but-unauthenticated caller
/// still denied while an allowlisted-and-authenticated caller succeeds — are the
/// house-rule partial-failure tests that prove the gate branches on document
/// name / auth state rather than over- or under-blocking.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ManagementDocsGateTests : IAsyncLifetime
{
    // Allowlist that excludes loopback so the test client is denied management
    // docs but the protocol docs are still reachable from the same client.
    private const string NonLoopbackAllowlist = "10.0.0.0/8";

    private readonly BlockedIpFactory _blockedFactory = new();
    private readonly LoopbackFactory _loopbackFactory = new();

    public async Task InitializeAsync()
    {
        await _blockedFactory.InitializeAsync();
        await _loopbackFactory.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _blockedFactory.DisposeAsync();
        await _loopbackFactory.DisposeAsync();
    }

    // ── Non-allowlisted IP: management gated ─────────────────────────────────

    [Fact]
    public async Task ManagementSpec_NonAllowlistedIp_Returns403()
    {
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsShell_NonAllowlistedIp_Returns403()
    {
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsAsset_NonAllowlistedIp_Returns403()
    {
        // Static asset under the management prefix must also be gated.
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/swagger-ui-bundle.js");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Mixed scenario: same non-allowlisted client sees protocol as public ───
    // This is the house-rule partial-failure test: management is blocked while
    // protocol remains accessible in the same restrictive allowlist configuration.

    [Fact]
    public async Task ProtocolSpec_NonAllowlistedIp_Returns200()
    {
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ProtocolDocsShell_NonAllowlistedIp_IsNotForbidden()
    {
        // The protocol Swagger UI (/docs/) must not be blocked by the IP gate.
        // In the test environment the swagger index.html is not present so the
        // shell handler returns 404 (file-not-found) rather than 200 — that is
        // fine: the assertion is that the IP gate does not fire 403, not that
        // the static file exists.
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/docs/");
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Loopback, no session: management still denied ────────────────────────
    // The IP allowlist alone is not sufficient — a caller inside the allowlist
    // with no authenticated management session must not be able to read the
    // control-plane API contract. This is the regression pin for the finding:
    // it fails against the IP-allowlist-only gate and passes once an
    // authenticated session is required in addition to the allowlist.

    [Fact]
    public async Task ManagementSpec_LoopbackIpNoSession_Returns401()
    {
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsShell_LoopbackIpNoSession_Returns401()
    {
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsAsset_LoopbackIpNoSession_Returns401()
    {
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/swagger-ui-bundle.js");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Loopback (default allowlist) + authenticated session: management accessible ──
    // Regression guard: an allowlisted caller who also holds a valid management
    // session (the only path a real operator uses) still reaches management docs.

    [Fact]
    public async Task ManagementSpec_LoopbackIpWithSession_Returns200()
    {
        using var client = _loopbackFactory.CreateClient();
        string jwt = await _loopbackFactory.CreateAdminJwtAsync();
        var req = new HttpRequestMessage(HttpMethod.Get, "/openapi/management.json");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsShell_LoopbackIpWithSession_IsNotForbiddenOrUnauthorized()
    {
        // From an allowlisted IP with a valid session the gate must not fire. The
        // shell handler returns 404 in the test environment (no swagger index.html)
        // rather than 200 — the assertion is that neither the IP gate nor the
        // session gate produces 403/401.
        using var client = _loopbackFactory.CreateClient();
        string jwt = await _loopbackFactory.CreateAdminJwtAsync();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/docs/");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        var resp = await client.SendAsync(req);
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ProtocolSpec_LoopbackIp_Returns200()
    {
        // Protocol document carries neither the IP nor the session gate.
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Factory: loopback IP, default allowlist (127.0.0.1/::1) ─────────────

    private sealed class LoopbackFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly InMemoryBlobStore _blob = new();
        private readonly TestMetadataStore _metadataStore = new();

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

            // Inject loopback as the connection IP — default allowlist (127.0.0.1/::1)
            // permits it, so management docs are reachable.
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }
        public new async Task DisposeAsync() { await _metadataStore.DisposeAsync(); await base.DisposeAsync(); }

        /// <summary>
        /// Issues a tenant-scoped JWT for the seeded bootstrap owner, matching the
        /// shape <c>HasAuthenticatedManagementSession</c> in <c>Program.cs</c> requires
        /// (a validated JWT carrying <c>scope=tenant</c> or <c>scope=system</c>).
        /// </summary>
        public async Task<string> CreateAdminJwtAsync()
        {
            await using var conn = await _metadataStore.OpenAsync();

            string orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");

            string adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found. Was first-boot run?");

            string jwtSecret = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
                ?? throw new InvalidOperationException("JWT secret not found.");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // now-ok: mints a JWT the host validates against its (default: real) clock.
            var now = DateTime.UtcNow;

            var token = new JwtSecurityToken(
                issuer: Dependably.Security.JwtTokenBinding.Issuer,
                audience: Dependably.Security.JwtTokenBinding.SessionAudience,
                claims: new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, adminId),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                    new Claim("org_id", orgId),
                    new Claim("tid", orgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                },
                notBefore: now,
                expires: now.AddHours(8),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private sealed class LoopbackRemoteIpFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
                => app =>
                {
                    app.Use(async (ctx, n) => { ctx.Connection.RemoteIpAddress = IPAddress.Loopback; await n(); });
                    next(app);
                };
        }
    }

    // ── Factory: loopback IP, allowlist excludes loopback ────────────────────
    // Management docs are blocked; protocol docs remain public.

    private sealed class BlockedIpFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly InMemoryBlobStore _blob = new();
        private readonly TestMetadataStore _metadataStore = new();

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

            // Inject loopback as the connection IP, but restrict the allowlist
            // to a CIDR that excludes loopback — so management docs return 403
            // while protocol docs (no IP gate) return 200.
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("METRICS_ALLOWED_IPS", NonLoopbackAllowlist);
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }
        public new async Task DisposeAsync() { await _metadataStore.DisposeAsync(); await base.DisposeAsync(); }

        private sealed class LoopbackRemoteIpFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
                => app =>
                {
                    app.Use(async (ctx, n) => { ctx.Connection.RemoteIpAddress = IPAddress.Loopback; await n(); });
                    next(app);
                };
        }
    }
}
