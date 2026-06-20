using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using WireMock.Server;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Multi-tenant fixture (<c>DEPLOYMENT_MODE=multi</c>, apex <c>localhost</c>) that additionally
/// wires a WireMock upstream plus permissive SSRF, so tests can exercise per-tenant proxy and
/// passthrough behaviour routed by subdomain <c>Host</c> header.
///
/// <see cref="DependablyMultiFactory"/> has no upstream mock, so it cannot assert the 200 a
/// non-air-gapped tenant serves by reaching upstream; this fixture fills that gap. Each tenant is
/// reached at <c>{slug}.localhost</c>; the apex is <c>localhost</c>.
/// </summary>
public sealed class DependablyMultiUpstreamFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public WireMockServer MockUpstream { get; } = WireMockServer.Start();
    public InMemoryBlobStore BlobStore { get; } = new();
    public const string ApexHost = "localhost";
    public const string SystemAdminEmail = "system@dependably.local";
    // deepcode ignore NoHardcodedCredentials/test: static test-fixture password for a WebApplicationFactory first-boot seed, not a real secret.
    public const string SystemAdminPassword = "TestPassword12345!";

    private const string PullCapabilitiesJson = """["read:artifact","read:metadata"]""";

    private readonly TestMetadataStore _metadataStore = new();

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();

        // Inject DEPLOYMENT_MODE + APEX_HOST + first-boot env BEFORE ConfigureBuilder runs so the
        // resolver registration (which reads DEPLOYMENT_MODE) picks up multi mode.
        builder.Configuration["DEPLOYMENT_MODE"] = "multi";
        builder.Configuration["APEX_HOST"] = ApexHost;
        builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] = SystemAdminEmail;
        builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"] = SystemAdminPassword;

        Program.ConfigureBuilder(builder);

        builder.Services.RemoveAll<IBlobStore>();
        builder.Services.AddSingleton<IBlobStore>(BlobStore);
        builder.Services.RemoveAll<TieredBlobStorage>();
        builder.Services.AddSingleton(new TieredBlobStorage(BlobStore, BlobStore));
        builder.Services.RemoveAll<IMetadataStore>();
        builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

        // Point Upstream URLs at WireMock on loopback; the production SSRF validator and
        // connect-time guard both block 127.0.0.0/8, so swap in permissive variants.
        builder.Services.RemoveAll<IUpstreamUrlValidator>();
        builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();
        builder.Services.RemoveAll<SsrfConnectCallback>();
        builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

        // TestServer leaves Connection.RemoteIpAddress null, which the metrics IP allowlist
        // treats as denied; inject loopback so IP-gated endpoints are reachable.
        builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

        builder.WebHost.UseTestServer();

        builder.WebHost.UseSetting("PyPI:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("Npm:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("NuGet:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
        // TestServer requests share one "unknown" rate-limit partition (no remote IP); keep the
        // shared fixture clear of its own login/anon/management/metadata budgets.
        builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("METADATA_RATE_LIMIT_PERMITS", "100000");

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
        MockUpstream.Stop();
        MockUpstream.Dispose();
        await _metadataStore.DisposeAsync();
        await base.DisposeAsync();
    }

    /// <summary>Returns an HttpClient whose default <c>Host</c> header is <paramref name="host"/>.</summary>
    public HttpClient CreateClientForHost(string host)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Host = host;
        return client;
    }

    /// <summary>Convenience: a subdomain-host client for <c>{slug}.localhost</c>.</summary>
    public HttpClient CreateTenantClient(string slug) => CreateClientForHost($"{slug}.{ApexHost}");

    /// <summary>Issues a system-scoped JWT for the seeded system_admin (apex login realm).</summary>
    public async Task<string> CreateSystemAdminJwt()
    {
        await using var conn = await _metadataStore.OpenAsync();
        string sysId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM system_admins LIMIT 1")
            ?? throw new InvalidOperationException("system_admin not found. Was first-boot run?");
        await conn.ExecuteAsync(
            "UPDATE system_admins SET must_change_password = 0 WHERE id = @sysId", new { sysId });
        string jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its real clock.
        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, sysId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("role", "system_admin"),
                new Claim("scope", "system"),
            },
            notBefore: now,
            expires: now.AddHours(1),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>System-admin Bearer client pinned to the apex host.</summary>
    public async Task<HttpClient> CreateSystemAdminClient()
    {
        string jwt = await CreateSystemAdminJwt();
        var client = CreateClientForHost(ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    /// <summary>Issues a tenant-scoped JWT for a user/tenant pair (default role owner).</summary>
    public async Task<string> CreateTenantJwt(string userId, string tenantId, string role = "owner")
    {
        await using var conn = await _metadataStore.OpenAsync();
        string jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its real clock.
        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("org_id", tenantId),
                new Claim("tid", tenantId),
                new Claim("role", role),
                new Claim("scope", "tenant"),
            },
            notBefore: now,
            expires: now.AddHours(1),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Creates a tenant atomically via the system API and returns its slug, id, and owner user id.
    /// The owner id is read back so callers can mint a tenant-admin JWT for it.
    /// </summary>
    public async Task<(string Slug, string TenantId, string OwnerId)> CreateTenantAsync(string slugPrefix)
    {
        string slug = $"{slugPrefix}-{Guid.NewGuid():N}"[..18];
        using var sys = await CreateSystemAdminClient();
        var resp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slugPrefix}-{Guid.NewGuid():N}@example.com",
        });
        resp.EnsureSuccessStatusCode();
        var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        string tenantId = doc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        await using var conn = await _metadataStore.OpenAsync();
        string ownerId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @tenantId LIMIT 1", new { tenantId })
            ?? throw new InvalidOperationException("owner user missing after tenant creation");

        // The freshly-created owner is flagged must_change_password; clear it so a tenant-admin
        // JWT minted for this owner isn't 403'd by PasswordRotationGuard on /api/v1 calls.
        await conn.ExecuteAsync(
            "UPDATE users SET must_change_password = 0 WHERE id = @ownerId", new { ownerId });

        // Tenants created post-first-boot seed the hard-coded npm default (registry.npmjs.org),
        // not this fixture's WireMock. Repoint npm upstream at the mock so passthrough resolves
        // to a stubbed packument rather than the public registry.
        await conn.ExecuteAsync(
            "UPDATE upstream_registry SET url = @url WHERE org_id = @tenantId AND ecosystem = 'npm'",
            new { url = MockUpstream.Urls[0], tenantId });
        return (slug, tenantId, ownerId);
    }

    /// <summary>Creates a pull-scoped service token (read:artifact + read:metadata) for a tenant.</summary>
    public async Task<string> CreatePullToken(string tenantId)
    {
        var tokens = Services.GetRequiredService<TokenRepository>();
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            tenantId, $"test-pull-{Guid.NewGuid():N}", PullCapabilitiesJson, expiresAt: null);
        return raw;
    }

    private sealed class LoopbackRemoteIpFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (ctx, nextMw) =>
            {
                ctx.Connection.RemoteIpAddress ??= System.Net.IPAddress.Loopback;
                await nextMw();
            });
            next(app);
        };
    }
}
