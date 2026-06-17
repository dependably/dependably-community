using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Multi-tenant test fixture. Configures <c>DEPLOYMENT_MODE=multi</c> and pins the apex host to
/// <c>localhost</c> so the in-process TestServer can simulate apex-vs-subdomain routing via the
/// <c>Host</c> header on each request:
///
///   - Apex hits:        <c>Host: localhost</c>          → TenantContext.Apex
///   - Tenant subdomain: <c>Host: acme.localhost</c>    → TenantContext.ForTenant(...)
///
/// Unlike single-mode <see cref="DependablyFactory"/>, multi-mode FirstBoot creates only the
/// system_admin (no default tenant). Tenants are created by tests as needed.
/// </summary>
public sealed class DependablyMultiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public InMemoryBlobStore BlobStore { get; } = new();
    public const string ApexHost = "localhost";
    public const string SystemAdminEmail = "system@dependably.local";
    public const string SystemAdminPassword = "TestPassword12345!";

    private readonly TestMetadataStore _metadataStore = new();

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();

        // Inject DEPLOYMENT_MODE + APEX_HOST + first-boot env BEFORE ConfigureBuilder runs so
        // the resolver registration (which reads DEPLOYMENT_MODE) picks up multi mode.
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

        builder.WebHost.UseTestServer();
        builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
        // TestServer requests share one "unknown" rate-limit partition (no remote IP);
        // keep shared-fixture tests out of each other's login/anon/management budgets.
        builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

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

    /// <summary>
    /// Returns an HttpClient whose default <c>Host</c> header is <paramref name="host"/>. Use
    /// <c>localhost</c> for apex hits and <c>{slug}.localhost</c> for tenant hits.
    /// </summary>
    public HttpClient CreateClientForHost(string host)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Host = host;
        return client;
    }

    /// <summary>
    /// Issues a system-scoped JWT for the seeded system_admin (apex login realm).
    /// </summary>
    public async Task<string> CreateSystemAdminJwt()
    {
        await using var conn = await _metadataStore.OpenAsync();
        string sysId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM system_admins LIMIT 1")
            ?? throw new InvalidOperationException("system_admin not found. Was first-boot run?");
        // Onboarded-admin session: clear the first-boot must_change_password flag so
        // PasswordRotationGuard doesn't 403 non-allowlisted /api/v1/system calls.
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

    /// <summary>
    /// Issues a tenant-scoped JWT for an arbitrary user/tenant pair (used for cross-realm tests).
    /// </summary>
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
    /// Creates an authenticated HttpClient for the system_admin, with the apex host header.
    /// </summary>
    public async Task<HttpClient> CreateSystemAdminClient()
    {
        string jwt = await CreateSystemAdminJwt();
        var client = CreateClientForHost(ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }
}
