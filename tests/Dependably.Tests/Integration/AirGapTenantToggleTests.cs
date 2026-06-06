using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Dependably.Storage;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the per-tenant air-gap toggle: PUT/GET /api/v1/settings,
/// the tenant.setting.change audit, the proxy-passthrough 404 for an uncached upstream
/// package while air-gapped (npm + PyPI), and the multi-tenant property that one tenant's
/// air-gap does not affect another. A second class boots the instance with AIR_GAPPED=true
/// to assert the enforced posture surfaces in the GET.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AirGapTenantToggleTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public AirGapTenantToggleTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminJwtClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task SetDefaultAirGapped(bool on)
    {
        using var admin = await AdminJwtClient();
        var resp = await admin.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true,
            allowlistMode = false,
            airGapped = on,
        });
        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task PutThenGet_AirGapped_PersistsAndAuditsTenantSettingChange()
    {
        using var client = await AdminJwtClient();

        // Start from a known-off state so the toggle change is observable + audited.
        (await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true, allowlistMode = false, airGapped = false,
        })).EnsureSuccessStatusCode();

        var put = await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true, allowlistMode = false, airGapped = true,
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var get = await client.GetAsync("/api/v1/settings");
        get.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.True(doc.GetProperty("airGapped").GetBoolean());
        // Instance AIR_GAPPED is not set on the shared factory → not enforced.
        Assert.False(doc.GetProperty("airGappedEnforced").GetBoolean());

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'tenant.setting.change' AND detail LIKE '%air_gapped%' ORDER BY created_at DESC LIMIT 1");
        Assert.False(string.IsNullOrEmpty(detail));
        Assert.Contains("\"new_value\":true", detail);

        // Reset so other tests on the shared factory aren't left air-gapped.
        await SetDefaultAirGapped(false);
    }

    [Fact]
    public async Task NpmMetadata_AirGapped_UncachedUpstreamReturns404_EvenWhenUpstreamHasIt()
    {
        var pkg = $"airgap-npm-{Guid.NewGuid():N}";
        StubNpmPackument(pkg);

        try
        {
            await SetDefaultAirGapped(true);

            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);
            var resp = await client.GetAsync($"/npm/{pkg}");
            // Upstream WOULD serve it, but air-gap forces passthrough off → not found.
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetDefaultAirGapped(false);
        }
    }

    [Fact]
    public async Task PyPiSimpleIndex_AirGapped_UncachedUpstreamReturns404_EvenWhenUpstreamHasIt()
    {
        var name = $"airgap-pypi-{Guid.NewGuid():N}";
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<!DOCTYPE html><html><body><a href=\"https://files.pythonhosted.org/packages/aa/bb/{name}-1.0.0.tar.gz#sha256=cafe\">{name}-1.0.0.tar.gz</a></body></html>"));

        try
        {
            await SetDefaultAirGapped(true);

            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetDefaultAirGapped(false);
        }
    }

    [Fact]
    public async Task MultiTenant_OneAirGapped_OtherUnaffected()
    {
        var pkg = $"airgap-multi-{Guid.NewGuid():N}";
        StubNpmPackument(pkg);

        // A second org that is NOT air-gapped.
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var other = await orgs.CreateOrgAsync($"other-{Guid.NewGuid():N}"[..18]);

        try
        {
            await SetDefaultAirGapped(true);

            // Default (air-gapped) tenant: passthrough off → 404 for the uncached package.
            var defaultToken = await _factory.CreateToken("pull");
            using (var c1 = _factory.CreateClientWithBearer(defaultToken))
            {
                var r1 = await c1.GetAsync($"/npm/{pkg}");
                Assert.Equal(HttpStatusCode.NotFound, r1.StatusCode);
            }

            // Second tenant: not air-gapped → passthrough reaches upstream and serves the
            // package (200), in contrast to the air-gapped tenant's 404 above. The status
            // contrast is the per-tenant-isolation signal.
            var otherToken = await _factory.CreateToken("pull", other.Slug);
            using (var c2 = _factory.CreateClientWithBearer(otherToken))
            {
                var r2 = await c2.GetAsync($"/o/{other.Slug}/npm/{pkg}");
                Assert.Equal(HttpStatusCode.OK, r2.StatusCode);
            }
        }
        finally
        {
            await SetDefaultAirGapped(false);
        }
    }

    // Stubs the upstream npm packument so a connected tenant's metadata GET resolves to 200.
    private void StubNpmPackument(string pkg)
    {
        var packument = JsonSerializer.Serialize(new
        {
            name = pkg,
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new
                {
                    name = pkg,
                    version = "1.0.0",
                    dist = new { tarball = $"{_factory.MockUpstream.Urls[0]}/{pkg}/-/{pkg}-1.0.0.tgz" },
                },
            },
        });
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{pkg}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(packument));
    }
}

/// <summary>
/// Boots the instance with AIR_GAPPED=true and asserts GET /api/v1/settings reports
/// airGappedEnforced:true so the UI can render the toggle checked + read-only.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AirGapEnforcedSettingsTests : IAsyncLifetime
{
    private readonly EnforcedAirGapFactory _factory = new();

    public Task InitializeAsync() => _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task GetSettings_InstanceAirGapped_ReportsEnforced()
    {
        var jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/settings");
        resp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(doc.GetProperty("airGappedEnforced").GetBoolean());
    }

    /// <summary>
    /// Mirror of DependablyFactory but with AIR_GAPPED=true. Exposes CreateAdminJwt via the
    /// same JWT-minting path the base factory uses.
    /// </summary>
    private sealed class EnforcedAirGapFactory : WebApplicationFactory<Program>, IAsyncLifetime
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

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("AIR_GAPPED", "true");
            builder.WebHost.UseSetting("OSV_MODE", "local");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

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

        public async Task<string> CreateAdminJwt()
        {
            await using var conn = await _metadataStore.OpenAsync();
            var orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
            var adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");
            // Onboarded-admin session: clear the first-boot must_change_password flag so
            // PasswordRotationGuard doesn't 403 non-allowlisted /api/v1 calls.
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @adminId", new { adminId });
            var jwtSecret = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
                ?? throw new InvalidOperationException("JWT secret not found.");

            var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(jwtSecret));
            var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
            var now = DateTime.UtcNow;
            var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                claims: new[]
                {
                    new System.Security.Claims.Claim("sub", adminId),
                    new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString("N")),
                    new System.Security.Claims.Claim("org_id", orgId),
                    new System.Security.Claims.Claim("tid", orgId),
                    new System.Security.Claims.Claim("role", "owner"),
                    new System.Security.Claims.Claim("scope", "tenant"),
                },
                notBefore: now,
                expires: now.AddHours(8),
                signingCredentials: creds);
            return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
