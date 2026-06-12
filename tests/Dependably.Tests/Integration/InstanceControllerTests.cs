using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Single-tenant mode coverage for /api/v1/instance/settings and
/// /api/v1/instance/background-jobs. In single mode the tenant owner is
/// also the operator, so these routes must remain accessible.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public InstanceControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task Anonymous_Get_Returns401Or404()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Member_Get_Returns403()
    {
        // tenant:admin is owner-only; a plain member is rejected even though authenticated.
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_GetSettings_Returns200WithDictionary_AndOmitsJwtSecret()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);

        // jwt_secret is filtered from the public response — checking the field is missing
        // pins that the controller never accidentally surfaces it.
        Assert.False(doc.RootElement.TryGetProperty("jwt_secret", out _));
    }

    [Fact]
    public async Task Admin_UpdateSettings_PersistsAndAudits()
    {
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "1048576",
            ["max_upload_bytes_npm"] = "524288",
        });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Verify the rows landed.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? value = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes' LIMIT 1");
        Assert.Equal("1048576", value);

        // Audit row recorded for the change.
        long audited = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'instance_settings_updated'");
        Assert.True(audited >= 1);
    }

    [Fact]
    public async Task Admin_UpdateSettings_RejectsUnknownKey()
    {
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string> { ["totally_unknown"] = "nope" });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        string detail = await resp.Content.ReadAsStringAsync();
        Assert.Contains("totally_unknown", detail);
    }
}

/// <summary>
/// Multi-tenant mode coverage for /api/v1/instance/*. In multi mode these are
/// control-plane endpoints owned by the operator, not tenants. A tenant owner — even
/// with the <c>tenant:admin</c> capability — must receive 404, matching the project's
/// 404-on-unauthorized invariant. The system realm counterparts remain accessible to the
/// system_admin at /api/v1/system/settings and /api/v1/system/background-jobs.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceControllerMultiModeTests
    : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public InstanceControllerMultiModeTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Creates a tenant via the system surface and returns a JWT for its owner, plus the
    /// subdomain host used to reach the tenant. The owner has <c>tenant:admin</c> capability
    /// (role=owner), which would normally be sufficient for single-mode instance-settings access.
    /// </summary>
    private async Task<(string ownerJwt, string tenantHost)> CreateTenantOwnerAsync()
    {
        string slug = "im-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await _factory.CreateSystemAdminClient();
        var createResp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, createResp.StatusCode);

        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string tenantId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        string ownerId;
        await using (var conn = await _factory.Services
            .GetRequiredService<IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @tenantId LIMIT 1",
                new { tenantId })
                ?? throw new InvalidOperationException("owner user missing");

            // Clear the first-boot must_change_password flag so PasswordRotationGuard
            // doesn't intercept the request with 403 before the controller gate is reached.
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @ownerId",
                new { ownerId });
        }

        string jwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId, role: "owner");
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        return (jwt, host);
    }

    // ── Multi mode: tenant owner cannot reach instance-settings endpoints ────

    [Fact]
    public async Task MultiMode_TenantOwner_GetSettings_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/settings");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_PutSettings_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "999999",
        });
        var resp = await client.PutAsync("/api/v1/instance/settings", body);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_GetBackgroundJobs_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/background-jobs");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Multi mode: system_admin still reaches the system-realm equivalents ──

    [Fact]
    public async Task MultiMode_SystemAdmin_GetSystemSettings_Returns200()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var resp = await client.GetAsync("/api/v1/system/settings");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public async Task MultiMode_SystemAdmin_PutSystemSettings_Persists()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "2097152",
        });
        var putResp = await client.PutAsync("/api/v1/system/settings", body);
        Assert.Equal(HttpStatusCode.NoContent, putResp.StatusCode);

        // Verify the value persisted.
        await using var conn = await _factory.Services
            .GetRequiredService<IMetadataStore>().OpenAsync();
        string? value = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes' LIMIT 1");
        Assert.Equal("2097152", value);
    }
}
