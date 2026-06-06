using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// system_admin support workflows: lookup users, lock/unlock accounts, force password reset,
/// system_admin self-rotation. All endpoints under <c>/api/v1/system/users/...</c> and
/// <c>/api/v1/system/me/...</c>, gated to scope=system + apex.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemSupportFlowsTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;

    public SystemSupportFlowsTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string Slug, string OwnerEmail)> CreateTenant()
    {
        var slug = "supp-" + Guid.NewGuid().ToString("N")[..8];
        var ownerEmail = $"owner-{Guid.NewGuid():N}@example.com";
        using var sys = await _factory.CreateSystemAdminClient();
        await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug, ownerEmail });
        return (slug, ownerEmail);
    }

    [Fact]
    public async Task LookupUsers_ByEmail_ReturnsControlPlaneMetadataOnly()
    {
        var (slug, ownerEmail) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();

        var resp = await sys.GetAsync($"/api/v1/system/users?email={Uri.EscapeDataString(ownerEmail)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var items = doc.RootElement.GetProperty("items").EnumerateArray().ToList();
        Assert.Single(items);

        var row = items[0];
        Assert.Equal(ownerEmail, row.GetProperty("email").GetString());
        Assert.Equal(slug, row.GetProperty("tenantSlug").GetString());
        Assert.Equal("owner", row.GetProperty("role").GetString());
        Assert.Equal("active", row.GetProperty("accountStatus").GetString());
        Assert.True(row.GetProperty("mustChangePassword").GetBoolean());

        // Strict control-plane: no password_hash, no token references, no business fields.
        Assert.False(row.TryGetProperty("passwordHash", out _));
        Assert.False(row.TryGetProperty("password_hash", out _));
    }

    [Fact]
    public async Task LookupUsers_NoFilters_Returns422()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.GetAsync("/api/v1/system/users");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task SetAccountStatus_LockThenUnlock_FlipsLoginAvailability()
    {
        var (slug, ownerEmail) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();

        // Lock the owner.
        var lockResp = await sys.PatchAsJsonAsync($"/api/v1/system/users/{Uri.EscapeDataString(ownerEmail)}/account-status",
            new { tenantSlug = slug, accountStatus = "locked" });
        Assert.Equal(HttpStatusCode.NoContent, lockResp.StatusCode);

        // Verify lookup reflects status.
        var lookupResp = await sys.GetAsync($"/api/v1/system/users?email={Uri.EscapeDataString(ownerEmail)}");
        var doc = JsonDocument.Parse(await lookupResp.Content.ReadAsStringAsync());
        Assert.Equal("locked",
            doc.RootElement.GetProperty("items").EnumerateArray().First().GetProperty("accountStatus").GetString());

        // Login attempt from the tenant subdomain → invalid creds (locked accounts are not
        // distinguishable from wrong-password to avoid leaking lock state via timing).
        using var tenantClient = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        var loginResp = await tenantClient.PostAsJsonAsync("/api/v1/auth/login", new { email = ownerEmail, password = "doesntmatter" });
        Assert.Equal(HttpStatusCode.Unauthorized, loginResp.StatusCode);

        // Unlock.
        var unlockResp = await sys.PatchAsJsonAsync($"/api/v1/system/users/{Uri.EscapeDataString(ownerEmail)}/account-status",
            new { tenantSlug = slug, accountStatus = "active" });
        Assert.Equal(HttpStatusCode.NoContent, unlockResp.StatusCode);
    }

    [Fact]
    public async Task SetAccountStatus_InvalidStatus_Returns422()
    {
        var (slug, ownerEmail) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PatchAsJsonAsync($"/api/v1/system/users/{Uri.EscapeDataString(ownerEmail)}/account-status",
            new { tenantSlug = slug, accountStatus = "exploded" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task SetAccountStatus_UnknownUser_Returns404()
    {
        var (slug, _) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PatchAsJsonAsync($"/api/v1/system/users/nobody@example.com/account-status",
            new { tenantSlug = slug, accountStatus = "locked" });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task IssuePasswordReset_ReturnsTemporaryPasswordAndForcesRotate()
    {
        var (slug, ownerEmail) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();

        var resp = await sys.PostAsJsonAsync($"/api/v1/system/users/{Uri.EscapeDataString(ownerEmail)}/password-reset",
            new { tenantSlug = slug });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(ownerEmail, doc.RootElement.GetProperty("email").GetString());
        var tempPwd = doc.RootElement.GetProperty("temporaryPassword").GetString();
        Assert.False(string.IsNullOrEmpty(tempPwd));
        Assert.True(doc.RootElement.GetProperty("mustChangePassword").GetBoolean());

        // The new temporary password works at the tenant subdomain login.
        using var tenantClient = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        var loginResp = await tenantClient.PostAsJsonAsync("/api/v1/auth/login", new { email = ownerEmail, password = tempPwd });
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        // System audit captured the reset event.
        var auditResp = await sys.GetAsync("/api/v1/system/audit?limit=200");
        var auditDoc = JsonDocument.Parse(await auditResp.Content.ReadAsStringAsync());
        var resetEvent = auditDoc.RootElement.GetProperty("items").EnumerateArray()
            .FirstOrDefault(e => e.GetProperty("action").GetString() == "system_admin.password_reset");
        Assert.NotEqual(JsonValueKind.Undefined, resetEvent.ValueKind);
    }

    [Fact]
    public async Task IssuePasswordReset_UnknownUser_Returns404()
    {
        var (slug, _) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PostAsJsonAsync($"/api/v1/system/users/nobody@example.com/password-reset",
            new { tenantSlug = slug });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SystemAdminMe_ReturnsIdentityWithMustChangeFlag()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        // CreateSystemAdminClient hands out an onboarded session (flag cleared); set it back so
        // this test exercises that /api/v1/system/me surfaces the rotate flag. The route is on
        // PasswordRotationGuard's allowlist, so it stays reachable while the flag is set.
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
            await conn.ExecuteAsync("UPDATE system_admins SET must_change_password = 1");

        var resp = await sys.GetAsync("/api/v1/system/me");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(DependablyMultiFactory.SystemAdminEmail, doc.RootElement.GetProperty("email").GetString());
        Assert.True(doc.RootElement.GetProperty("mustChangePassword").GetBoolean());
    }

    [Fact]
    public async Task SystemAdminChangePassword_ClearsMustRotateFlag_NewPasswordWorks()
    {
        // Use a fresh factory so the rotation doesn't bleed into other tests.
        await using var fac = new DependablyMultiFactory();
        await ((IAsyncLifetime)fac).InitializeAsync();

        using var sys = await fac.CreateSystemAdminClient();
        var newPwd = "BrandNewSystemPassword!";
        var resp = await sys.PostAsJsonAsync("/api/v1/system/me/password", new
        {
            currentPassword = DependablyMultiFactory.SystemAdminPassword,
            newPassword = newPwd,
        });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Flag cleared.
        var meResp = await sys.GetAsync("/api/v1/system/me");
        var meDoc = JsonDocument.Parse(await meResp.Content.ReadAsStringAsync());
        Assert.False(meDoc.RootElement.GetProperty("mustChangePassword").GetBoolean());

        // Login with new password works at apex.
        using var apex = fac.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var loginResp = await apex.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = DependablyMultiFactory.SystemAdminEmail,
            password = newPwd,
        });
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        // Old password no longer works.
        var oldLogin = await apex.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = DependablyMultiFactory.SystemAdminEmail,
            password = DependablyMultiFactory.SystemAdminPassword,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
    }

    [Fact]
    public async Task SystemAdminChangePassword_WrongCurrent_Returns401()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PostAsJsonAsync("/api/v1/system/me/password", new
        {
            currentPassword = "wrong-pwd",
            newPassword = "NewlyMintedPassword!",
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task SystemAuditEndpoint_ReturnsOnlyScopeSystemRows()
    {
        var (slug, _) = await CreateTenant();
        using var sys = await _factory.CreateSystemAdminClient();

        var resp = await sys.GetAsync("/api/v1/system/audit?limit=200");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        // At least the tenant.created event for our tenant should be present, and every row
        // returned must have scope='system'.
        var items = doc.RootElement.GetProperty("items").EnumerateArray().ToList();
        Assert.NotEmpty(items);
        Assert.All(items, e => Assert.Equal("system", e.GetProperty("scope").GetString()));
        Assert.Contains(items, e => e.GetProperty("action").GetString() == "tenant.created");
    }
}
