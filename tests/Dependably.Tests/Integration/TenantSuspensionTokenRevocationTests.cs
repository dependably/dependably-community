using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end revocation of a tenant's API credentials when a system operator locks it out
/// (suspends or soft-deletes it) and later restores it. Each token is proven to work before the
/// lockout through the real protocol pipeline, which also fills the service-token resolve cache
/// the way a CI burst does, so a revocation that leaves a cached resolution behind shows up as a
/// 200. The same tokens are refused after the restore on the npm and OCI surfaces; a token issued
/// after the restore works; a reset link and an invite issued before the lockout are dead; and a
/// bystander tenant keeps every token throughout.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantSuspensionTokenRevocationTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    // test-only placeholder password
    private const string TestPassword = "TenantTokenRevoke1!";
    private const string NewPassword = "Zq8-violet-harbour-lantern";

    private readonly DependablyMultiFactory _factory;

    public TenantSuspensionTokenRevocationTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private sealed record TenantUser(string UserId, string OrgId, string Slug, string Email)
    {
        public string Host => $"{Slug}.{DependablyMultiFactory.ApexHost}";
    }

    private sealed record TenantTokens(string Pat, string Service);

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();
    private TokenRepository Tokens => _factory.Services.GetRequiredService<TokenRepository>();

    private async Task<TenantUser> SeedTenantUserAsync()
    {
        string slug = $"ttr-{Guid.NewGuid():N}"[..20];
        string orgId = await OrgSeeder.InsertAsync(Db, slug);
        string email = $"user-{Guid.NewGuid():N}@test.local";
        string userId = await UserSeeder.InsertAsync(Db, orgId, email, password: TestPassword);
        return new TenantUser(userId, orgId, slug, email);
    }

    private async Task<TenantTokens> IssueTokensAsync(TenantUser user)
    {
        var (pat, _) = await Tokens.CreateUserTokenAsync(user.OrgId, user.UserId, Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        // A reader service token, the kind an edge node pulls from its hub with.
        var (service, _) = await Tokens.CreateServiceTokenAsync(user.OrgId, "edge-reader", Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        return new TenantTokens(pat, service);
    }

    private HttpClient CreateClient(string host)
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });
        client.DefaultRequestHeaders.Host = host;
        return client;
    }

    private async Task<HttpStatusCode> GetWithTokenAsync(TenantUser user, string token, string path)
    {
        using var client = CreateClient(user.Host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (await client.GetAsync(path)).StatusCode;
    }

    private Task<HttpStatusCode> WhoAmIAsync(TenantUser user, string token) =>
        GetWithTokenAsync(user, token, "/npm/-/whoami");

    private Task<HttpStatusCode> OciPingAsync(TenantUser user, string token) =>
        GetWithTokenAsync(user, token, "/v2/");

    // ── Operator lifecycle actions ────────────────────────────────────────────

    private async Task SetTenantStatusAsync(TenantUser user, string status)
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PatchAsJsonAsync($"/api/v1/system/tenants/{user.Slug}/status", new { status });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private async Task LockOutAsync(TenantUser user, string lockout)
    {
        if (lockout == "soft-deleted")
        {
            using var sys = await _factory.CreateSystemAdminClient();
            var resp = await sys.DeleteAsync($"/api/v1/system/tenants/{user.Slug}");
            Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        }
        else
        {
            await SetTenantStatusAsync(user, lockout);
        }
    }

    private async Task RestoreAsync(TenantUser user, string lockout, string restoredTo)
    {
        if (lockout == "soft-deleted")
        {
            using var sys = await _factory.CreateSystemAdminClient();
            var resp = await sys.PatchAsync($"/api/v1/system/tenants/{user.Slug}/restore", null);
            Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        }
        else
        {
            await SetTenantStatusAsync(user, restoredTo);
        }
    }

    // ── Lockout then restore ──────────────────────────────────────────────────

    [Theory]
    [InlineData("suspended", "active")]
    [InlineData("suspended", "read_only")]
    [InlineData("soft-deleted", "active")]
    public async Task LockoutThenRestore_RevokesTokensForGood_FreshTokenWorks_OtherTenantsUntouched(
        string lockout, string restoredTo)
    {
        var target = await SeedTenantUserAsync();
        var bystander = await SeedTenantUserAsync();
        var targetTokens = await IssueTokensAsync(target);
        var bystanderTokens = await IssueTokensAsync(bystander);

        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(target, targetTokens.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(target, targetTokens.Service));
        Assert.Equal(HttpStatusCode.OK, await OciPingAsync(target, targetTokens.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(bystander, bystanderTokens.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(bystander, bystanderTokens.Service));

        await LockOutAsync(target, lockout);
        Assert.NotEqual(HttpStatusCode.OK, await WhoAmIAsync(target, targetTokens.Pat));
        await RestoreAsync(target, lockout, restoredTo);

        Assert.Equal(HttpStatusCode.Unauthorized, await WhoAmIAsync(target, targetTokens.Pat));
        Assert.Equal(HttpStatusCode.Unauthorized, await WhoAmIAsync(target, targetTokens.Service));
        Assert.Equal(HttpStatusCode.Unauthorized, await OciPingAsync(target, targetTokens.Pat));
        Assert.Equal(HttpStatusCode.Unauthorized, await OciPingAsync(target, targetTokens.Service));

        var reissued = await IssueTokensAsync(target);
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(target, reissued.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(target, reissued.Service));
        Assert.Equal(HttpStatusCode.OK, await OciPingAsync(target, reissued.Pat));

        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(bystander, bystanderTokens.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(bystander, bystanderTokens.Service));
        Assert.Equal(HttpStatusCode.OK, await OciPingAsync(bystander, bystanderTokens.Pat));
    }

    [Fact]
    public async Task ReadOnly_IsNotALockout_TokensSurviveTheRoundTrip()
    {
        var user = await SeedTenantUserAsync();
        var tokens = await IssueTokensAsync(user);
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(user, tokens.Pat));

        await SetTenantStatusAsync(user, "read_only");
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(user, tokens.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(user, tokens.Service));
        await SetTenantStatusAsync(user, "active");

        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(user, tokens.Pat));
        Assert.Equal(HttpStatusCode.OK, await WhoAmIAsync(user, tokens.Service));
        Assert.Equal(HttpStatusCode.OK, await OciPingAsync(user, tokens.Pat));
    }

    // ── Links and invites issued before the lockout ───────────────────────────

    [Theory]
    [InlineData("suspended")]
    [InlineData("soft-deleted")]
    public async Task ResetLinkIssuedBeforeTheLockout_IsDeadAfterTheRestore(string lockout)
    {
        var user = await SeedTenantUserAsync();
        string link = await _factory.Services.GetRequiredService<PasswordResetTokenRepository>()
            .IssueAsync(user.UserId, user.OrgId);

        await LockOutAsync(user, lockout);
        await RestoreAsync(user, lockout, "active");

        using var client = CreateClient(user.Host);
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password", new { token = link, newPassword = NewPassword });
        Assert.Equal(HttpStatusCode.Gone, resp.StatusCode);

        // The password is unchanged: the old one still signs in.
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = user.Email, password = TestPassword });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("soft-deleted")]
    public async Task InviteSentBeforeTheLockout_CannotBeAcceptedAfterTheRestore(string lockout)
    {
        var admin = await SeedTenantUserAsync();
        string invitee = $"invitee-{Guid.NewGuid():N}@test.local";
        var invite = await _factory.Services.GetRequiredService<InviteRepository>()
            .CreateAsync(admin.OrgId, invitee, admin.UserId);
        Assert.NotNull(invite);

        await LockOutAsync(admin, lockout);
        await RestoreAsync(admin, lockout, "active");

        using var client = CreateClient(admin.Host);
        var resp = await client.PostAsJsonAsync("/api/v1/invites/accept", new { token = invite!.RawToken, password = NewPassword });
        Assert.Equal(HttpStatusCode.Gone, resp.StatusCode);

        await using var conn = await Db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = @orgId AND email = @invitee",
            new { orgId = admin.OrgId, invitee }));
    }

    // ── The operator's audit entry ────────────────────────────────────────────

    [Fact]
    public async Task Suspension_RecordsWhatItRevokedOnTheStatusAuditEntry()
    {
        var user = await SeedTenantUserAsync();
        await IssueTokensAsync(user);

        await SetTenantStatusAsync(user, "suspended");

        await using var conn = await Db.OpenAsync();
        string detail = await conn.QuerySingleAsync<string>(
            "SELECT detail FROM audit_log WHERE scope = 'system' AND action = 'tenant.status_changed' AND org_id = @orgId",
            new { orgId = user.OrgId });
        using var doc = JsonDocument.Parse(detail);
        var revoked = doc.RootElement.GetProperty("revoked");
        Assert.Equal(1, revoked.GetProperty("members").GetInt32());
        Assert.Equal(1, revoked.GetProperty("userTokens").GetInt32());
        Assert.Equal(1, revoked.GetProperty("serviceTokens").GetInt32());
        Assert.Equal(0, revoked.GetProperty("pendingInvites").GetInt32());
    }
}
