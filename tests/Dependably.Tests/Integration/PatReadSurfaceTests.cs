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
/// Covers the API-token (PAT) read-only management surface: read GETs across
/// OrgController, VulnerabilityController, SearchController, OrgAuditController,
/// OrgSettingsController, QuarantineController, and AuthController.Me now accept the
/// ApiToken scheme in addition to a JWT session, gated by the matching read:* capability.
/// Also covers the three blockers that made the surface a dead letter for automation before
/// this change: service/CI tokens 404ing on every capability-gated route (no users-table
/// row), require_mfa orgs 403ing token principals, and read:* not being mintable.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PatReadSurfaceTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public PatReadSurfaceTests(DependablyFactory factory) => _factory = factory;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private async Task<HttpClient> AdminJwtClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private HttpClient BearerClient(string token)
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    /// <summary>Mints a service/CI token (no users-table row) with an explicit capability set.</summary>
    private async Task<string> CreateServiceToken(string capabilitiesJson, string org = "default")
    {
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var orgRecord = await orgs.GetBySlugAsync(org)
            ?? throw new InvalidOperationException($"Org '{org}' not found.");
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            orgRecord.Id, $"test-svc-{Guid.NewGuid():N}", capabilitiesJson, expiresAt: null);
        return raw;
    }

    // ── read:packages (OrgController, VulnerabilityController, SearchController) ──────────

    [Fact]
    public async Task ListPackages_UserPatWithReadPackages_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ListPackages_UserPatWithoutReadPackages_Returns403()
    {
        // Carries a different read leaf only — proves the capability gate, not just the scheme.
        string pat = await _factory.CreateAdminUserToken("""["read:audit"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ListPackages_ServiceTokenWithReadPackages_Returns200()
    {
        // Fix 1: a service token's `sub` is the token's own id, not a users-table row — before
        // the OrgAccessGuard fallback this 404'd every capability-gated management route.
        string svc = await CreateServiceToken("""["read:packages"]""");
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Search_UserPatWithReadPackages_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/search?q=ac");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task VulnReport_UserPatWithReadPackages_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/vuln-report");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── read:audit (OrgAuditController) ───────────────────────────────────────────────────

    [Fact]
    public async Task GetActivity_UserPatWithReadAudit_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:audit"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/activity");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task GetAudit_ServiceTokenWithReadAudit_Returns200()
    {
        string svc = await CreateServiceToken("""["read:audit"]""");
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/audit");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── read:tenant (OrgSettingsController, QuarantineController, AuthController.Me) ─────

    [Fact]
    public async Task GetOrgSettings_UserPatWithReadTenant_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:tenant"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task QuarantineList_UserPatWithReadTenant_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:tenant"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/quarantine");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task AuthMe_UserPatWithReadTenant_Returns200()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:tenant"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task AuthMe_UserPatWithoutReadTenant_Returns403()
    {
        string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
        using var client = BearerClient(pat);
        var resp = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task AuthMe_JwtSession_StillUnconditionallyAllowed()
    {
        // JWT/session callers must keep working regardless of role/capability — every tenant
        // role depends on this call to bootstrap the UI shell. A plain member (no read:tenant)
        // must still get 200.
        string email = $"pat-me-member-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "Test1234!", role: "member");
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var client = BearerClient(jwt);
        var resp = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Settings_ServiceTokenWithReadTenant_Returns200()
    {
        string svc = await CreateServiceToken("""["read:tenant"]""");
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/proxy-settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>
    /// Mints a service token whose <c>capabilities</c> column is exactly <paramref name="capabilitiesColumn"/>
    /// (including <c>null</c>), bypassing the normal issuance path so a legacy/pre-capability
    /// row can be reproduced. <see cref="TokenRepository.CreateServiceTokenAsync"/> always
    /// writes a validated JSON array, so a raw insert is the only way to seed the NULL/empty
    /// case this test targets.
    /// </summary>
    private async Task<string> CreateServiceTokenWithRawCapabilities(string? capabilitiesColumn, string org = "default")
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var orgRecord = await orgs.GetBySlugAsync(org)
            ?? throw new InvalidOperationException($"Org '{org}' not found.");

        string raw = Dependably.Security.TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        string id = Guid.NewGuid().ToString("N");

        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities) VALUES (@id, @orgId, @name, @hash, @capabilities)",
            new { id, orgId = orgRecord.Id, name = $"legacy-svc-{id}", hash, capabilities = capabilitiesColumn });

        return raw;
    }

    // ── Deny-all invariant: a legacy service token with no cap claims must never fall back ──
    // ── to a role-based default (privilege escalation closed) ───────────────────────────────

    [Fact]
    public async Task ListPackages_ServiceTokenWithNullCapabilities_Returns403()
    {
        string svc = await CreateServiceTokenWithRawCapabilities(capabilitiesColumn: null);
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ListPackages_ServiceTokenWithEmptyArrayCapabilities_Returns403()
    {
        string svc = await CreateServiceTokenWithRawCapabilities(capabilitiesColumn: "[]");
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task AuthMe_ServiceTokenWithNullCapabilities_Returns403()
    {
        // AuthController.Me read-gates ApiToken-scheme principals on read:tenant. A legacy
        // service token with no cap claims must be resolved from its explicit cap claims only
        // (empty set here) and never coalesced into Capabilities.ForRole("member") — pinning
        // this against role-fallback logic rather than trusting that ReaderCaps happens not to
        // include read:tenant today; a future role-capability change could otherwise silently
        // re-open this endpoint to legacy tokens the same way CheckServiceTokenCap was closed.
        string svc = await CreateServiceTokenWithRawCapabilities(capabilitiesColumn: null);
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task AuthMe_ServiceTokenWithEmptyArrayCapabilities_Returns403()
    {
        string svc = await CreateServiceTokenWithRawCapabilities(capabilitiesColumn: "[]");
        using var client = BearerClient(svc);
        var resp = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Service token yank (fix 1 also unblocks DeleteVersion for CI tokens) ─────────────

    [Fact]
    public async Task DeleteVersion_ServiceTokenWithYankNpm_Returns204()
    {
        string pkg = $"acme-svc-yank-{Guid.NewGuid():N}";
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string svc = await CreateServiceToken("""["yank:npm","read:packages"]""");
        using var client = BearerClient(svc);
        var resp = await client.DeleteAsync($"/api/v1/packages/npm/{pkg}/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ── Writes stay JWT-only: an opaque PAT never satisfies the default JWT scheme ────────

    [Fact]
    public async Task PutSettings_UserPat_Returns401()
    {
        // Even a PAT carrying tenant:configure cannot reach the write action — it is not
        // opted into the ApiToken scheme, so the opaque token fails the default JWT scheme.
        string pat = await _factory.CreateAdminUserToken("""["tenant:configure","read:tenant"]""");
        using var client = BearerClient(pat);
        var resp = await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true,
            allowlistMode = false,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task QuarantineDecide_UserPat_Returns401()
    {
        string pat = await _factory.CreateAdminUserToken("""["tenant:configure","read:tenant"]""");
        using var client = BearerClient(pat);
        var resp = await client.PostAsJsonAsync("/api/v1/quarantine/does-not-exist/decide", new
        {
            decision = "approve",
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Fix 3: require_mfa orgs must not block token principals ───────────────────────────

    [Fact]
    public async Task RequireMfaOrg_PatSucceeds_JwtSessionOfSameUnenrolledUserBlocked()
    {
        string orgId;
        await using (var conn = await Db.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
            await conn.ExecuteAsync("UPDATE org_settings SET require_mfa = 1 WHERE org_id = @orgId", new { orgId });
        }
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        try
        {
            // The bootstrap owner is not MFA-enrolled. A PAT minted for them must still reach
            // a non-allowlisted read route — MfaEnrollmentGuard exempts non-JWT principals.
            string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
            using var patClient = BearerClient(pat);
            var patResp = await patClient.GetAsync("/api/v1/packages");
            Assert.Equal(HttpStatusCode.OK, patResp.StatusCode);

            // The same unenrolled owner's JWT session, hitting the same route, is still blocked.
            string jwt = await _factory.CreateAdminJwt();
            using var jwtClient = BearerClient(jwt);
            var jwtResp = await jwtClient.GetAsync("/api/v1/packages");
            Assert.Equal(HttpStatusCode.Forbidden, jwtResp.StatusCode);
            string body = await jwtResp.Content.ReadAsStringAsync();
            Assert.Contains("mfa_enrollment_required", body);
        }
        finally
        {
            await using var conn = await Db.OpenAsync();
            await conn.ExecuteAsync("UPDATE org_settings SET require_mfa = 0 WHERE org_id = @orgId", new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    // ── Fix 2: read:* is mintable and grants every read:* leaf ────────────────────────────

    [Fact]
    public async Task MintReadAll_OwnerJwt_GrantsPackagesAndAuditLeaves()
    {
        using var owner = await AdminJwtClient();
        var mintResp = await owner.PostAsJsonAsync("/api/v1/tokens", new { capabilities = new[] { "read:*" } });
        Assert.Equal(HttpStatusCode.OK, mintResp.StatusCode);
        var doc = JsonDocument.Parse(await mintResp.Content.ReadAsStringAsync()).RootElement;
        string raw = doc.GetProperty("token").GetString()!;

        using var client = BearerClient(raw);
        var packagesResp = await client.GetAsync("/api/v1/packages");
        Assert.Equal(HttpStatusCode.OK, packagesResp.StatusCode);

        var activityResp = await client.GetAsync("/api/v1/activity");
        Assert.Equal(HttpStatusCode.OK, activityResp.StatusCode);

        var settingsResp = await client.GetAsync("/api/v1/settings");
        Assert.Equal(HttpStatusCode.OK, settingsResp.StatusCode);
    }

    [Fact]
    public async Task MintReadAll_MemberJwt_Returns400ExceedsRole()
    {
        // Member holds each individual read:* leaf it's entitled to but never the wildcard —
        // minting read:* must not let a member escalate to read:audit/read:tenant.
        string email = $"pat-readall-member-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "Test1234!", role: "member");
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var client = BearerClient(jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new { capabilities = new[] { "read:*" } });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }
}
