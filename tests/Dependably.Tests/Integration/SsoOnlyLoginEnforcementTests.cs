using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that a tenant switched to SAML-only (<c>forms_login_enabled=false</c>) has the
/// password grant refused server-side at POST /api/v1/auth/login, not merely hidden from the
/// SPA by GET /api/v1/auth/methods. Before the fix, HandleTenantLoginAsync never read the
/// tenant's SAML config, so a correct local password kept working even after an admin switched
/// the tenant to SSO-only — bypassing every control the IdP enforces (MFA, conditional access,
/// deprovisioning).
/// </summary>
[Trait("Category", "Integration")]
public sealed class SsoOnlyLoginEnforcementTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    // test-only placeholder password
    private const string TestPassword = "SsoEnforceTest1!";

    public SsoOnlyLoginEnforcementTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private HttpClient CreateLoginClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });

    private async Task<string> DefaultOrgIdAsync()
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    // Seeds a SAML-ready, SSO-only config row for the default org — enabled, IdP metadata
    // present, forms login switched off. Mirrors the state the lockout guard in
    // OrgAuthConfigController only allows a tenant to reach after a successful SAML test.
    private async Task SeedSsoOnlyConfigAsync(string orgId)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config
                (org_id, enabled, forms_login_enabled, idp_entity_id, idp_sso_url, idp_signing_cert)
            VALUES (@orgId, 1, 0, 'https://idp.example/entity', 'https://idp.example/sso', 'cert-base64')
            ON CONFLICT(org_id) DO UPDATE SET
                enabled = 1, forms_login_enabled = 0,
                idp_entity_id = 'https://idp.example/entity',
                idp_sso_url = 'https://idp.example/sso',
                idp_signing_cert = 'cert-base64'
            """,
            new { orgId });
    }

    private async Task ClearSamlConfigAsync(string orgId)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM tenant_saml_config WHERE org_id = @orgId", new { orgId });
    }

    // Seeds a SAML-ready, SSO-only config row where readiness comes from an admin-pinned
    // idp_signing_cert_override rather than the metadata-parsed idp_signing_cert — the
    // certless-metadata-plus-override shape POST /api/v1/auth-config/metadata and
    // POST /api/v1/auth-config/signing-cert support together (IdpMetadataParser.Parse is called
    // with requireCert=false whenever an override is already pinned).
    private async Task SeedSsoOnlyConfigWithOverrideAsync(string orgId)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config
                (org_id, enabled, forms_login_enabled, idp_entity_id, idp_sso_url,
                 idp_signing_cert, idp_signing_cert_override)
            VALUES (@orgId, 1, 0, 'https://idp.example/entity', 'https://idp.example/sso',
                    NULL, 'override-cert-base64')
            ON CONFLICT(org_id) DO UPDATE SET
                enabled = 1, forms_login_enabled = 0,
                idp_entity_id = 'https://idp.example/entity',
                idp_sso_url = 'https://idp.example/sso',
                idp_signing_cert = NULL,
                idp_signing_cert_override = 'override-cert-base64'
            """,
            new { orgId });
    }

    [Fact]
    public async Task TenantLogin_FormsDisabled_CorrectPassword_Refused()
    {
        string email = $"sso-only-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();

        await SeedSsoOnlyConfigAsync(orgId);
        try
        {
            using var client = CreateLoginClient();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });

            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal("Invalid credentials.", doc.GetProperty("detail").GetString());
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    /// <summary>
    /// Mixed/partial-failure across state transitions on the same account: password login
    /// succeeds while forms is enabled, fails once the tenant switches to SAML-only (even
    /// though the password is correct), and succeeds again once forms is re-enabled — proving
    /// the enforcement tracks the live config rather than caching a stale decision, and that a
    /// correctly-configured tenant is never left permanently locked out.
    /// </summary>
    [Fact]
    public async Task TenantLogin_FormsToggle_MixedOutcomesAcrossState()
    {
        string email = $"sso-toggle-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();

        try
        {
            using var client = CreateLoginClient();

            // Forms enabled (no SAML config row yet) — password login succeeds.
            var beforeResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);

            // Tenant switches to SAML-only — the SAME correct password is now refused.
            await SeedSsoOnlyConfigAsync(orgId);
            var duringResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, duringResp.StatusCode);

            // An outright wrong password against the same SSO-only tenant gets the identical
            // response shape — the enforcement adds no distinguishing signal beyond what
            // GET /api/v1/auth/methods already discloses.
            var wrongPasswordResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = "not-the-password" });
            Assert.Equal(HttpStatusCode.Unauthorized, wrongPasswordResp.StatusCode);
            string? duringBody = JsonDocument.Parse(await duringResp.Content.ReadAsStringAsync()).RootElement
                .GetProperty("detail").GetString();
            string? wrongBody = JsonDocument.Parse(await wrongPasswordResp.Content.ReadAsStringAsync()).RootElement
                .GetProperty("detail").GetString();
            Assert.Equal(wrongBody, duringBody);

            // Forms re-enabled — the correct password works again.
            await using (var conn = await Db.OpenAsync())
            {
                await conn.ExecuteAsync(
                    "UPDATE tenant_saml_config SET forms_login_enabled = 1 WHERE org_id = @orgId",
                    new { orgId });
            }
            var afterResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    /// <summary>
    /// forms_login_enabled=false with an incomplete SAML config (no IdP metadata) does NOT
    /// block password login — matching the readiness check GET /api/v1/auth/methods already
    /// uses to decide whether to show the password form. The API's lockout guard prevents a
    /// tenant from reaching this combination through normal use, but the enforcement must not
    /// turn a stray/incomplete config row into a hard lockout with no escape hatch.
    /// </summary>
    [Fact]
    public async Task TenantLogin_FormsDisabled_SamlNotReady_StillAllowsPassword()
    {
        string email = $"sso-notready-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();

        await using (var conn = await Db.OpenAsync())
        {
            // enabled + forms disabled, but no IdP metadata at all — not SAML-ready.
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled)
                VALUES (@orgId, 1, 0)
                """,
                new { orgId });
        }

        try
        {
            using var client = CreateLoginClient();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    /// <summary>
    /// SSO-only readiness reached via an admin-pinned idp_signing_cert_override rather than a
    /// metadata-parsed idp_signing_cert — the same "either cert source" rule
    /// SamlController.IsSamlConfigured applies when deciding whether an assertion can be
    /// validated at all. A readiness check that only recognises idp_signing_cert would treat
    /// this fully-functional SSO-only tenant as not-ready and leave the password grant live.
    /// </summary>
    [Fact]
    public async Task TenantLogin_FormsDisabled_OverrideCertOnly_CorrectPassword_Refused()
    {
        string email = $"sso-override-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();

        await SeedSsoOnlyConfigWithOverrideAsync(orgId);
        try
        {
            using var client = CreateLoginClient();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });

            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal("Invalid credentials.", doc.GetProperty("detail").GetString());
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    /// <summary>
    /// The silent-reopen path: a tenant already correctly enforced via its metadata-parsed cert
    /// pins an admin override and then re-uploads certless metadata — SamlConfigRepository.
    /// UpsertMetadataAsync writes idp_signing_cert unconditionally, so it goes NULL while
    /// forms_login_enabled stays 0 and is never re-validated by any admin-facing guard. Nothing
    /// about that sequence is an admin action to re-enable forms login, so password login must
    /// stay refused throughout — readiness has to keep tracking the override, not silently drop
    /// to "not ready" (and reopen the password grant) the moment idp_signing_cert goes NULL.
    /// </summary>
    [Fact]
    public async Task TenantLogin_FormsDisabled_MetadataReuploadCertlessWithOverridePinned_StaysRefused()
    {
        string email = $"sso-reopen-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();

        // Step 1: enforced via the metadata-parsed cert alone (no override yet).
        await SeedSsoOnlyConfigAsync(orgId);
        try
        {
            using var client = CreateLoginClient();
            var enforcedResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, enforcedResp.StatusCode);

            // Step 2: admin pins an override (SetSigningCertOverrideAsync leaves idp_signing_cert
            // untouched), then re-uploads certless metadata (UpsertMetadataAsync overwrites
            // idp_signing_cert to NULL unconditionally). forms_login_enabled is never touched by
            // either write.
            await using (var conn = await Db.OpenAsync())
            {
                await conn.ExecuteAsync(
                    "UPDATE tenant_saml_config SET idp_signing_cert_override = @cert WHERE org_id = @orgId",
                    new { orgId, cert = "override-cert-base64" });
                await conn.ExecuteAsync(
                    "UPDATE tenant_saml_config SET idp_signing_cert = NULL WHERE org_id = @orgId",
                    new { orgId });
            }

            var afterReuploadResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, afterReuploadResp.StatusCode);
            var doc = JsonDocument.Parse(await afterReuploadResp.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal("Invalid credentials.", doc.GetProperty("detail").GetString());
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    // ── Invite acceptance: the onboarding path must honour the same enforcement ──

    private async Task<(string RawToken, string Email)> SeedInviteAsync(string orgId)
    {
        string ownerId;
        await using (var conn = await Db.OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");
        }

        var invites = _factory.Services.GetRequiredService<InviteRepository>();
        string email = $"sso-invite-{Guid.NewGuid():N}@test.local";
        var (raw, _) = (await invites.CreateAsync(orgId, email, ownerId, "member"))!;
        return (raw, email);
    }

    private async Task<int> CountUsersAsync(string email)
    {
        await using var conn = await Db.OpenAsync();
        // xtenant: test assertion keyed by a globally unique generated email.
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM users WHERE email = @email", new { email });
    }

    /// <summary>
    /// POST /api/v1/invites/accept is the second password grant: it stores a BCrypt local
    /// password and mints a dependably_session cookie without ever going through the login
    /// endpoint. On an SSO-only tenant it must refuse — otherwise the normal onboarding flow
    /// mints exactly the local credential SSO-only exists to eliminate, and the resulting user
    /// keeps signing in with a password the IdP has never seen.
    ///
    /// Mixed outcomes on one invite across a state change: refused while the tenant is SSO-only
    /// (no user row, no session cookie, invite unburned), accepted the moment forms login is
    /// re-enabled — the refusal must not consume the single-use token.
    /// </summary>
    [Fact]
    public async Task InviteAccept_FormsDisabled_Refused_ThenAcceptedWhenFormsReenabled()
    {
        string orgId = await DefaultOrgIdAsync();
        var (rawToken, inviteEmail) = await SeedInviteAsync(orgId);

        await SeedSsoOnlyConfigAsync(orgId);
        try
        {
            using var client = CreateLoginClient();
            var blocked = await client.PostAsJsonAsync(
                "/api/v1/invites/accept", new { token = rawToken, password = TestPassword });

            Assert.Equal(HttpStatusCode.Conflict, blocked.StatusCode);
            // A localized problem the Join page renders verbatim, plus the machine-readable
            // reason a client can branch on — distinct from the "account already exists" 409
            // the same endpoint returns for a spent invite.
            var problem = JsonDocument.Parse(await blocked.Content.ReadAsStringAsync()).RootElement;
            Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("detail").GetString()));
            Assert.Equal("forms_login_disabled", problem.GetProperty("reason").GetString());
            // No session was minted — the auto-login is the whole point of the bypass.
            Assert.DoesNotContain(
                blocked.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : Array.Empty<string>(),
                c => c.Contains("dependably_session", StringComparison.Ordinal));
            // No local account, and therefore no local password hash, was created.
            Assert.Equal(0, await CountUsersAsync(inviteEmail));

            // The invite is not consumed: a refusal is not a use.
            var invites = _factory.Services.GetRequiredService<InviteRepository>();
            Assert.NotNull(await invites.PeekPendingAsync(rawToken));

            // The refusal is recorded against the tenant rather than silently dropped. The
            // invite's own email hash scopes the count — this class shares one factory database
            // across its tests, so an unscoped COUNT would drift with execution order.
            await using (var conn = await Db.OpenAsync())
            {
                long blockedRows = await conn.ExecuteScalarAsync<long>(
                    """
                    SELECT COUNT(*) FROM audit_log
                    WHERE action = 'invite_accept_blocked' AND org_id = @orgId
                      AND detail LIKE '%' || @emailHash || '%'
                    """,
                    new { orgId, emailHash = LoginService.HashEmail(inviteEmail) });
                Assert.Equal(1, blockedRows);
            }

            // Forms login comes back — the same untouched invite now works.
            await using (var conn = await Db.OpenAsync())
            {
                await conn.ExecuteAsync(
                    "UPDATE tenant_saml_config SET forms_login_enabled = 1 WHERE org_id = @orgId",
                    new { orgId });
            }

            var accepted = await client.PostAsJsonAsync(
                "/api/v1/invites/accept", new { token = rawToken, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            Assert.Equal(1, await CountUsersAsync(inviteEmail));
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    // ── Detection: a refused attempt is still an attempt ────────────────────────

    private async Task<long> CountBlockedAuditRowsAsync(string orgId)
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE action = 'login.failure' AND org_id = @orgId
              AND detail LIKE '%forms_login_disabled%'
            """,
            new { orgId });
    }

    /// <summary>
    /// The SSO-only refusal short-circuits the credential check, so it must record the attempt
    /// itself: without it, password spraying an SSO-only tenant — including with a correct,
    /// IdP-deprovisioned credential, the exact population this enforcement protects — leaves no
    /// audit_log row, no activity row, nothing for the SIEM auth feed, and never trips lockout.
    ///
    /// Mixed inputs against the same SSO-only tenant: a correct password and a wrong one are
    /// both refused, and both are recorded identically (same action, same reason, same source_ip
    /// treatment) — the record adds no signal the response itself withholds — while the shared
    /// (realm, tenant, email) lockout budget counts every one of them.
    /// </summary>
    [Fact]
    public async Task TenantLogin_FormsDisabled_RecordsFailureAndChargesLockout()
    {
        string email = $"sso-audit-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();

        var lockout = _factory.Services.GetRequiredService<ILockoutStore>();
        string lockoutKey = LoginService.HashLockoutKey("tenant", orgId, email);

        // Baselines: sibling tests in this class share one factory database and also drive
        // refused logins, so every assertion below is a delta, never an absolute count.
        long auditBefore = await CountBlockedAuditRowsAsync(orgId);

        await SeedSsoOnlyConfigAsync(orgId);
        try
        {
            using var client = CreateLoginClient();

            // Three refused attempts: the correct password, a wrong one, and an address with no
            // account at all. All three are refused identically and all three must be recorded —
            // a record that appeared only for real accounts would itself be the enumeration
            // oracle the uniform 401 avoids.
            var correct = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            var wrong = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = "not-the-password" });
            var unknown = await client.PostAsJsonAsync(
                "/api/v1/auth/login",
                new { email = $"nobody-{Guid.NewGuid():N}@test.local", password = "whatever" });
            Assert.Equal(HttpStatusCode.Unauthorized, correct.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);

            await using var conn = await Db.OpenAsync();

            // audit_log — the SIEM auth feed reads this table on the 'login.' prefix, and the
            // reason distinguishes an SSO-only refusal from a plain bad password.
            var rows = (await conn.QueryAsync<(string Detail, string? SourceIp)>(
                """
                SELECT detail AS Detail, source_ip AS SourceIp FROM audit_log
                WHERE action = 'login.failure' AND org_id = @orgId
                  AND detail LIKE '%forms_login_disabled%'
                """,
                new { orgId })).ToList();
            Assert.Equal(auditBefore + 3, rows.Count);
            Assert.All(rows, r => Assert.Contains("\"realm\":\"tenant\"", r.Detail));
            // Attributable to a caller: source_ip is the field that makes a spray visible.
            Assert.All(rows, r => Assert.False(string.IsNullOrEmpty(r.SourceIp)));

            // The matching activity row (ecosystem='auth', event_type='login.failure') is written
            // by the same RecordFailureAsync helper, but through the batching ActivityWriter the
            // integration host wires up, so it lands after this assertion would read it —
            // audit_log is the surface asserted here, and it is also the one the SIEM feed reads.

            // The refused attempts charge the same lockout budget a wrong password would, so a
            // spray against an SSO-only tenant still walks into the lockout. The counter is keyed
            // on (realm, tenant, email), so this account's budget counts only its own two
            // attempts — the unknown address above has its own.
            var (failedCount, _) = await lockout.GetAsync(lockoutKey, CancellationToken.None);
            Assert.Equal(2, failedCount);
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }

    /// <summary>
    /// Once the shared budget locks, an SSO-only refusal answers the same 429 with Retry-After a
    /// locked password-backed account gets, and records a <c>lockout.triggered</c> row — the
    /// twin of the test above: charging the budget is only half the posture if the lock, once
    /// reached, stayed invisible behind more 401s. The budget is per (realm, tenant, email), so
    /// the sibling address used here never collides with the other tests in this class.
    /// </summary>
    [Fact]
    public async Task TenantLogin_FormsDisabled_LockedBudget_Answers429AndRecordsLockout()
    {
        string email = $"sso-lock-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);
        string orgId = await DefaultOrgIdAsync();
        string emailHash = LoginService.HashEmail(email);

        await SeedSsoOnlyConfigAsync(orgId);
        try
        {
            using var client = CreateLoginClient();

            // LoginService.MaxFailedAttempts is 10: the tenth refusal locks the budget.
            for (int i = 0; i < 10; i++)
            {
                var refused = await client.PostAsJsonAsync(
                    "/api/v1/auth/login", new { email, password = TestPassword });
                Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
            }

            var locked = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
            Assert.NotNull(locked.Headers.RetryAfter);
            var doc = JsonDocument.Parse(await locked.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal(LoginService.LockedAccountError, doc.GetProperty("detail").GetString());

            await using var conn = await Db.OpenAsync();
            long lockoutRows = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM audit_log
                WHERE action = 'lockout.triggered' AND org_id = @orgId
                  AND detail LIKE '%' || @emailHash || '%'
                """,
                new { orgId, emailHash });
            Assert.Equal(1, lockoutRows);
        }
        finally
        {
            await ClearSamlConfigAsync(orgId);
        }
    }
}
