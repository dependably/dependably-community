using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Sociable unit coverage for LoginService. The integration suite already exercises
/// /auth/login over the HTTP boundary; these tests drive the service directly to lift
/// branch coverage on the success paths (JWT issuance, last_login_at stamp, lockout
/// ClearAsync, audit + emitter calls) and the SAML JIT-provision + email-link branches.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LoginServiceUnitTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly IAuditEmitter _emitter = Substitute.For<IAuditEmitter>();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public LoginServiceUnitTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private LoginService NewSut()
    {
        var orgs = new OrgRepository(_fixture.Store);
        return new LoginService(new LoginService.Dependencies(
            _fixture.Store,
            orgs,
            new SystemAdminRepository(_fixture.Store),
            new SqliteLockoutStore(_fixture.Store, _clock),
            new AuditRepository(_fixture.Store),
            new ExternalIdentityRepository(_fixture.Store, _clock),
            _emitter,
            _clock,
            Substitute.For<IMfaEnrollmentService>(),
            Substitute.For<ISystemMfaEnrollmentService>()));
    }

    private async Task EnsureJwtSecretAsync()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', 'unit-test-secret-min-32-chars-xxxxxx') ON CONFLICT(key) DO NOTHING");
    }

    // ── LoginTenantAsync happy path ─────────────────────────────────────────

    [Fact]
    public async Task LoginTenantAsync_CorrectPassword_ReturnsToken_AndStampsLastLogin()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email, role: "member", password: "RealPass12345");

        var sut = NewSut();
        var (token, error, retry) = await sut.LoginTenantAsync(email, "RealPass12345", orgId);

        Assert.NotNull(token);
        Assert.Null(error);
        Assert.Null(retry);

        await using var conn = await _fixture.Store.OpenAsync();
        string? lastLogin = await conn.ExecuteScalarAsync<string?>(
            "SELECT last_login_at FROM users WHERE id = @id", new { id = userId });
        Assert.False(string.IsNullOrEmpty(lastLogin));

        // Audit + emitter both fired on success.
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'login.success' AND actor_id = @id",
            new { id = userId });
        Assert.True(auditCount >= 1);

        await _emitter.Received().EmitAsync(
            "auth.login.success", orgId, "user", userId, "accepted",
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginTenantAsync_WrongPassword_ReturnsErrorAndIncrementsLockoutCounter()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"u-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "Correct12345");

        var sut = NewSut();
        var (Token, Error, _) = await sut.LoginTenantAsync(email, "wrong-1", orgId);
        var second = await sut.LoginTenantAsync(email, "wrong-2", orgId);

        Assert.Null(Token);
        Assert.NotNull(Error);
        Assert.Null(second.Token);

        // Lockout counter rose to 2. The key is realm+tenant scoped.
        await using var conn = await _fixture.Store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT failed_count FROM login_attempts WHERE email_hash = @h",
            new { h = HashLockoutKey("tenant", orgId, email) });
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task LoginTenantAsync_UnknownEmail_ReturnsGenericInvalidCredentials()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var (token, error, _) = await NewSut().LoginTenantAsync(
            $"ghost-{Guid.NewGuid():N}@nowhere.test", "anything", orgId);

        Assert.Null(token);
        Assert.NotNull(error);
        Assert.DoesNotContain("not found", error!, StringComparison.OrdinalIgnoreCase);
    }

    // ── Constant-time credential verification (timing-oracle hardening) ─────

    /// <summary>
    /// The sentinel must be a VALID bcrypt hash: Verify on the unknown-email path runs
    /// against it for real (full cost-12 work, no exception) instead of short-circuiting,
    /// so response timing cannot distinguish "unknown email" from "wrong password".
    /// </summary>
    [Fact]
    public void TimingSentinelHash_IsValidBcryptHash_AndMatchesNothing()
    {
        Assert.StartsWith("$2", LoginService.TimingSentinelHash, StringComparison.Ordinal);
        // Verify must complete without throwing (it throws on malformed hashes) and never match.
        Assert.False(BCrypt.Net.BCrypt.Verify("any-password", LoginService.TimingSentinelHash));
    }

    /// <summary>
    /// Verify executes even when no stored hash exists (unknown account or SAML-only user
    /// with an empty password_hash) — and the result is always a rejection.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void VerifyPasswordConstantTime_NoUsableStoredHash_RunsVerifyAndRejects(string? storedHash)
    {
        Assert.False(LoginService.VerifyPasswordConstantTime("anything", storedHash));
    }

    [Fact]
    public void VerifyPasswordConstantTime_RealHash_MatchesOnlyTheCorrectPassword()
    {
        string hash = BCrypt.Net.BCrypt.HashPassword("Correct12345", workFactor: 4);
        Assert.True(LoginService.VerifyPasswordConstantTime("Correct12345", hash));
        Assert.False(LoginService.VerifyPasswordConstantTime("Wrong12345", hash));
    }

    [Fact]
    public async Task LoginTenantAsync_LockedAccountStatus_RejectedSameAsInvalidCredentials()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"locked-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "Correct12345");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE users SET account_status = 'locked' WHERE id = @id", new { id = userId });
        }

        var (token, error, _) = await NewSut().LoginTenantAsync(email, "Correct12345", orgId);

        Assert.Null(token);
        Assert.NotNull(error);   // generic — must not reveal account_status
    }

    [Fact]
    public async Task LoginTenantAsync_PreviouslyLockedOut_Returns429WithRetryAfter()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"lo-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "Correct12345");

        // Stamp lockout state directly using the realm+tenant scoped key.
        string lockoutKey = HashLockoutKey("tenant", orgId, email);
        string lockedUntil = _clock.GetUtcNow().AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO login_attempts (email_hash, failed_count, locked_until) VALUES (@h, 10, @t)",
                new { h = lockoutKey, t = lockedUntil });
        }

        var (token, error, retry) = await NewSut().LoginTenantAsync(email, "Correct12345", orgId);

        Assert.Null(token);
        Assert.NotNull(error);
        Assert.NotNull(retry);
        // Frozen clock: lockout ends exactly 5 minutes from "now", +1s rounding guard.
        Assert.Equal(301, retry!.Value);
    }

    // ── LoginSystemAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task LoginSystemAsync_CorrectPassword_ReturnsSystemScopedJwt()
    {
        await EnsureJwtSecretAsync();
        string adminEmail = $"sys-{Guid.NewGuid():N}@example.com";
        string adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store, adminEmail, "SysPass12345");

        var (token, error, _) = await NewSut().LoginSystemAsync(adminEmail, "SysPass12345");

        Assert.NotNull(token);
        Assert.Null(error);

        await _emitter.Received().EmitAsync(
            Arg.Is<string>(t => t == "auth.login.success"),
            Arg.Is<string?>(o => o == null),
            Arg.Is<string>(at => at == "user"),
            Arg.Is<string?>(a => a == adminId),
            Arg.Is<string>(oc => oc == "accepted"),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginSystemAsync_UnknownEmail_ReturnsErrorWithoutLeakingExistence()
    {
        await EnsureJwtSecretAsync();
        var (token, error, _) = await NewSut().LoginSystemAsync($"ghost-{Guid.NewGuid():N}@nowhere", "anything");
        Assert.Null(token);
        Assert.NotNull(error);
        Assert.DoesNotContain("not found", error!, StringComparison.OrdinalIgnoreCase);
    }

    // ── login.failure audit scoping (tenant-isolation guarantee) ─────────────

    /// <summary>
    /// A tenant login failure is pinned to that tenant's audit list at scope='tenant' with
    /// org_id=<that tenant>: only that tenant's admin sees it. It must never surface to another
    /// tenant's audit list, nor to the system/operator audit list.
    /// </summary>
    [Fact]
    public async Task LoginTenantAsync_BadCredentials_AuditFailureScopedToThatTenantOnly()
    {
        await EnsureJwtSecretAsync();
        string tenantOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string otherOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"u-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, tenantOrg, email, password: "Correct12345");

        var (token, error, _) = await NewSut().LoginTenantAsync(email, "wrong-pass", tenantOrg);
        Assert.Null(token);
        Assert.NotNull(error);

        var audit = new AuditRepository(_fixture.Store);

        // Visible to the owning tenant.
        var (ownItems, _) = await audit.ListAuditAsync(tenantOrg, limit: 50, offset: 0, action: "login.failure");
        Assert.Single(ownItems);
        Assert.All(ownItems, e => Assert.Equal(tenantOrg, e.OrgId));

        // Not visible to a different tenant.
        var (otherItems, otherTotal) = await audit.ListAuditAsync(otherOrg, limit: 50, offset: 0, action: "login.failure");
        Assert.Empty(otherItems);
        Assert.Equal(0, otherTotal);

        // Not visible on the system/operator audit list. The shared fixture may hold system-realm
        // login.failure rows from other tests, but a tenant-realm failure must never appear there.
        var (sysItems, _) = await audit.ListSystemAuditAsync(limit: 200, offset: 0, action: "login.failure");
        Assert.DoesNotContain(sysItems, e => e.Detail is not null && e.Detail.Contains("\"realm\":\"tenant\"", StringComparison.Ordinal));
    }

    /// <summary>
    /// A system/master login failure is recorded at scope='system' (org_id NULL) so only system
    /// admins see it on the operator audit list. It must never leak into any tenant's audit list.
    /// </summary>
    [Fact]
    public async Task LoginSystemAsync_BadCredentials_AuditFailureScopedToSystemOnly()
    {
        await EnsureJwtSecretAsync();
        string tenantOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string adminEmail = $"sys-{Guid.NewGuid():N}@example.com";
        await SystemAdminSeeder.InsertAsync(_fixture.Store, adminEmail, "SysPass12345");

        var (token, error, _) = await NewSut().LoginSystemAsync(adminEmail, "wrong-pass");
        Assert.Null(token);
        Assert.NotNull(error);

        var audit = new AuditRepository(_fixture.Store);

        // Visible on the system/operator audit list, with no org binding. The class shares an
        // in-memory DB fixture, so other system-login-failure tests may add rows — assert the
        // category is present and every system-scoped login.failure row stays org-unbound.
        var (sysItems, _) = await audit.ListSystemAuditAsync(limit: 50, offset: 0, action: "login.failure");
        Assert.NotEmpty(sysItems);
        Assert.All(sysItems, e => Assert.Null(e.OrgId));

        // Not visible to any tenant's audit list.
        var (tenantItems, tenantTotal) = await audit.ListAuditAsync(tenantOrg, limit: 50, offset: 0, action: "login.failure");
        Assert.Empty(tenantItems);
        Assert.Equal(0, tenantTotal);
    }

    // ── LoginSamlAsync — three branches ──────────────────────────────────────

    [Fact]
    public async Task LoginSamlAsync_ExistingExternalIdentity_ReturnsTokenWithoutProvisioning()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, "existing@x.test", role: "owner");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, @idp, @nameId)
                """, new { id = Guid.NewGuid().ToString("N"), orgId, userId, idp = "https://idp", nameId = "saml-name-1" });
        }

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "saml-name-1", "existing@x.test");

        Assert.NotNull(result.Token);
        Assert.Null(result.Error);
        Assert.False(result.Provisioned);
        Assert.False(result.Linked);
    }

    [Fact]
    public async Task LoginSamlAsync_NoExternalIdentity_LinksByEmail()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"link-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "saml-name-link", email);

        Assert.NotNull(result.Token);
        Assert.Null(result.Error);
        Assert.False(result.Provisioned);
        Assert.True(result.Linked);
    }

    [Fact]
    public async Task LoginSamlAsync_NoMatchingUser_JitProvisions()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "saml-jit-1", "fresh@x.test");

        Assert.NotNull(result.Token);
        Assert.Null(result.Error);
        Assert.True(result.Provisioned);
        Assert.False(result.Linked);
        Assert.Equal("member", result.Role);
    }

    [Fact]
    public async Task LoginSamlAsync_NoEmailInAssertion_Fails()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "saml-no-email", null);

        Assert.Null(result.Token);
        Assert.NotNull(result.Error);
        Assert.False(result.Provisioned);
    }

    [Fact]
    public async Task LoginSamlAsync_LinkedUserDisabled_Rejected()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, "disabled@x.test", accountStatus: "disabled");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, 'https://idp', 'saml-disabled')
                """, new { id = Guid.NewGuid().ToString("N"), orgId, userId });
        }

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "saml-disabled", "disabled@x.test");

        Assert.Null(result.Token);
        Assert.NotNull(result.Error);
    }

    // ── LoginSamlAsync — remaining branches ─────────────────────────────────

    /// <summary>
    /// Orphan external_identity row referencing a user_id that no longer exists. The
    /// repo's FK isn't enforced in our in-memory store, so this models the post-delete
    /// race that the "Linked user not found" guard exists to handle.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_ExternalIdentity_PointsToMissingUser_ReturnsLinkedUserNotFound()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        // Create then delete the user so the external identity becomes orphaned. We
        // CASCADE-delete the external identity along with the user, so we insert the
        // external_identity row again after the user is gone — with FKs off so the
        // orphan reference is accepted (mirrors a real post-delete race).
        string transientUserId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"transient-{Guid.NewGuid():N}@x.test");
        string externalId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM users WHERE id = @id", new { id = transientUserId });
            await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, 'https://idp', 'orphan-nameid')
                """, new { id = externalId, orgId, userId = transientUserId });
            await conn.ExecuteAsync("PRAGMA foreign_keys = ON");
        }

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "orphan-nameid", "noone@x.test");

        Assert.Null(result.Token);
        Assert.Equal("Linked user not found.", result.Error);
        Assert.False(result.Provisioned);
        Assert.False(result.Linked);
    }

    /// <summary>
    /// Email-link path (no external identity yet) where the email-matched user is locked.
    /// Distinct from the previously covered branch where the external identity already exists.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_EmailLinkPath_LockedUser_Rejected()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"locked-link-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email, accountStatus: "locked");

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "new-nameid-locked", email);

        Assert.Null(result.Token);
        Assert.Equal("Account is not active.", result.Error);
        Assert.False(result.Provisioned);
        Assert.False(result.Linked);
    }

    /// <summary>
    /// IdP rotated the user's email between logins: external identity exists, but the
    /// assertion's email no longer matches the stored email. Hits the emailChanged branch
    /// in <c>StampUserLoginAsync</c> which writes both last_login_at and the new email.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_AssertionEmailRotated_UpdatesUserEmail()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string oldEmail = $"old-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, oldEmail);
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, 'https://idp', 'rotated-nameid')
                """, new { id = Guid.NewGuid().ToString("N"), orgId, userId });
        }

        string newEmail = $"new-{Guid.NewGuid():N}@x.test";
        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "rotated-nameid", newEmail);

        Assert.NotNull(result.Token);
        Assert.Null(result.Error);

        await using var verify = await _fixture.Store.OpenAsync();
        string? storedEmail = await verify.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE id = @id", new { id = userId });
        Assert.Equal(newEmail, storedEmail);
    }

    // ── LoginSamlAsync — email-link privilege escalation gate ────────────────

    /// <summary>
    /// Owner account is never silently linked via email: no external_identities row is
    /// created and the attempt is audited as a login failure with reason
    /// "email_link_privileged_account_blocked". The owner's role is unchanged.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_EmailLinkPath_OwnerAccount_Blocked_NotLinked_Audited()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string ownerEmail = $"owner-elink-{Guid.NewGuid():N}@x.test";
        string ownerId = await UserSeeder.InsertAsync(_fixture.Store, orgId, ownerEmail, role: "owner");

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "new-nameid-owner", ownerEmail);

        Assert.Null(result.Token);
        Assert.NotNull(result.Error);
        Assert.False(result.Provisioned);
        Assert.False(result.Linked);

        await using var conn = await _fixture.Store.OpenAsync();

        // No external_identities row was created.
        long linked = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM external_identities WHERE user_id = @id", new { id = ownerId });
        Assert.Equal(0, linked);

        // Owner's role is unchanged.
        string? storedRole = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = ownerId });
        Assert.Equal("owner", storedRole);

        // Audit event with the new reason code was emitted.
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.login.failure' AND org_id = @orgId AND actor_id = @actor",
            new { orgId, actor = ownerId });
        Assert.Equal(1, auditCount);

        string? detail = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM audit_log WHERE action = 'auth.saml.login.failure' AND actor_id = @actor",
            new { actor = ownerId });
        Assert.Contains("email_link_privileged_account_blocked", detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Admin account is blocked without the idp_can_assign_admin opt-in.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_EmailLinkPath_AdminAccount_WithoutOptIn_Blocked()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string adminEmail = $"admin-elink-{Guid.NewGuid():N}@x.test";
        string adminId = await UserSeeder.InsertAsync(_fixture.Store, orgId, adminEmail, role: "admin");

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "new-nameid-admin", adminEmail);

        Assert.Null(result.Token);
        Assert.NotNull(result.Error);
        Assert.False(result.Linked);

        await using var conn = await _fixture.Store.OpenAsync();
        long linked = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM external_identities WHERE user_id = @id", new { id = adminId });
        Assert.Equal(0, linked);
    }

    /// <summary>
    /// Admin account is allowed when idp_can_assign_admin is set — parallels the JIT ceiling test.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_EmailLinkPath_AdminAccount_WithOptIn_Linked()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string adminEmail = $"admin-elink-optin-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, adminEmail, role: "admin");

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "new-nameid-admin-optin", adminEmail,
            new SamlLoginOptions(IdpCanAssignAdmin: true));

        Assert.NotNull(result.Token);
        Assert.True(result.Linked);
    }

    /// <summary>
    /// Member/auditor accounts are still silently linked — the fix must not over-block
    /// non-privileged accounts (regression guard).
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_EmailLinkPath_MemberAccount_StillLinks()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string memberEmail = $"member-elink-{Guid.NewGuid():N}@x.test";
        string memberId = await UserSeeder.InsertAsync(_fixture.Store, orgId, memberEmail, role: "member");

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "new-nameid-member", memberEmail);

        Assert.NotNull(result.Token);
        Assert.True(result.Linked);

        await using var conn = await _fixture.Store.OpenAsync();
        long linked = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM external_identities WHERE user_id = @id", new { id = memberId });
        Assert.Equal(1, linked);
    }

    /// <summary>
    /// Mixed scenario (house rule): one tenant has a member and an owner both matching
    /// different assertions in the same login flow. The member links successfully; the
    /// owner is blocked. Both are verified in a single test run.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_EmailLinkPath_MixedPrivilege_MemberLinksOwnerBlocked()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        string memberEmail = $"member-mixed-{Guid.NewGuid():N}@x.test";
        string memberId = await UserSeeder.InsertAsync(_fixture.Store, orgId, memberEmail, role: "member");

        string ownerEmail = $"owner-mixed-{Guid.NewGuid():N}@x.test";
        string ownerId = await UserSeeder.InsertAsync(_fixture.Store, orgId, ownerEmail, role: "owner");

        var sut = NewSut();

        // Member assertion — should link and receive a session.
        var memberResult = await sut.LoginSamlAsync(orgId, "https://idp", "mixed-nameid-member", memberEmail);
        Assert.NotNull(memberResult.Token);
        Assert.True(memberResult.Linked);

        // Owner assertion — should be blocked with no link.
        var ownerResult = await sut.LoginSamlAsync(orgId, "https://idp", "mixed-nameid-owner", ownerEmail);
        Assert.Null(ownerResult.Token);
        Assert.False(ownerResult.Linked);

        await using var conn = await _fixture.Store.OpenAsync();

        // Member has an external_identities row; owner does not.
        long memberLinks = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM external_identities WHERE user_id = @id", new { id = memberId });
        Assert.Equal(1, memberLinks);

        long ownerLinks = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM external_identities WHERE user_id = @id", new { id = ownerId });
        Assert.Equal(0, ownerLinks);

        // Owner's role is unchanged.
        string? ownerRole = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = ownerId });
        Assert.Equal("owner", ownerRole);

        // An audit failure was emitted for the owner attempt, none for the member.
        long ownerFailures = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.login.failure' AND actor_id = @id",
            new { id = ownerId });
        Assert.Equal(1, ownerFailures);

        long memberFailures = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.login.failure' AND actor_id = @id",
            new { id = memberId });
        Assert.Equal(0, memberFailures);
    }

    // ── LoginSamlAsync — IdP role ceiling ────────────────────────────────────

    [Fact]
    public async Task LoginSamlAsync_JitMappedToOwner_CappedToMember_AndAudited()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "ceiling-jit-owner", "jit-owner@x.test",
            new SamlLoginOptions(MappedRole: "owner"));

        Assert.NotNull(result.Token);
        Assert.True(result.Provisioned);
        Assert.Equal("member", result.Role);

        await using var conn = await _fixture.Store.OpenAsync();
        string? storedRole = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = result.UserId });
        Assert.Equal("member", storedRole);

        long blocked = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.role_mapping_blocked' AND org_id = @orgId AND actor_id = @actor",
            new { orgId, actor = result.UserId });
        Assert.Equal(1, blocked);
    }

    [Fact]
    public async Task LoginSamlAsync_JitMappedToAdmin_WithoutOptIn_CappedToMember()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "ceiling-jit-admin", "jit-admin@x.test",
            new SamlLoginOptions(MappedRole: "admin"));

        Assert.Equal("member", result.Role);
    }

    [Fact]
    public async Task LoginSamlAsync_JitMappedToAdmin_WithOptIn_AssignsAdmin()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "ceiling-jit-admin-optin", "jit-admin-optin@x.test",
            new SamlLoginOptions(MappedRole: "admin", IdpCanAssignAdmin: true));

        Assert.Equal("admin", result.Role);

        await using var conn = await _fixture.Store.OpenAsync();
        long blocked = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.role_mapping_blocked' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(0, blocked);
    }

    [Fact]
    public async Task LoginSamlAsync_JitMappedToOwner_WithAdminOptIn_CappedToAdmin()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "ceiling-jit-owner-optin", "jit-owner-optin@x.test",
            new SamlLoginOptions(MappedRole: "owner", IdpCanAssignAdmin: true));

        Assert.Equal("admin", result.Role);
    }

    /// <summary>
    /// Returning user (external identity already linked): an over-ceiling mapping never
    /// changes the stored role — a tenant-admin demotion can't be silently re-promoted by
    /// the IdP attribute — and the attempt is audited.
    /// </summary>
    [Fact]
    public async Task LoginSamlAsync_ResyncToOwner_BlockedKeepsCurrentRole_AndAudited()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"resync-{Guid.NewGuid():N}@x.test");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, 'https://idp', 'ceiling-resync-owner')
                """, new { id = Guid.NewGuid().ToString("N"), orgId, userId });
        }

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "ceiling-resync-owner", null,
            new SamlLoginOptions(MappedRole: "owner"));

        Assert.NotNull(result.Token);
        Assert.Equal("member", result.Role);

        await using var verify = await _fixture.Store.OpenAsync();
        string? storedRole = await verify.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = userId });
        Assert.Equal("member", storedRole);

        long blocked = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.role_mapping_blocked' AND org_id = @orgId AND actor_id = @actor",
            new { orgId, actor = userId });
        Assert.Equal(1, blocked);

        long changed = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.role_changed' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(0, changed);
    }

    /// <summary>Within-ceiling resync still works: admin opt-in allows IdP-driven promotion to admin.</summary>
    [Fact]
    public async Task LoginSamlAsync_ResyncToAdmin_WithOptIn_PromotesAndAuditsRoleChange()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"resync-ok-{Guid.NewGuid():N}@x.test");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, 'https://idp', 'ceiling-resync-admin')
                """, new { id = Guid.NewGuid().ToString("N"), orgId, userId });
        }

        var result = await NewSut().LoginSamlAsync(
            orgId, "https://idp", "ceiling-resync-admin", null,
            new SamlLoginOptions(MappedRole: "admin", IdpCanAssignAdmin: true));

        Assert.Equal("admin", result.Role);

        await using var verify = await _fixture.Store.OpenAsync();
        long changed = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.role_changed' AND org_id = @orgId AND actor_id = @actor",
            new { orgId, actor = userId });
        Assert.Equal(1, changed);
    }

    /// <summary>RecordSamlTestAsync writes a single audit row and does not provision.</summary>
    [Fact]
    public async Task RecordSamlTestAsync_WritesAuditRow()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        await NewSut().RecordSamlTestAsync(orgId, "https://idp-test", "test-nameid", "test@x.test", actorId: null);

        await using var conn = await _fixture.Store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.test.success' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(1, count);
    }

    /// <summary>IssueTenantJwtForUser is the public re-entry point used by SamlController.</summary>
    [Fact]
    public void IssueTenantJwtForUser_ReturnsParseableJwt()
    {
        string token = NewSut().IssueTenantJwtForUser("user-1", "tenant-1", "owner", "unit-test-secret-min-32-chars-xxxxxx");
        Assert.False(string.IsNullOrEmpty(token));
        // Three base64url-encoded segments separated by dots.
        Assert.Equal(2, token.Count(c => c == '.'));
    }

    private static string HashEmail(string email)
    {
        byte[] bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(email.ToLowerInvariant()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string HashLockoutKey(string realm, string? tenantId, string email) =>
        LoginService.HashLockoutKey(realm, tenantId, email);

    // ── HashLockoutKey — realm+tenant isolation invariants ───────────────────

    /// <summary>
    /// Three identities sharing an email in different realms/tenants must produce distinct
    /// lockout keys so their counters never collide in login_attempts.
    /// </summary>
    [Fact]
    public void HashLockoutKey_DifferentRealmsAndTenants_ProduceDifferentKeys()
    {
        const string email = "alice@corp.com";
        const string tenant1 = "t1";
        const string tenant2 = "t2";

        string keyTenant1 = LoginService.HashLockoutKey("tenant", tenant1, email);
        string keyTenant2 = LoginService.HashLockoutKey("tenant", tenant2, email);
        string keySystem = LoginService.HashLockoutKey("system", null, email);

        Assert.NotEqual(keyTenant1, keyTenant2);
        Assert.NotEqual(keyTenant1, keySystem);
        Assert.NotEqual(keyTenant2, keySystem);
    }

    /// <summary>Same inputs always produce the same output (determinism) and email is case-folded.</summary>
    [Fact]
    public void HashLockoutKey_IsStableAndCaseInsensitiveOnEmail()
    {
        string a = LoginService.HashLockoutKey("tenant", "t1", "Alice@CORP.COM");
        string b = LoginService.HashLockoutKey("tenant", "t1", "alice@corp.com");
        string c = LoginService.HashLockoutKey("tenant", "t1", "ALICE@corp.com");

        Assert.Equal(a, b);
        Assert.Equal(b, c);

        // Stable across two calls.
        Assert.Equal(a, LoginService.HashLockoutKey("tenant", "t1", "Alice@CORP.COM"));
    }

    /// <summary>
    /// Delimiter-safety: a pipe in the email must not collide with the same bytes formed by
    /// splitting the tenantId field differently (guards against ambiguous concatenation).
    /// </summary>
    [Fact]
    public void HashLockoutKey_DelimiterSafe_NoPipeAmbiguityCollision()
    {
        // "tenant|a" + "|" + "b|c@x" vs "tenant|a|b" + "|" + "c@x"
        // These two inputs differ in where the tenantId/email boundary falls.
        string key1 = LoginService.HashLockoutKey("tenant", "a", "b|c@x");
        string key2 = LoginService.HashLockoutKey("tenant", "a|b", "c@x");

        Assert.NotEqual(key1, key2);
    }

    // ── Lockout isolation: one tenant's failures must not lock another ────────

    /// <summary>
    /// Ten wrong-password attempts against tenant A must not lock tenant B's counter for the
    /// same email. This is the cross-tenant lockout-isolation correctness test.
    /// </summary>
    [Fact]
    public async Task LoginTenantAsync_TenantA_Lockout_DoesNotLockTenantB()
    {
        await EnsureJwtSecretAsync();
        string tenantA = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string tenantB = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"shared-{Guid.NewGuid():N}@x.test";

        // Create the same email in both tenants.
        await UserSeeder.InsertAsync(_fixture.Store, tenantA, email, password: "PassA12345");
        await UserSeeder.InsertAsync(_fixture.Store, tenantB, email, password: "PassB12345");

        var sut = NewSut();

        // Drive tenant A to full lockout with 10 wrong-password attempts.
        for (int i = 0; i < 10; i++)
        {
            await sut.LoginTenantAsync(email, "wrong", tenantA);
        }

        // Tenant A is now locked — even correct password is refused.
        var (tokenA, errorA, retryA) = await sut.LoginTenantAsync(email, "PassA12345", tenantA);
        Assert.Null(tokenA);
        Assert.NotNull(errorA);
        Assert.NotNull(retryA);

        // Tenant B is completely unaffected — correct password still works.
        var (tokenB, errorB, _) = await sut.LoginTenantAsync(email, "PassB12345", tenantB);
        Assert.NotNull(tokenB);
        Assert.Null(errorB);
    }

    /// <summary>
    /// Failed system-realm logins for an email must not lock the same-email tenant identity.
    /// </summary>
    [Fact]
    public async Task LoginSystemAsync_Lockout_DoesNotLockTenantIdentity()
    {
        await EnsureJwtSecretAsync();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"shared-{Guid.NewGuid():N}@x.test";

        await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "TenantPass12345");
        await SystemAdminSeeder.InsertAsync(_fixture.Store, email, "SysPass12345");

        var sut = NewSut();

        // Drive the system realm to full lockout with 10 wrong-password attempts.
        for (int i = 0; i < 10; i++)
        {
            await sut.LoginSystemAsync(email, "wrong");
        }

        // System realm is now locked.
        var (sysToken, _, sysRetry) = await sut.LoginSystemAsync(email, "SysPass12345");
        Assert.Null(sysToken);
        Assert.NotNull(sysRetry);

        // Tenant identity with the same email is completely unaffected.
        var (tenantToken, tenantError, _) = await sut.LoginTenantAsync(email, "TenantPass12345", orgId);
        Assert.NotNull(tenantToken);
        Assert.Null(tenantError);
    }

    /// <summary>
    /// A successful login in tenant A must not clear tenant B's failure counter for the same
    /// email.
    /// </summary>
    [Fact]
    public async Task LoginTenantAsync_SuccessInTenantA_DoesNotClearTenantBCounter()
    {
        await EnsureJwtSecretAsync();
        string tenantA = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string tenantB = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"shared-clear-{Guid.NewGuid():N}@x.test";

        await UserSeeder.InsertAsync(_fixture.Store, tenantA, email, password: "PassA12345");
        await UserSeeder.InsertAsync(_fixture.Store, tenantB, email, password: "PassB12345");

        var sut = NewSut();

        // Accumulate 5 failures for tenant B.
        for (int i = 0; i < 5; i++)
        {
            await sut.LoginTenantAsync(email, "wrong", tenantB);
        }

        // Successful login for tenant A.
        var (tokenA, _, _) = await sut.LoginTenantAsync(email, "PassA12345", tenantA);
        Assert.NotNull(tokenA);

        // Tenant B's counter is still at 5 — not zeroed by A's success.
        await using var conn = await _fixture.Store.OpenAsync();
        long bCount = await conn.ExecuteScalarAsync<long>(
            "SELECT failed_count FROM login_attempts WHERE email_hash = @h",
            new { h = HashLockoutKey("tenant", tenantB, email) });
        Assert.Equal(5, bCount);
    }

    /// <summary>
    /// Mixed partial-failure scenario (house rule): interleave failures across three
    /// identities (tenant A, tenant B, system) that share an email. After 9 failures in
    /// each realm, no identity should be locked. Then drive tenant A to exactly 10 and assert
    /// only tenant A is locked while tenant B and system remain usable.
    /// </summary>
    [Fact]
    public async Task LockoutCounters_PartialFailure_OnlyOverThresholdIdentityIsLocked()
    {
        await EnsureJwtSecretAsync();
        string tenantA = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string tenantB = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"partial-{Guid.NewGuid():N}@x.test";

        await UserSeeder.InsertAsync(_fixture.Store, tenantA, email, password: "PassA12345");
        await UserSeeder.InsertAsync(_fixture.Store, tenantB, email, password: "PassB12345");
        await SystemAdminSeeder.InsertAsync(_fixture.Store, email, "SysPass12345");

        var sut = NewSut();

        // Interleave: 9 failures for each identity.
        for (int i = 0; i < 9; i++)
        {
            await sut.LoginTenantAsync(email, "wrong", tenantA);
            await sut.LoginTenantAsync(email, "wrong", tenantB);
            await sut.LoginSystemAsync(email, "wrong");
        }

        // At 9 failures each, no identity is locked yet.
        var (tA_9, _, _) = await sut.LoginTenantAsync(email, "PassA12345", tenantA);
        // 9th tenant-A failure was already recorded above; this is the 10th attempt with
        // correct password: it is still before the threshold fires (threshold is >= 10
        // failures). Counter starts at 0 and 9 wrongs means the counter is at 9; the
        // 10th wrong would fire it. Correct password on 10th attempt should succeed.
        Assert.NotNull(tA_9);

        // Reset tenant A's counter (success clears it), then inflict exactly 10 wrong.
        for (int i = 0; i < 10; i++)
        {
            await sut.LoginTenantAsync(email, "wrong", tenantA);
        }

        // Tenant A is now locked.
        var (lockedTokenA, _, lockedRetryA) = await sut.LoginTenantAsync(email, "PassA12345", tenantA);
        Assert.Null(lockedTokenA);
        Assert.NotNull(lockedRetryA);

        // Tenant B and system remain unlocked and usable despite the same email.
        var (tokenB, errorB, _) = await sut.LoginTenantAsync(email, "PassB12345", tenantB);
        Assert.NotNull(tokenB);
        Assert.Null(errorB);

        var (sysToken, sysError, _) = await sut.LoginSystemAsync(email, "SysPass12345");
        Assert.NotNull(sysToken);
        Assert.Null(sysError);
    }
}
