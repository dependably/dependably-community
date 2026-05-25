using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using NSubstitute;
using Xunit;

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

    public LoginServiceUnitTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private LoginService NewSut()
    {
        var orgs = new OrgRepository(_fixture.Store);
        return new LoginService(
            _fixture.Store,
            orgs,
            new SystemAdminRepository(_fixture.Store),
            new SqliteLockoutStore(_fixture.Store),
            new AuditRepository(_fixture.Store),
            new ExternalIdentityRepository(_fixture.Store),
            _emitter);
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var email = $"u-{Guid.NewGuid():N}@x.test";
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email, role: "member", password: "RealPass12345");

        var sut = NewSut();
        var (token, error, retry) = await sut.LoginTenantAsync(email, "RealPass12345", orgId);

        Assert.NotNull(token);
        Assert.Null(error);
        Assert.Null(retry);

        await using var conn = await _fixture.Store.OpenAsync();
        var lastLogin = await conn.ExecuteScalarAsync<string?>(
            "SELECT last_login_at FROM users WHERE id = @id", new { id = userId });
        Assert.False(string.IsNullOrEmpty(lastLogin));

        // Audit + emitter both fired on success.
        var auditCount = await conn.ExecuteScalarAsync<long>(
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var email = $"u-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "Correct12345");

        var sut = NewSut();
        var first  = await sut.LoginTenantAsync(email, "wrong-1", orgId);
        var second = await sut.LoginTenantAsync(email, "wrong-2", orgId);

        Assert.Null(first.Token);
        Assert.NotNull(first.Error);
        Assert.Null(second.Token);

        // Lockout counter rose to 2.
        await using var conn = await _fixture.Store.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT failed_count FROM login_attempts WHERE email_hash = @h",
            new { h = HashEmail(email) });
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task LoginTenantAsync_LockedAccountStatus_RejectedSameAsInvalidCredentials()
    {
        await EnsureJwtSecretAsync();
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var email = $"locked-{Guid.NewGuid():N}@x.test";
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "Correct12345");
        await using (var conn = await _fixture.Store.OpenAsync())
            await conn.ExecuteAsync("UPDATE users SET account_status = 'locked' WHERE id = @id", new { id = userId });

        var (token, error, _) = await NewSut().LoginTenantAsync(email, "Correct12345", orgId);

        Assert.Null(token);
        Assert.NotNull(error);   // generic — must not reveal account_status
    }

    [Fact]
    public async Task LoginTenantAsync_PreviouslyLockedOut_Returns429WithRetryAfter()
    {
        await EnsureJwtSecretAsync();
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var email = $"lo-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email, password: "Correct12345");

        // Stamp lockout state directly.
        var emailHash = HashEmail(email);
        var lockedUntil = DateTimeOffset.UtcNow.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO login_attempts (email_hash, failed_count, locked_until) VALUES (@h, 10, @t)",
                new { h = emailHash, t = lockedUntil });
        }

        var (token, error, retry) = await NewSut().LoginTenantAsync(email, "Correct12345", orgId);

        Assert.Null(token);
        Assert.NotNull(error);
        Assert.NotNull(retry);
        Assert.True(retry!.Value > 0);
    }

    // ── LoginSystemAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task LoginSystemAsync_CorrectPassword_ReturnsSystemScopedJwt()
    {
        await EnsureJwtSecretAsync();
        var adminEmail = $"sys-{Guid.NewGuid():N}@example.com";
        var adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store, adminEmail, "SysPass12345");

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

    // ── LoginSamlAsync — three branches ──────────────────────────────────────

    [Fact]
    public async Task LoginSamlAsync_ExistingExternalIdentity_ReturnsTokenWithoutProvisioning()
    {
        await EnsureJwtSecretAsync();
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, "existing@x.test", role: "owner");
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var email = $"link-{Guid.NewGuid():N}@x.test";
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "saml-no-email", null);

        Assert.Null(result.Token);
        Assert.NotNull(result.Error);
        Assert.False(result.Provisioned);
    }

    [Fact]
    public async Task LoginSamlAsync_LinkedUserDisabled_Rejected()
    {
        await EnsureJwtSecretAsync();
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, "disabled@x.test", accountStatus: "disabled");
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        // Create then delete the user so the external identity becomes orphaned. We
        // CASCADE-delete the external identity along with the user, so we insert the
        // external_identity row again after the user is gone — with FKs off so the
        // orphan reference is accepted (mirrors a real post-delete race).
        var transientUserId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"transient-{Guid.NewGuid():N}@x.test");
        var externalId = Guid.NewGuid().ToString("N");
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var email = $"locked-link-{Guid.NewGuid():N}@x.test";
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var oldEmail = $"old-{Guid.NewGuid():N}@x.test";
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, oldEmail);
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid)
                VALUES (@id, @orgId, @userId, 'https://idp', 'rotated-nameid')
                """, new { id = Guid.NewGuid().ToString("N"), orgId, userId });
        }

        var newEmail = $"new-{Guid.NewGuid():N}@x.test";
        var result = await NewSut().LoginSamlAsync(orgId, "https://idp", "rotated-nameid", newEmail);

        Assert.NotNull(result.Token);
        Assert.Null(result.Error);

        await using var verify = await _fixture.Store.OpenAsync();
        var storedEmail = await verify.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE id = @id", new { id = userId });
        Assert.Equal(newEmail, storedEmail);
    }

    /// <summary>RecordSamlTestAsync writes a single audit row and does not provision.</summary>
    [Fact]
    public async Task RecordSamlTestAsync_WritesAuditRow()
    {
        await EnsureJwtSecretAsync();
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        await NewSut().RecordSamlTestAsync(orgId, "https://idp-test", "test-nameid", "test@x.test", actorId: null);

        await using var conn = await _fixture.Store.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.saml.test.success' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(1, count);
    }

    /// <summary>IssueTenantJwtForUser is the public re-entry point used by SamlController.</summary>
    [Fact]
    public void IssueTenantJwtForUser_ReturnsParseableJwt()
    {
        var token = NewSut().IssueTenantJwtForUser("user-1", "tenant-1", "owner", "unit-test-secret-min-32-chars-xxxxxx");
        Assert.False(string.IsNullOrEmpty(token));
        // Three base64url-encoded segments separated by dots.
        Assert.Equal(2, token.Count(c => c == '.'));
    }

    private static string HashEmail(string email)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(email.ToLowerInvariant()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
