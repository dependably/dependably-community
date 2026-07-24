using System.Linq;
using System.Net;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for the self-serve "forgot password" flow (<c>POST /api/v1/auth/forgot-password</c>
/// and <c>POST /api/v1/auth/reset-password</c>): the enumeration defense (identical response for a
/// known vs. unknown email, token never in the response body), the one-shot token lifecycle
/// (single-use, expiry), the full credential-invalidation blast radius a reset produces
/// (token_version bump so outstanding session JWTs go stale, security_stamp rotation, lockout
/// clearing), and the replay defense (any other credential-change path voids an outstanding
/// reset link). Each test constructs its own <see cref="DependablyFactory"/> (rather than sharing
/// one via <c>IClassFixture</c>) so a frozen clock can control the 30-minute expiry window
/// precisely.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PasswordResetTests : IAsyncLifetime
{
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Forgot-password: enumeration defense ────────────────────────────────

    [Fact]
    public async Task ForgotPassword_KnownEmail_Returns202_AndIssuesAResetToken()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "forgot-known@example.com";
        string userId = await factory.CreateUser(email, "originalPassword123");

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });

        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        int pending = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = @id AND consumed_at IS NULL",
            new { id = userId });
        Assert.Equal(1, pending);
    }

    /// <summary>Enumeration twin: an unknown email gets the exact same response shape, and no
    /// token row is ever created for it.</summary>
    [Fact]
    public async Task ForgotPassword_UnknownEmail_Returns202_SameShape_NoTokenIssued()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            _ = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM password_reset_tokens");
        }

        using var client = factory.CreateClient();
        string known = await factory.CreateUser("forgot-known-twin@example.com", "originalPassword123");
        var knownResp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password",
            new { email = "forgot-known-twin@example.com" });
        var unknownResp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password",
            new { email = "definitely-not-registered@example.com" });

        // Identical status and (empty) body shape regardless of whether the email resolved.
        Assert.Equal(HttpStatusCode.Accepted, knownResp.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, unknownResp.StatusCode);
        Assert.Equal(await knownResp.Content.ReadAsStringAsync(), await unknownResp.Content.ReadAsStringAsync());

        await using var verify = await store.OpenAsync();
        int tokensForUnknown = await verify.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM password_reset_tokens prt
            JOIN users u ON u.id = prt.user_id
            WHERE u.email = @email
            """,
            new { email = "definitely-not-registered@example.com" });
        Assert.Equal(0, tokensForUnknown);

        int tokensForKnown = await verify.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = @id", new { id = known });
        Assert.Equal(1, tokensForKnown);
    }

    /// <summary>The response body never carries the raw token — it reaches the user only via
    /// the emailed link, never in the HTTP response.</summary>
    [Fact]
    public async Task ForgotPassword_ResponseBody_NeverContainsToken()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "forgot-no-leak@example.com";
        await factory.CreateUser(email, "originalPassword123");

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });

        string body = await resp.Content.ReadAsStringAsync();
        Assert.True(string.IsNullOrEmpty(body), $"Expected an empty response body; got: {body}");
    }

    [Fact]
    public async Task ForgotPassword_MissingEmail_Returns400()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = "" });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── Forgot-password: request observability ───────────────────────────────

    /// <summary>A request for a known email writes exactly one tenant-scoped audit row naming the
    /// resolved user as actor, with a non-null source IP.</summary>
    [Fact]
    public async Task ForgotPassword_KnownEmail_WritesExactlyOnePasswordResetRequestedAuditRow()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "forgot-audit-known@example.com";
        string userId = await factory.CreateUser(email, "originalPassword123");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT tenant_id FROM users WHERE id = @id", new { id = userId })
                ?? throw new InvalidOperationException("tenant not found");
        }

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        await using var verify = await store.OpenAsync();
        var rows = (await verify.QueryAsync<(string Scope, string? OrgId, string? ActorId, string? SourceIp)>(
            "SELECT scope, org_id, actor_id, source_ip FROM audit_log WHERE action = 'user.password_reset_requested' AND actor_id = @userId",
            new { userId })).ToList();

        var (scope, rowOrgId, actorId, sourceIp) = Assert.Single(rows);
        Assert.Equal("tenant", scope);
        Assert.Equal(orgId, rowOrgId);
        Assert.Equal(userId, actorId);
        Assert.False(string.IsNullOrEmpty(sourceIp));
    }

    /// <summary>Adversarial twin A: the response is still 202 with the same empty-body shape as
    /// the unknown-email case even though the request now writes an audit row server-side.</summary>
    [Fact]
    public async Task ForgotPassword_KnownEmail_ResponseStillCarriesNoEnumerationSignal()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string knownEmail = "forgot-audit-noenum-known@example.com";
        await factory.CreateUser(knownEmail, "originalPassword123");

        using var client = factory.CreateClient();
        var knownResp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = knownEmail });
        var unknownResp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password",
            new { email = "forgot-audit-noenum-unknown@example.com" });

        Assert.Equal(HttpStatusCode.Accepted, knownResp.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, unknownResp.StatusCode);
        Assert.Equal(await knownResp.Content.ReadAsStringAsync(), await unknownResp.Content.ReadAsStringAsync());
    }

    /// <summary>An unmatched email is itself a security-recon signal: it now writes exactly one
    /// <c>user.password_reset_requested</c> row with a null actor (there is no account to
    /// attribute it to) and <c>detail.matched == false</c> — the enumeration defense lives
    /// entirely in the identical HTTP response, never in whether the row exists.</summary>
    [Fact]
    public async Task ForgotPassword_UnknownEmail_WritesExactlyOnePasswordResetRequestedAuditRow_MatchedFalse()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string unknownEmail = "forgot-audit-unknown@example.com";

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("default org not found");
        }

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = unknownEmail });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        await using var verify = await store.OpenAsync();
        var rows = (await verify.QueryAsync<(string Scope, string? OrgId, string? ActorId, string? SourceIp, string Detail)>(
            "SELECT scope, org_id, actor_id, source_ip, detail FROM audit_log WHERE action = 'user.password_reset_requested'"))
            .ToList();

        var (scope, rowOrgId, actorId, sourceIp, detail) = Assert.Single(rows);
        Assert.Equal("tenant", scope);
        Assert.Equal(orgId, rowOrgId);
        Assert.Null(actorId);
        Assert.False(string.IsNullOrEmpty(sourceIp));

        var parsed = System.Text.Json.JsonDocument.Parse(detail);
        Assert.False(parsed.RootElement.GetProperty("matched").GetBoolean());
        Assert.Equal(LoginService.HashEmail(unknownEmail), parsed.RootElement.GetProperty("email_hash").GetString());
        Assert.Equal("tenant", parsed.RootElement.GetProperty("realm").GetString());
    }

    /// <summary>A matched email writes the same audit row shape with <c>detail.matched == true</c>
    /// and the resolved user as actor.</summary>
    [Fact]
    public async Task ForgotPassword_KnownEmail_AuditRow_HasMatchedTrue()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "forgot-audit-outcome-known@example.com";
        string userId = await factory.CreateUser(email, "originalPassword123");

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var verify = await store.OpenAsync();
        string? detail = await verify.ExecuteScalarAsync<string?>(
            "SELECT detail FROM audit_log WHERE action = 'user.password_reset_requested' AND actor_id = @userId",
            new { userId });

        Assert.NotNull(detail);
        var parsed = System.Text.Json.JsonDocument.Parse(detail!);
        Assert.True(parsed.RootElement.GetProperty("matched").GetBoolean());
        Assert.Equal(LoginService.HashEmail(email), parsed.RootElement.GetProperty("email_hash").GetString());
        Assert.Equal("tenant", parsed.RootElement.GetProperty("realm").GetString());
    }

    /// <summary>Adversarial twin — no side effects on the unmatched path: an unknown-email
    /// request still issues no <c>password_reset_tokens</c> row. The new audit row proves the
    /// request was observed; it must not also fabricate reset state for a non-account.</summary>
    [Fact]
    public async Task ForgotPassword_UnknownEmail_IssuesNoPasswordResetTokenRow()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string unknownEmail = "forgot-no-token-unknown@example.com";

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = unknownEmail });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var verify = await store.OpenAsync();
        long tokensForUnknown = await verify.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM password_reset_tokens prt
            JOIN users u ON u.id = prt.user_id
            WHERE u.email = @email
            """,
            new { email = unknownEmail });
        Assert.Equal(0, tokensForUnknown);
    }

    /// <summary>Adversarial twin C: the raw email address never lands in the written audit row —
    /// not in <c>detail</c>, not in <c>source_ip</c>, nowhere. <c>detail</c> carries only the
    /// <c>via</c>/<c>matched</c>/<c>email_hash</c>/<c>realm</c> fields, and <c>email_hash</c> is
    /// the SHA-256 pseudonym, never the raw address, for both the matched and unmatched paths.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ForgotPassword_AuditRow_NeverContainsTheRawEmailAddress(bool knownEmail)
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string email = knownEmail ? "forgot-audit-noleak-known@example.com" : "forgot-audit-noleak-unknown@example.com";
        string? userId = knownEmail ? await factory.CreateUser(email, "originalPassword123") : null;

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var verify = await store.OpenAsync();
        string sql = knownEmail
            ? "SELECT detail, source_ip FROM audit_log WHERE action = 'user.password_reset_requested' AND actor_id = @userId"
            : "SELECT detail, source_ip FROM audit_log WHERE action = 'user.password_reset_requested' AND actor_id IS NULL";
        var (detail, sourceIp) = await verify.QuerySingleAsync<(string Detail, string? SourceIp)>(sql, new { userId });

        Assert.DoesNotContain(email, detail);
        Assert.True(string.IsNullOrEmpty(sourceIp) || !sourceIp!.Contains(email));
        var parsed = System.Text.Json.JsonDocument.Parse(detail);
        var props = parsed.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(p => p, StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { "email_hash", "matched", "realm", "via" }, props);
        Assert.Equal("self_serve_reset_link", parsed.RootElement.GetProperty("via").GetString());
        string emailHash = parsed.RootElement.GetProperty("email_hash").GetString()!;
        Assert.NotEqual(email, emailHash);
        Assert.Equal(LoginService.HashEmail(email), emailHash);
    }

    // ── Reset-password: happy path + full invalidation blast radius ─────────

    [Fact]
    public async Task ResetPassword_ValidToken_Returns200_ChangesPasswordAndRotatesSecurityStamp()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "reset-happy@example.com";
        const string oldPassword = "originalPassword123";
        const string newPassword = "brandNewPassword456!";
        string userId = await factory.CreateUser(email, oldPassword);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string oldHash;
        string? oldStamp;
        await using (var conn = await store.OpenAsync())
        {
            (oldHash, oldStamp) = await conn.QuerySingleAsync<(string, string?)>(
                "SELECT password_hash, security_stamp FROM users WHERE id = @id", new { id = userId });
        }

        string rawToken = await IssueResetTokenAsync(factory, userId);

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        await using var verify = await store.OpenAsync();
        var (newHash, newStamp) = await verify.QuerySingleAsync<(string, string?)>(
            "SELECT password_hash, security_stamp FROM users WHERE id = @id", new { id = userId });

        Assert.True(BCrypt.Net.BCrypt.Verify(newPassword, newHash));
        Assert.False(BCrypt.Net.BCrypt.Verify(oldPassword, newHash));
        Assert.NotEqual(oldHash, newHash);
        Assert.NotEqual(oldStamp, newStamp);

        // The new password logs in immediately; no auto-login was issued by the reset itself.
        using var login = factory.CreateClient();
        var loginResp = await login.PostAsJsonAsync("/api/v1/auth/login", new { email, password = newPassword });
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
    }

    /// <summary>A successful reset bumps token_version so a pre-reset session JWT is rejected —
    /// asserted as an exact equality on the DB value, not just "different".</summary>
    [Fact]
    public async Task ResetPassword_Success_BumpsTokenVersionExactly_RejectingOldSessionJwt()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "reset-tver@example.com";
        string userId = await factory.CreateUser(email, "originalPassword123");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        long versionBefore;
        await using (var conn = await store.OpenAsync())
        {
            versionBefore = await conn.ExecuteScalarAsync<long>(
                "SELECT token_version FROM users WHERE id = @id", new { id = userId });
        }

        // A session minted under the pre-reset token_version.
        string staleJwt = await factory.CreateUserJwt(userId, "member");
        using var staleClient = factory.CreateClientWithBearer(staleJwt);
        Assert.Equal(HttpStatusCode.OK, (await staleClient.GetAsync("/api/v1/auth/me")).StatusCode);

        string rawToken = await IssueResetTokenAsync(factory, userId);
        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "postResetPassword789!" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        await using var verify = await store.OpenAsync();
        long versionAfter = await verify.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });
        Assert.Equal(versionBefore + 1, versionAfter);

        // The stale session, minted before the reset, is now rejected.
        Assert.Equal(HttpStatusCode.Unauthorized, (await staleClient.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task ResetPassword_ClearsLockout_SoFreshLoginSucceedsRatherThanStayingLocked()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "reset-lockout@example.com";
        const string oldPassword = "originalPassword123";
        const string newPassword = "afterLockoutReset456!";
        string userId = await factory.CreateUser(email, oldPassword);

        // Exhaust the failed-attempt budget (10) to trip the lockout.
        using var attackClient = factory.CreateClient();
        for (int i = 0; i < 10; i++)
        {
            await attackClient.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong-password" });
        }

        // Confirm the account is genuinely locked: even the *correct* old password is rejected
        // with 429 (lockout is checked before credential verification).
        var lockedProbe = await attackClient.PostAsJsonAsync("/api/v1/auth/login", new { email, password = oldPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, lockedProbe.StatusCode);

        string rawToken = await IssueResetTokenAsync(factory, userId);
        using var resetClient = factory.CreateClient();
        var resetResp = await resetClient.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword });
        Assert.Equal(HttpStatusCode.OK, resetResp.StatusCode);

        // Lockout is cleared by the reset — a fresh login with the new password succeeds
        // immediately rather than still returning 429.
        using var freshClient = factory.CreateClient();
        var freshLogin = await freshClient.PostAsJsonAsync("/api/v1/auth/login", new { email, password = newPassword });
        Assert.Equal(HttpStatusCode.OK, freshLogin.StatusCode);
    }

    // ── Reset-password: single-use + expiry twins ────────────────────────────

    /// <summary>Single-use twin: consuming the same token twice returns 410 the second time.</summary>
    [Fact]
    public async Task ResetPassword_SecondConsumeOfSameToken_Returns410()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string userId = await factory.CreateUser("reset-single-use@example.com", "originalPassword123");
        string rawToken = await IssueResetTokenAsync(factory, userId);

        using var client = factory.CreateClient();
        var first = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "firstNewPassword123!" });
        var second = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "secondNewPassword456!" });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Gone, second.StatusCode);
    }

    /// <summary>Expiry: seeded far past the 30-minute boundary (2 hours) per the
    /// time-determinism rule against flipping near the cutoff.</summary>
    [Fact]
    public async Task ResetPassword_ExpiredToken_Returns410()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        await using var factory = new DependablyFactory { FrozenClock = clock };
        await factory.InitializeAsync();
        string userId = await factory.CreateUser("reset-expired@example.com", "originalPassword123");
        string rawToken = await IssueResetTokenAsync(factory, userId);

        clock.Advance(TimeSpan.FromHours(2));

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "tooLateNewPassword789!" });

        Assert.Equal(HttpStatusCode.Gone, resp.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_UnknownToken_Returns410()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = "totally-unknown-token", newPassword = "somePassword123!" });

        Assert.Equal(HttpStatusCode.Gone, resp.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_PolicyRejectedPassword_Returns400_AndDoesNotConsumeToken()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string userId = await factory.CreateUser("reset-weak@example.com", "originalPassword123");
        string rawToken = await IssueResetTokenAsync(factory, userId);

        using var client = factory.CreateClient();
        var weak = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);

        // The failed policy check must not have burned the link's single use.
        var strong = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "actuallyStrongPassword123!" });
        Assert.Equal(HttpStatusCode.OK, strong.StatusCode);
    }

    // ── Replay defense: any other credential-change path voids the reset link ────

    /// <summary>A password change via the authenticated change-password endpoint must void an
    /// outstanding self-serve reset link — the replay twin: without this, a stale reset link
    /// mailed earlier could reset the account back to a password the legitimate user just moved
    /// away from.</summary>
    [Fact]
    public async Task PasswordChange_VoidsOutstandingResetLink_SubsequentResetIs410()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "replay-change@example.com";
        const string oldPassword = "originalPassword123";
        string userId = await factory.CreateUser(email, oldPassword);

        string rawToken = await IssueResetTokenAsync(factory, userId);

        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClientWithBearer(jwt);
        var change = await client.PostAsJsonAsync("/api/v1/users/me/password",
            new { currentPassword = oldPassword, newPassword = "changedViaSessionPassword456!" });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        using var resetClient = factory.CreateClient();
        var replay = await resetClient.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "replayAttemptPassword789!" });

        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    /// <summary>An operator-issued temporary-password reset (<see cref="SystemAdminRepository.IssuePasswordResetAsync"/>)
    /// is itself a credential change and must void the same outstanding reset link.</summary>
    [Fact]
    public async Task OperatorIssuedReset_VoidsOutstandingResetLink_SubsequentResetIs410()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string email = "replay-operator@example.com";
        string userId = await factory.CreateUser(email, "originalPassword123");

        string rawToken = await IssueResetTokenAsync(factory, userId);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string tenantSlug;
        await using (var conn = await store.OpenAsync())
        {
            tenantSlug = await conn.ExecuteScalarAsync<string>(
                "SELECT o.slug FROM orgs o JOIN users u ON u.tenant_id = o.id WHERE u.id = @id", new { id = userId })
                ?? throw new InvalidOperationException("tenant slug not found");
        }

        var admins = factory.Services.GetRequiredService<SystemAdminRepository>();
        var issued = await admins.IssuePasswordResetAsync(email, tenantSlug);
        Assert.NotNull(issued);

        using var resetClient = factory.CreateClient();
        var replay = await resetClient.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "replayAfterOperatorReset123!" });

        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    // ── Cross-tenant twin ─────────────────────────────────────────────────────

    /// <summary>
    /// Two orgs each seed a user with the identical email. A reset token minted for org A's user
    /// must never be usable to reset org B's same-email user — the consume path is keyed on the
    /// token's own bound <c>user_id</c>, never re-derived from the email at consume time.
    /// </summary>
    [Fact]
    public async Task ResetPassword_TokenMintedForOrgAUser_CannotResetOrgBUserWithSameEmail()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string sharedEmail = "shared-cross-tenant@example.com";
        string userAId = await factory.CreateUser(sharedEmail, "orgAOriginalPassword123");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgBId;
        await using (var conn = await store.OpenAsync())
        {
            orgBId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = orgBId, slug = $"org-b-{Guid.NewGuid():N}" });
        }
        string userBId = Guid.NewGuid().ToString("N");
        await using (var conn = await store.OpenAsync())
        {
            string hash = BCrypt.Net.BCrypt.HashPassword("orgBOriginalPassword123", workFactor: 4);
            await conn.ExecuteAsync(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @tenantId, @email, @hash, 'member')",
                new { id = userBId, tenantId = orgBId, email = sharedEmail, hash });
        }

        string rawToken = await IssueResetTokenAsync(factory, userAId);

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "resetForOrgAOnly123!" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        await using var verify = await store.OpenAsync();
        var (hashA, tverA) = await verify.QuerySingleAsync<(string, long)>(
            "SELECT password_hash, token_version FROM users WHERE id = @id", new { id = userAId });
        var (hashB, tverB) = await verify.QuerySingleAsync<(string, long)>(
            "SELECT password_hash, token_version FROM users WHERE id = @id", new { id = userBId });

        // Org A's user actually changed…
        Assert.True(BCrypt.Net.BCrypt.Verify("resetForOrgAOnly123!", hashA));
        // …org B's same-email user is completely untouched: original password still verifies,
        // and its session-invalidation counter never moved.
        Assert.True(BCrypt.Net.BCrypt.Verify("orgBOriginalPassword123", hashB));
        Assert.Equal(1, tverB);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static async Task<string> IssueResetTokenAsync(DependablyFactory factory, string userId)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT tenant_id FROM users WHERE id = @id", new { id = userId })
                ?? throw new InvalidOperationException("User not found.");
        }

        var repo = factory.Services.GetRequiredService<PasswordResetTokenRepository>();
        return await repo.IssueAsync(userId, orgId);
    }
}
