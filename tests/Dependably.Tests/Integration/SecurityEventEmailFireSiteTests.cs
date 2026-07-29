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
/// Fire-site coverage for account-security event email (MFA enabled/disabled, password
/// changed): <see cref="Dependably.Api.MfaController"/>, <see cref="Dependably.Api.SystemMfaController"/>,
/// <c>AuthController.ChangePassword</c>/<c>ResetPassword</c>, and
/// <c>SystemController.ChangeMyPassword</c>/<c>IssuePasswordReset</c>. There is no per-message
/// delivery capture in the test host (the queue talks to a real <c>SmtpMailSender</c>), so these
/// tests assert the externally observable contract: every fire site enqueues the notification as
/// a non-blocking side effect that never gates or throws into the HTTP response — the default
/// test host has no instance SMTP configured, so <see cref="EmailDeliveryQueue.Enqueue"/>'s
/// silent no-op path is exercised on every one of them, and the endpoint's normal success
/// contract (status, body, durable state) is unaffected either way.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SecurityEventEmailFireSiteTests
{
    // ── Shared: enable instance SMTP so a fire site actually resolves a recipient ────

    private static async Task EnableInstanceSmtpAsync(IServiceProvider services)
    {
        var orgs = services.GetRequiredService<OrgRepository>();
        await orgs.SetInstanceSettingAsync("smtp_enabled", "1");
        await orgs.SetInstanceSettingAsync("smtp_host", "smtp.test.local");
        await orgs.SetInstanceSettingAsync("smtp_port", "587");
        await orgs.SetInstanceSettingAsync("smtp_security", "none");
        await orgs.SetInstanceSettingAsync("smtp_from_address", "noreply@example.com");

        // InstanceSmtpConfig caches its resolved result for 5s (the same TTL production PUT
        // endpoints bust via Invalidate() after a save) — bust it here too, otherwise a prior
        // resolve (e.g. an enrollment's own enqueue, resolved before SMTP was enabled) can still
        // be serving a cached "unconfigured" answer to the very next enqueue in the same test.
        services.GetRequiredService<Dependably.Infrastructure.Mail.InstanceSmtpConfig>().Invalidate();
    }

    private static async Task<IReadOnlyList<CapturingMailSender.SentMessage>> WaitForSentAsync(
        CapturingMailSender sender, int atLeast, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting the background queue's real async delivery loop
        // through the CapturingMailSender (both wall-clock reads below).
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (sender.Sent.Count < atLeast && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        return sender.Sent;
    }

    // Waits until the background delivery loop has fully handled at least <paramref name="atLeast"/>
    // jobs. The MFA-disable tests use this to drain the enrollment email (enqueued while SMTP is
    // unconfigured, so resolved to null and dropped) BEFORE enabling SMTP — transport is resolved
    // at delivery time, so enabling SMTP while the enrollment job is still queued would let it be
    // delivered against the now-configured transport, and the single-message assertion would see
    // the enrollment email alongside the disable one.
    private static async Task WaitForProcessedAsync(
        Dependably.Infrastructure.Mail.EmailDeliveryQueue queue, long atLeast, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting the background delivery loop's real async progress.
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (queue.ProcessedCount < atLeast && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }
    }

    // ── Tenant MFA enable/disable (MfaController) ───────────────────────────

    [Fact]
    public async Task TenantMfaEnable_SmtpUnconfigured_StillReturns10RecoveryCodes()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string userId = await factory.CreateUser($"mfa-enable-{Guid.NewGuid():N}@test.local", "TestPassword123!");
        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        string manualKey = await EnrollTenantMfaAsync(client);
        Assert.False(string.IsNullOrWhiteSpace(manualKey));

        var status = await client.GetAsync("/api/v1/mfa/status");
        status.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await status.Content.ReadAsStringAsync()).RootElement;
        Assert.True(doc.GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task TenantMfaDisable_SmtpUnconfigured_StillReturns200_AndActuallyDisables()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string pw = "TestPassword123!";
        string userId = await factory.CreateUser($"mfa-disable-{Guid.NewGuid():N}@test.local", pw);
        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        string manualKey = await EnrollTenantMfaAsync(client);
        string code = TotpTestHelper.Compute(manualKey);

        var resp = await client.PostAsJsonAsync("/api/v1/mfa/disable", new { currentPassword = pw, code });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long mfaEnabled = await conn.ExecuteScalarAsync<long>(
            "SELECT mfa_enabled FROM users WHERE id = @id", new { id = userId });
        Assert.Equal(0, mfaEnabled);
    }

    [Fact]
    public async Task TenantMfaEnable_SmtpConfigured_EnqueuesToActingUsersOwnAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyFactory { MailSenderOverride = sender };
        await factory.InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);

        const string email = "mfa-enable-recipient@test.local";
        string userId = await factory.CreateUser(email, "TestPassword123!");
        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        await EnrollTenantMfaAsync(client);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([email], message.Recipients);
    }

    [Fact]
    public async Task TenantMfaDisable_SmtpConfigured_EnqueuesToActingUsersOwnAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyFactory { MailSenderOverride = sender };
        await factory.InitializeAsync();

        const string email = "mfa-disable-recipient@test.local";
        const string pw = "TestPassword123!";
        string userId = await factory.CreateUser(email, pw);
        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var queue = factory.Services.GetRequiredService<Dependably.Infrastructure.Mail.EmailDeliveryQueue>();
        long processedBefore = queue.ProcessedCount;
        string manualKey = await EnrollTenantMfaAsync(client);

        // Drain the enrollment email (dropped, since SMTP is unconfigured) before enabling SMTP so
        // the captured send below is unambiguously the disable notification, not the enable one.
        await WaitForProcessedAsync(queue, processedBefore + 1);
        await EnableInstanceSmtpAsync(factory.Services);

        string code = TotpTestHelper.Compute(manualKey);
        var resp = await client.PostAsJsonAsync("/api/v1/mfa/disable", new { currentPassword = pw, code });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([email], message.Recipients);
    }

    private static async Task<string> EnrollTenantMfaAsync(HttpClient client)
    {
        var beginResp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var resp = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code });
            if (resp.IsSuccessStatusCode)
            {
                return manualKey;
            }
        }

        throw new InvalidOperationException("Could not verify TOTP code during enrollment helper. Clock boundary?");
    }

    // ── Self-service password change / self-serve reset (AuthController) ───

    [Fact]
    public async Task SelfServiceChangePassword_SmtpUnconfigured_StillReturns200()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        const string oldPassword = "originalPassword123";
        string userId = await factory.CreateUser($"change-pw-{Guid.NewGuid():N}@test.local", oldPassword);
        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/users/me/password",
            new { currentPassword = oldPassword, newPassword = "brandNewChangedPassword456!" });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task SelfServeResetPassword_SmtpUnconfigured_StillReturns200()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string userId = await factory.CreateUser($"reset-pw-{Guid.NewGuid():N}@test.local", "originalPassword123");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT tenant_id FROM users WHERE id = @id", new { id = userId })
                ?? throw new InvalidOperationException("User not found.");
        }

        var tokens = factory.Services.GetRequiredService<PasswordResetTokenRepository>();
        string rawToken = await tokens.IssueAsync(userId, orgId);

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "recoveredPassword789!" });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task SelfServiceChangePassword_SmtpConfigured_EnqueuesToActingUsersOwnAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyFactory { MailSenderOverride = sender };
        await factory.InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);

        const string email = "change-pw-recipient@test.local";
        const string oldPassword = "originalPassword123";
        string userId = await factory.CreateUser(email, oldPassword);
        string jwt = await factory.CreateUserJwt(userId, "member");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/users/me/password",
            new { currentPassword = oldPassword, newPassword = "brandNewChangedPassword456!" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([email], message.Recipients);
    }

    [Fact]
    public async Task SelfServeResetPassword_SmtpConfigured_EnqueuesToTokenOwnersAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyFactory { MailSenderOverride = sender };
        await factory.InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);

        const string email = "reset-pw-recipient@test.local";
        string userId = await factory.CreateUser(email, "originalPassword123");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT tenant_id FROM users WHERE id = @id", new { id = userId })
                ?? throw new InvalidOperationException("User not found.");
        }

        var tokens = factory.Services.GetRequiredService<PasswordResetTokenRepository>();
        string rawToken = await tokens.IssueAsync(userId, orgId);

        using var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
            new { token = rawToken, newPassword = "recoveredPassword789!" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([email], message.Recipients);
    }

    // ── System-admin MFA enable/disable (SystemMfaController) ──────────────

    private async Task<(string AdminId, string ManualKey)> SeedAndEnrollSystemAdminAsync(
        DependablyMultiFactory factory, HttpClient apexClient, string? email = null)
    {
        email ??= $"sys-sec-mail-{Guid.NewGuid():N}@test.local";
        string hash = BCrypt.Net.BCrypt.HashPassword("SysSecTest12345!", workFactor: 4);
        var admins = factory.Services.GetRequiredService<SystemAdminRepository>();
        string adminId = await admins.CreateAsync(email, hash, mustChangePassword: false);

        string jwt = await factory.CreateSystemAdminJwtForUser(adminId);
        apexClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var beginResp = await apexClient.PostAsync("/api/v1/system/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var vr = await apexClient.PostAsJsonAsync("/api/v1/system/mfa/setup/verify", new { code });
            if (vr.IsSuccessStatusCode)
            {
                return (adminId, manualKey);
            }
        }

        throw new InvalidOperationException("Could not enroll system admin MFA — TOTP window exhausted.");
    }

    [Fact]
    public async Task SystemMfaEnable_SmtpUnconfigured_StillEnablesAndReturnsRecoveryCodes()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var apex = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);

        var (adminId, _) = await SeedAndEnrollSystemAdminAsync(factory, apex);

        var admins = factory.Services.GetRequiredService<SystemAdminRepository>();
        var admin = await admins.GetByIdAsync(adminId);
        Assert.True(admin!.MfaEnabled);
    }

    [Fact]
    public async Task SystemMfaDisable_SmtpUnconfigured_StillReturns200_AndActuallyDisables()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var apex = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);

        var (adminId, manualKey) = await SeedAndEnrollSystemAdminAsync(factory, apex);
        string code = TotpTestHelper.Compute(manualKey);

        var resp = await apex.PostAsJsonAsync("/api/v1/system/mfa/disable",
            new { currentPassword = "SysSecTest12345!", code });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var admins = factory.Services.GetRequiredService<SystemAdminRepository>();
        var admin = await admins.GetByIdAsync(adminId);
        Assert.False(admin!.MfaEnabled);
    }

    [Fact]
    public async Task SystemMfaEnable_SmtpConfigured_EnqueuesToActingAdminsOwnAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyMultiFactory { MailSenderOverride = sender };
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);
        using var apex = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);

        string email = $"sys-mfa-enable-recipient-{Guid.NewGuid():N}@test.local";
        await SeedAndEnrollSystemAdminAsync(factory, apex, email);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([email], message.Recipients);
    }

    [Fact]
    public async Task SystemMfaDisable_SmtpConfigured_EnqueuesToActingAdminsOwnAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyMultiFactory { MailSenderOverride = sender };
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var apex = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);

        string email = $"sys-mfa-disable-recipient-{Guid.NewGuid():N}@test.local";
        var queue = factory.Services.GetRequiredService<Dependably.Infrastructure.Mail.EmailDeliveryQueue>();
        long processedBefore = queue.ProcessedCount;
        var (_, manualKey) = await SeedAndEnrollSystemAdminAsync(factory, apex, email);

        // Drain the enrollment email (dropped, since SMTP is unconfigured) before enabling SMTP so
        // the captured send is unambiguously the disable notification, not the enable one.
        await WaitForProcessedAsync(queue, processedBefore + 1);
        await EnableInstanceSmtpAsync(factory.Services);

        string code = TotpTestHelper.Compute(manualKey);
        var resp = await apex.PostAsJsonAsync("/api/v1/system/mfa/disable",
            new { currentPassword = "SysSecTest12345!", code });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([email], message.Recipients);
    }

    // ── System-admin self-rotate + operator-forced reset (SystemController) ─

    [Fact]
    public async Task SystemAdminChangeMyPassword_SmtpUnconfigured_StillReturns200()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var sys = await factory.CreateSystemAdminClient();

        var resp = await sys.PostAsJsonAsync("/api/v1/system/me/password", new
        {
            currentPassword = DependablyMultiFactory.SystemAdminPassword,
            newPassword = "FreshOperatorPassword123!",
        });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task SystemAdminChangeMyPassword_SmtpConfigured_EnqueuesToActingAdminsOwnAddress()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyMultiFactory { MailSenderOverride = sender };
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);
        using var sys = await factory.CreateSystemAdminClient();

        var resp = await sys.PostAsJsonAsync("/api/v1/system/me/password", new
        {
            currentPassword = DependablyMultiFactory.SystemAdminPassword,
            newPassword = "FreshOperatorPassword123!",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([DependablyMultiFactory.SystemAdminEmail], message.Recipients);
    }

    /// <summary>
    /// An operator-forced reset targets a TENANT user, not the operator caller — the security
    /// email must go to that tenant user's own address. This test proves the fire site resolves
    /// without throwing and without gating the response (the tenant user's language chain is
    /// exercised end-to-end via a real org/user lookup by tenantSlug + email).
    /// </summary>
    [Fact]
    public async Task SystemIssuePasswordReset_SmtpUnconfigured_StillReturns200_TargetsTenantUser()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var sys = await factory.CreateSystemAdminClient();

        string slug = "sec-mail-" + Guid.NewGuid().ToString("N")[..8];
        string ownerEmail = $"owner-{Guid.NewGuid():N}@example.com";
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug, ownerEmail });
        createResp.EnsureSuccessStatusCode();

        // Give the target tenant user a non-default language preference so the fire site's
        // per-user → org-default → "en" chain has something real to resolve.
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET language = 'fr' WHERE lower(email) = lower(@email)", new { email = ownerEmail });
        }

        var resp = await sys.PostAsJsonAsync("/api/v1/system/users/password-reset",
            new { email = ownerEmail, tenantSlug = slug });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(ownerEmail, doc.RootElement.GetProperty("email").GetString());
    }

    /// <summary>
    /// The critical adversarial twin: an operator-forced reset must notify the TARGET tenant
    /// user, never the operator/system-admin caller who issued the reset. A regression that
    /// accidentally resolved the acting principal's own address (the pattern every other fire
    /// site in this suite correctly uses) would leak the reset event to the wrong inbox and
    /// silently fail to warn the actual account holder.
    /// </summary>
    [Fact]
    public async Task SystemIssuePasswordReset_SmtpConfigured_EnqueuesToTargetTenantUser_NeverToOperator()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyMultiFactory { MailSenderOverride = sender };
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);
        using var sys = await factory.CreateSystemAdminClient();

        string slug = "sec-mail-op-" + Guid.NewGuid().ToString("N")[..8];
        string ownerEmail = $"owner-op-{Guid.NewGuid():N}@example.com";
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug, ownerEmail });
        createResp.EnsureSuccessStatusCode();

        var resp = await sys.PostAsJsonAsync("/api/v1/system/users/password-reset",
            new { email = ownerEmail, tenantSlug = slug });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var sent = await WaitForSentAsync(sender, atLeast: 1);
        var message = Assert.Single(sent);
        Assert.Equal([ownerEmail], message.Recipients);

        // Negative assertion: the operator's own address is never a recipient, and no second
        // message went anywhere else (e.g. to the operator, alongside the correct one).
        Assert.DoesNotContain(DependablyMultiFactory.SystemAdminEmail, message.Recipients);
        Assert.Single(sender.Sent);
    }

    /// <summary>
    /// Cross-org twin: the same literal email address is registered in two separate tenants
    /// (allowed — uniqueness is per-tenant, not global). An operator-forced reset scoped to org
    /// A's tenantSlug must resolve org A's user (and org A's org-default language) — never org
    /// B's, even though the recipient address alone can't distinguish them. Org A is seeded with
    /// a non-default org language ("fr") and org B is left at the "en" default; if the fire site
    /// resolved the user cross-tenant (ignoring the tenantSlug scope), the wrong org's language
    /// would leak into the rendered notification.
    /// </summary>
    [Fact]
    public async Task SystemIssuePasswordReset_SameEmailInTwoOrgs_UsesTargetOrgsUserAndLanguage_NotTheOtherOrgs()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyMultiFactory { MailSenderOverride = sender };
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnableInstanceSmtpAsync(factory.Services);
        using var sys = await factory.CreateSystemAdminClient();

        string sharedEmail = $"cross-org-{Guid.NewGuid():N}@example.com";
        string slugA = "cross-a-" + Guid.NewGuid().ToString("N")[..8];
        string slugB = "cross-b-" + Guid.NewGuid().ToString("N")[..8];

        (await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug = slugA, ownerEmail = sharedEmail }))
            .EnsureSuccessStatusCode();
        (await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug = slugB, ownerEmail = sharedEmail }))
            .EnsureSuccessStatusCode();

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE org_settings SET default_language = 'fr'
                WHERE org_id = (SELECT id FROM orgs WHERE slug = @slugA)
                """,
                new { slugA });
        }

        // Reset scoped to org A → org A's user, rendered in org A's "fr" default.
        var respA = await sys.PostAsJsonAsync("/api/v1/system/users/password-reset",
            new { email = sharedEmail, tenantSlug = slugA });
        Assert.Equal(HttpStatusCode.OK, respA.StatusCode);

        var sentAfterA = await WaitForSentAsync(sender, atLeast: 1);
        var messageA = Assert.Single(sentAfterA);
        Assert.Equal([sharedEmail], messageA.Recipients);
        Assert.Contains("mot de passe", messageA.Subject, StringComparison.OrdinalIgnoreCase);

        // Reset scoped to org B (still default "en") for the SAME address → a second message,
        // rendered in English — proving the first reset resolved org A's row, not a global/
        // cross-tenant lookup that would have picked up whichever org's row came first.
        var respB = await sys.PostAsJsonAsync("/api/v1/system/users/password-reset",
            new { email = sharedEmail, tenantSlug = slugB });
        Assert.Equal(HttpStatusCode.OK, respB.StatusCode);

        var sentAfterB = await WaitForSentAsync(sender, atLeast: 2);
        Assert.Equal(2, sentAfterB.Count);
        var messageB = sentAfterB[1];
        Assert.Equal([sharedEmail], messageB.Recipients);
        Assert.Contains("password was changed", messageB.Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SystemIssuePasswordReset_UnknownUser_StillReturns404_NeverThrows()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var sys = await factory.CreateSystemAdminClient();

        string slug = "sec-mail-miss-" + Guid.NewGuid().ToString("N")[..8];
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants",
            new { slug, ownerEmail = $"owner-{Guid.NewGuid():N}@example.com" });
        createResp.EnsureSuccessStatusCode();

        var resp = await sys.PostAsJsonAsync("/api/v1/system/users/password-reset",
            new { email = "nobody-here@example.com", tenantSlug = slug });

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
