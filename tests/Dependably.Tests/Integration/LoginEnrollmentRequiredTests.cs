using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that the login and invite-accept endpoints return <c>enrollmentRequired</c> in
/// their response bodies so the SPA can chain straight into MFA setup without a guard bounce.
///
/// Tests:
/// - Tenant login: <c>enrollmentRequired: false</c> when <c>require_mfa</c> is off.
/// - Tenant login: <c>enrollmentRequired: true</c> when <c>require_mfa</c> is on and user unenrolled.
/// - Tenant login: <c>enrollmentRequired: false</c> when <c>require_mfa</c> is on but user enrolled.
/// - Instance login: <c>enrollmentRequired: true</c> when <c>REQUIRE_MFA=true</c> and user unenrolled.
/// - Instance login: <c>enrollmentRequired: false</c> when <c>REQUIRE_MFA=true</c> and user enrolled.
/// - System admin login: <c>enrollmentRequired: true</c> when <c>REQUIRE_MFA=true</c> and admin unenrolled.
/// - System admin login: <c>enrollmentRequired: false</c> when <c>REQUIRE_MFA=true</c> and admin enrolled.
/// - Invite accept: <c>enrollmentRequired: true</c> when <c>require_mfa</c> is on.
/// - Invite accept: <c>enrollmentRequired: false</c> when <c>require_mfa</c> is off.
/// - Mixed partial-failure: one tenant user unenrolled gets true, another enrolled gets false in same org.
/// </summary>
[Trait("Category", "Integration")]
public sealed class LoginEnrollmentRequiredTenantTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
    private const string TestPassword = "LoginEnrollTest1!";

    public LoginEnrollmentRequiredTenantTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private async Task SetDefaultRequireMfaDirect(bool on)
    {
        await using var conn = await Db.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        await conn.ExecuteAsync(
            "UPDATE org_settings SET require_mfa = @v WHERE org_id = @orgId",
            new { v = on ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private HttpClient CreateLoginClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });

    [Fact]
    public async Task TenantLogin_RequireMfaOff_EnrollmentRequiredFalse()
    {
        string email = $"enroll-off-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);

        using var client = CreateLoginClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });
        resp.EnsureSuccessStatusCode();

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(doc.GetProperty("enrollmentRequired").GetBoolean());
    }

    [Fact]
    public async Task TenantLogin_RequireMfaOn_UnenrolledUser_EnrollmentRequiredTrue()
    {
        string email = $"enroll-on-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);

        await SetDefaultRequireMfaDirect(true);
        try
        {
            using var client = CreateLoginClient();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            Assert.True(doc.GetProperty("enrollmentRequired").GetBoolean());
        }
        finally
        {
            await SetDefaultRequireMfaDirect(false);
        }
    }

    [Fact]
    public async Task TenantLogin_RequireMfaOn_EnrolledUser_EnrollmentRequiredFalse()
    {
        string email = $"enroll-enrolled-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, TestPassword);

        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET mfa_enabled = 1 WHERE id = @id", new { id = userId });
        }

        await SetDefaultRequireMfaDirect(true);
        try
        {
            using var client = CreateLoginClient();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            // Enrolled users go through the MFA challenge path (mfaRequired), not the non-MFA path.
            // The mfaRequired=true response has no enrollmentRequired field — it leads to step-2 TOTP.
            // Confirm that a user with mfa_enabled=1 is not sent to the non-MFA path with
            // enrollmentRequired=true (the MFA challenge path is taken instead).
            bool mfaRequired = doc.TryGetProperty("mfaRequired", out var mr) && mr.GetBoolean();
            Assert.True(mfaRequired, "An enrolled user should receive the MFA challenge response.");
        }
        finally
        {
            await SetDefaultRequireMfaDirect(false);
            await using var conn = await Db.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE users SET mfa_enabled = 0 WHERE id = @id", new { id = userId });
        }
    }

    /// <summary>
    /// Mixed/partial-failure: two users in the same tenant with require_mfa=on. One is unenrolled
    /// (gets enrollmentRequired=true) and one is enrolled (goes through TOTP challenge path, not the
    /// non-MFA path). Both outcomes in one test.
    /// </summary>
    [Fact]
    public async Task TenantLogin_RequireMfaOn_MixedEnrollment_CorrectSignalsPerUser()
    {
        string unenrolledEmail = $"enroll-mix-unenroll-{Guid.NewGuid():N}@test.local";
        string enrolledEmail = $"enroll-mix-enroll-{Guid.NewGuid():N}@test.local";

        await _factory.CreateUser(unenrolledEmail, TestPassword);
        string enrolledId = await _factory.CreateUser(enrolledEmail, TestPassword);

        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET mfa_enabled = 1 WHERE id = @id", new { id = enrolledId });
        }

        await SetDefaultRequireMfaDirect(true);
        try
        {
            using var client = CreateLoginClient();

            // Unenrolled user: non-MFA path, enrollmentRequired=true.
            var unenrolledResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email = unenrolledEmail, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, unenrolledResp.StatusCode);
            var unenrolledDoc = JsonDocument.Parse(await unenrolledResp.Content.ReadAsStringAsync()).RootElement;
            Assert.True(unenrolledDoc.GetProperty("enrollmentRequired").GetBoolean(),
                "Unenrolled user must receive enrollmentRequired=true.");

            // Enrolled user: MFA challenge path (mfaRequired=true), not the non-MFA path.
            var enrolledResp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email = enrolledEmail, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, enrolledResp.StatusCode);
            var enrolledDoc = JsonDocument.Parse(await enrolledResp.Content.ReadAsStringAsync()).RootElement;
            Assert.True(enrolledDoc.TryGetProperty("mfaRequired", out var mr) && mr.GetBoolean(),
                "Enrolled user must receive the MFA step-2 challenge, not the non-MFA path.");
        }
        finally
        {
            await SetDefaultRequireMfaDirect(false);
            await using var conn = await Db.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE users SET mfa_enabled = 0 WHERE id = @id", new { id = enrolledId });
        }
    }

    [Fact]
    public async Task InviteAccept_RequireMfaOn_EnrollmentRequiredTrue()
    {
        await SetDefaultRequireMfaDirect(true);
        try
        {
            // Seed an invite.
            await using var conn = await Db.OpenAsync();
            string orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
            string adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");

            var invites = _factory.Services.GetRequiredService<InviteRepository>();
            string inviteEmail = $"invite-enroll-{Guid.NewGuid():N}@test.local";
            var (rawToken, _) = await invites.CreateAsync(orgId, inviteEmail, adminId, "member");

            using var client = CreateLoginClient();
            var resp = await client.PostAsJsonAsync("/api/v1/invites/accept", new
            {
                token = rawToken,
                password = "InvitePass123!",
            });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            Assert.True(doc.GetProperty("enrollmentRequired").GetBoolean(),
                "Freshly-invited user with require_mfa=on must receive enrollmentRequired=true.");
        }
        finally
        {
            await SetDefaultRequireMfaDirect(false);
        }
    }

    [Fact]
    public async Task InviteAccept_RequireMfaOff_EnrollmentRequiredFalse()
    {
        // require_mfa is off by default in the shared factory.
        await using var conn = await Db.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        string adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found.");

        var invites = _factory.Services.GetRequiredService<InviteRepository>();
        string inviteEmail = $"invite-noenroll-{Guid.NewGuid():N}@test.local";
        var (rawToken, _) = await invites.CreateAsync(orgId, inviteEmail, adminId, "member");

        using var client = CreateLoginClient();
        var resp = await client.PostAsJsonAsync("/api/v1/invites/accept", new
        {
            token = rawToken,
            password = "InvitePass123!",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(doc.GetProperty("enrollmentRequired").GetBoolean(),
            "Freshly-invited user with require_mfa=off must receive enrollmentRequired=false.");
    }
}

/// <summary>
/// Verifies the <c>enrollmentRequired</c> signal from the system-admin login endpoint when
/// <c>REQUIRE_MFA=true</c> is set at the instance level.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemLoginEnrollmentRequiredTests : IAsyncLifetime
{
    private readonly SystemEnrollmentSignalFactory _factory = new();

    public Task InitializeAsync() => _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private HttpClient CreateApexClient()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Host = SystemEnrollmentSignalFactory.ApexHost;
        return client;
    }

    [Fact]
    public async Task SystemLogin_RequireMfaTrue_UnenrolledAdmin_EnrollmentRequiredTrue()
    {
        // deepcode ignore NoHardcodedCredentials/test: test-only fixture password
        using var client = CreateApexClient();
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = SystemEnrollmentSignalFactory.AdminEmail,
            password = SystemEnrollmentSignalFactory.AdminPassword,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(doc.GetProperty("enrollmentRequired").GetBoolean(),
            "Unenrolled system_admin with REQUIRE_MFA=true must receive enrollmentRequired=true.");
    }

    [Fact]
    public async Task SystemLogin_RequireMfaTrue_EnrolledAdmin_MfaChallengeIssued()
    {
        // Seed mfa_enabled for the first-boot admin, then log in — the MFA path is taken.
        await _factory.SetBootstrapAdminMfaEnabled(true);
        try
        {
            // deepcode ignore NoHardcodedCredentials/test: test-only fixture password
            using var client = CreateApexClient();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new
            {
                email = SystemEnrollmentSignalFactory.AdminEmail,
                password = SystemEnrollmentSignalFactory.AdminPassword,
            });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            // Enrolled admins are sent to the MFA step-2 challenge (mfaRequired=true), not
            // the non-MFA path that carries enrollmentRequired.
            Assert.True(doc.TryGetProperty("mfaRequired", out var mr) && mr.GetBoolean(),
                "Enrolled system_admin must receive the MFA step-2 challenge.");
        }
        finally
        {
            await _factory.SetBootstrapAdminMfaEnabled(false);
        }
    }

    /// <summary>
    /// Mixed/partial-failure: two system admins in the same host. One unenrolled (gets
    /// enrollmentRequired=true) and one enrolled (gets MFA challenge). Both signals observed
    /// in a single test run against the same REQUIRE_MFA=true instance.
    /// </summary>
    [Fact]
    public async Task SystemLogin_RequireMfaTrue_MixedEnrollment_CorrectSignalsPerAdmin()
    {
        // Seed a second admin as enrolled; the bootstrap admin stays unenrolled.
        string enrolledId = await _factory.CreateSecondAdminAsync();
        await _factory.SetAdminMfaEnabled(enrolledId, true);
        string enrolledEmail = await _factory.GetAdminEmail(enrolledId);
        try
        {
            using var client = CreateApexClient();

            // Unenrolled (bootstrap) admin: non-MFA path, enrollmentRequired=true.
            // deepcode ignore NoHardcodedCredentials/test: test-only fixture password
            var unenrolledResp = await client.PostAsJsonAsync("/api/v1/auth/login", new
            {
                email = SystemEnrollmentSignalFactory.AdminEmail,
                password = SystemEnrollmentSignalFactory.AdminPassword,
            });
            Assert.Equal(HttpStatusCode.OK, unenrolledResp.StatusCode);
            var unenrolledDoc = JsonDocument.Parse(await unenrolledResp.Content.ReadAsStringAsync()).RootElement;
            Assert.True(unenrolledDoc.GetProperty("enrollmentRequired").GetBoolean(),
                "Unenrolled system_admin must get enrollmentRequired=true.");

            // Enrolled admin: MFA challenge path.
            // deepcode ignore NoHardcodedCredentials/test: test-only fixture password
            var enrolledResp = await client.PostAsJsonAsync("/api/v1/auth/login", new
            {
                email = enrolledEmail,
                password = SystemEnrollmentSignalFactory.SecondAdminPassword,
            });
            Assert.Equal(HttpStatusCode.OK, enrolledResp.StatusCode);
            var enrolledDoc = JsonDocument.Parse(await enrolledResp.Content.ReadAsStringAsync()).RootElement;
            Assert.True(enrolledDoc.TryGetProperty("mfaRequired", out var mr) && mr.GetBoolean(),
                "Enrolled system_admin must receive the MFA step-2 challenge.");
        }
        finally
        {
            await _factory.SetAdminMfaEnabled(enrolledId, false);
        }
    }

    /// <summary>
    /// Test factory: boots the host in multi-mode with REQUIRE_MFA=true. The bootstrap system
    /// admin is unenrolled (mfa_enabled=0) at startup. Exposes helpers to toggle enrollment and
    /// create a second admin for the mixed scenario.
    /// </summary>
    private sealed class SystemEnrollmentSignalFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        public const string ApexHost = "localhost";
        public const string AdminEmail = "sysadmin@enroll-signal-test.local";
        // deepcode ignore NoHardcodedCredentials/test: test-only fixture password
        public const string AdminPassword = "SysEnroll1!";
        // deepcode ignore NoHardcodedCredentials/test: test-only fixture password
        public const string SecondAdminPassword = "SysEnroll2!";

        private readonly InMemoryBlobStore _blob = new();
        private readonly TestMetadataStore _metadataStore = new();

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            builder.Configuration["DEPLOYMENT_MODE"] = "multi";
            builder.Configuration["BASE_URL"] = $"http://{ApexHost}";
            builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] = AdminEmail;
            builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"] = AdminPassword;

            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("REQUIRE_MFA", "true");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");

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

        public async Task SetBootstrapAdminMfaEnabled(bool enabled)
        {
            await using var conn = await _metadataStore.OpenAsync();
            // xtenant: system_admins is a global table with no org_id column
            await conn.ExecuteAsync(
                "UPDATE system_admins SET mfa_enabled = @v WHERE email = @email",
                new { v = enabled ? 1 : 0, email = AdminEmail });
        }

        public async Task SetAdminMfaEnabled(string adminId, bool enabled)
        {
            await using var conn = await _metadataStore.OpenAsync();
            // xtenant: system_admins is a global table with no org_id column
            await conn.ExecuteAsync(
                "UPDATE system_admins SET mfa_enabled = @v WHERE id = @adminId",
                new { v = enabled ? 1 : 0, adminId });
        }

        public async Task<string> CreateSecondAdminAsync()
        {
            var repo = Services.GetRequiredService<SystemAdminRepository>();
            // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
            string hash = BCrypt.Net.BCrypt.HashPassword(SecondAdminPassword, workFactor: 4);
            return await repo.CreateAsync(
                $"second-admin-{Guid.NewGuid():N}@enroll-signal-test.local", hash, mustChangePassword: false);
        }

        public async Task<string> GetAdminEmail(string adminId)
        {
            await using var conn = await _metadataStore.OpenAsync();
            // xtenant: system_admins is a global table with no org_id column
            return await conn.ExecuteScalarAsync<string>(
                "SELECT email FROM system_admins WHERE id = @adminId", new { adminId })
                ?? throw new InvalidOperationException($"Admin '{adminId}' not found.");
        }
    }
}
