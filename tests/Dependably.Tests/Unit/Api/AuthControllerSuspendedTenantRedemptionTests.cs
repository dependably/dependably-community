using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The three anonymous redemption endpoints, and the reset-link request that precedes one, on a
/// tenant whose suspension committed after the request was admitted. Each redemption must refuse
/// with the tenant-not-ready refusal (answered 423 by <see cref="TenantNotReadyExceptionMiddleware"/>)
/// and change nothing: the credential stays unconsumed, and no account, password, or address is
/// written, so restoring the tenant does not bring back a change made while it was suspended. The
/// reset-link request instead answers the same 202 for a known and an unknown address, because a
/// replica whose tenant cache still reads the tenant as active would otherwise answer a known
/// address with 423 and an unknown one with 202.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuthControllerSuspendedTenantRedemptionTests : IAsyncLifetime
{
    private const string OriginalPassword = "Original-Passw0rd-1";
    private const string NewPassword = "Brand-New-Passphrase-Zebra-42";

    private readonly InMemoryDbFixture _fixture = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', @secret) ON CONFLICT(key) DO NOTHING",
            new { secret = "unit-test-secret-min-32-chars-xxxxxx" });
    }

    public Task DisposeAsync() => _fixture.DisposeAsync();

    private IMetadataStore Db => _fixture.Store;

    private AuthController BuildController(string? tenantId = null, string? tenantSlug = null)
    {
        var orgs = new OrgRepository(Db);
        var users = new UserService(Db, orgs);
        var audit = new AuditRepository(Db);
        var admins = new SystemAdminRepository(Db);
        var login = new LoginService(new LoginService.Dependencies(
            Db: Db,
            Orgs: orgs,
            SystemAdmins: admins,
            Lockout: Substitute.For<ILockoutStore>(),
            Audit: audit,
            ExternalIdentities: new ExternalIdentityRepository(Db, _clock),
            AuditEmitter: Substitute.For<Dependably.Infrastructure.Audit.IAuditEmitter>(),
            Time: _clock,
            Mfa: Substitute.For<IMfaEnrollmentService>(),
            SystemMfa: Substitute.For<ISystemMfaEnrollmentService>()));

        var urls = Substitute.For<IPublicUrlBuilder>();
        urls.SessionCookieOptions(Arg.Any<HttpContext>(), Arg.Any<SameSiteMode>()).Returns(new CookieOptions());
        urls.Absolute(Arg.Any<HttpContext>(), Arg.Any<string>()).Returns(ci => "https://acme.example.test" + ci.ArgAt<string>(1));

        var controller = new AuthController(
            login, users, new JwtRevocationRepository(Db), audit, urls, _clock, orgs,
            Substitute.For<IRequireMfaMode>(), admins);

        var http = new DefaultHttpContext { Request = { Scheme = "https", Host = new HostString("acme.example.test") } };
        if (tenantId is not null)
        {
            // The context the status middleware admitted the request under: a tenant cache entry
            // filled before the suspension still reads it as active.
            http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(tenantId, tenantSlug!, "active");
        }

        controller.ControllerContext = new ControllerContext { HttpContext = http };
        return controller;
    }

    private TransactionalEmailService Mailer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        var localizer = services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
        var queue = new EmailDeliveryQueue(new NoopSender(), _clock, NullLogger<EmailDeliveryQueue>.Instance);
        return new TransactionalEmailService(
            queue,
            new InstanceSmtpConfig((_, _) => Task.FromResult<string?>(null), _clock),
            new ConfigurationBuilder().Build(),
            localizer,
            NullLogger<TransactionalEmailService>.Instance);
    }

    private sealed class NoopSender : SmtpMailSender
    {
        public NoopSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false)) { }

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed record Seeded(string OrgId, string Slug, string UserId, string Email);

    private async Task<Seeded> SeedAsync()
    {
        string slug = $"acme{Guid.NewGuid():N}"[..20];
        string orgId = await OrgSeeder.InsertAsync(Db, slug);
        string email = $"member-{Guid.NewGuid():N}@acme.test";
        string userId = await UserSeeder.InsertAsync(Db, orgId, email, role: "owner", password: OriginalPassword);
        return new Seeded(orgId, slug, userId, email);
    }

    private async Task SuspendAsync(string orgId)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET status = 'suspended' WHERE id = @orgId", new { orgId });
    }

    private async Task<T> ScalarAsync<T>(string sql, object args)
    {
        await using var conn = await Db.OpenAsync();
        return (await conn.ExecuteScalarAsync<T>(sql, args))!;
    }

    [Fact]
    public async Task AcceptInvite_OnASuspendedTenant_IsRefused_AndNeitherSpendsTheInviteNorCreatesTheAccount()
    {
        var t = await SeedAsync();
        var invites = new InviteRepository(Db, _clock);
        const string invitee = "joiner@acme.test";
        var (raw, _) = (await invites.CreateAsync(t.OrgId, invitee, t.UserId))!;
        await SuspendAsync(t.OrgId);

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => BuildController().AcceptInvite(
            new AcceptInviteRequest(raw, NewPassword), invites,
            new SamlConfigRepository(Db, _clock), new ProblemResults(Substitute.For<IStringLocalizer<SharedResource>>()),
            CancellationToken.None));

        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);
        Assert.NotNull(await invites.PeekPendingAsync(raw));
        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = @OrgId AND email = @invitee", new { t.OrgId, invitee }));
    }

    [Fact]
    public async Task AcceptInvite_OnAnActiveTenant_CreatesTheAccount_AndSpendsTheInvite()
    {
        var t = await SeedAsync();
        var invites = new InviteRepository(Db, _clock);
        const string invitee = "joiner@acme.test";
        var (raw, _) = (await invites.CreateAsync(t.OrgId, invitee, t.UserId))!;

        var result = await BuildController().AcceptInvite(
            new AcceptInviteRequest(raw, NewPassword), invites,
            new SamlConfigRepository(Db, _clock), new ProblemResults(Substitute.For<IStringLocalizer<SharedResource>>()),
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        Assert.Null(await invites.PeekPendingAsync(raw));
        Assert.Equal(1L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = @OrgId AND email = @invitee", new { t.OrgId, invitee }));
    }

    [Fact]
    public async Task AcceptInvite_ForAnAddressThatAlreadyHasAnAccount_SpendsTheInvite_AndConflicts()
    {
        var t = await SeedAsync();
        var invites = new InviteRepository(Db, _clock);
        // Seeded directly: the invite mint itself would not refuse an address that already
        // belongs to a member, and this is the state the conflict answer exists for.
        var (raw, _) = (await invites.CreateAsync(t.OrgId, "Twin@Acme.test", t.UserId))!;
        await UserSeeder.InsertAsync(Db, t.OrgId, "twin@acme.test");

        var result = await BuildController().AcceptInvite(
            new AcceptInviteRequest(raw, NewPassword), invites,
            new SamlConfigRepository(Db, _clock), new ProblemResults(Substitute.For<IStringLocalizer<SharedResource>>()),
            CancellationToken.None);

        Assert.IsType<ConflictObjectResult>(result);
        Assert.Null(await invites.PeekPendingAsync(raw));
        Assert.Equal(1L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = @OrgId AND email = 'twin@acme.test'", new { t.OrgId }));
    }

    [Fact]
    public async Task ResetPassword_OnASuspendedTenant_IsRefused_AndNeitherSpendsTheLinkNorChangesThePassword()
    {
        var t = await SeedAsync();
        var tokens = new PasswordResetTokenRepository(Db, _clock);
        string raw = await tokens.IssueAsync(t.UserId, t.OrgId);
        string hashBefore = await ScalarAsync<string>("SELECT password_hash FROM users WHERE id = @UserId", new { t.UserId });
        await SuspendAsync(t.OrgId);

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => BuildController().ResetPassword(
            new ResetPasswordRequest(raw, NewPassword), tokens, Substitute.For<ILockoutStore>(), Mailer(),
            CancellationToken.None));

        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);
        Assert.NotNull(await tokens.PeekAsync(raw));
        Assert.Equal(hashBefore, await ScalarAsync<string>("SELECT password_hash FROM users WHERE id = @UserId", new { t.UserId }));
    }

    [Fact]
    public async Task ResetPassword_OnAnActiveTenant_ChangesThePassword_AndSpendsTheLink()
    {
        var t = await SeedAsync();
        var tokens = new PasswordResetTokenRepository(Db, _clock);
        string raw = await tokens.IssueAsync(t.UserId, t.OrgId);
        long versionBefore = await ScalarAsync<long>("SELECT token_version FROM users WHERE id = @UserId", new { t.UserId });

        var result = await BuildController().ResetPassword(
            new ResetPasswordRequest(raw, NewPassword), tokens, Substitute.For<ILockoutStore>(), Mailer(),
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        Assert.Null(await tokens.PeekAsync(raw));
        string hashAfter = await ScalarAsync<string>("SELECT password_hash FROM users WHERE id = @UserId", new { t.UserId });
        Assert.True(BCrypt.Net.BCrypt.Verify(NewPassword, hashAfter));
        Assert.Equal(versionBefore + 1, await ScalarAsync<long>("SELECT token_version FROM users WHERE id = @UserId", new { t.UserId }));
    }

    [Fact]
    public async Task ConfirmEmailChange_OnASuspendedTenant_IsRefused_AndNeitherSpendsTheLinkNorMovesTheAddress()
    {
        var t = await SeedAsync();
        var tokens = new EmailChangeTokenRepository(Db, _clock);
        string raw = await tokens.IssueAsync(t.UserId, t.OrgId, "moved@acme.test");
        await SuspendAsync(t.OrgId);

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => BuildController().ConfirmEmailChange(
            new ConfirmEmailChangeRequest(raw), tokens, Mailer(), CancellationToken.None));

        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);
        Assert.Equal(1L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM email_change_tokens WHERE user_id = @UserId AND consumed_at IS NULL", new { t.UserId }));
        Assert.Equal(t.Email, await ScalarAsync<string>("SELECT email FROM users WHERE id = @UserId", new { t.UserId }));
    }

    [Fact]
    public async Task ConfirmEmailChange_OnAnActiveTenant_MovesTheAddress_AndSpendsTheLink()
    {
        var t = await SeedAsync();
        var tokens = new EmailChangeTokenRepository(Db, _clock);
        string raw = await tokens.IssueAsync(t.UserId, t.OrgId, "moved@acme.test");

        var result = await BuildController().ConfirmEmailChange(
            new ConfirmEmailChangeRequest(raw), tokens, Mailer(), CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("moved@acme.test", await ScalarAsync<string>("SELECT email FROM users WHERE id = @UserId", new { t.UserId }));
        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM email_change_tokens WHERE user_id = @UserId AND consumed_at IS NULL", new { t.UserId }));
    }

    [Fact]
    public async Task ConfirmEmailChange_ToAnAddressClaimedMeanwhile_SpendsTheLink_AndConflicts()
    {
        var t = await SeedAsync();
        var tokens = new EmailChangeTokenRepository(Db, _clock);
        string raw = await tokens.IssueAsync(t.UserId, t.OrgId, "claimed@acme.test");
        await UserSeeder.InsertAsync(Db, t.OrgId, "claimed@acme.test");

        var result = await BuildController().ConfirmEmailChange(
            new ConfirmEmailChangeRequest(raw), tokens, Mailer(), CancellationToken.None);

        Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(t.Email, await ScalarAsync<string>("SELECT email FROM users WHERE id = @UserId", new { t.UserId }));
        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM email_change_tokens WHERE user_id = @UserId AND consumed_at IS NULL", new { t.UserId }));
    }

    [Fact]
    public async Task ForgotPassword_WhileTheTenantCacheStillReadsActive_AnswersAKnownAddressExactlyLikeAnUnknownOne()
    {
        var t = await SeedAsync();
        await SuspendAsync(t.OrgId);
        var throttle = new AccountSendThrottle(Db, _clock, new ConfigurationBuilder().Build(), NullLogger<AccountSendThrottle>.Instance);
        var tokens = new PasswordResetTokenRepository(Db, _clock);

        var known = await BuildController(t.OrgId, t.Slug).ForgotPassword(
            new ForgotPasswordRequest(t.Email), tokens, throttle, Mailer(), CancellationToken.None);
        var unknown = await BuildController(t.OrgId, t.Slug).ForgotPassword(
            new ForgotPasswordRequest("nobody@acme.test"), tokens, throttle, Mailer(), CancellationToken.None);

        Assert.IsType<AcceptedResult>(known);
        Assert.IsType<AcceptedResult>(unknown);
        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE org_id = @OrgId", new { t.OrgId }));

        // The refusal is recorded on the known address's request row, not hidden.
        string detail = await ScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE org_id = @OrgId AND action = 'user.password_reset_requested' AND actor_id = @UserId",
            new { t.OrgId, t.UserId });
        using var doc = JsonDocument.Parse(detail);
        Assert.False(doc.RootElement.GetProperty("link_issued").GetBoolean());
        Assert.Equal("tenant_not_ready", doc.RootElement.GetProperty("refused").GetString());
    }
}
