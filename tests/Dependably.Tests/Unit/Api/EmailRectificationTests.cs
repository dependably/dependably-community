using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Self-service email rectification (GDPR Art. 16). The whole security property of the flow is
/// that the confirmation link goes to the address being moved TO, so possession of that mailbox —
/// not merely a session — is what authorizes the move. Everything here exists to pin that: the
/// request must change nothing, the confirmation must change everything, and the paths that would
/// let a change happen without proving mailbox control must stay closed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailRectificationTests
{
    private const string NewAddress = "rectified@example.test";

    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    // A mailer whose queue never delivers (no SMTP configured) — these tests assert on the token
    // and the row, not on delivery, which SecurityEventEmailTests already covers end to end.
    private static TransactionalEmailService Mailer(FakeTimeProvider clock)
    {
        var queue = new EmailDeliveryQueue(
            new NoopSender(), clock, NullLogger<EmailDeliveryQueue>.Instance);
        return new TransactionalEmailService(
            queue,
            new InstanceSmtpConfig((_, _) => Task.FromResult<string?>(null), clock),
            RealLocalizer(),
            NullLogger<TransactionalEmailService>.Instance);
    }

    private sealed class NoopSender : SmtpMailSender
    {
        public NoopSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false)) { }

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default) => Task.CompletedTask;
    }

    // ── The request changes nothing ──────────────────────────────────────────

    /// <summary>
    /// The load-bearing assertion. A request issues a link and leaves the account exactly as it
    /// was — so a mistyped address cannot strand a user, and a stolen session cannot repoint the
    /// mailbox that receives password resets just by asking.
    /// </summary>
    [Fact]
    public async Task RequestingAChange_LeavesTheAccountUntouched_AndIssuesExactlyOnePendingToken()
    {
        var f = await FixtureAsync();

        var result = await f.Request(f.ActorId, NewAddress, f.Password);

        Assert.IsType<AcceptedResult>(result);
        Assert.Equal(f.OriginalEmail, await f.CurrentEmailAsync());
        Assert.Equal(1, await f.PendingTokenCountAsync());
        // No session was invalidated — nothing has happened to the account yet.
        Assert.Equal(f.OriginalTokenVersion, await f.TokenVersionAsync());
    }

    /// <summary>
    /// Only the most recent request is live. Two requests in sequence must not leave the earlier
    /// link redeemable — otherwise an address the user thought better of can still be applied.
    /// </summary>
    [Fact]
    public async Task ASecondRequest_VoidsTheFirstLink()
    {
        var f = await FixtureAsync();

        Assert.IsType<AcceptedResult>(await f.Request(f.ActorId, "first@example.test", f.Password));
        string firstToken = await f.PendingRawTokenSpyAsync();
        Assert.IsType<AcceptedResult>(await f.Request(f.ActorId, "second@example.test", f.Password));

        Assert.Equal(1, await f.PendingTokenCountAsync());
        // The first link is gone, not merely superseded.
        Assert.IsType<ObjectResult>(await f.Confirm(firstToken));
        Assert.Equal(f.OriginalEmail, await f.CurrentEmailAsync());
    }

    // ── The confirmation changes everything ──────────────────────────────────

    [Fact]
    public async Task ConfirmingTheLink_MovesTheAddress_AndInvalidatesEverySession()
    {
        var f = await FixtureAsync();
        Assert.IsType<AcceptedResult>(await f.Request(f.ActorId, NewAddress, f.Password));
        string token = await f.PendingRawTokenSpyAsync();

        var result = await f.Confirm(token);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(NewAddress, await f.CurrentEmailAsync());
        // Email is the login identifier and the reset destination, so the change is
        // credential-class: sessions issued to the old identity must not survive it.
        Assert.True(await f.TokenVersionAsync() > f.OriginalTokenVersion);
    }

    [Fact]
    public async Task AConfirmedLink_CannotBeRedeemedTwice()
    {
        var f = await FixtureAsync();
        Assert.IsType<AcceptedResult>(await f.Request(f.ActorId, NewAddress, f.Password));
        string token = await f.PendingRawTokenSpyAsync();

        Assert.IsType<OkObjectResult>(await f.Confirm(token));
        var replay = await f.Confirm(token);

        Assert.Equal(StatusCodes.Status410Gone, Assert.IsType<ObjectResult>(replay).StatusCode);
    }

    [Fact]
    public async Task AnExpiredLink_IsRefused_AndTheAddressStays()
    {
        var f = await FixtureAsync();
        Assert.IsType<AcceptedResult>(await f.Request(f.ActorId, NewAddress, f.Password));
        string token = await f.PendingRawTokenSpyAsync();

        // Past the 24h window.
        f.Clock.Advance(TimeSpan.FromHours(30));

        Assert.Equal(StatusCodes.Status410Gone,
            Assert.IsType<ObjectResult>(await f.Confirm(token)).StatusCode);
        Assert.Equal(f.OriginalEmail, await f.CurrentEmailAsync());
    }

    [Fact]
    public async Task AnUnknownToken_IsRefused()
        => Assert.Equal(StatusCodes.Status410Gone,
            Assert.IsType<ObjectResult>(await (await FixtureAsync()).Confirm("not-a-real-token")).StatusCode);

    // ── The paths that must stay closed ──────────────────────────────────────

    /// <summary>
    /// Reauthentication is the difference between "holds a session" and "is the account holder".
    /// Without it a hijacked session repoints account recovery to the attacker's mailbox.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrong-password")]
    public async Task SelfService_WithoutTheCurrentPassword_IsRefused_AndIssuesNoToken(string? password)
    {
        var f = await FixtureAsync();

        var result = await f.Request(f.ActorId, NewAddress, password);

        Assert.IsType<ObjectResult>(result);
        Assert.Equal(0, await f.PendingTokenCountAsync());
        Assert.Equal(f.OriginalEmail, await f.CurrentEmailAsync());
    }

    /// <summary>
    /// The IdP is authoritative for a SAML account: a local edit would be overwritten at the next
    /// login, so the account would silently drift back rather than stay rectified.
    /// </summary>
    [Fact]
    public async Task ASamlAccount_IsRefused()
    {
        var f = await FixtureAsync();
        await using (var conn = await f.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET account_type = 'saml' WHERE id = @id", new { id = f.ActorId });
        }

        Assert.IsType<ObjectResult>(await f.Request(f.ActorId, NewAddress, f.Password));
        Assert.Equal(0, await f.PendingTokenCountAsync());
    }

    [Fact]
    public async Task AnAddressAlreadyUsedInTheTenant_IsRefused()
    {
        var f = await FixtureAsync();
        string taken = await f.AddMemberAsync("colleague@example.test");
        Assert.NotNull(taken);

        Assert.IsType<ObjectResult>(await f.Request(f.ActorId, "colleague@example.test", f.Password));
        Assert.Equal(0, await f.PendingTokenCountAsync());
    }

    [Fact]
    public async Task RequestingTheAddressTheAccountAlreadyHas_IsRefused()
    {
        var f = await FixtureAsync();

        Assert.IsType<ObjectResult>(await f.Request(f.ActorId, f.OriginalEmail, f.Password));
        Assert.Equal(0, await f.PendingTokenCountAsync());
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("\"Display Name\" <a@b.test>")]
    [InlineData("a@b.test\r\nBcc: attacker@evil.test")]
    public async Task AMalformedOrHeaderInjectingAddress_IsRefused(string bad)
    {
        var f = await FixtureAsync();

        Assert.IsType<ObjectResult>(await f.Request(f.ActorId, bad, f.Password));
        Assert.Equal(0, await f.PendingTokenCountAsync());
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    private static async Task<Fixture> FixtureAsync()
    {
        var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var built = await s.BuildAsync();
        return await Fixture.CreateAsync(s, built);
    }

    private sealed class Fixture
    {
        public required ControllerScenario Scenario { get; init; }
        public required ControllerScenarioResult Built { get; init; }
        public required IMetadataStore Db { get; init; }
        public required FakeTimeProvider Clock { get; init; }
        public required EmailChangeTokenRepository Tokens { get; init; }
        public required UserService Users { get; init; }
        public required AuthController Auth { get; init; }
        public required string ActorId { get; init; }
        public required string OriginalEmail { get; init; }
        public required string Password { get; init; }
        public required long OriginalTokenVersion { get; init; }

        public static async Task<Fixture> CreateAsync(ControllerScenario s, ControllerScenarioResult built)
        {
            var clock = TestTime.Frozen();
            var db = built.Db;
            string actorId = built.ActorUserId!;

            // Give the actor a known password so the reauthentication gate can be exercised.
            const string password = "Correct-Horse-Battery-9!";
            await using (var conn = await db.OpenAsync())
            {
                await conn.ExecuteAsync(
                    "UPDATE users SET password_hash = @h WHERE id = @id",
                    new { h = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4), id = actorId });
            }

            var users = new UserService(db, new OrgRepository(db));

            await using var read = await db.OpenAsync();
            var (email, version) = await read.QuerySingleAsync<(string Email, long TokenVersion)>(
                "SELECT email, token_version AS TokenVersion FROM users WHERE id = @id", new { id = actorId });

            return new Fixture
            {
                Scenario = s,
                Built = built,
                Db = db,
                Clock = clock,
                Tokens = new EmailChangeTokenRepository(db, clock),
                Users = users,
                Auth = BuildAuthController(db, clock, users),
                ActorId = actorId,
                OriginalEmail = email,
                Password = password,
                OriginalTokenVersion = version,
            };
        }

        // AuthController is built directly rather than taken from the scenario, which does not
        // expose it. Only ConfirmEmailChange is exercised, and it depends on nothing beyond the
        // token repository, UserService, and the audit sink.
        private static AuthController BuildAuthController(IMetadataStore db, FakeTimeProvider clock, UserService users)
        {
            var orgs = new OrgRepository(db);
            var audit = new AuditRepository(db);
            var admins = new SystemAdminRepository(db);
            var login = new LoginService(new LoginService.Dependencies(
                Db: db, Orgs: orgs, SystemAdmins: admins,
                Lockout: Substitute.For<ILockoutStore>(), Audit: audit,
                ExternalIdentities: new ExternalIdentityRepository(db, clock),
                AuditEmitter: Substitute.For<Dependably.Infrastructure.Audit.IAuditEmitter>(),
                Time: clock, Mfa: Substitute.For<IMfaEnrollmentService>(),
                SystemMfa: Substitute.For<ISystemMfaEnrollmentService>()));

            var urls = Substitute.For<IPublicUrlBuilder>();
            urls.SessionCookieOptions(Arg.Any<HttpContext>(), Arg.Any<SameSiteMode>()).Returns(new CookieOptions());

            return new AuthController(
                login, users, new JwtRevocationRepository(db), audit, urls, clock, orgs,
                Substitute.For<IRequireMfaMode>(), admins)
            {
                ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
            };
        }

        public Task<IActionResult> Request(string userId, string? email, string? currentPassword) =>
            Built.OrgUsersController.RequestEmailChange(
                userId, new ChangeEmailRequest(email, currentPassword),
                Tokens, Users, Mailer(Clock), Clock, CancellationToken.None);

        public Task<IActionResult> Confirm(string token) =>
            Auth.ConfirmEmailChange(
                new ConfirmEmailChangeRequest(token), Tokens, Mailer(Clock), CancellationToken.None);

        public async Task<string> CurrentEmailAsync()
        {
            await using var conn = await Db.OpenAsync();
            return await conn.ExecuteScalarAsync<string>(
                "SELECT email FROM users WHERE id = @id", new { id = ActorId }) ?? "";
        }

        public async Task<long> TokenVersionAsync()
        {
            await using var conn = await Db.OpenAsync();
            return await conn.ExecuteScalarAsync<long>(
                "SELECT token_version FROM users WHERE id = @id", new { id = ActorId });
        }

        public async Task<int> PendingTokenCountAsync()
        {
            await using var conn = await Db.OpenAsync();
            return await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM email_change_tokens WHERE user_id = @id AND consumed_at IS NULL",
                new { id = ActorId });
        }

        /// <summary>
        /// The raw token never leaves the request (it is mailed, never returned), so a test that
        /// needs to redeem one re-issues against the same pending row and reads the value back.
        /// Deliberately explicit rather than reaching into the mailer: what is being tested is the
        /// redemption, and the mail path has its own coverage.
        /// </summary>
        public async Task<string> PendingRawTokenSpyAsync()
        {
            await using var conn = await Db.OpenAsync();
            string pendingEmail = await conn.ExecuteScalarAsync<string>(
                "SELECT new_email FROM email_change_tokens WHERE user_id = @id AND consumed_at IS NULL",
                new { id = ActorId }) ?? "";
            return await Tokens.IssueAsync(ActorId, Built.PrimaryOrgId, pendingEmail);
        }

        // Seeded directly rather than through the scenario, which is immutable after BuildAsync.
        public async Task<string> AddMemberAsync(string email)
        {
            string id = Guid.NewGuid().ToString("N");
            await using var conn = await Db.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO users (id, tenant_id, email, password_hash, role)
                VALUES (@id, @tenant, @email, 'x', 'member')
                """,
                new { id, tenant = Built.PrimaryOrgId, email });
            return id;
        }
    }
}
