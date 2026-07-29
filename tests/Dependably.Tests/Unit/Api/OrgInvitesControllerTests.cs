using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Unit tests for invite creation delivery behavior:
/// <list type="bullet">
///   <item>SMTP absent — link returned, delivered_via = "link" (unchanged from pre-SMTP path)</item>
///   <item>SMTP present, send succeeds — invite_link null, delivered_via = "email"</item>
///   <item>SMTP present, send throws — link returned as fallback, delivered_via = "link" (fail-open)</item>
/// </list>
/// Auth rejection and role-validation paths are covered by OrgControllerUnitTests.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgInvitesControllerTests
{
    private static readonly System.Text.Json.JsonSerializerOptions WebJsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    // ── Invite link uses tenant subdomain host ────────────────────────────────

    [Fact]
    public async Task CreateInvite_LinkUsesTenantSubdomainHost_NotApex()
    {
        // ControllerScenario sets Request.Host = "{slug}.example.test" (https) to simulate
        // a multi-mode request arriving on the tenant subdomain. The invite link must target
        // that host, not a bare apex host.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("invitee@example.test", "member"),
            CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);

        // Extract invite_link value from the JSON response.
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        string inviteLink = doc.RootElement.GetProperty("invite_link").GetString()!;

        // Must target the tenant subdomain host (acme.example.test), not a bare apex.
        Assert.Contains("://acme.example.test/join?token=", inviteLink);
        // Must not be rooted at a bare apex host (i.e. no "://example.test/").
        Assert.DoesNotContain("://example.test/", inviteLink);
    }

    // ── SMTP absent ──────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateInvite_SmtpAbsent_ReturnsLinkInResponse()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("invitee@example.test", "member"),
            CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);
        // Link is present in the response so the inviter can deliver it manually.
        Assert.Contains("\"invite_link\"", json);
        Assert.DoesNotContain("\"invite_link\":null", json);
        Assert.Contains("\"delivered_via\":\"link\"", json);
    }

    // ── Mailer registered but instance SMTP unconfigured ────────────────────

    [Fact]
    public async Task CreateInvite_MailerRegisteredButUnavailable_ReturnsLinkInResponse()
    {
        // SmtpInviteMailer is always registered (no more SMTP_HOST env gate), but the DB-backed
        // instance SMTP config can still be disabled/unconfigured — IsAvailableAsync surfaces
        // that at request time and the controller must fall back to the link, exactly like the
        // no-mailer-registered case.
        var mailer = Substitute.For<IInviteMailer>();
        mailer.IsAvailableAsync(Arg.Any<CancellationToken>()).Returns(false);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync(mailer: mailer);

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("invitee@example.test", "member"),
            CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);
        Assert.Contains("\"invite_link\"", json);
        Assert.DoesNotContain("\"invite_link\":null", json);
        Assert.Contains("\"delivered_via\":\"link\"", json);

        await mailer.DidNotReceive().SendInviteAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ── SMTP present, delivery succeeds ─────────────────────────────────────

    [Fact]
    public async Task CreateInvite_SmtpPresent_SendSucceeds_ReturnsNullLink()
    {
        var mailer = Substitute.For<IInviteMailer>();
        mailer.IsAvailableAsync(Arg.Any<CancellationToken>()).Returns(true);
        mailer.SendInviteAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync(mailer: mailer);

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("invitee@example.test", "member"),
            CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);
        // Link must be null when delivery succeeded — the token is consumed on the SMTP path.
        Assert.Contains("\"invite_link\":null", json);
        Assert.Contains("\"delivered_via\":\"email\"", json);

        // Mailer must have been called exactly once.
        await mailer.Received(1).SendInviteAsync(
            "invitee@example.test",
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<DateTimeOffset>(),
            "en",
            Arg.Any<CancellationToken>());
    }

    // ── SMTP present, delivery fails — fail-open ─────────────────────────────

    [Fact]
    public async Task CreateInvite_SmtpPresent_SendThrows_FallsBackToLink()
    {
        var mailer = Substitute.For<IInviteMailer>();
        mailer.IsAvailableAsync(Arg.Any<CancellationToken>()).Returns(true);
        mailer.SendInviteAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("SMTP relay rejected connection"));

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync(mailer: mailer);

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("invitee@example.test", "member"),
            CancellationToken.None);

        // Response is still 200 — the endpoint is fail-open on deliverability.
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);
        // Fallback link present so the inviter can deliver it manually.
        Assert.Contains("\"invite_link\"", json);
        Assert.DoesNotContain("\"invite_link\":null", json);
        Assert.Contains("\"delivered_via\":\"link\"", json);
    }

    // ── SMTP availability probe throws — fail-safe ───────────────────────────

    [Fact]
    public async Task CreateInvite_AvailabilityProbeThrows_FallsBackToLink()
    {
        // The probe reads instance_settings and decrypts the stored SMTP secret, so it has its
        // own failure modes. It runs after the invite row is committed: a throw that escapes
        // would 500 an invite that already exists and that the inviter can never retrieve.
        var mailer = Substitute.For<IInviteMailer>();
        mailer.IsAvailableAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("instance_settings read failed"));

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync(mailer: mailer);

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("probe-throws@example.test", "member"),
            CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);
        Assert.DoesNotContain("\"invite_link\":null", json);
        Assert.Contains("\"delivered_via\":\"link\"", json);

        // A probe that could not answer must not be treated as "available" and dispatched to.
        await mailer.DidNotReceive().SendInviteAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>());

        // The invite is still a real, listable row — the fallback does not orphan it.
        var pending = await new InviteRepository(b.Db, s.Clock).ListAsync(b.PrimaryOrgId, CancellationToken.None);
        Assert.Equal("probe-throws@example.test", Assert.Single(pending).Email);
    }

    // ── Duplicate pending invite ─────────────────────────────────────────────

    [Fact]
    public async Task CreateInvite_DuplicatePendingEmail_ReturnsConflict_NotUnhandled()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var first = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("dupe@example.test", "member"),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(first);

        // Same address while the first invite is still pending: the partial unique index
        // idx_invites_unique_pending (org_id, email) WHERE accepted_at IS NULL rejects the row.
        // The endpoint must answer 409, not let the store exception escape as a 500.
        var second = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("dupe@example.test", "member"),
            CancellationToken.None);

        var conflict = Assert.IsAssignableFrom<ObjectResult>(second);
        Assert.Equal(409, conflict.StatusCode);
    }

    [Fact]
    public async Task CreateInvite_DuplicatePendingEmail_LosesPreCheckRace_StillReturnsConflict()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Simulates the interleaving the pre-check cannot cover: the row lands between
        // HasPendingAsync and the INSERT. Seeding directly after a controller-visible gap is
        // the deterministic stand-in — the INSERT's conflict target is what has to absorb it.
        var repo = new InviteRepository(b.Db, s.Clock);
        Assert.NotNull(await repo.CreateAsync(b.PrimaryOrgId, "raced@example.test", b.ActorUserId!, "member"));

        // A second repository-level create for the same pending address resolves to null
        // instead of throwing, which is what keeps the racing request off the 500 path.
        Assert.Null(await repo.CreateAsync(b.PrimaryOrgId, "raced@example.test", b.ActorUserId!, "member"));

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("raced@example.test", "member"),
            CancellationToken.None);
        Assert.Equal(409, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task CreateInvite_MixedBatch_DuplicateRejected_FreshAddressesStillSucceed()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string[] requested = ["a@example.test", "b@example.test", "a@example.test", "c@example.test"];
        var statuses = new List<int>();
        foreach (string email in requested)
        {
            var r = await b.OrgInvitesController.CreateInvite(
                new CreateInviteRequest(email, "member"), CancellationToken.None);
            statuses.Add(Assert.IsAssignableFrom<ObjectResult>(r).StatusCode ?? 0);
        }

        // Only the repeat of "a@example.test" fails; the surrounding fresh addresses are
        // unaffected — one bad element in the sequence must not poison the rest.
        Assert.Equal([200, 200, 409, 200], statuses);

        var pending = await new InviteRepository(b.Db, s.Clock).ListAsync(b.PrimaryOrgId, CancellationToken.None);
        Assert.Equal(3, pending.Count);
    }

    [Fact]
    public async Task CreateInvite_SameEmailInAnotherTenant_Succeeds()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // The index is scoped to (org_id, email), so an address pending in another tenant must
        // not block this one — the guard must not become a cross-tenant existence oracle.
        string otherOrgId = await OrgSeeder.InsertAsync(b.Db, "other");
        string otherInviter = await UserSeeder.InsertAsync(b.Db, otherOrgId, "owner@other.test", "owner");
        var repo = new InviteRepository(b.Db, s.Clock);
        Assert.NotNull(await repo.CreateAsync(otherOrgId, "shared@example.test", otherInviter, "member"));

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("shared@example.test", "member"),
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateInvite_AfterPreviousInviteAccepted_SameEmailSucceeds()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var repo = new InviteRepository(b.Db, s.Clock);
        var created = await repo.CreateAsync(b.PrimaryOrgId, "rehire@example.test", b.ActorUserId!, "member");
        Assert.NotNull(await repo.AcceptAsync(created!.RawToken, CancellationToken.None));

        // The unique index is partial (WHERE accepted_at IS NULL), so a consumed invite does
        // not block a fresh one for the same address.
        var again = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("rehire@example.test", "member"),
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(again);
    }

    // ── Email format validation ──────────────────────────────────────────────

    [Theory]
    [InlineData("<script>alert(1);</script>")]  // no mailbox at all — reaches the listing when unvalidated
    [InlineData("not-an-email")]
    [InlineData("missing-domain@")]
    [InlineData("@missing-local.test")]
    [InlineData("spaces in@example.test")]
    [InlineData("\"Display Name\" <real@example.test>")]  // TryCreate parses this; the bare-address check rejects it
    [InlineData("victim@example.test\r\nBcc: attacker@evil.test")]  // header injection
    public async Task CreateInvite_MalformedEmail_Returns422_AndPersistsNothing(string email)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest(email, "member"),
            CancellationToken.None);

        // 422, matching the emailRequired path — ProblemResults.ValidationErrorAction is the
        // shared validation-failure shape for this surface.
        Assert.Equal(422, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);

        // The refusal must happen before the INSERT: an unvalidated address is what let the
        // value persist and surface again in the GET listing. Query the real store rather than
        // trusting the status code — a 400 returned after a write would still leave the row.
        var pending = await new InviteRepository(b.Db, s.Clock).ListAsync(b.PrimaryOrgId, CancellationToken.None);
        Assert.Empty(pending);
    }

    [Theory]
    [InlineData("invitee@example.test")]
    [InlineData("first.last+tag@sub.example.test")]
    public async Task CreateInvite_ValidEmail_StillSucceeds(string email)
    {
        // The must-NOT twin of the rejection theory: the new format check has to stay narrow
        // enough that ordinary addresses (dotted local parts, + tags, subdomains) keep working.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest(email, "member"),
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateInvite_PaddedEmail_StoredTrimmed_AndCollidesWithBareForm()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("  padded@example.test  ", "member"),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        // Trimming happens before both the uniqueness check and the INSERT, so the stored value
        // is the bare address — otherwise the padded and bare forms would be distinct rows and
        // the one-pending-invite-per-address guard would be bypassable with a leading space.
        var pending = await new InviteRepository(b.Db, s.Clock).ListAsync(b.PrimaryOrgId, CancellationToken.None);
        Assert.Equal("padded@example.test", Assert.Single(pending).Email);

        var duplicate = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("padded@example.test", "member"),
            CancellationToken.None);
        Assert.Equal(409, Assert.IsAssignableFrom<ObjectResult>(duplicate).StatusCode);
    }
}
