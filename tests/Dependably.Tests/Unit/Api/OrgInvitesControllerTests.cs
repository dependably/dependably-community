using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
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

    // ── SMTP present, delivery succeeds ─────────────────────────────────────

    [Fact]
    public async Task CreateInvite_SmtpPresent_SendSucceeds_ReturnsNullLink()
    {
        var mailer = Substitute.For<IInviteMailer>();
        mailer.SendInviteAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>())
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
            Arg.Any<CancellationToken>());
    }

    // ── SMTP present, delivery fails — fail-open ─────────────────────────────

    [Fact]
    public async Task CreateInvite_SmtpPresent_SendThrows_FallsBackToLink()
    {
        var mailer = Substitute.For<IInviteMailer>();
        mailer.SendInviteAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>())
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
}
