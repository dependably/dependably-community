using System.Globalization;
using Dependably.Infrastructure.Mail;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Renders the invite email through the real resource-backed localizer so the resx
/// entries, the {0}/{1}/{2} placeholder wiring, and the language fallback are all
/// exercised — not just a stubbed IStringLocalizer.
/// </summary>
public class InviteMailComposeTests
{
    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    private static readonly DateTimeOffset Expiry = new(2026, 7, 9, 18, 30, 0, TimeSpan.Zero);

    [Fact]
    public void ComposeInvite_English()
    {
        var (subject, body) = SmtpInviteMailer.ComposeInvite(
            RealLocalizer(), "en", "acme", "https://acme.example/join?token=t", Expiry);

        Assert.Equal("You've been invited to acme on Dependably", subject);
        Assert.Contains("You have been invited to join acme on Dependably.", body);
        Assert.Contains("The link expires at 2026-07-09 18:30 UTC.", body);
        Assert.Contains("https://acme.example/join?token=t", body);
        Assert.Contains("you can ignore this email", body);
    }

    [Fact]
    public void ComposeInvite_French()
    {
        var (subject, body) = SmtpInviteMailer.ComposeInvite(
            RealLocalizer(), "fr", "acme", "https://acme.example/join?token=t", Expiry);

        Assert.Equal("Invitation à rejoindre acme sur Dependably", subject);
        Assert.Contains("Vous avez reçu une invitation à rejoindre acme sur Dependably.", body);
        Assert.Contains("Le lien expire le 2026-07-09 18:30 UTC.", body);
        Assert.Contains("https://acme.example/join?token=t", body);
        Assert.Contains("vous pouvez ignorer ce courriel", body);
    }

    [Fact]
    public void ComposeInvite_UnsupportedLanguage_FallsBackToEnglish()
    {
        var (subject, _) = SmtpInviteMailer.ComposeInvite(
            RealLocalizer(), "de", "acme", "https://acme.example/join", Expiry);

        Assert.Equal("You've been invited to acme on Dependably", subject);
    }

    [Fact]
    public void ComposeInvite_RestoresTheAmbientUiCulture()
    {
        var before = CultureInfo.CurrentUICulture;
        SmtpInviteMailer.ComposeInvite(RealLocalizer(), "fr", "acme", "https://x.example", Expiry);
        Assert.Equal(before, CultureInfo.CurrentUICulture);
    }
}
