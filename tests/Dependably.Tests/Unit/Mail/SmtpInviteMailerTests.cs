using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// <see cref="SmtpInviteMailer"/>'s credential-mail cleartext gate (#539): an invite link doubles
/// as a bearer credential (possession creates an account and joins the org at the invited role),
/// so it is refused over an unencrypted transport absent an explicit operator override —
/// mirroring the SIEM webhook's <c>ALLOW_INSECURE</c> posture (<see cref="CredentialMailPolicy"/>).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SmtpInviteMailerTests
{
    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    private static InstanceSmtpConfig BuildInstance(Dictionary<string, string?> db)
    {
        var clock = TestTime.Frozen();
        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);
        return new InstanceSmtpConfig(Reader, clock);
    }

    private static readonly DateTimeOffset InviteExpiry = TestTime.KnownNow.AddDays(1);

    /// <summary>Records every call without touching a socket, exactly like
    /// <c>EmailDeliveryQueueTests.FakeMailSender</c>.</summary>
    private sealed class RecordingMailSender : SmtpMailSender
    {
        public RecordingMailSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false))
        {
        }

        public int Calls { get; private set; }

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default)
        {
            Calls++;
            return Task.CompletedTask;
        }
    }

    private static readonly Dictionary<string, string?> CleartextConfigured = new()
    {
        ["smtp_enabled"] = "1",
        ["smtp_host"] = "smtp.example.com",
        ["smtp_from_address"] = "noreply@example.com",
        ["smtp_security"] = "none",
    };

    private static readonly Dictionary<string, string?> EncryptedConfigured = new()
    {
        ["smtp_enabled"] = "1",
        ["smtp_host"] = "smtp.example.com",
        ["smtp_from_address"] = "noreply@example.com",
        ["smtp_security"] = "starttls",
        ["smtp_username"] = "user",
        ["smtp_password"] = "pass",
    };

    [Fact]
    public async Task IsAvailableAsync_CleartextTransport_NoOverride_ReturnsFalse()
    {
        var mailer = new SmtpInviteMailer(
            BuildInstance(CleartextConfigured), new RecordingMailSender(), Cfg(), NullLogger<SmtpInviteMailer>.Instance, RealLocalizer());

        Assert.False(await mailer.IsAvailableAsync());
    }

    /// <summary>Adversarial twin: the override makes the same cleartext transport available.</summary>
    [Fact]
    public async Task IsAvailableAsync_CleartextTransport_WithOverride_ReturnsTrue()
    {
        var mailer = new SmtpInviteMailer(
            BuildInstance(CleartextConfigured), new RecordingMailSender(),
            Cfg((CredentialMailPolicy.AllowInsecureEnvVar, "true")),
            NullLogger<SmtpInviteMailer>.Instance, RealLocalizer());

        Assert.True(await mailer.IsAvailableAsync());
    }

    /// <summary>Second adversarial twin: an encrypted transport needs no override.</summary>
    [Fact]
    public async Task IsAvailableAsync_EncryptedTransport_NoOverrideNeeded_ReturnsTrue()
    {
        var mailer = new SmtpInviteMailer(
            BuildInstance(EncryptedConfigured), new RecordingMailSender(), Cfg(), NullLogger<SmtpInviteMailer>.Instance, RealLocalizer());

        Assert.True(await mailer.IsAvailableAsync());
    }

    [Fact]
    public async Task SendInviteAsync_CleartextTransport_NoOverride_ThrowsAndNeverDispatches()
    {
        var sender = new RecordingMailSender();
        var mailer = new SmtpInviteMailer(
            BuildInstance(CleartextConfigured), sender, Cfg(), NullLogger<SmtpInviteMailer>.Instance, RealLocalizer());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            mailer.SendInviteAsync("user@example.com", "acme", "https://x.example/join?token=t", InviteExpiry, "en"));

        Assert.Equal(0, sender.Calls);
    }

    [Fact]
    public async Task SendInviteAsync_CleartextTransport_WithOverride_Dispatches()
    {
        var sender = new RecordingMailSender();
        var mailer = new SmtpInviteMailer(
            BuildInstance(CleartextConfigured), sender,
            Cfg((CredentialMailPolicy.AllowInsecureEnvVar, "true")),
            NullLogger<SmtpInviteMailer>.Instance, RealLocalizer());

        await mailer.SendInviteAsync("user@example.com", "acme", "https://x.example/join?token=t", InviteExpiry, "en");

        Assert.Equal(1, sender.Calls);
    }

    [Fact]
    public async Task SendInviteAsync_EncryptedTransport_NoOverrideNeeded_Dispatches()
    {
        var sender = new RecordingMailSender();
        var mailer = new SmtpInviteMailer(
            BuildInstance(EncryptedConfigured), sender, Cfg(), NullLogger<SmtpInviteMailer>.Instance, RealLocalizer());

        await mailer.SendInviteAsync("user@example.com", "acme", "https://x.example/join?token=t", InviteExpiry, "en");

        Assert.Equal(1, sender.Calls);
    }
}
