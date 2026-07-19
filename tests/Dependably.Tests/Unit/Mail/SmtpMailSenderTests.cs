using Dependably.Infrastructure.Mail;
using Dependably.Protocol;
using Dependably.Security;
using MailKit.Security;
using Xunit;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// Covers <see cref="SmtpMailSender.ToSecureSocketOptions"/> (the <c>starttls|ssl|none</c> →
/// MailKit <see cref="SecureSocketOptions"/> mapping), the guard-clause validation on
/// <see cref="SmtpMailSender.SendAsync"/>, and the connect-time SSRF guard every send now runs
/// before MailKit ever sees the host. A live SMTP send against a real relay is not exercised
/// here — MailKit's wire protocol is third-party-tested; this class pins Dependably's own
/// mapping, input-validation, and SSRF-gating logic.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SmtpMailSenderTests
{
    [Theory]
    [InlineData("starttls", SecureSocketOptions.StartTls)]
    [InlineData("STARTTLS", SecureSocketOptions.StartTls)]
    [InlineData("ssl", SecureSocketOptions.SslOnConnect)]
    [InlineData("SSL", SecureSocketOptions.SslOnConnect)]
    [InlineData("none", SecureSocketOptions.None)]
    [InlineData("None", SecureSocketOptions.None)]
    // Unrecognized values default to StartTls (the safer choice over an unencrypted connection).
    [InlineData("bogus", SecureSocketOptions.StartTls)]
    public void ToSecureSocketOptions_MapsSecurityVocabulary(string security, SecureSocketOptions expected)
    {
        Assert.Equal(expected, SmtpMailSender.ToSecureSocketOptions(security));
    }

    [Fact]
    public async Task SendAsync_NoRecipients_Throws()
    {
        var sut = new SmtpMailSender(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));
        var transport = new SmtpTransportSettings("smtp.example.com", 587, "starttls", "u", "p", "from@example.com");

        await Assert.ThrowsAsync<ArgumentException>(
            () => sut.SendAsync(transport, [], "subject", "body"));
    }

    [Fact]
    public async Task SendAsync_MissingHost_Throws()
    {
        var sut = new SmtpMailSender(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));
        var transport = new SmtpTransportSettings(null, 587, "starttls", "u", "p", "from@example.com");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sut.SendAsync(transport, ["to@example.com"], "subject", "body"));
    }

    [Fact]
    public async Task SendAsync_MissingFromAddress_Throws()
    {
        var sut = new SmtpMailSender(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));
        var transport = new SmtpTransportSettings("smtp.example.com", 587, "starttls", "u", "p", null);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sut.SendAsync(transport, ["to@example.com"], "subject", "body"));
    }

    // ── Connect-time SSRF guard ──────────────────────────────────────────────
    //
    // Regression coverage for the SMTP host having no SSRF check at connect time: before this
    // fix, SendAsync handed transport.Host straight to MailKit's SmtpClient.ConnectAsync, which
    // resolves and dials it with no vetting at all — an org admin (tenant:configure, not
    // system-admin) could point the SMTP relay at a cloud-metadata address or any internal
    // host:port and reach it via the test-send endpoint. A blocked host must now be rejected by
    // SmtpMailSender itself, before any DNS lookup or socket connect MailKit could perform.

    [Theory]
    [InlineData("169.254.169.254")]  // cloud metadata endpoint
    [InlineData("127.0.0.1")]        // loopback
    [InlineData("10.0.0.5")]         // RFC 1918 internal service
    public async Task SendAsync_BlockedHost_ThrowsSsrfBlockedException_BeforeAnyNetworkAttempt(string blockedHost)
    {
        var sut = new SmtpMailSender(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));
        var transport = new SmtpTransportSettings(blockedHost, 587, "none", null, null, "from@example.com");

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(
            () => sut.SendAsync(transport, ["to@example.com"], "subject", "body"));

        Assert.Contains(blockedHost, ex.Message);
    }

    [Fact]
    public async Task SendAsync_HostLiteralBlockedOnlyByPrivatePredicate_RespectsInjectedGuard()
    {
        // The RFC 1918 range is only blocked when the caller wires up the full IsBlockedIp
        // predicate (WEBHOOK_ALLOW_PRIVATE=false, the default); a guard constructed with the
        // excluding-private predicate (WEBHOOK_ALLOW_PRIVATE=true) must let it dial instead of
        // rejecting up front — proving SmtpMailSender defers entirely to whichever predicate DI
        // wired up rather than hardcoding its own block list. A short external cancellation
        // bounds the test's runtime regardless of how the sandbox's network stack reacts to
        // dialing an address nothing is listening on.
        var permissiveGuard = new SsrfConnectCallback(SsrfGuard.IsBlockedIpExcludingPrivate);
        var sut = new SmtpMailSender(permissiveGuard);
        var transport = new SmtpTransportSettings("10.0.0.5", 58925, "none", null, null, "from@example.com");

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => sut.SendAsync(transport, ["to@example.com"], "subject", "body", cts.Token));

        // Allowed past the guard — whatever failure follows (unreachable/refused, or the
        // 500ms bound firing while still trying) is never the guard's own rejection.
        Assert.IsNotType<SsrfBlockedException>(ex);
    }
}
