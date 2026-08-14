using Dependably.Infrastructure.Mail;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// <see cref="CredentialMailPolicy"/>: the opt-in override gate for credential-bearing mail sent
/// over an unencrypted transport (#539), mirroring <c>WebhookSiemForwarder.AllowsInsecure</c>'s
/// naming, accepted spellings, and posture.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CredentialMailPolicyTests
{
    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    private static SmtpTransportSettings Transport(string security) =>
        new(Host: "smtp.example.com", Port: 587, Security: security, Username: null, Password: null, FromAddress: "noreply@example.com");

    [Fact]
    public void AllowsInsecure_Unset_ReturnsFalse()
    {
        Assert.False(CredentialMailPolicy.AllowsInsecure(Cfg()));
    }

    [Theory]
    [InlineData("true")]
    [InlineData("True")]
    [InlineData("1")]
    [InlineData("yes")]
    [InlineData("YES")]
    public void AllowsInsecure_AcceptsThePlausibleSpellings(string value)
    {
        Assert.True(CredentialMailPolicy.AllowsInsecure(Cfg((CredentialMailPolicy.AllowInsecureEnvVar, value))));
    }

    [Theory]
    [InlineData("false")]
    [InlineData("0")]
    [InlineData("no")]
    [InlineData("")]
    public void AllowsInsecure_RejectsEverythingElse(string value)
    {
        Assert.False(CredentialMailPolicy.AllowsInsecure(Cfg((CredentialMailPolicy.AllowInsecureEnvVar, value))));
    }

    [Fact]
    public void RefusesCredentialMail_CleartextNoOverride_True()
    {
        Assert.True(CredentialMailPolicy.RefusesCredentialMail(Transport("none"), Cfg()));
        Assert.True(CredentialMailPolicy.RefusesCredentialMail(Transport("none"), allowsInsecure: false));
    }

    [Fact]
    public void RefusesCredentialMail_CleartextWithOverride_False()
    {
        var cfg = Cfg((CredentialMailPolicy.AllowInsecureEnvVar, "true"));
        Assert.False(CredentialMailPolicy.RefusesCredentialMail(Transport("none"), cfg));
        Assert.False(CredentialMailPolicy.RefusesCredentialMail(Transport("none"), allowsInsecure: true));
    }

    [Theory]
    [InlineData("starttls")]
    [InlineData("ssl")]
    public void RefusesCredentialMail_EncryptedTransport_NeverRefusesEvenWithoutOverride(string security)
    {
        Assert.False(CredentialMailPolicy.RefusesCredentialMail(Transport(security), Cfg()));
        Assert.False(CredentialMailPolicy.RefusesCredentialMail(Transport(security), allowsInsecure: false));
    }

    /// <summary>Fail-closed on an unrecognized security value — same refusal as <c>none</c>.</summary>
    [Fact]
    public void RefusesCredentialMail_UnrecognizedSecurity_True()
    {
        Assert.True(CredentialMailPolicy.RefusesCredentialMail(Transport("tls-magic"), Cfg()));
    }
}
