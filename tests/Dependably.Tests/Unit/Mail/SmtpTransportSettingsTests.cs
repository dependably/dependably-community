using Dependably.Infrastructure.Mail;
using Xunit;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// <see cref="SmtpTransportSettings.IsConfigured"/> truth table and the static
/// <see cref="SmtpTransportSettings.Validate"/> helper shared by both email-config endpoints.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SmtpTransportSettingsTests
{
    private static SmtpTransportSettings Build(
        string? host = "smtp.example.com",
        int port = 587,
        string security = "starttls",
        string? username = "user",
        string? password = "pass",
        string? fromAddress = "noreply@example.com") =>
        new(host, port, security, username, password, fromAddress);

    [Fact]
    public void IsConfigured_True_WhenHostFromAndCredentialsPresent()
    {
        var sut = Build();
        Assert.True(sut.IsConfigured);
    }

    [Fact]
    public void IsConfigured_False_WhenHostMissing()
    {
        var sut = Build(host: null);
        Assert.False(sut.IsConfigured);
    }

    [Fact]
    public void IsConfigured_False_WhenFromAddressMissing()
    {
        var sut = Build(fromAddress: null);
        Assert.False(sut.IsConfigured);
    }

    [Fact]
    public void IsConfigured_False_WhenSecurityRequiresCredsButNoneSupplied()
    {
        var sut = Build(security: "starttls", username: null, password: null);
        Assert.False(sut.IsConfigured);
    }

    [Fact]
    public void IsConfigured_False_WhenOnlyUsernamePresent()
    {
        var sut = Build(username: "user", password: null);
        Assert.False(sut.IsConfigured);
    }

    [Fact]
    public void IsConfigured_False_WhenOnlyPasswordPresent()
    {
        var sut = Build(username: null, password: "pass");
        Assert.False(sut.IsConfigured);
    }

    [Fact]
    public void IsConfigured_True_WhenSecurityNone_BypassesCredentialRequirement()
    {
        var sut = Build(security: "none", username: null, password: null);
        Assert.True(sut.IsConfigured);
    }

    [Theory]
    [InlineData("SSL")]
    [InlineData("None")]
    [InlineData("STARTTLS")]
    public void IsConfigured_SecurityCheck_IsCaseInsensitive(string security)
    {
        // "none" bypasses creds regardless of case; the other two still require creds, which
        // Build() supplies, so every case in this theory should resolve to configured=true.
        var sut = Build(security: security);
        Assert.True(sut.IsConfigured);
    }

    // ── Validate ─────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_AllFieldsValid_ReturnsNull()
    {
        var (field, key) = SmtpTransportSettings.Validate(587, "starttls", "a@example.com");
        Assert.Null(field);
        Assert.Null(key);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(100000)]
    public void Validate_PortOutOfRange_ReturnsPortError(int port)
    {
        var (field, key) = SmtpTransportSettings.Validate(port, "starttls", "a@example.com");
        Assert.Equal("port", field);
        Assert.Equal("error.email.invalidPort", key);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(65535)]
    public void Validate_PortBoundaries_AreValid(int port)
    {
        var (field, key) = SmtpTransportSettings.Validate(port, "starttls", "a@example.com");
        Assert.Null(field);
        Assert.Null(key);
    }

    [Fact]
    public void Validate_NullPort_IsNotValidated()
    {
        var (field, key) = SmtpTransportSettings.Validate(null, "starttls", "a@example.com");
        Assert.Null(field);
        Assert.Null(key);
    }

    [Theory]
    [InlineData("starttls")]
    [InlineData("ssl")]
    [InlineData("none")]
    [InlineData("SSL")]
    public void Validate_KnownSecurityModes_AreValid(string security)
    {
        var (field, key) = SmtpTransportSettings.Validate(587, security, "a@example.com");
        Assert.Null(field);
        Assert.Null(key);
    }

    [Fact]
    public void Validate_UnknownSecurity_ReturnsSecurityError()
    {
        var (field, key) = SmtpTransportSettings.Validate(587, "tls-magic", "a@example.com");
        Assert.Equal("security", field);
        Assert.Equal("error.email.invalidSecurity", key);
    }

    [Fact]
    public void Validate_InvalidFromAddress_ReturnsFromError()
    {
        var (field, key) = SmtpTransportSettings.Validate(587, "starttls", "not-an-email");
        Assert.Equal("fromAddress", field);
        Assert.Equal("error.email.invalidFrom", key);
    }

    [Fact]
    public void Validate_EmptyFromAddress_IsNotValidated()
    {
        // An empty from address is treated as "unset", not "invalid" — the caller may be
        // clearing the field (e.g. disabling email).
        var (field, key) = SmtpTransportSettings.Validate(587, "starttls", "");
        Assert.Null(field);
        Assert.Null(key);
    }
}
