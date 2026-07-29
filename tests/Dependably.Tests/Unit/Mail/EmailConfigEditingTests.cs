using Dependably.Infrastructure;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// Covers the shared validation and view-building helpers used by both
/// <c>SystemController.EmailConfig</c> and <c>InstanceController</c>'s email-config routes, plus
/// the <see cref="EmailConfigEditing.ApplyAsync"/> write path (secret preserved on empty
/// password, non-secret fields always overwritten).
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailConfigEditingTests : IClassFixture<InMemoryDbFixture>
{
    private readonly OrgRepository _repo;

    public EmailConfigEditingTests(InMemoryDbFixture fixture)
    {
        _repo = new OrgRepository(fixture.Store, time: TestTime.Frozen());
    }

    private static EmailConfigRequest FullRequest(string? password = null) => new()
    {
        Enabled = true,
        Host = "smtp.example.com",
        Port = 587,
        Security = "starttls",
        Username = "user",
        Password = password,
        FromAddress = "noreply@example.com",
    };

    [Fact]
    public void Validate_ValidRequest_ReturnsNull()
    {
        var (field, key) = EmailConfigEditing.Validate(FullRequest());
        Assert.Null(field);
        Assert.Null(key);
    }

    [Fact]
    public void Validate_InvalidSecurity_ReturnsError()
    {
        var req = FullRequest();
        req.Security = "bogus";
        var (field, key) = EmailConfigEditing.Validate(req);
        Assert.Equal("security", field);
        Assert.Equal("error.email.invalidSecurity", key);
    }

    [Fact]
    public void BuildView_NeverExposesRawPassword()
    {
        var transport = new SmtpTransportSettings(
            "smtp.example.com", 587, "starttls", "user", "super-secret", "noreply@example.com");
        var resolved = new InstanceSmtpConfig.ResolvedSmtpConfig(true, transport, true);

        object view = EmailConfigEditing.BuildView(resolved, secretsAvailable: true);
        string json = System.Text.Json.JsonSerializer.Serialize(view);

        Assert.DoesNotContain("super-secret", json);
        Assert.Contains("\"hasPassword\":true", json);
        Assert.Contains("\"configured\":true", json);
        Assert.Contains("\"secretsAvailable\":true", json);
    }

    [Fact]
    public void BuildView_HasPassword_FalseWhenNoPasswordStored()
    {
        var transport = new SmtpTransportSettings(
            "smtp.example.com", 587, "starttls", null, null, "noreply@example.com");
        var resolved = new InstanceSmtpConfig.ResolvedSmtpConfig(false, transport, false);

        object view = EmailConfigEditing.BuildView(resolved, secretsAvailable: false);
        string json = System.Text.Json.JsonSerializer.Serialize(view);

        Assert.Contains("\"hasPassword\":false", json);
    }

    [Fact]
    public async Task ApplyAsync_EmptyPassword_PreservesStoredSecret()
    {
        await _repo.SetInstanceSettingAsync("smtp_password", "original-secret");

        await EmailConfigEditing.ApplyAsync(_repo, FullRequest(password: null), default);

        Assert.Equal("original-secret", await _repo.GetInstanceSettingAsync("smtp_password"));
    }

    [Fact]
    public async Task ApplyAsync_NonEmptyPassword_Rotates()
    {
        await _repo.SetInstanceSettingAsync("smtp_password", "original-secret");

        await EmailConfigEditing.ApplyAsync(_repo, FullRequest(password: "new-secret"), default);

        Assert.Equal("new-secret", await _repo.GetInstanceSettingAsync("smtp_password"));
    }

    [Fact]
    public async Task ApplyAsync_AlwaysOverwritesNonSecretFields()
    {
        await _repo.SetInstanceSettingAsync("smtp_host", "old.example.com");

        var req = FullRequest();
        req.Host = "new.example.com";
        await EmailConfigEditing.ApplyAsync(_repo, req, default);

        Assert.Equal("new.example.com", await _repo.GetInstanceSettingAsync("smtp_host"));
        Assert.Equal("starttls", await _repo.GetInstanceSettingAsync("smtp_security"));
        Assert.Equal("587", await _repo.GetInstanceSettingAsync("smtp_port"));
        Assert.Equal("1", await _repo.GetInstanceSettingAsync("smtp_enabled"));
    }

    /// <summary>
    /// The view reports the cleartext-credential finding on every read, not only on the save that
    /// introduced it — an operator who inherited someone else's configuration never sees that save,
    /// and the DB-backed config gives no boot-time moment at which to warn instead.
    /// </summary>
    [Fact]
    public void BuildView_ReportsCleartextCredentials_WhenSecurityIsNoneWithCredentials()
    {
        var transport = new SmtpTransportSettings(
            "smtp.example.com", 25, "none", "user", "super-secret", "noreply@example.com");
        var resolved = new InstanceSmtpConfig.ResolvedSmtpConfig(true, transport, true);

        string json = System.Text.Json.JsonSerializer.Serialize(
            EmailConfigEditing.BuildView(resolved, secretsAvailable: true));

        Assert.Contains("\"cleartextCredentials\":true", json);
        Assert.DoesNotContain("super-secret", json);
    }

    /// <summary>Adversarial twin: an unauthenticated relay on security=none is not a finding.</summary>
    [Fact]
    public void BuildView_DoesNotReportCleartextCredentials_ForAnUnauthenticatedRelay()
    {
        var transport = new SmtpTransportSettings(
            "smtp.example.com", 25, "none", null, null, "noreply@example.com");
        var resolved = new InstanceSmtpConfig.ResolvedSmtpConfig(true, transport, true);

        string json = System.Text.Json.JsonSerializer.Serialize(
            EmailConfigEditing.BuildView(resolved, secretsAvailable: true));

        Assert.Contains("\"cleartextCredentials\":false", json);
    }

    [Fact]
    public void BuildView_DoesNotReportCleartextCredentials_WhenTheSessionIsProtected()
    {
        var transport = new SmtpTransportSettings(
            "smtp.example.com", 587, "starttls", "user", "super-secret", "noreply@example.com");
        var resolved = new InstanceSmtpConfig.ResolvedSmtpConfig(true, transport, true);

        string json = System.Text.Json.JsonSerializer.Serialize(
            EmailConfigEditing.BuildView(resolved, secretsAvailable: true));

        Assert.Contains("\"cleartextCredentials\":false", json);
    }
}
