using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// <see cref="AlertSettingsRepository"/>'s email-channel surface: the column-scoped
/// <c>UpdateEmailAsync</c> upsert (password preservation/rotation, no clobbering of gates/Slack),
/// the decrypted delivery-config read, and the success/failure health-column pair mirroring the
/// Slack auto-disable arithmetic.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertSettingsRepositoryEmailTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static EnvelopeProtector MakeProtector()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(key)
            })
            .Build();
        return new EnvelopeProtector(new EnvFileMasterKeyProvider(config));
    }

    private static UpdateAlertEmail BuildRequest(
        bool inherit = false,
        string? host = "smtp.example.com", string? password = "hunter2", string? from = "noreply@example.com") =>
        new(
            EmailInheritInstance: inherit,
            EmailSmtpHost: host,
            EmailSmtpPort: 587,
            EmailSmtpSecurity: "starttls",
            EmailSmtpUsername: "user",
            EmailSmtpPassword: password,
            EmailSmtpFrom: from);

    /// <summary>The delivery gate (email_enabled + email_recipients) lives on the gates upsert.</summary>
    private static Task<AlertSettings> EnableEmailAsync(
        AlertSettingsRepository settings, string? recipients = "a@example.com") =>
        settings.UpdateGatesAsync("org1", new UpdateAlertGates(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            EmailEnabled: true, EmailRecipients: recipients));

    [Fact]
    public async Task UpdateEmail_NonEmptyPassword_EncryptsAtRest()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);

        await settings.UpdateEmailAsync("org1", BuildRequest(password: "hunter2"));

        await using var conn = await _db.OpenAsync();
        string? raw = await conn.ExecuteScalarAsync<string>(
            "SELECT email_smtp_password FROM alert_settings WHERE org_id = 'org1'");
        Assert.NotNull(raw);
        Assert.StartsWith("enc:v1:", raw);

        var updated = await settings.GetAsync("org1");
        Assert.True(updated.HasEmailSmtpPassword);
    }

    [Fact]
    public async Task UpdateEmail_NullPassword_PreservesPreviouslyStoredValue()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);

        await EnableEmailAsync(settings);
        await settings.UpdateEmailAsync("org1", BuildRequest(password: "original-secret"));
        await settings.UpdateEmailAsync("org1", BuildRequest(password: null, host: "smtp2.example.com"));

        var updated = await settings.GetAsync("org1");
        Assert.True(updated.HasEmailSmtpPassword);
        Assert.Equal("smtp2.example.com", updated.EmailSmtpHost);

        var delivery = await settings.GetDecryptedEmailDeliveryConfigAsync("org1");
        Assert.NotNull(delivery);
        Assert.Equal("original-secret", delivery!.OwnTransport.Password);
    }

    [Fact]
    public async Task UpdateEmail_EmptyStringPassword_PreservesPreviouslyStoredValue()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);

        await EnableEmailAsync(settings);
        await settings.UpdateEmailAsync("org1", BuildRequest(password: "original-secret"));
        await settings.UpdateEmailAsync("org1", BuildRequest(password: ""));

        var delivery = await settings.GetDecryptedEmailDeliveryConfigAsync("org1");
        Assert.Equal("original-secret", delivery!.OwnTransport.Password);
    }

    [Fact]
    public async Task UpdateEmail_DoesNotClobberGatesOrSlack()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);

        await settings.UpdateGatesAsync("org1", new UpdateAlertGates(
            QuarantineAlertsEnabled: false, VulnAlertsEnabled: false, VulnMinSeverity: "CRITICAL",
            EmailEnabled: true, EmailRecipients: "a@example.com"));
        await settings.UpdateSlackAsync("org1", new UpdateAlertSlack(
            SlackEnabled: true, SlackWebhookUrl: "https://hooks.slack.com/services/T/B/x"));

        await settings.UpdateEmailAsync("org1", BuildRequest());

        var updated = await settings.GetAsync("org1");
        Assert.False(updated.QuarantineAlertsEnabled);
        Assert.False(updated.VulnAlertsEnabled);
        Assert.Equal("CRITICAL", updated.VulnMinSeverity);
        Assert.True(updated.SlackEnabled);
        Assert.True(updated.HasSlackWebhook);
        Assert.True(updated.EmailEnabled);
        Assert.Equal("a@example.com", updated.EmailRecipients);
    }

    [Fact]
    public async Task UpdateGates_DoesNotClobberEmailTransport()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);

        await settings.UpdateEmailAsync("org1", BuildRequest(password: "hunter2"));
        await EnableEmailAsync(settings, recipients: "b@example.com");

        var updated = await settings.GetAsync("org1");
        Assert.Equal("smtp.example.com", updated.EmailSmtpHost);
        Assert.True(updated.HasEmailSmtpPassword);
        Assert.Equal("noreply@example.com", updated.EmailSmtpFrom);
        Assert.True(updated.EmailEnabled);
        Assert.Equal("b@example.com", updated.EmailRecipients);
    }

    [Fact]
    public async Task GetDecryptedEmailDeliveryConfig_Disabled_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        // Transport configured, but the delivery gate (email_enabled) was never turned on.
        await settings.UpdateEmailAsync("org1", BuildRequest());

        Assert.Null(await settings.GetDecryptedEmailDeliveryConfigAsync("org1"));
    }

    [Fact]
    public async Task RecordEmailFailure_AutoDisablesAfterConsecutiveThreshold()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings);
        await settings.UpdateEmailAsync("org1", BuildRequest());

        for (int i = 0; i < AlertDeliveryPolicy.AutoDisableAfterFailures - 1; i++)
        {
            bool disabled = await settings.RecordEmailFailureAsync(
                "org1", "err", AlertDeliveryPolicy.AutoDisableAfterFailures, AlertDeliveryPolicy.AutoDisableAfterDuration);
            Assert.False(disabled, $"Should not disable at failure {i + 1}");
        }

        bool finalDisabled = await settings.RecordEmailFailureAsync(
            "org1", "err", AlertDeliveryPolicy.AutoDisableAfterFailures, AlertDeliveryPolicy.AutoDisableAfterDuration);
        Assert.True(finalDisabled);

        var updated = await settings.GetAsync("org1");
        Assert.False(updated.EmailEnabled);
    }

    [Fact]
    public async Task RecordEmailSuccess_ResetsFailureCounters()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await settings.UpdateEmailAsync("org1", BuildRequest());

        await settings.RecordEmailFailureAsync(
            "org1", "err", AlertDeliveryPolicy.AutoDisableAfterFailures, AlertDeliveryPolicy.AutoDisableAfterDuration);
        await settings.RecordEmailSuccessAsync("org1");

        var updated = await settings.GetAsync("org1");
        Assert.Equal(0, updated.EmailConsecutiveFailures);
        Assert.Null(updated.EmailFailingSince);
        Assert.Null(updated.EmailLastError);
        Assert.Equal("ok", updated.EmailLastStatus);
    }
}
