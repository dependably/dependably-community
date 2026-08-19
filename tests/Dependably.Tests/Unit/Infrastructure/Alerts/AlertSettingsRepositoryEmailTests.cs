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
/// <see cref="AlertSettingsRepository"/>'s email-channel surface. There is no per-org SMTP
/// transport — SMTP is an instance-level transport and an org owns only the gate and the recipient
/// list — so what remains here is the delivery-config read and the health-column pair.
///
/// The load-bearing test is <c>RecordEmailFailure_NeverDisablesTheChannel</c>: failure updates
/// health and never rewrites the tenant's intent, which is what stops one operator relay outage
/// from turning into a per-org configuration failure across the whole deployment. The Slack arm
/// deliberately keeps auto-disabling; that is pinned in <see cref="AlertSettingsRepositoryTests"/>.
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

    /// <summary>The delivery gate (email_enabled + email_recipients) lives on the gates upsert.</summary>
    private static Task<AlertSettings> EnableEmailAsync(
        AlertSettingsRepository settings, string? recipients = "a@example.com") =>
        settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: recipients));

    [Fact]
    public async Task GetDecryptedEmailDeliveryConfig_Enabled_ReturnsParsedRecipients()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings, recipients: "a@example.com, b@example.com");

        var delivery = await settings.GetDecryptedEmailDeliveryConfigAsync("org1");

        Assert.NotNull(delivery);
        Assert.Equal(["a@example.com", "b@example.com"], delivery!.Recipients);
    }

    [Fact]
    public async Task GetDecryptedEmailDeliveryConfig_Disabled_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        // Recipients present, but the delivery gate (email_enabled) was never turned on.
        await settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: false, EmailRecipients: "a@example.com"));

        Assert.Null(await settings.GetDecryptedEmailDeliveryConfigAsync("org1"));
    }

    [Fact]
    public async Task GetDecryptedEmailDeliveryConfig_NoRecipients_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings, recipients: null);

        Assert.Null(await settings.GetDecryptedEmailDeliveryConfigAsync("org1"));
    }

    [Fact]
    public async Task UpdateGates_DoesNotClobberSlack()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);

        await settings.UpdateSlackAsync("org1", new UpdateAlertSlack(
            SlackEnabled: true, SlackWebhookUrl: "https://hooks.slack.com/services/T/B/x"));
        await EnableEmailAsync(settings, recipients: "b@example.com");

        var updated = await settings.GetAsync("org1");
        Assert.True(updated.SlackEnabled);
        Assert.True(updated.HasSlackWebhook);
        Assert.True(updated.EmailEnabled);
        Assert.Equal("b@example.com", updated.EmailRecipients);
    }

    /// <summary>
    /// The whole point of the failure-domain rule: alert email rides the instance transport, so a
    /// delivery failure is an operator infrastructure failure shared by every org. Recording it
    /// must never rewrite this org's configuration — otherwise one relay outage silently turns
    /// email alerting off fleet-wide and every tenant has to re-enable by hand.
    /// </summary>
    [Fact]
    public async Task RecordEmailFailure_NeverDisablesTheChannel()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings);

        // Well past any threshold the Slack arm would have auto-disabled at.
        for (int i = 0; i < (AlertDeliveryPolicy.AutoDisableAfterFailures * 2) + 1; i++)
        {
            await settings.RecordEmailFailureAsync("org1", "err");
        }

        var updated = await settings.GetAsync("org1");
        Assert.True(updated.EmailEnabled);
        Assert.Equal("a@example.com", updated.EmailRecipients);
    }

    [Fact]
    public async Task RecordEmailFailure_StillClimbsTheHealthCounters()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings);

        await settings.RecordEmailFailureAsync("org1", "relay refused the connection");
        await settings.RecordEmailFailureAsync("org1", "relay refused the connection");

        var updated = await settings.GetAsync("org1");
        Assert.Equal("failed", updated.EmailLastStatus);
        Assert.Equal(2, updated.EmailConsecutiveFailures);
        Assert.NotNull(updated.EmailFailingSince);
        Assert.Equal("relay refused the connection", updated.EmailLastError);
    }

    [Fact]
    public async Task RecordEmailFailure_TruncatesAnOverlongError()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings);

        await settings.RecordEmailFailureAsync("org1", new string('x', 900));

        var updated = await settings.GetAsync("org1");
        Assert.Equal(500, updated.EmailLastError!.Length);
    }

    [Fact]
    public async Task RecordEmailSuccess_ResetsFailureCounters()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await EnableEmailAsync(settings);

        await settings.RecordEmailFailureAsync("org1", "err");
        await settings.RecordEmailSuccessAsync("org1");

        var updated = await settings.GetAsync("org1");
        Assert.Equal(0, updated.EmailConsecutiveFailures);
        Assert.Null(updated.EmailFailingSince);
        Assert.Null(updated.EmailLastError);
        Assert.Equal("ok", updated.EmailLastStatus);
    }

}
