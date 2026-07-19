using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// Full enabled × inherit × instanceConfigured × ownConfigured matrix for
/// <see cref="EffectiveEmailConfigResolver"/> — the resolver the delivery queue and the
/// test-send endpoint both use, so every branch here has real production consequences.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EffectiveEmailConfigResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider Clock = TestTime.Frozen();

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

    private static InstanceSmtpConfig BuildInstance(bool enabled, bool configured)
    {
        var db = new Dictionary<string, string?>
        {
            ["smtp_enabled"] = enabled ? "1" : "0",
        };
        if (configured)
        {
            db["smtp_host"] = "instance.example.com";
            db["smtp_from_address"] = "instance@example.com";
            db["smtp_security"] = "none";
        }

        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);
        return new InstanceSmtpConfig(Reader, Clock);
    }

    private static async Task SeedOrgAsync(
        AlertSettingsRepository settings,
        bool emailEnabled,
        bool inheritInstance,
        bool ownConfigured,
        string? recipients = "admin@example.com")
    {
        // The delivery gate (email_enabled + recipients) lives on the gates upsert; the
        // transport columns on the email upsert.
        await settings.UpdateGatesAsync("org1", new UpdateAlertGates(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            EmailEnabled: emailEnabled, EmailRecipients: recipients));
        await settings.UpdateEmailAsync("org1", new UpdateAlertEmail(
            EmailInheritInstance: inheritInstance,
            EmailSmtpHost: ownConfigured ? "org.example.com" : null,
            EmailSmtpPort: 587,
            EmailSmtpSecurity: "none",
            EmailSmtpUsername: null,
            EmailSmtpPassword: null,
            EmailSmtpFrom: ownConfigured ? "org@example.com" : null));
    }

    [Fact]
    public async Task Disabled_ReturnsNull_RegardlessOfTransportState()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: false, inheritInstance: true, ownConfigured: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }

    [Fact]
    public async Task Enabled_NoRecipients_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: true, ownConfigured: true, recipients: null);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }

    [Fact]
    public async Task Enabled_Inherit_InstanceConfigured_ResolvesInstanceTransport()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: true, ownConfigured: false);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.NotNull(resolved);
        Assert.Equal("instance.example.com", resolved!.Transport.Host);
        Assert.Equal(["admin@example.com"], resolved.Recipients);
    }

    [Fact]
    public async Task Enabled_Inherit_InstanceEnabledButUnconfigured_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: true, ownConfigured: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: false));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }

    [Fact]
    public async Task Enabled_Inherit_InstanceConfiguredButNotEnabled_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: true, ownConfigured: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: false, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }

    [Fact]
    public async Task Enabled_NotInheriting_OwnConfigured_ResolvesOwnTransport()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: false, ownConfigured: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.NotNull(resolved);
        Assert.Equal("org.example.com", resolved!.Transport.Host);
    }

    [Fact]
    public async Task Enabled_NotInheriting_OwnUnconfigured_ReturnsNull_EvenWhenInstanceConfigured()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: false, ownConfigured: false);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }

    [Fact]
    public async Task Enabled_NotInheriting_OwnUnconfigured_InstanceAlsoUnconfigured_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, inheritInstance: false, ownConfigured: false);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: false, configured: false));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }

    [Fact]
    public async Task NoSettingsRow_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.Null(resolved);
    }
}
