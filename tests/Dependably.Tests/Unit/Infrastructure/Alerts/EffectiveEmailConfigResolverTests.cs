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
/// Full enabled × recipients × instanceEnabled × instanceConfigured matrix for
/// <see cref="EffectiveEmailConfigResolver"/> — the resolver the delivery queue and the
/// test-send endpoint both use, so every branch here has real production consequences. There is no
/// per-org transport arm: SMTP is an instance-level transport, so an org contributes only the gate
/// and the recipient list.
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

    private static Task SeedOrgAsync(
        AlertSettingsRepository settings,
        bool emailEnabled,
        string? recipients = "admin@example.com") =>
        settings.UpdateEmailChannelAsync("org1", new UpdateAlertEmailChannel(
            EmailEnabled: emailEnabled, EmailRecipients: recipients));

    /// <summary>
    /// Writes the transport columns a pre-removal release would have persisted, straight to the
    /// row. Nothing reads them any more; the tests that use this assert exactly that.
    /// </summary>
    private async Task SeedRetiredOwnTransportAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE alert_settings
            SET email_inherit_instance = 0,
                email_smtp_host = 'org.example.com',
                email_smtp_port = 587,
                email_smtp_security = 'none',
                email_smtp_from = 'org@example.com'
            WHERE org_id = 'org1'
            """);
    }

    [Fact]
    public async Task Disabled_ReturnsNull_RegardlessOfTransportState()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: false);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        Assert.Null(await resolver.ResolveAsync("org1"));
    }

    [Fact]
    public async Task Enabled_NoRecipients_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true, recipients: null);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        Assert.Null(await resolver.ResolveAsync("org1"));
    }

    [Fact]
    public async Task Enabled_InstanceConfigured_ResolvesInstanceTransport()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.NotNull(resolved);
        Assert.Equal("instance.example.com", resolved!.Transport.Host);
        Assert.Equal(["admin@example.com"], resolved.Recipients);
    }

    /// <summary>
    /// The primary upgrade hazard, and the reason the startup advisory exists: an org that used to
    /// carry its own working transport now resolves to nothing when the instance relay is
    /// unconfigured, and nothing about that is loud — null means "nothing to send", so no failure
    /// is recorded and no error surfaces.
    /// </summary>
    [Fact]
    public async Task Enabled_InstanceEnabledButUnconfigured_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: false));

        Assert.Null(await resolver.ResolveAsync("org1"));
    }

    [Fact]
    public async Task Enabled_InstanceConfiguredButNotEnabled_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: false, configured: true));

        Assert.Null(await resolver.ResolveAsync("org1"));
    }

    /// <summary>
    /// A row upgraded from a release with a per-org transport still carries those columns. They are
    /// inert: the org resolves to the instance transport like every other org, never to the host it
    /// used to be pointed at.
    /// </summary>
    [Fact]
    public async Task Enabled_RowWithRetiredOwnTransport_StillResolvesTheInstanceTransport()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true);
        await SeedRetiredOwnTransportAsync();
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        var resolved = await resolver.ResolveAsync("org1");

        Assert.NotNull(resolved);
        Assert.Equal("instance.example.com", resolved!.Transport.Host);
    }

    /// <summary>
    /// The same row with the instance relay unconfigured resolves to nothing — it does NOT fall
    /// back to the retired per-org host.
    /// </summary>
    [Fact]
    public async Task Enabled_RowWithRetiredOwnTransport_InstanceUnconfigured_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        await SeedOrgAsync(settings, emailEnabled: true);
        await SeedRetiredOwnTransportAsync();
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: false));

        Assert.Null(await resolver.ResolveAsync("org1"));
    }

    [Fact]
    public async Task NoSettingsRow_ReturnsNull()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, Clock);
        var resolver = new EffectiveEmailConfigResolver(settings, BuildInstance(enabled: true, configured: true));

        Assert.Null(await resolver.ResolveAsync("org1"));
    }
}
