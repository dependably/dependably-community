using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies the production DI wiring, not just the queue in isolation: <see cref="IAlertNotifier"/>
/// resolves to <see cref="CompositeAlertNotifier"/> (never a bare queue), and a real
/// <c>AlertService.RaiseQuarantineAlertAsync</c> call reaches <see cref="AlertEmailQueue"/>'s
/// genuine delivery attempt end-to-end through the full composition root — no queue is
/// constructed by hand here, unlike the <c>AlertEmailQueueTests</c> unit suite.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AlertNotifierWiringTests : IAsyncLifetime
{
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task IAlertNotifier_ResolvesToCompositeAlertNotifier_FanningToBothIndependentlyResolvableQueues()
    {
        await using var factory = new DependablyFactory();

        var notifier = factory.Services.GetRequiredService<IAlertNotifier>();
        Assert.IsType<CompositeAlertNotifier>(notifier);

        // CompositeAlertNotifier fans out to these — it doesn't replace them, so each queue is
        // still independently resolvable (and is the same hosted-service instance).
        Assert.NotNull(factory.Services.GetRequiredService<AlertSlackQueue>());
        Assert.NotNull(factory.Services.GetRequiredService<AlertEmailQueue>());
    }

    /// <summary>
    /// Configures the org's own SMTP transport at a host:port nothing listens on, so the real
    /// MailKit connect genuinely fails (connection refused) rather than being stubbed — proving
    /// the alert travels <c>AlertService</c> → <c>CompositeAlertNotifier</c> →
    /// <c>AlertEmailQueue</c> → <c>SmtpMailSender</c> through the actual composition root, not a
    /// hand-wired test double. The frozen clock lets the test pump through the real 1s/5s/30s
    /// backoff without waiting out 36 real seconds.
    /// </summary>
    [Fact]
    public async Task RaiseQuarantineAlert_WithEmailConfigured_ReachesEmailQueueThroughRealDIWiring()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        await using var factory = new DependablyFactory { FrozenClock = clock };

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        var settings = factory.Services.GetRequiredService<AlertSettingsRepository>();
        await settings.UpdateGatesAsync(orgId, new UpdateAlertGates(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            EmailEnabled: true, EmailRecipients: "ops@example.com"));
        await settings.UpdateEmailAsync(orgId, new UpdateAlertEmail(
            EmailInheritInstance: false,
            EmailSmtpHost: "127.0.0.1", EmailSmtpPort: 1, EmailSmtpSecurity: "none",
            EmailSmtpUsername: null, EmailSmtpPassword: null, EmailSmtpFrom: "alerts@example.com"));

        var alerts = factory.Services.GetRequiredService<AlertRepository>();
        var alertService = factory.Services.GetRequiredService<AlertService>();

        string sourceRef = Guid.NewGuid().ToString("N");
        await alertService.RaiseQuarantineAlertAsync(
            orgId, sourceRef, "npm", "pkg:npm/wiring-test@1.0.0", "quarantine", "Held pending review.");

        // now-ok: polling deadline awaiting the background queue's real async delivery loop;
        // the frozen clock (not this wall-clock read) drives the retry backoff itself.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        AlertRecord? reread = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            reread = (await alerts.ListAsync(orgId, null, 50, 0)).Items
                .FirstOrDefault(a => a.SourceRef == sourceRef);
            if (reread?.EmailStatus is not null)
            {
                break;
            }

            clock.Advance(TimeSpan.FromSeconds(1));
            await Task.Delay(50);
        }

        Assert.NotNull(reread);
        Assert.Equal("failed", reread!.EmailStatus);
        Assert.NotNull(reread.EmailError);

        // Slack was never configured for this org — its outcome column stays untouched,
        // confirming the two channels record independently.
        Assert.Null(reread.SlackStatus);
    }
}
