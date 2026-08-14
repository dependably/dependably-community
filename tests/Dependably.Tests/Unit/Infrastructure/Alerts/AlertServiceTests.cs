using Dapper;
using Dependably.Infrastructure.Alerts;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// Covers <see cref="AlertService"/>'s settings-gated raise + notify-on-fresh-insert. The
/// notifier is substituted so each test asserts exactly when <see cref="IAlertNotifier.NotifyAsync"/>
/// fires, independent of the Slack delivery plane.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertServiceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly AlertRepository _alerts;

    public AlertServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _alerts = new AlertRepository(_fixture.Store, TimeProvider.System);
    }

    private AlertService BuildService(IAlertNotifier notifier) =>
        new(_alerts, notifier, NullLogger<AlertService>.Instance);

    private async Task SeedSettingsAsync(
        string orgId, bool quarantineEnabled = true, bool vulnEnabled = true, string minSeverity = "HIGH")
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, quarantine_alerts_enabled, vuln_alerts_enabled, vuln_min_severity, created_at, updated_at)
            VALUES (@orgId, @q, @v, @sev, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { orgId, q = quarantineEnabled ? 1 : 0, v = vulnEnabled ? 1 : 0, sev = minSeverity });
    }

    // ── Quarantine trigger ───────────────────────────────────────────────────

    [Fact]
    public async Task RaiseQuarantine_DefaultSettings_RaisesAndNotifies()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-a-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseQuarantineAlertAsync(orgId, Guid.NewGuid().ToString("N"), "npm", "pkg:npm/x@1.0.0", "kev", null);

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RaiseQuarantine_TypeDisabled_DoesNotRaise()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-b-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, quarantineEnabled: false);
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseQuarantineAlertAsync(orgId, Guid.NewGuid().ToString("N"), "npm", "pkg:npm/x@1.0.0", "kev", null);

        Assert.Equal(0, await _alerts.CountActiveAsync(orgId));
        await notifier.DidNotReceive().NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A deduped repeat (same quarantine row id) does not re-notify.</summary>
    [Fact]
    public async Task RaiseQuarantine_RepeatSameQuarantineId_NotifiesOnlyOnce()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-c-{Guid.NewGuid():N}");
        string quarantineId = Guid.NewGuid().ToString("N");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseQuarantineAlertAsync(orgId, quarantineId, "npm", "pkg:npm/x@1.0.0", "kev", null);
        await svc.RaiseQuarantineAlertAsync(orgId, quarantineId, "npm", "pkg:npm/x@1.0.0", "kev", null);

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A throwing notifier is swallowed — the alert row is already persisted before NotifyAsync runs.</summary>
    [Fact]
    public async Task RaiseQuarantine_NotifierThrows_DoesNotPropagate_AlertStillPersisted()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-d-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        notifier.NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("boom")));
        var svc = BuildService(notifier);

        await svc.RaiseQuarantineAlertAsync(orgId, Guid.NewGuid().ToString("N"), "npm", "pkg:npm/x@1.0.0", "kev", null);

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
    }

    // ── Vuln trigger ─────────────────────────────────────────────────────────

    [Fact]
    public async Task RaiseVuln_SeverityMeetsFloor_RaisesAndNotifies()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-e-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnAlertAsync(orgId, "npm", "vuln-pkg", "pkg:npm/vuln-pkg@1.0.0", "GHSA-xyz", "CRITICAL");

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RaiseVuln_SeverityBelowFloor_DoesNotRaise()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-f-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, minSeverity: "HIGH");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnAlertAsync(orgId, "npm", "vuln-pkg", "pkg:npm/vuln-pkg@1.0.0", "GHSA-low", "MEDIUM");

        Assert.Equal(0, await _alerts.CountActiveAsync(orgId));
        await notifier.DidNotReceive().NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>Unscored (null severity) never alerts, even against the org's floor.</summary>
    [Fact]
    public async Task RaiseVuln_UnscoredSeverity_NeverAlerts()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-g-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, minSeverity: "LOW");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnAlertAsync(orgId, "npm", "vuln-pkg", "pkg:npm/vuln-pkg@1.0.0", "GHSA-unscored", null);

        Assert.Equal(0, await _alerts.CountActiveAsync(orgId));
        await notifier.DidNotReceive().NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RaiseVuln_TypeDisabled_DoesNotRaise()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-h-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, vulnEnabled: false);
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnAlertAsync(orgId, "npm", "vuln-pkg", "pkg:npm/vuln-pkg@1.0.0", "GHSA-off", "CRITICAL");

        Assert.Equal(0, await _alerts.CountActiveAsync(orgId));
    }

    /// <summary>Mixed partial-outcome: two advisories for the same org, one above and one below the floor — only one alerts.</summary>
    [Fact]
    public async Task RaiseVuln_MixedBatch_OnlyQualifyingAdvisoryAlerts()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-i-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, minSeverity: "HIGH");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnAlertAsync(orgId, "npm", "pkg-one", "pkg:npm/pkg-one@1.0.0", "GHSA-high", "HIGH");
        await svc.RaiseVulnAlertAsync(orgId, "npm", "pkg-two", "pkg:npm/pkg-two@1.0.0", "GHSA-low", "LOW");

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }
}
