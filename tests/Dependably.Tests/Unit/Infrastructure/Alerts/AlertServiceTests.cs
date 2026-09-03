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
        string orgId, bool quarantineEnabled = true, bool vulnEnabled = true,
        bool sbomPolicyEnabled = true, string minSeverity = "HIGH")
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, quarantine_alerts_enabled, vuln_alerts_enabled, sbom_policy_alerts_enabled,
                 vuln_min_severity, created_at, updated_at)
            VALUES (@orgId, @q, @v, @s, @sev, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { orgId, q = quarantineEnabled ? 1 : 0, v = vulnEnabled ? 1 : 0, s = sbomPolicyEnabled ? 1 : 0, sev = minSeverity });
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

    // ── KEV trigger ──────────────────────────────────────────────────────────

    /// <summary>The headline bug: an unscored (null severity) advisory still raises the KEV alert.</summary>
    [Fact]
    public async Task RaiseVulnKev_UnscoredSeverity_StillRaises()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-n-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-unscored", null, null));

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A KEV advisory scored below the org's severity floor still raises the KEV alert, even
    /// though the existing vuln_severity arm correctly would not.
    /// </summary>
    [Fact]
    public async Task RaiseVulnKev_ScoredBelowFloor_StillRaises()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-o-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, minSeverity: "HIGH");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-below-floor", "MEDIUM", null));

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        var (items, _) = await _alerts.ListAsync(orgId, "active", 10, 0);
        Assert.Contains(items, a => a.Type == AlertTypes.VulnKev);
    }

    [Fact]
    public async Task RaiseVulnKev_TypeDisabled_DoesNotRaise()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-p-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, vulnEnabled: false);
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-off", "CRITICAL", true));

        Assert.Equal(0, await _alerts.CountActiveAsync(orgId));
        await notifier.DidNotReceive().NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A repeat raise for the same advisory/package dedups to exactly one row.</summary>
    [Fact]
    public async Task RaiseVulnKev_RepeatSameAdvisory_NotifiesOnlyOnce()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-q-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-repeat", "CRITICAL", true));
        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-repeat", "CRITICAL", true));

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// vuln_severity and vuln_kev are independent alert types: the same advisory, both KEV and
    /// above the severity floor, raises two distinct rows.
    /// </summary>
    [Fact]
    public async Task RaiseVulnSeverityAndVulnKev_SameAdvisory_RaisesTwoIndependentAlerts()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-r-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, minSeverity: "HIGH");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnAlertAsync(orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", "GHSA-kev-both", "CRITICAL");
        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-both", "CRITICAL", true));

        Assert.Equal(2, await _alerts.CountActiveAsync(orgId));
        var (items, _) = await _alerts.ListAsync(orgId, "active", 10, 0);
        Assert.Contains(items, a => a.Type == AlertTypes.VulnSeverity);
        Assert.Contains(items, a => a.Type == AlertTypes.VulnKev);
    }

    /// <summary>
    /// The ransomware tri-state must render as three distinguishable Detail texts on the alert
    /// itself — not just be correct somewhere upstream. true/false/null must not collapse.
    /// </summary>
    [Theory]
    [InlineData(true, "CISA marks this entry as used in ransomware campaigns.")]
    [InlineData(false, "CISA has not recorded ransomware-campaign use for this entry.")]
    [InlineData(null, "No ransomware-campaign assertion is recorded for this entry.")]
    public async Task RaiseVulnKev_RansomwareTriState_RendersDistinctDetailText(bool? known, string expectedSentence)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-s-{known?.ToString() ?? "null"}-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnKevAlertAsync(
            orgId, "npm", "kev-pkg", "pkg:npm/kev-pkg@1.0.0", new AlertService.KevAlertAdvisory("GHSA-kev-ransomware", "HIGH", known));

        var (items, _) = await _alerts.ListAsync(orgId, "active", 10, 0);
        var alert = Assert.Single(items);
        Assert.Contains(expectedSentence, alert.Detail);
    }

    /// <summary>The three tri-state renderings are pairwise distinct — no two states share text.</summary>
    [Fact]
    public async Task RaiseVulnKev_RansomwareTriState_AllThreeRenderingsAreDistinct()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-t-{Guid.NewGuid():N}");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseVulnKevAlertAsync(orgId, "npm", "pkg-true", "pkg:npm/pkg-true@1.0.0", new AlertService.KevAlertAdvisory("GHSA-tri-true", "HIGH", true));
        await svc.RaiseVulnKevAlertAsync(orgId, "npm", "pkg-false", "pkg:npm/pkg-false@1.0.0", new AlertService.KevAlertAdvisory("GHSA-tri-false", "HIGH", false));
        await svc.RaiseVulnKevAlertAsync(orgId, "npm", "pkg-null", "pkg:npm/pkg-null@1.0.0", new AlertService.KevAlertAdvisory("GHSA-tri-null", "HIGH", null));

        var (items, _) = await _alerts.ListAsync(orgId, "active", 10, 0);
        var details = items.Select(a => a.Detail).ToHashSet();
        Assert.Equal(3, details.Count);
    }

    // ── SBOM policy trigger ──────────────────────────────────────────────────

    [Fact]
    public async Task RaiseSbomPolicy_DefaultSettings_RaisesAndNotifies()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-j-{Guid.NewGuid():N}");
        string versionId = Guid.NewGuid().ToString("N");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseSbomPolicyViolationAlertAsync(orgId, versionId, "checkout-service", "1.0.0", 3);

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RaiseSbomPolicy_TypeDisabled_DoesNotRaise()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-k-{Guid.NewGuid():N}");
        await SeedSettingsAsync(orgId, sbomPolicyEnabled: false);
        string versionId = Guid.NewGuid().ToString("N");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseSbomPolicyViolationAlertAsync(orgId, versionId, "checkout-service", "1.0.0", 3);

        Assert.Equal(0, await _alerts.CountActiveAsync(orgId));
        await notifier.DidNotReceive().NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>Re-evaluation of the same project version (same source_ref) does not re-notify.</summary>
    [Fact]
    public async Task RaiseSbomPolicy_RepeatSameProjectVersion_NotifiesOnlyOnce()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-l-{Guid.NewGuid():N}");
        string versionId = Guid.NewGuid().ToString("N");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseSbomPolicyViolationAlertAsync(orgId, versionId, "checkout-service", "1.0.0", 1);
        await svc.RaiseSbomPolicyViolationAlertAsync(orgId, versionId, "checkout-service", "1.0.0", 5);

        Assert.Equal(1, await _alerts.CountActiveAsync(orgId));
        await notifier.Received(1).NotifyAsync(Arg.Any<AlertRecord>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// Per CONTRACT D5, the coalescing key must be exactly <c>sbom_policy_violation:{projectVersionId}</c>.
    /// <c>EmailOutboxCoalescing.ForAlert</c> derives that from the type plus (purl ?? source_ref),
    /// so the alert row must carry a null purl and a source_ref equal to the project version id —
    /// this pins the exact shape that makes the coalescing key fall out for free.
    /// </summary>
    [Fact]
    public async Task RaiseSbomPolicy_SourceRefIsProjectVersionId_AndPurlIsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"asvc-m-{Guid.NewGuid():N}");
        string versionId = Guid.NewGuid().ToString("N");
        var notifier = Substitute.For<IAlertNotifier>();
        var svc = BuildService(notifier);

        await svc.RaiseSbomPolicyViolationAlertAsync(orgId, versionId, "checkout-service", "1.0.0", 2);

        var (items, _) = await _alerts.ListAsync(orgId, null, 10, 0);
        var alert = Assert.Single(items);
        Assert.Equal(versionId, alert.SourceRef);
        Assert.Null(alert.Purl);
        Assert.Equal(AlertTypes.SbomPolicyViolation, alert.Type);
    }
}
