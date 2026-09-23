using System.Security.Claims;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Endpoint-level coverage for <see cref="PolicyController"/>'s <c>active</c> wiring — the piece
/// no full-stack integration test can exercise cheaply, because the shared
/// <see cref="Dependably.Tests.Infrastructure.DependablyFactory"/> always disables the
/// <c>threat-feed</c> job (to keep every other test off the public internet) and there is no mock
/// vulnerability-tracker connection to flip between paused and unconfigured. Constructs
/// <see cref="PolicyController"/> directly against real repositories over an in-memory DB, with a
/// fake <see cref="IAirGapMode"/> and a directly-constructed <see cref="InstanceVulnTrackerConfig"/>
/// so both inputs can vary independently per test. The default-shape ControllerScenario test at
/// the bottom of this file exercises the same controller through the shared multi-controller
/// harness other unit suites use, so the harness wiring itself has coverage too.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PolicyControllerTests : IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private string _orgId = "";
    private string _ownerId = "";

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_fixture.Store, "acme");
        _ownerId = await UserSeeder.InsertAsync(_fixture.Store, _orgId, "owner@acme.test", "owner");
    }

    public async Task DisposeAsync() => await _fixture.DisposeAsync();

    private async Task SetBlockPolicyAsync(string blockMaliciousLive, string blockSsvcExploitation)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_malicious_live = @blockMaliciousLive, " +
            "block_ssvc_exploitation = @blockSsvcExploitation WHERE org_id = @orgId",
            new { blockMaliciousLive, blockSsvcExploitation, orgId = _orgId });
    }

    private static InstanceVulnTrackerConfig BuildTracker(
        Microsoft.Extensions.Time.Testing.FakeTimeProvider clock, bool enabled, bool configured)
    {
        var values = new Dictionary<string, string?>
        {
            ["vuln_tracker_enabled"] = enabled ? "true" : "false",
            ["vuln_tracker_base_url"] = configured ? "https://tracker.example.test" : null,
        };
        return new InstanceVulnTrackerConfig(
            (key, _) => Task.FromResult(values.GetValueOrDefault(key)), clock);
    }

    private PolicyController Build(IAirGapMode airGap, InstanceVulnTrackerConfig tracker)
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, _ownerId),
                new Claim("sub", _ownerId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var trustStore = new StubPerOrgTrustAnchorStore();
        var anchors = new ProvenanceAnchorStatusResolver(
            new NpmProvenanceVerifier(new NpmSignatureKeyStore(trustStore)),
            new NuGetProvenanceVerifier(
                new NuGetSignatureTrustStore(trustStore), NullLogger<NuGetProvenanceVerifier>.Instance),
            new PyPiProvenanceVerifier(trustStore, NullLogger<PyPiProvenanceVerifier>.Instance),
            new RpmProvenanceVerifier(trustStore, NullLogger<RpmProvenanceVerifier>.Instance),
            new MavenProvenanceVerifier(trustStore, NullLogger<MavenProvenanceVerifier>.Instance),
            new TerraformProvenanceVerifier(trustStore, NullLogger<TerraformProvenanceVerifier>.Instance));

        return new PolicyController(
            new OrgSettingsRepository(_fixture.Store),
            new LicenseRepository(_fixture.Store, _clock, TestNormalizers.License(_fixture.Store)),
            new OrgAccessGuard(_fixture.Store, TestProblems.Create()),
            tracker,
            anchors,
            airGap)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    [Fact]
    public async Task VulnTrackerPausedButConfigured_MaliciousLiveAndSsvcExploitationAreNotActive_ButStillEnforce()
    {
        await SetBlockPolicyAsync(blockMaliciousLive: "block", blockSsvcExploitation: "block");
        // Enabled=false, Configured=true — IsActive=false, distinct from never having been
        // configured. ResolvedVulnTrackerConfig.IsActive is Enabled && Configured, so a paused
        // connection must read the same as active=false as an unconfigured one at this surface.
        var tracker = BuildTracker(_clock, enabled: false, configured: true);
        var controller = Build(new FakeAirGap(), tracker);

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        var maliciousLive = (TriStateControl)controls["malicious_live"];
        var ssvc = (TriStateControl)controls["ssvc_exploitation"];

        Assert.False(maliciousLive.Active);
        Assert.False(ssvc.Active);
        // Not active does not mean not enforcing — the stored mode still governs effect.
        Assert.Equal("block", maliciousLive.Effect);
        Assert.Equal("block", ssvc.Effect);
    }

    [Fact]
    public async Task VulnTrackerEnabledAndConfigured_MaliciousLiveAndSsvcExploitationAreActive()
    {
        await SetBlockPolicyAsync(blockMaliciousLive: "block", blockSsvcExploitation: "block");
        var tracker = BuildTracker(_clock, enabled: true, configured: true);
        var controller = Build(new FakeAirGap(), tracker);

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        Assert.True(((TriStateControl)controls["malicious_live"]).Active);
        Assert.True(((TriStateControl)controls["ssvc_exploitation"]).Active);
    }

    [Fact]
    public async Task VulnTrackerReadyButBothScanJobsDisabled_MaliciousLiveAndSsvcExploitationAreNotActive_ButStillEnforce()
    {
        // Enabled=true, Configured=true — the connection itself is ready. But
        // VulnerabilityScanService.EnrichBatchAsync (which actually writes the malicious-live/
        // SSVC-exploitation signals) only runs from inside RunScanPassInnerAsync's and
        // RunRescanPassInnerAsync's shared batch pipeline; with both named in
        // DISABLE_BACKGROUND_JOBS (the AIR_GAPPED shape), neither ever calls it, and the
        // on-demand ScanVersionAsync path never enriches at all. A ready connection nobody ever
        // asks anything of must not read as active.
        await SetBlockPolicyAsync(blockMaliciousLive: "block", blockSsvcExploitation: "block");
        var tracker = BuildTracker(_clock, enabled: true, configured: true);
        var controller = Build(new FakeAirGap("vuln-scan", "vuln-rescan"), tracker);

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        var maliciousLive = (TriStateControl)controls["malicious_live"];
        var ssvc = (TriStateControl)controls["ssvc_exploitation"];

        Assert.False(maliciousLive.Active);
        Assert.False(ssvc.Active);
        Assert.Equal("block", maliciousLive.Effect);
        Assert.Equal("block", ssvc.Effect);
    }

    [Fact]
    public async Task VulnTrackerReady_OnlyOneScanJobDisabled_MaliciousLiveAndSsvcExploitationAreStillActive()
    {
        // Either pass alone keeps EnrichBatchAsync running, so disabling only one of the two must
        // not flip active to false — the exact case a naive "either job disabled" check would get
        // wrong.
        var tracker = BuildTracker(_clock, enabled: true, configured: true);
        var controller = Build(new FakeAirGap("vuln-rescan"), tracker);

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        Assert.True(((TriStateControl)controls["malicious_live"]).Active);
        Assert.True(((TriStateControl)controls["ssvc_exploitation"]).Active);
    }

    [Fact]
    public async Task ThreatFeedJobDisabled_KevAndEpssControlsAreNotActive_ButStillEnforce()
    {
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET block_kev = 'block', block_kev_ransomware = 'block', " +
                "max_epss_tolerance = 0.5, max_epss_percentile_tolerance = 0.5 WHERE org_id = @orgId",
                new { orgId = _orgId });
        }
        var tracker = BuildTracker(_clock, enabled: false, configured: false);
        var controller = Build(new FakeAirGap("threat-feed"), tracker);

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        Assert.False(((TriStateControl)controls["kev"]).Active);
        Assert.False(((TriStateControl)controls["kev_ransomware"]).Active);
        Assert.False(((EpssControl)controls["epss"]).Active);
        Assert.False(((EpssPercentileControl)controls["epss_percentile"]).Active);
        // Still enforcing — effect reflects the configured mode/threshold regardless of active.
        Assert.Equal("block", ((TriStateControl)controls["kev"]).Effect);
        Assert.Equal("block", ((EpssControl)controls["epss"]).Effect);
    }

    [Fact]
    public async Task ThreatFeedJobEnabled_KevAndEpssControlsAreActive()
    {
        var tracker = BuildTracker(_clock, enabled: false, configured: false);
        var controller = Build(new FakeAirGap(), tracker);

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        Assert.True(((TriStateControl)controls["kev"]).Active);
        Assert.True(((TriStateControl)controls["kev_ransomware"]).Active);
        Assert.True(((EpssControl)controls["epss"]).Active);
        Assert.True(((EpssPercentileControl)controls["epss_percentile"]).Active);
    }

    [Theory]
    [InlineData(1.0, "off")]
    [InlineData(0.999999, "block")]
    public async Task EpssTolerance_AtOrAboveOne_ReadsAsOff(double tolerance, string expectedEffect)
    {
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_epss_tolerance = @tolerance WHERE org_id = @orgId",
                new { tolerance, orgId = _orgId });
        }
        var controller = Build(
            new FakeAirGap(), BuildTracker(_clock, enabled: false, configured: false));

        object payload = OkPayload(await controller.Get(CancellationToken.None));
        var controls = Field<Dictionary<string, object>>(payload, "controls")!;

        Assert.Equal(expectedEffect, ((EpssControl)controls["epss"]).Effect);
    }

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeAirGap : IAirGapMode
    {
        public FakeAirGap(params string[] disabledJobs) => DisabledJobs = new HashSet<string>(disabledJobs);
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs { get; }
        public bool IsJobDisabled(string jobName) => DisabledJobs.Contains(jobName);
    }

    // The controller returns an anonymous payload exactly as the JSON serializer sees it; reading
    // it reflectively (mirroring ProjectsControllerTests' idiom) keeps these assertions bound to
    // the wire shape rather than to a DTO that could drift from it.
    private static object OkPayload(IActionResult result) => Assert.IsType<OkObjectResult>(result).Value!;

    private static T? Field<T>(object payload, string name)
    {
        var prop = payload.GetType().GetProperty(name);
        Assert.True(prop is not null, $"payload has no property '{name}'");
        return (T?)prop!.GetValue(payload);
    }
}

/// <summary>
/// Confirms <see cref="ControllerScenario"/>'s <c>PolicyController</c> entry actually resolves and
/// returns a well-formed payload for the scenario's default org — the harness-wiring counterpart
/// to <see cref="PolicyControllerTests"/>'s direct-construction active/inactive coverage above.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PolicyControllerScenarioTests
{
    [Fact]
    public async Task Get_ThroughControllerScenario_ReturnsEveryControlKey()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "member");
        var scenario = await s.BuildAsync();

        object payload = Assert.IsType<OkObjectResult>(
            await scenario.PolicyController.Get(CancellationToken.None)).Value!;
        var controls = (Dictionary<string, object>)payload.GetType().GetProperty("controls")!.GetValue(payload)!;

        foreach (string key in new[]
        {
            "malicious", "malicious_live", "kev", "kev_ransomware", "deprecated", "revoked",
            "install_script", "ssvc_exploitation", "release_age", "vuln_score", "epss",
            "epss_percentile", "provenance", "license",
        })
        {
            Assert.True(controls.ContainsKey(key), $"missing controls.{key}");
        }
    }
}
