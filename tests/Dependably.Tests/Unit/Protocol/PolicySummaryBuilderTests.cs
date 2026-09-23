using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit tests for the pure <see cref="PolicySummaryBuilder"/> derivation — no I/O, no DB, no
/// HTTP. Each test mutates exactly one input off a known baseline and asserts the one output
/// field that input governs, so a broken mapping fails at the specific control rather than at
/// "the payload changed somehow".
///
/// <c>vulnTrackerActive</c>/<c>threatFeedActive</c> are plain booleans at this layer — the
/// distinction between "never configured" and "configured but paused" is resolved upstream
/// (<c>ResolvedVulnTrackerConfig.IsActive</c>) before it reaches the builder, so that specific
/// wiring is covered at the controller level
/// (<c>Dependably.Tests.Unit.Api.PolicyControllerTests</c>) rather than here.
/// </summary>
public sealed class PolicySummaryBuilderTests
{
    private static readonly ProvenanceAnchorStatus AllAnchorsConfigured =
        new(Npm: true, NuGet: true, PyPi: true, Rpm: true, Maven: true, Terraform: true);

    private static readonly ProvenanceAnchorStatus NoAnchorsConfigured =
        new(Npm: false, NuGet: false, PyPi: false, Rpm: false, Maven: false, Terraform: false);

    [Fact]
    public void NullSettings_UsesTheSameDefaultsAsGetProxySettings()
    {
        var summary = PolicySummaryBuilder.Build(
            settings: null, vulnTrackerActive: false, threatFeedActive: false, anchors: NoAnchorsConfigured);

        Assert.Equal("off", summary.AllowlistMode);
        Assert.True(summary.ProxyPassthroughEnabled);

        var malicious = Assert.IsType<TriStateControl>(summary.Controls["malicious"]);
        Assert.Equal("block", malicious.Mode);
        Assert.Equal("block", malicious.Effect);

        var revoked = Assert.IsType<TriStateControl>(summary.Controls["revoked"]);
        Assert.Equal("warn", revoked.Mode);

        var kev = Assert.IsType<TriStateControl>(summary.Controls["kev"]);
        Assert.Equal("off", kev.Mode);

        var vulnScore = Assert.IsType<VulnScoreControl>(summary.Controls["vuln_score"]);
        Assert.Equal(10.0, vulnScore.MaxScore);
        Assert.Equal("off", vulnScore.Effect);

        var license = Assert.IsType<TriStateControl>(summary.Controls["license"]);
        Assert.Equal("off", license.Mode);
    }

    [Fact]
    public void VulnScore_AtCvssCeiling_ReadsAsOff()
    {
        var settings = new OrgSettings { MaxOsvScoreTolerance = 10.0 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<VulnScoreControl>(summary.Controls["vuln_score"]);
        Assert.Equal("off", control.Effect);
    }

    [Fact]
    public void VulnScore_BelowCvssCeiling_ReadsAsBlock()
    {
        var settings = new OrgSettings { MaxOsvScoreTolerance = 7.0 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<VulnScoreControl>(summary.Controls["vuln_score"]);
        Assert.Equal(7.0, control.MaxScore);
        Assert.Equal("block", control.Effect);
    }

    [Theory]
    [InlineData("block_new")]
    [InlineData("block_all")]
    public void Deprecated_BlockNewOrBlockAll_BothReadAsBlock(string mode)
    {
        var settings = new OrgSettings { BlockDeprecated = mode };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<TriStateControl>(summary.Controls["deprecated"]);
        // The raw mode survives verbatim — this is what lets the frontend still tell 'block_new'
        // apart from 'block_all' even though both collapse to the same normalized effect below.
        Assert.Equal(mode, control.Mode);
        Assert.Equal("block", control.Effect);
    }

    [Fact]
    public void Epss_NullTolerance_ReadsAsOff()
    {
        var settings = new OrgSettings { MaxEpssTolerance = null };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssControl>(summary.Controls["epss"]);
        Assert.Null(control.MaxProbability);
        Assert.Equal("off", control.Effect);
    }

    [Fact]
    public void Epss_SetTolerance_ReadsAsBlock()
    {
        var settings = new OrgSettings { MaxEpssTolerance = 0.5 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssControl>(summary.Controls["epss"]);
        Assert.Equal(0.5, control.MaxProbability);
        Assert.Equal("block", control.Effect);
    }

    [Fact]
    public void Epss_ToleranceExactlyOne_ReadsAsOff()
    {
        // The block arm compares with a strict `>` against a value that can never exceed 1.0
        // (EPSS is a probability), so a tolerance AT 1.0 accepts everything — same as null.
        var settings = new OrgSettings { MaxEpssTolerance = 1.0 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssControl>(summary.Controls["epss"]);
        Assert.Equal("off", control.Effect);
    }

    [Fact]
    public void Epss_ToleranceJustBelowOne_ReadsAsBlock()
    {
        var settings = new OrgSettings { MaxEpssTolerance = 0.999999 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssControl>(summary.Controls["epss"]);
        Assert.Equal("block", control.Effect);
    }

    [Fact]
    public void EpssPercentile_NullTolerance_ReadsAsOff()
    {
        var settings = new OrgSettings { MaxEpssPercentileTolerance = null };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssPercentileControl>(summary.Controls["epss_percentile"]);
        Assert.Equal("off", control.Effect);
    }

    [Fact]
    public void EpssPercentile_ToleranceExactlyOne_ReadsAsOff()
    {
        var settings = new OrgSettings { MaxEpssPercentileTolerance = 1.0 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssPercentileControl>(summary.Controls["epss_percentile"]);
        Assert.Equal("off", control.Effect);
    }

    [Fact]
    public void EpssPercentile_ToleranceJustBelowOne_ReadsAsBlock()
    {
        var settings = new OrgSettings { MaxEpssPercentileTolerance = 0.999999 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<EpssPercentileControl>(summary.Controls["epss_percentile"]);
        Assert.Equal("block", control.Effect);
    }

    [Fact]
    public void ReleaseAge_NullMinHours_ReadsAsOff()
    {
        var settings = new OrgSettings { MinReleaseAgeHours = null };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<ReleaseAgeControl>(summary.Controls["release_age"]);
        Assert.Null(control.MinHours);
        Assert.Equal("off", control.Effect);
    }

    [Fact]
    public void ReleaseAge_PositiveMinHours_ReadsAsBlock()
    {
        var settings = new OrgSettings { MinReleaseAgeHours = 72 };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var control = Assert.IsType<ReleaseAgeControl>(summary.Controls["release_age"]);
        Assert.Equal(72, control.MinHours);
        Assert.Equal("block", control.Effect);
    }

    [Fact]
    public void VulnTrackerInactive_MaliciousLiveAndSsvcExploitationAreNotActive_ButStillEnforce()
    {
        var settings = new OrgSettings
        {
            BlockMaliciousLive = "block",
            BlockSsvcExploitation = "block",
        };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: false, threatFeedActive: true, AllAnchorsConfigured);

        var maliciousLive = Assert.IsType<TriStateControl>(summary.Controls["malicious_live"]);
        Assert.False(maliciousLive.Active);
        // Not active does not mean it cannot fire — the stored mode still governs effect. See
        // Dependably.Tests.Unit.Api.PolicyControllerTests for the paused-vs-never-configured
        // distinction this boolean collapses (both resolve to false here).
        Assert.Equal("block", maliciousLive.Effect);

        var ssvc = Assert.IsType<TriStateControl>(summary.Controls["ssvc_exploitation"]);
        Assert.False(ssvc.Active);
        Assert.Equal("block", ssvc.Effect);
    }

    [Fact]
    public void VulnTrackerActive_MaliciousLiveAndSsvcExploitationAreActive()
    {
        var settings = new OrgSettings
        {
            BlockMaliciousLive = "block",
            BlockSsvcExploitation = "block",
        };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        Assert.True(((TriStateControl)summary.Controls["malicious_live"]).Active);
        Assert.True(((TriStateControl)summary.Controls["ssvc_exploitation"]).Active);
    }

    [Fact]
    public void ThreatFeedInactive_KevAndEpssControlsAreNotActive_ButStillEnforce()
    {
        var settings = new OrgSettings
        {
            BlockKev = "block",
            BlockKevRansomware = "block",
            MaxEpssTolerance = 0.5,
            MaxEpssPercentileTolerance = 0.5,
        };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: false, AllAnchorsConfigured);

        var kev = Assert.IsType<TriStateControl>(summary.Controls["kev"]);
        Assert.False(kev.Active);
        Assert.Equal("block", kev.Effect);

        var kevRansomware = Assert.IsType<TriStateControl>(summary.Controls["kev_ransomware"]);
        Assert.False(kevRansomware.Active);

        var epss = Assert.IsType<EpssControl>(summary.Controls["epss"]);
        Assert.False(epss.Active);
        Assert.Equal("block", epss.Effect);

        var epssPercentile = Assert.IsType<EpssPercentileControl>(summary.Controls["epss_percentile"]);
        Assert.False(epssPercentile.Active);
    }

    [Fact]
    public void ThreatFeedActive_KevAndEpssControlsAreActive()
    {
        var summary = PolicySummaryBuilder.Build(
            settings: null, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        Assert.True(((TriStateControl)summary.Controls["kev"]).Active);
        Assert.True(((TriStateControl)summary.Controls["kev_ransomware"]).Active);
        Assert.True(((EpssControl)summary.Controls["epss"]).Active);
        Assert.True(((EpssPercentileControl)summary.Controls["epss_percentile"]).Active);
    }

    [Fact]
    public void MaliciousAndVulnScore_AreAlwaysActive_RegardlessOfTrackerOrThreatFeedState()
    {
        // Neither reads the vuln-tracker connection or the threat-feed job: malicious comes from
        // the regular OSV scan, and the CVSS ceiling is a pure local comparison.
        var summary = PolicySummaryBuilder.Build(
            settings: null, vulnTrackerActive: false, threatFeedActive: false, AllAnchorsConfigured);

        Assert.True(((TriStateControl)summary.Controls["malicious"]).Active);
        Assert.True(((VulnScoreControl)summary.Controls["vuln_score"]).Active);
    }

    [Fact]
    public void SignatureBlock_WithNoAnchors_ReportsAnchorsConfiguredFalse()
    {
        var settings = new OrgSettings { VerifyNpmSignatures = "block" };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, NoAnchorsConfigured);

        var provenance = Assert.IsType<Dictionary<string, ProvenanceEcosystemControl>>(
            summary.Controls["provenance"]);
        var npm = provenance["npm"];
        Assert.Equal("block", npm.Mode);
        Assert.Equal("block", npm.Effect);
        Assert.False(npm.AnchorsConfigured);
    }

    [Fact]
    public void SignatureBlock_WithAnchorsConfigured_ReportsAnchorsConfiguredTrue()
    {
        var settings = new OrgSettings { VerifyNpmSignatures = "block" };

        var summary = PolicySummaryBuilder.Build(
            settings, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var provenance = Assert.IsType<Dictionary<string, ProvenanceEcosystemControl>>(
            summary.Controls["provenance"]);
        Assert.True(provenance["npm"].AnchorsConfigured);
    }

    [Fact]
    public void Provenance_CoversAllSixBlockGateDispatchedEcosystems()
    {
        var summary = PolicySummaryBuilder.Build(
            settings: null, vulnTrackerActive: true, threatFeedActive: true, AllAnchorsConfigured);

        var provenance = Assert.IsType<Dictionary<string, ProvenanceEcosystemControl>>(
            summary.Controls["provenance"]);

        Assert.Equal(
            new[] { "maven", "npm", "nuget", "pypi", "rpm", "terraform" },
            provenance.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
    }
}
