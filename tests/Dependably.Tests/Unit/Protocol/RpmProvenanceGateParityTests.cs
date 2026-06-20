using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that the provenance block-gate arm resolves its mode per-ecosystem from the version's
/// PURL, so an RPM version is gated by <see cref="OrgSettings.VerifyRpmSignatures"/> and a Maven
/// version by <see cref="OrgSettings.VerifyMavenSignatures"/> — the stored
/// <c>provenance_status</c> column is ecosystem-agnostic, but the toggle that interprets it is not.
/// A mixed scenario (both ecosystems present in the same tenant, only one verify toggle on) must
/// block exactly the matching ecosystem and leave the other servable.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmProvenanceGateParityTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    [Theory]
    [InlineData("failed")]
    [InlineData("unsigned")]
    public void RpmVersion_FailedOrUnsigned_BlocksUnderRpmBlockMode(string status)
    {
        var version = RpmVersion(status);
        var settings = new OrgSettings { VerifyRpmSignatures = "block", VerifyMavenSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void RpmVersion_MavenToggleOnly_IsServable()
    {
        // The Maven toggle must NOT gate an RPM version.
        var version = RpmVersion("failed");
        var settings = new OrgSettings { VerifyRpmSignatures = "off", VerifyMavenSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MavenVersion_RpmToggleOnly_IsServable()
    {
        // Symmetric: the RPM toggle must NOT gate a Maven version.
        var version = MavenVersion("failed");
        var settings = new OrgSettings { VerifyRpmSignatures = "block", VerifyMavenSignatures = "off" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MixedTenant_OnlyMatchingEcosystemBlocks()
    {
        // Same tenant: RPM verification on, Maven off. RPM version blocks; Maven version serves.
        var settings = new OrgSettings { VerifyRpmSignatures = "block", VerifyMavenSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(MavenVersion("failed"), settings, null, _now));
    }

    [Fact]
    public void MixedTenant_MavenBlockRpmOff_OnlyMavenBlocks()
    {
        // Same tenant: Maven verification on, RPM off. Maven version blocks; RPM version serves.
        var settings = new OrgSettings { VerifyRpmSignatures = "off", VerifyMavenSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
        Assert.True(BlockGateService.IsHardBlockedByStoredState(MavenVersion("failed"), settings, null, _now));
    }

    [Fact]
    public void RpmVersion_Verified_IsServable()
    {
        var version = RpmVersion("verified");
        var settings = new OrgSettings { VerifyRpmSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MavenVersion_Verified_IsServable()
    {
        var version = MavenVersion("verified");
        var settings = new OrgSettings { VerifyMavenSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public void RpmVersion_Failed_NonBlockModes_AreServable(string mode)
    {
        var version = RpmVersion("failed");
        var settings = new OrgSettings { VerifyRpmSignatures = mode };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public void MavenVersion_Failed_NonBlockModes_AreServable(string mode)
    {
        var version = MavenVersion("failed");
        var settings = new OrgSettings { VerifyMavenSignatures = mode };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    // Mixed partial-failure: both RPM and Maven failed, different policy modes.
    [Fact]
    public void Mixed_RpmBlockMavenWarn_RpmBlocksMavenServes()
    {
        var settings = new OrgSettings { VerifyRpmSignatures = "block", VerifyMavenSignatures = "warn" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(MavenVersion("failed"), settings, null, _now));
    }

    private static PackageVersion RpmVersion(string provenanceStatus) => new()
    {
        Id = "v-rpm",
        Purl = "pkg:rpm/linux/fedora/tree@2.1.0-5",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };

    private static PackageVersion MavenVersion(string provenanceStatus) => new()
    {
        Id = "v-maven",
        Purl = "pkg:maven/com.example/lib@1.0.0",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };
}
