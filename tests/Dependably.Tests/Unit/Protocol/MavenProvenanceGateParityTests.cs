using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that the provenance block-gate arm resolves its mode per-ecosystem from the version's
/// PURL, so a Maven version is gated by <see cref="OrgSettings.VerifyMavenSignatures"/> and not
/// by any other ecosystem toggle. Mirrors <see cref="RpmProvenanceGateParityTests"/> for Maven
/// and the existing <see cref="NuGetProvenanceGateParityTests"/> for NuGet.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenProvenanceGateParityTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    [Theory]
    [InlineData("failed")]
    [InlineData("unsigned")]
    public void MavenVersion_FailedOrUnsigned_BlocksUnderMavenBlockMode(string status)
    {
        var version = MavenVersion(status);
        var settings = new OrgSettings { VerifyMavenSignatures = "block", VerifyRpmSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MavenVersion_NpmToggleOnly_IsServable()
    {
        // No other ecosystem toggle should gate a Maven version.
        var version = MavenVersion("failed");
        var settings = new OrgSettings { VerifyMavenSignatures = "off", VerifyNpmSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MavenVersion_NuGetToggleOnly_IsServable()
    {
        var version = MavenVersion("failed");
        var settings = new OrgSettings { VerifyMavenSignatures = "off", VerifyNuGetSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MavenVersion_RpmToggleOnly_IsServable()
    {
        var version = MavenVersion("failed");
        var settings = new OrgSettings { VerifyMavenSignatures = "off", VerifyRpmSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MixedTenant_MavenBlockOnly_OnlyMavenVersionBlocks()
    {
        // Same settings; only the Maven version must be blocked.
        var settings = new OrgSettings
        {
            VerifyMavenSignatures = "block",
            VerifyNpmSignatures = "off",
            VerifyRpmSignatures = "off",
        };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(MavenVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
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
    public void MavenVersion_Failed_NonBlockModes_AreServable(string mode)
    {
        var version = MavenVersion("failed");
        var settings = new OrgSettings { VerifyMavenSignatures = mode };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    // Mixed partial-failure scenario: some versions of different ecosystems, only Maven blocked.
    [Fact]
    public void Mixed_AllEcosystemsFailed_OnlyMavenBlockPolicy_OnlyMavenBlocks()
    {
        var settings = new OrgSettings
        {
            VerifyMavenSignatures = "block",
            VerifyRpmSignatures = "warn",
            VerifyNpmSignatures = "off",
            VerifyNuGetSignatures = "off",
        };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(MavenVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NuGetVersion("failed"), settings, null, _now));
    }

    private static PackageVersion MavenVersion(string provenanceStatus) => new()
    {
        Id = "v-maven",
        Purl = "pkg:maven/com.example/lib@1.0.0",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };

    private static PackageVersion NpmVersion(string provenanceStatus) => new()
    {
        Id = "v-npm",
        Purl = "pkg:npm/lib@1.0.0",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };

    private static PackageVersion RpmVersion(string provenanceStatus) => new()
    {
        Id = "v-rpm",
        Purl = "pkg:rpm/linux/fedora/tree@2.1.0-5",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };

    private static PackageVersion NuGetVersion(string provenanceStatus) => new()
    {
        Id = "v-nuget",
        Purl = "pkg:nuget/lib@1.0.0",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };
}
