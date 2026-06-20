using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that the provenance block-gate arm resolves its mode per-ecosystem from the version's
/// PURL, so a NuGet version is gated by <see cref="OrgSettings.VerifyNuGetSignatures"/> and an npm
/// version by <see cref="OrgSettings.VerifyNpmSignatures"/> — the stored
/// <c>provenance_status</c> column is ecosystem-agnostic, but the toggle that interprets it is not.
/// A mixed scenario (both ecosystems present in the same tenant, only one verify toggle on) must
/// block exactly the matching ecosystem and leave the other servable.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetProvenanceGateParityTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    [Theory]
    [InlineData("failed")]
    [InlineData("unsigned")]
    public void NuGetVersion_FailedOrUnsigned_BlocksUnderNuGetBlockMode(string status)
    {
        var version = NuGetVersion(status);
        var settings = new OrgSettings { VerifyNuGetSignatures = "block", VerifyNpmSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void NuGetVersion_NpmToggleOnly_IsServable()
    {
        // The npm toggle must NOT gate a NuGet version: the per-ecosystem resolution keeps them
        // independent.
        var version = NuGetVersion("failed");
        var settings = new OrgSettings { VerifyNuGetSignatures = "off", VerifyNpmSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void NpmVersion_NuGetToggleOnly_IsServable()
    {
        // Symmetric: the NuGet toggle must NOT gate an npm version.
        var version = NpmVersion("failed");
        var settings = new OrgSettings { VerifyNuGetSignatures = "block", VerifyNpmSignatures = "off" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MixedTenant_OnlyMatchingEcosystemBlocks()
    {
        // Same tenant, NuGet verification on and npm off: the NuGet version blocks, the npm one
        // (with the identical failed status) keeps serving.
        var settings = new OrgSettings { VerifyNuGetSignatures = "block", VerifyNpmSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(NuGetVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
    }

    [Fact]
    public void NuGetVersion_Verified_IsServable()
    {
        var version = NuGetVersion("verified");
        var settings = new OrgSettings { VerifyNuGetSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public void NuGetVersion_Failed_NonBlockModes_AreServable(string mode)
    {
        var version = NuGetVersion("failed");
        var settings = new OrgSettings { VerifyNuGetSignatures = mode };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    private static PackageVersion NuGetVersion(string provenanceStatus) => new()
    {
        Id = "v-nuget",
        Purl = "pkg:nuget/lib@1.0.0",
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
}
