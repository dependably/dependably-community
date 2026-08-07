using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that the provenance block-gate arm resolves its mode per-ecosystem from the version's
/// PURL, so a Terraform version is gated by <see cref="OrgSettings.VerifyTerraformSignatures"/>
/// and not by any other ecosystem toggle. Mirrors <see cref="MavenProvenanceGateParityTests"/> and
/// <see cref="RpmProvenanceGateParityTests"/> for Terraform.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerraformProvenanceGateParityTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    [Theory]
    [InlineData("failed")]
    [InlineData("unsigned")]
    public void TerraformVersion_FailedOrUnsigned_BlocksUnderTerraformBlockMode(string status)
    {
        var version = TerraformVersion(status);
        var settings = new OrgSettings { VerifyTerraformSignatures = "block", VerifyRpmSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void TerraformVersion_NpmToggleOnly_IsServable()
    {
        // No other ecosystem toggle should gate a Terraform version.
        var version = TerraformVersion("failed");
        var settings = new OrgSettings { VerifyTerraformSignatures = "off", VerifyNpmSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void TerraformVersion_MavenToggleOnly_IsServable()
    {
        var version = TerraformVersion("failed");
        var settings = new OrgSettings { VerifyTerraformSignatures = "off", VerifyMavenSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void TerraformVersion_RpmToggleOnly_IsServable()
    {
        var version = TerraformVersion("failed");
        var settings = new OrgSettings { VerifyTerraformSignatures = "off", VerifyRpmSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void MixedTenant_TerraformBlockOnly_OnlyTerraformVersionBlocks()
    {
        // Same settings; only the Terraform version must be blocked.
        var settings = new OrgSettings
        {
            VerifyTerraformSignatures = "block",
            VerifyNpmSignatures = "off",
            VerifyRpmSignatures = "off",
        };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(TerraformVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
    }

    [Fact]
    public void TerraformVersion_Verified_IsServable()
    {
        var version = TerraformVersion("verified");
        var settings = new OrgSettings { VerifyTerraformSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public void TerraformVersion_Failed_NonBlockModes_AreServable(string mode)
    {
        var version = TerraformVersion("failed");
        var settings = new OrgSettings { VerifyTerraformSignatures = mode };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    // Mixed partial-failure scenario: some versions of different ecosystems, only Terraform blocked.
    [Fact]
    public void Mixed_AllEcosystemsFailed_OnlyTerraformBlockPolicy_OnlyTerraformBlocks()
    {
        var settings = new OrgSettings
        {
            VerifyTerraformSignatures = "block",
            VerifyMavenSignatures = "warn",
            VerifyRpmSignatures = "off",
            VerifyNpmSignatures = "off",
        };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(TerraformVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(MavenVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(RpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
    }

    private static PackageVersion TerraformVersion(string provenanceStatus) => new()
    {
        Id = "v-terraform",
        Purl = "pkg:terraform/acme/internal@1.2.3?registry=registry.example.test",
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

    private static PackageVersion MavenVersion(string provenanceStatus) => new()
    {
        Id = "v-maven",
        Purl = "pkg:maven/com.example/lib@1.0.0",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };
}
