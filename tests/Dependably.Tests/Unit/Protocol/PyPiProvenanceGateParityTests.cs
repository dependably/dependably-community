using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that the provenance block-gate arm resolves its mode per-ecosystem from the version's
/// PURL for PyPI, so a PyPI version is gated by <see cref="OrgSettings.VerifyPyPiAttestations"/> and
/// not by the npm or NuGet toggles — the stored <c>provenance_status</c> column is
/// ecosystem-agnostic, but the toggle that interprets it is not. A mixed-tenant scenario (PyPI, npm,
/// and NuGet versions present with only the PyPI toggle on) must block exactly the PyPI version and
/// leave the others servable.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiProvenanceGateParityTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    [Theory]
    [InlineData("failed")]
    [InlineData("unsigned")]
    public void PyPiVersion_FailedOrUnsigned_BlocksUnderPyPiBlockMode(string status)
    {
        var version = PyPiVersion(status);
        var settings = new OrgSettings { VerifyPyPiAttestations = "block", VerifyNpmSignatures = "off", VerifyNuGetSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void PyPiVersion_NpmAndNuGetTogglesOnly_IsServable()
    {
        // Neither the npm nor the NuGet toggle must gate a PyPI version.
        var version = PyPiVersion("failed");
        var settings = new OrgSettings { VerifyPyPiAttestations = "off", VerifyNpmSignatures = "block", VerifyNuGetSignatures = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Fact]
    public void NpmAndNuGetVersions_PyPiToggleOnly_AreServable()
    {
        // Symmetric: the PyPI toggle must NOT gate an npm or NuGet version.
        var settings = new OrgSettings { VerifyPyPiAttestations = "block", VerifyNpmSignatures = "off", VerifyNuGetSignatures = "off" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NuGetVersion("failed"), settings, null, _now));
    }

    [Fact]
    public void MixedTenant_OnlyPyPiBlocks()
    {
        // Same tenant, PyPI verification on and npm/NuGet off: the PyPI version blocks, the npm and
        // NuGet versions (with the identical failed status) keep serving.
        var settings = new OrgSettings { VerifyPyPiAttestations = "block", VerifyNpmSignatures = "off", VerifyNuGetSignatures = "off" };

        Assert.True(BlockGateService.IsHardBlockedByStoredState(PyPiVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NpmVersion("failed"), settings, null, _now));
        Assert.False(BlockGateService.IsHardBlockedByStoredState(NuGetVersion("failed"), settings, null, _now));
    }

    [Fact]
    public void PyPiVersion_Verified_IsServable()
    {
        var version = PyPiVersion("verified");
        var settings = new OrgSettings { VerifyPyPiAttestations = "block" };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public void PyPiVersion_Failed_NonBlockModes_AreServable(string mode)
    {
        var version = PyPiVersion("failed");
        var settings = new OrgSettings { VerifyPyPiAttestations = mode };

        Assert.False(BlockGateService.IsHardBlockedByStoredState(version, settings, signals: null, _now));
    }

    private static PackageVersion PyPiVersion(string provenanceStatus) => new()
    {
        Id = "v-pypi",
        Purl = "pkg:pypi/example@1.0.0",
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

    private static PackageVersion NuGetVersion(string provenanceStatus) => new()
    {
        Id = "v-nuget",
        Purl = "pkg:nuget/lib@1.0.0",
        Origin = "proxy",
        ProvenanceStatus = provenanceStatus,
    };
}
