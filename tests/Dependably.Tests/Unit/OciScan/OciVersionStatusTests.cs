using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// An OCI image's display status may only say <c>blocked</c> when a pull is actually refused. The
/// OCI pull path enforces the score tolerance only under <c>oci_scan_enforcement = block</c>, so
/// otherwise a scanned image whose score is above it reads <c>vulnerable</c>: the image still
/// pulls, and labelling it blocked would tell an operator it is contained when it is not. A manual
/// block keeps its own label.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciVersionStatusTests
{
    [Theory]
    [InlineData(9.8, 7.0, null, "vulnerable")]
    [InlineData(10.0, 0.0, null, "vulnerable")]
    [InlineData(6.5, 7.0, null, "vulnerable")]
    // A manual allow overrides only an enforced block, so above the tolerance it reads as the scan does.
    [InlineData(9.8, 7.0, "allowed", "vulnerable")]
    [InlineData(9.8, 7.0, "blocked", "blocked")]
    public void AScoreAboveTolerance_ReadsVulnerable_NeverBlocked(
        double maxScore, double tolerance, string? manual, string expected)
    {
        var version = new PackageVersion { ManualBlockState = manual };
        var facts = new OciScanFacts(GapCount: 0, AdvisoryCount: 2, MaxScore: maxScore);

        Assert.Equal(expected, PackageVersionStatus.ComputeOciVersionStatus(version, facts, covered: true, tolerance, "off"));
    }

    [Theory]
    [InlineData(9.8, 7.0, null, "blocked")]
    [InlineData(6.5, 7.0, null, "vulnerable")]
    [InlineData(9.8, 7.0, "allowed", "allowed")]
    public void UnderBlockEnforcement_AScoreAboveTolerance_ReadsBlocked(
        double maxScore, double tolerance, string? manual, string expected)
    {
        var version = new PackageVersion { ManualBlockState = manual };
        var facts = new OciScanFacts(GapCount: 0, AdvisoryCount: 2, MaxScore: maxScore);

        Assert.Equal(expected, PackageVersionStatus.ComputeOciVersionStatus(
            version, facts, covered: true, tolerance, "off", scoreEnforced: true));
    }

    [Fact]
    public void AScoreAboveTolerance_WithGaps_StillReadsVulnerable()
    {
        var facts = new OciScanFacts(GapCount: 3, AdvisoryCount: 1, MaxScore: 9.1);

        Assert.Equal("vulnerable", PackageVersionStatus.ComputeOciVersionStatus(new PackageVersion(), facts, true, 4.0, "off"));
    }
}
