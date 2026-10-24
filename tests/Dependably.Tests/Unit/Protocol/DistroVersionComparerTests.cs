using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The RPM (rpmvercmp + epoch) and Alpine apk orderings the offline distro query evaluates
/// advisory ranges with. The cases are the documented edge cases of each scheme, not round trips
/// of the implementation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DistroVersionComparerTests
{
    [Theory]
    [InlineData("1.0", "1.0", 0)]
    [InlineData("1.0", "2.0", -1)]
    [InlineData("1.10", "1.9", 1)]
    [InlineData("1.0a", "1.0", 1)]
    [InlineData("1.0", "1.0.1", -1)]
    [InlineData("1.0~rc1", "1.0", -1)]
    [InlineData("1.0~rc1", "1.0~rc2", -1)]
    [InlineData("1.0^git1", "1.0", 1)]
    [InlineData("1.0^git1", "1.0.1", -1)]
    [InlineData("1:1.0", "2.0", 1)]
    [InlineData("0:1.0", "1.0", 0)]
    [InlineData("3.0.7-24.el9", "3.0.7-27.el9", -1)]
    [InlineData("3.0.7-27.el9_4", "3.0.7-27.el9", 1)]
    [InlineData("3.0.7", "3.0.7-27.el9", -1)]
    [InlineData("7.76.1", "7.76.1-26.el9_3.2", -1)]
    [InlineData("1.01", "1.1", 0)]
    [InlineData("10", "9", 1)]
    [InlineData("a", "1", -1)]
    public void CompareRpm_FollowsRpmvercmp(string left, string right, int expected)
    {
        Assert.Equal(expected, Math.Sign(DistroVersionComparer.CompareRpm(left, right)));
        Assert.Equal(-expected, Math.Sign(DistroVersionComparer.CompareRpm(right, left)));
    }

    [Theory]
    [InlineData("1.2.3", "1.2.3", 0)]
    [InlineData("1.2.3", "1.2.10", -1)]
    [InlineData("1.2.3-r0", "1.2.3-r1", -1)]
    [InlineData("3.3.2", "3.3.2-r0", -1)]
    [InlineData("8.5.0-r0", "8.5.0-r12", -1)]
    [InlineData("1.2.3a", "1.2.3", 1)]
    [InlineData("1.2.3a", "1.2.3b", -1)]
    [InlineData("1.2.3_rc1", "1.2.3", -1)]
    [InlineData("1.2.3_alpha", "1.2.3_beta", -1)]
    [InlineData("1.2.3_beta", "1.2.3_pre", -1)]
    [InlineData("1.2.3_pre", "1.2.3_rc", -1)]
    [InlineData("1.2.3_rc1", "1.2.3_rc2", -1)]
    [InlineData("1.2.3_p1", "1.2.3", 1)]
    [InlineData("1.2.3_git20240101", "1.2.3", 1)]
    [InlineData("1.2.3_git20240101", "1.2.3_p1", -1)]
    [InlineData("1.2", "1.2.1", -1)]
    [InlineData("1.02", "1.1", -1)]
    [InlineData("2.0", "10.0", -1)]
    public void CompareApk_FollowsApkToolsOrdering(string left, string right, int expected)
    {
        Assert.Equal(expected, Math.Sign(DistroVersionComparer.CompareApk(left, right)));
        Assert.Equal(-expected, Math.Sign(DistroVersionComparer.CompareApk(right, left)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-version")]
    [InlineData("~~~")]
    [InlineData("99999999999999999999999999999999")]
    public void Comparers_NeverThrowOnMalformedInput(string malformed)
    {
        _ = DistroVersionComparer.CompareRpm(malformed, "1.0-1");
        _ = DistroVersionComparer.CompareApk(malformed, "1.0-r0");
        Assert.Equal(0, DistroVersionComparer.CompareRpm(malformed, malformed));
        Assert.Equal(0, DistroVersionComparer.CompareApk(malformed, malformed));
    }
}
