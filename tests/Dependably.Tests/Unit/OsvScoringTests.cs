using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class OsvScoringTests
{
    [Theory]
    [InlineData(9.5, "CRITICAL")]
    [InlineData(9.0, "CRITICAL")]
    [InlineData(8.9, "HIGH")]
    [InlineData(7.0, "HIGH")]
    [InlineData(6.9, "MEDIUM")]
    [InlineData(4.0, "MEDIUM")]
    [InlineData(3.9, "LOW")]
    [InlineData(0.1, "LOW")]
    [InlineData(0.0, "NONE")]
    public void CvssScoreToSeverity_BandBoundaries(double score, string band)
    {
        Assert.Equal(band, OsvScoring.CvssScoreToSeverity(score));
    }

    [Theory]
    [InlineData("critical", "CRITICAL")]
    [InlineData("MODERATE", "MEDIUM")]
    [InlineData("Medium", "MEDIUM")]
    [InlineData(null, null)]
    [InlineData("", "")]
    public void NormalizeSeverity_KnownAndUnknown(string? input, string? expected)
    {
        Assert.Equal(expected, OsvScoring.NormalizeSeverity(input));
    }

    [Fact]
    public void ParseCvssBaseScore_AppendedNumeric_PrefersIt()
    {
        var (s, sev) = OsvScoring.ParseCvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8");
        Assert.Equal(9.8, s);
        Assert.Equal("CRITICAL", sev);
    }

    [Fact]
    public void ParseCvssBaseScore_VectorOnly_Computes()
    {
        // High-severity worst-case 3.1 vector → 9.8
        var (s, sev) = OsvScoring.ParseCvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        Assert.NotNull(s);
        Assert.True(s is >= 9.0 and <= 10.0);
        Assert.Equal("CRITICAL", sev);
    }

    [Fact]
    public void ParseCvssBaseScore_BadVector_ReturnsNull()
    {
        var (s, sev) = OsvScoring.ParseCvssBaseScore("not a real vector");
        Assert.Null(s);
        Assert.Null(sev);
    }
}
