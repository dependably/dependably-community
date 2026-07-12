using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers <see cref="OsvScoring.SeverityRank"/> and <see cref="OsvScoring.MeetsSeverityThreshold"/>
/// — the alert-raising vulnerability-severity gate. Unscored advisories must never alert
/// regardless of the configured floor, even a nominally permissive LOW floor.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvScoringSeverityRankTests
{
    [Theory]
    [InlineData("CRITICAL", 4)]
    [InlineData("critical", 4)]
    [InlineData("HIGH", 3)]
    [InlineData("MEDIUM", 2)]
    [InlineData("LOW", 1)]
    [InlineData(null, 0)]
    [InlineData("", 0)]
    [InlineData("unknown", 0)]
    public void SeverityRank_MapsBandsToOrdinal(string? severity, int expectedRank)
    {
        Assert.Equal(expectedRank, OsvScoring.SeverityRank(severity));
    }

    [Theory]
    [InlineData("CRITICAL", "HIGH", true)]
    [InlineData("HIGH", "HIGH", true)]
    [InlineData("MEDIUM", "HIGH", false)]
    [InlineData("LOW", "HIGH", false)]
    public void MeetsSeverityThreshold_ComparesRank(string severity, string minSeverity, bool expected)
    {
        Assert.Equal(expected, OsvScoring.MeetsSeverityThreshold(severity, minSeverity));
    }

    /// <summary>
    /// Unscored (null/empty) severity never meets a threshold — even the lowest configured floor
    /// (LOW, rank 1) requires a rank &gt; 0. This is the "unscored advisories never alert" rule.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void MeetsSeverityThreshold_UnscoredNeverAlerts(string? severity)
    {
        Assert.False(OsvScoring.MeetsSeverityThreshold(severity, "LOW"));
        Assert.False(OsvScoring.MeetsSeverityThreshold(severity, "CRITICAL"));
    }

    /// <summary>A null/unrecognized minSeverity ranks 0 — a scored advisory (rank &gt; 0) always meets it.</summary>
    [Fact]
    public void MeetsSeverityThreshold_UnrecognizedFloor_AnyScoredSeverityMeetsIt()
    {
        Assert.True(OsvScoring.MeetsSeverityThreshold("LOW", null));
        Assert.True(OsvScoring.MeetsSeverityThreshold("LOW", "not-a-real-severity"));
    }
}
