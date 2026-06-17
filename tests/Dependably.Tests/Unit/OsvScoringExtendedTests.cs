using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Extends OsvScoringTests with coverage for the CVSS metric branches and the scope-changed
/// formula path — the largest single source of uncovered conditions in OsvScoring.cs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvScoringExtendedTests
{
    // ── ComputeCvss3Score: vector shape rejection ────────────────────────────

    [Fact]
    public void ComputeCvss3Score_NonCvss3Vector_ReturnsNull()
    {
        Assert.Null(OsvScoring.ComputeCvss3Score("CVSS:2.0/AV:N/AC:L"));
        Assert.Null(OsvScoring.ComputeCvss3Score("nonsense"));
    }

    [Fact]
    public void ComputeCvss3Score_MissingRequiredMetric_ReturnsNull()
    {
        // Missing the A: (availability) metric — must yield null without throwing.
        Assert.Null(OsvScoring.ComputeCvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"));
    }

    [Theory]
    [InlineData("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]  // unknown AV
    [InlineData("CVSS:3.1/AV:N/AC:Q/PR:N/UI:N/S:U/C:H/I:H/A:H")]  // unknown AC
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:Q/UI:N/S:U/C:H/I:H/A:H")]  // unknown PR
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:Q/S:U/C:H/I:H/A:H")]  // unknown UI
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:Q/I:H/A:H")]  // unknown C
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:Q/A:H")]  // unknown I
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Q")]  // unknown A
    public void ComputeCvss3Score_UnknownMetricValue_ReturnsNull(string vector)
    {
        Assert.Null(OsvScoring.ComputeCvss3Score(vector));
    }

    // ── ComputeCvss3Score: branch coverage on the value-lookup switches ──────

    [Fact]
    public void ComputeCvss3Score_ScopeChanged_PicksAlternateFormula()
    {
        // Same metrics with S:U vs S:C must produce different scores — the changed-scope
        // path uses the alternate ISC + raw formulas. Don't over-specify the exact value
        // (the CVSS 3.1 spec is the source of truth; this test guards branch coverage).
        double? unchanged = OsvScoring.ComputeCvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        double? changed = OsvScoring.ComputeCvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
        Assert.NotNull(unchanged);
        Assert.NotNull(changed);
        Assert.NotEqual(unchanged, changed);
        Assert.True(changed > unchanged, $"Scope-changed should outscore scope-unchanged for the same metrics; got {changed} vs {unchanged}");
    }

    [Theory]
    // Each row picks an AV value and confirms a score is produced (proves the AV switch branch
    // returned a non-negative value).
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    public void ComputeCvss3Score_EveryAttackVectorValue_ProducesScore(string vector)
    {
        Assert.NotNull(OsvScoring.ComputeCvss3Score(vector));
    }

    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")]   // PR:L unchanged
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")]   // PR:H unchanged
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")]   // PR:L scope-changed
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")]   // PR:H scope-changed
    public void ComputeCvss3Score_BothPrTables_Reachable(string vector)
    {
        // PR value lookup forks on Scope (Changed picks a different numeric table). Just
        // confirming each branch returns a score.
        Assert.NotNull(OsvScoring.ComputeCvss3Score(vector));
    }

    [Fact]
    public void ComputeCvss3Score_AllNoneImpact_ReturnsZero()
    {
        // When confidentiality/integrity/availability are all None, ISC <= 0 → returns 0.
        double? s = OsvScoring.ComputeCvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        Assert.Equal(0.0, s);
    }

    [Fact]
    public void ComputeCvss3Score_Cvss30_AlsoAccepted()
    {
        // The "CVSS:3." prefix accepts both 3.0 and 3.1.
        double? s = OsvScoring.ComputeCvss3Score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        Assert.NotNull(s);
        Assert.True(s >= 9.0);
    }

    // ── Severity bands sanity round-trip ─────────────────────────────────────

    [Fact]
    public void ParseCvssBaseScore_AppendedScore_MapsToSeverityBand()
    {
        var (s, sev) = OsvScoring.ParseCvssBaseScore("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L 3.5");
        Assert.Equal(3.5, s);
        Assert.Equal("LOW", sev);
    }

    [Fact]
    public void ParseCvssBaseScore_VectorOnly_Medium_BandIsMedium()
    {
        // Pick a vector that lands in the MEDIUM 4.0..6.9 band.
        var (s, sev) = OsvScoring.ParseCvssBaseScore("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
        Assert.NotNull(s);
        Assert.Equal("MEDIUM", sev);
    }
}
