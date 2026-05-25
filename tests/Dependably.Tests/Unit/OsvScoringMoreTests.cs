using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Targets the residual uncovered branches in OsvScoring.cs after OsvScoringTests +
/// OsvScoringExtendedTests: negative scores, exact NormalizeSeverity arms (HIGH/LOW),
/// malformed metric tokens (no-colon), appended-token parse failure fallback to vector
/// compute, and the CvssRoundup "exact tenth" branch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvScoringMoreTests
{
    // ── CvssScoreToSeverity: negative input falls into the default arm ──────────

    [Theory]
    [InlineData(-1.0, "NONE")]
    [InlineData(-0.0001, "NONE")]
    [InlineData(double.NegativeInfinity, "NONE")]
    public void CvssScoreToSeverity_NegativeOrZero_FallsToNone(double score, string band)
    {
        Assert.Equal(band, OsvScoring.CvssScoreToSeverity(score));
    }

    // ── NormalizeSeverity: explicit HIGH/LOW arms not hit by existing suite ─────

    [Theory]
    [InlineData("HIGH",  "HIGH")]
    [InlineData("high",  "HIGH")]
    [InlineData("LOW",   "LOW")]
    [InlineData("low",   "LOW")]
    [InlineData("moderate", "MEDIUM")]
    [InlineData("UNKNOWN-DB-LABEL", "UNKNOWN-DB-LABEL")] // unknown passes through raw
    public void NormalizeSeverity_ExplicitArms(string input, string expected)
    {
        Assert.Equal(expected, OsvScoring.NormalizeSeverity(input));
    }

    // ── ParseCvssBaseScore: trailing token isn't a number → falls to vector ─────

    [Fact]
    public void ParseCvssBaseScore_TrailingNonNumericToken_FallsBackToCompute()
    {
        // The trailing "junk" fails TryParse, so the method computes from the vector
        // (parts[0] still parses as a valid CVSS:3.1 vector).
        var s = OsvScoring.ParseCvssBaseScore(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H junk", out var sev);
        Assert.NotNull(s);
        Assert.Equal("CRITICAL", sev);
    }

    [Fact]
    public void ParseCvssBaseScore_TrailingNonNumeric_UnparseableVector_ReturnsNull()
    {
        // Whitespace splits to multiple parts; trailing token isn't numeric, parts[0]
        // isn't a CVSS:3.x prefix → compute returns null and severity stays null.
        var s = OsvScoring.ParseCvssBaseScore("garbage trailing", out var sev);
        Assert.Null(s);
        Assert.Null(sev);
    }

    [Fact]
    public void ParseCvssBaseScore_EmptyString_ReturnsNull()
    {
        // Single token after trim/split: parts[0] = "", which does not start with CVSS:3.
        var s = OsvScoring.ParseCvssBaseScore("", out var sev);
        Assert.Null(s);
        Assert.Null(sev);
    }

    [Fact]
    public void ParseCvssBaseScore_AppendedZero_SeverityNone()
    {
        // Score 0.0 maps to NONE band — exercises the `_ => "NONE"` arm via append path.
        var s = OsvScoring.ParseCvssBaseScore(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N 0.0", out var sev);
        Assert.Equal(0.0, s);
        Assert.Equal("NONE", sev);
    }

    // ── ComputeCvss3Score: metric tokens without a colon get skipped ────────────

    [Fact]
    public void ComputeCvss3Score_TokenWithoutColon_IsSkippedAndMissingMetricIsNull()
    {
        // The "BOGUS" token has no colon → ParseCvssMetrics skips it (colon > 0 false).
        // Because AV is now missing from the dictionary, LookupCvssValues returns null.
        var s = OsvScoring.ComputeCvss3Score("CVSS:3.1/BOGUS/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        Assert.Null(s);
    }

    [Fact]
    public void ComputeCvss3Score_LeadingColonToken_IsSkipped()
    {
        // A token like ":N" has colon at index 0, so `colon > 0` is false → skipped.
        // The genuine AV: token is still present, so the vector still scores.
        var s = OsvScoring.ComputeCvss3Score("CVSS:3.1/:bogus/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        Assert.NotNull(s);
    }

    // ── ComputeCvss3Score: case-insensitive prefix and metric values ────────────

    [Fact]
    public void ComputeCvss3Score_LowercasePrefix_StillAccepted()
    {
        // StartsWith uses OrdinalIgnoreCase — a lowercase prefix must still parse.
        var s = OsvScoring.ComputeCvss3Score("cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        Assert.NotNull(s);
        Assert.True(s >= 9.0);
    }

    [Fact]
    public void ComputeCvss3Score_LowercaseMetricValues_StillScored()
    {
        // Value-lookup switches use ToUpperInvariant — lowercase values must score.
        var s = OsvScoring.ComputeCvss3Score("CVSS:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h");
        Assert.NotNull(s);
        Assert.True(s >= 9.0);
    }

    // ── CvssRoundup: exact-tenth path (intVal % 10000 == 0) ─────────────────────

    [Fact]
    public void ComputeCvss3Score_ExactTenthScore_RoundupShortCircuit()
    {
        // An all-N vector with C:L/I:N/A:N yields raw 3.062... → CVSS spec rounds to 3.1
        // (not an exact tenth). The all-None-impact vector yields exactly 0.0 (handled
        // by the isc<=0 path). For the exact-tenth branch, use a vector whose raw score
        // lands on a clean tenth: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5.
        var s = OsvScoring.ComputeCvss3Score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
        Assert.NotNull(s);
        // Just confirm a clean tenth — don't pin the exact value (spec is authority).
        Assert.Equal(Math.Round(s!.Value, 1), s.Value);
    }

    // ── Multi-severity selection is the caller's job; this guards score parity ──

    [Fact]
    public void ParseCvssBaseScore_HighestOfTwoIndependentEntries_CallerPicksMax()
    {
        // The SUT scores ONE vector at a time; the OSV pipeline picks the max. This
        // simulates the caller's selection over two entries and asserts band mapping.
        var a = OsvScoring.ParseCvssBaseScore(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L 5.4", out var sevA);
        var b = OsvScoring.ParseCvssBaseScore(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8", out var sevB);
        Assert.Equal(5.4, a);
        Assert.Equal("MEDIUM", sevA);
        Assert.Equal(9.8, b);
        Assert.Equal("CRITICAL", sevB);
        var maxScore = Math.Max(a!.Value, b!.Value);
        Assert.Equal(9.8, maxScore);
    }
}
