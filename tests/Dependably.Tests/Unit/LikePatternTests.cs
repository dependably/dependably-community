using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Cover for the LIKE-pattern builder. These searches are parameterized, so the risk is not
/// injection but a silently wrong result: an unescaped <c>_</c> or <c>%</c> in a caller's term is a
/// wildcard, which widens the match instead of narrowing it.
/// </summary>
public class LikePatternTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankTerm_IsNull_SoTheIsNullGuardMeansNoFilter(string? term)
    {
        Assert.Null(LikePattern.Contains(term));
        Assert.Null(LikePattern.ContainsLower(term));
    }

    [Fact]
    public void OrdinaryTerm_IsWrappedForSubstringMatch()
    {
        Assert.Equal("%core%", LikePattern.Contains("core"));
        Assert.Equal("%core%", LikePattern.Contains("  core  "));
    }

    // The case that matters most in practice: PyPI and NuGet names routinely contain '_', which
    // LIKE reads as "any single character" — so an unescaped 'my_pkg' also matches 'myXpkg'.
    [Fact]
    public void Underscore_IsEscaped_SoItMatchesItselfOnly()
    {
        Assert.Equal(@"%my\_pkg%", LikePattern.Contains("my_pkg"));
    }

    // A bare '%' as the entire term matches every row — a filtered lookup silently becoming a full
    // scan over a leading-wildcard predicate no index can serve.
    [Fact]
    public void Percent_IsEscaped_SoItCannotMatchEverything()
    {
        Assert.Equal(@"%\%%", LikePattern.Contains("%"));
        Assert.Equal(@"%100\%%", LikePattern.Contains("100%"));
    }

    // Backslash must be escaped first, or the backslashes introduced for '%' and '_' would
    // themselves be doubled and stop functioning as escapes.
    [Fact]
    public void Backslash_IsEscapedFirst()
    {
        Assert.Equal(@"%a\\b%", LikePattern.Contains(@"a\b"));
        Assert.Equal(@"%a\\\_b%", LikePattern.Contains(@"a\_b"));
    }

    [Fact]
    public void ContainsLower_LowercasesForLowerColumnPredicates()
    {
        Assert.Equal("%mixed%", LikePattern.ContainsLower("MiXeD"));
        Assert.Equal(@"%a\_b%", LikePattern.ContainsLower("A_B"));
    }

    [Fact]
    public void Escape_LeavesOrdinaryTextUntouched()
    {
        Assert.Equal("plain-text.123", LikePattern.Escape("plain-text.123"));
    }
}
