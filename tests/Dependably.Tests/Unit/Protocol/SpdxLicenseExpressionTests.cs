using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public class SpdxLicenseExpressionTests
{
    [Fact]
    public void Or_TwoLeaves_LeavesContainsBoth()
    {
        var expr = SpdxLicenseExpression.Parse("MIT OR Apache-2.0");

        Assert.Equal(["MIT", "Apache-2.0"], expr.Leaves());
        Assert.True(expr.IsCompound);
    }

    [Fact]
    public void Or_AnySatisfiedSemantics()
    {
        var expr = SpdxLicenseExpression.Parse("MIT OR Apache-2.0");

        // Either operand alone is sufficient to satisfy the OR.
        Assert.True(expr.Evaluate(leaf => leaf == "MIT"));
        Assert.True(expr.Evaluate(leaf => leaf == "Apache-2.0"));
        // Both satisfied is also true.
        Assert.True(expr.Evaluate(_ => true));
        // Neither satisfied -> false.
        Assert.False(expr.Evaluate(_ => false));
    }

    [Fact]
    public void And_AllSatisfiedSemantics()
    {
        var expr = SpdxLicenseExpression.Parse("MIT AND PSF-2.0");

        Assert.Equal(["MIT", "PSF-2.0"], expr.Leaves());
        Assert.True(expr.IsCompound);

        Assert.True(expr.Evaluate(_ => true));
        Assert.False(expr.Evaluate(leaf => leaf == "MIT"));
        Assert.False(expr.Evaluate(leaf => leaf == "PSF-2.0"));
        Assert.False(expr.Evaluate(_ => false));
    }

    [Fact]
    public void ParenthesizedOr_ParsesAndEvaluates()
    {
        var expr = SpdxLicenseExpression.Parse("(MIT OR CC0-1.0)");

        Assert.Equal(["MIT", "CC0-1.0"], expr.Leaves());
        Assert.True(expr.Evaluate(leaf => leaf == "CC0-1.0"));
        Assert.False(expr.Evaluate(_ => false));
    }

    [Fact]
    public void NestedParens_AndOfOr_EvaluatesCorrectly()
    {
        // (A OR B) AND C
        var expr = SpdxLicenseExpression.Parse("(MIT OR Apache-2.0) AND PSF-2.0");

        Assert.Equal(["MIT", "Apache-2.0", "PSF-2.0"], expr.Leaves());

        // A satisfied, C satisfied -> true
        Assert.True(expr.Evaluate(leaf => leaf is "MIT" or "PSF-2.0"));
        // Only A satisfied, C not -> false (AND requires the right side)
        Assert.False(expr.Evaluate(leaf => leaf == "MIT"));
        // Only C satisfied, neither A nor B -> false (AND requires a satisfied left side too)
        Assert.False(expr.Evaluate(leaf => leaf == "PSF-2.0"));
    }

    [Fact]
    public void Precedence_OrBindsLooserThanAnd_MatchesExplicitParens()
    {
        // A OR B AND C == A OR (B AND C)
        var implicitExpr = SpdxLicenseExpression.Parse("MIT OR Apache-2.0 AND PSF-2.0");
        var explicitExpr = SpdxLicenseExpression.Parse("MIT OR (Apache-2.0 AND PSF-2.0)");

        Assert.Equal(explicitExpr.Leaves(), implicitExpr.Leaves());

        // Every combination of leaf satisfaction produces the same verdict for both forms.
        foreach (bool mit in new[] { true, false })
        {
            foreach (bool apache in new[] { true, false })
            {
                foreach (bool psf in new[] { true, false })
                {
                    bool LeafSatisfied(string leaf) => leaf switch
                    {
                        "MIT" => mit,
                        "Apache-2.0" => apache,
                        "PSF-2.0" => psf,
                        _ => false,
                    };

                    Assert.Equal(explicitExpr.Evaluate(LeafSatisfied), implicitExpr.Evaluate(LeafSatisfied));
                }
            }
        }

        // Sanity: MIT unsatisfied but both Apache-2.0 and PSF-2.0 satisfied -> true via the AND branch.
        Assert.True(implicitExpr.Evaluate(leaf => leaf is "Apache-2.0" or "PSF-2.0"));
        // MIT unsatisfied, only one of the AND operands satisfied -> false.
        Assert.False(implicitExpr.Evaluate(leaf => leaf == "Apache-2.0"));
    }

    [Fact]
    public void WithException_IsSingleAtomicLeaf()
    {
        var expr = SpdxLicenseExpression.Parse("GPL-2.0-only WITH Classpath-exception-2.0");

        Assert.Equal(["GPL-2.0-only WITH Classpath-exception-2.0"], expr.Leaves());
        Assert.False(expr.IsCompound);

        Assert.True(expr.Evaluate(leaf => leaf == "GPL-2.0-only WITH Classpath-exception-2.0"));
        // The base id alone must NOT satisfy the WITH leaf — it's a different, atomic leaf.
        Assert.False(expr.Evaluate(leaf => leaf == "GPL-2.0-only"));
    }

    [Fact]
    public void OrLater_PlusSuffix_KeptOnLeafId()
    {
        var expr = SpdxLicenseExpression.Parse("Apache-2.0+");

        Assert.Equal(["Apache-2.0+"], expr.Leaves());
        Assert.False(expr.IsCompound);
        Assert.True(expr.Evaluate(leaf => leaf == "Apache-2.0+"));
    }

    [Theory]
    [InlineData("MIT OR")]
    [InlineData("(MIT")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("MIT AND")]
    [InlineData("OR MIT")]
    [InlineData("MIT))")]
    public void Malformed_FallsBackToSingleLeaf_NeverThrows(string raw)
    {
        var expr = SpdxLicenseExpression.Parse(raw);

        // Never throws (implicit — we got here), and always yields exactly one leaf wrapping
        // the trimmed raw string.
        Assert.Single(expr.Leaves());
        Assert.Equal(raw.Trim(), expr.Leaves()[0]);
    }

    [Fact]
    public void SingleLeaf_IsNotCompound()
    {
        var expr = SpdxLicenseExpression.Parse("MIT");
        Assert.False(expr.IsCompound);
        Assert.Equal(["MIT"], expr.Leaves());
    }

    [Fact]
    public void CompoundExpression_IsCompound()
    {
        Assert.True(SpdxLicenseExpression.Parse("MIT OR Apache-2.0").IsCompound);
        Assert.True(SpdxLicenseExpression.Parse("MIT AND Apache-2.0").IsCompound);
    }

    [Fact]
    public void Leaves_DedupCaseInsensitive()
    {
        var expr = SpdxLicenseExpression.Parse("MIT OR mit");
        Assert.Single(expr.Leaves());
    }

    [Fact]
    public void CaseInsensitiveOperators_DoNotConfuseIdentLikeAnd()
    {
        // "and" as an operator (lowercase) still parses as AND, not as part of an identifier.
        var expr = SpdxLicenseExpression.Parse("MIT and Apache-2.0");
        Assert.Equal(["MIT", "Apache-2.0"], expr.Leaves());
        Assert.True(expr.IsCompound);
    }
}
