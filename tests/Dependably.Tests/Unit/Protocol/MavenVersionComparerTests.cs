using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Pins <see cref="MavenVersionComparer"/> as a TOTAL order, which is the property its callers
/// depend on rather than merely "newest first": the rendered <c>maven-metadata.xml</c> body feeds a
/// content-derived ETag and its generated <c>.sha1</c>/<c>.md5</c> sidecars, so the same version set
/// must sort to the same bytes however the rows arrive.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenVersionComparerTests
{
    private static readonly MavenVersionComparer Cmp = MavenVersionComparer.Instance;

    private static int Sign(int v) => Math.Sign(v);

    [Theory]
    // Numeric segments compare numerically — the inversion any text sort gets wrong.
    [InlineData("1.9", "1.10")]
    [InlineData("1.2", "1.10")]
    [InlineData("1.0.9", "1.0.10")]
    // A qualifier segment ranks below a numeric one.
    [InlineData("1.0-alpha-1", "1.0")]
    // The qualifier ladder: alpha < beta < milestone < rc < snapshot < release < sp.
    [InlineData("1.0-alpha", "1.0-beta")]
    [InlineData("1.0-beta", "1.0-rc")]
    [InlineData("1.0-SNAPSHOT", "1.0")]
    [InlineData("1.0", "1.0-sp1")]
    public void OrdersUnderMavenRules(string lower, string higher)
    {
        Assert.Equal(-1, Sign(Cmp.Compare(lower, higher)));
        Assert.Equal(1, Sign(Cmp.Compare(higher, lower)));
    }

    [Fact]
    public void IdenticalStringsCompareEqual()
    {
        Assert.Equal(0, Cmp.Compare("1.2.3", "1.2.3"));
        Assert.Equal(0, Cmp.Compare(null, null));
    }

    [Fact]
    public void NullSortsBelowAnyValue()
    {
        Assert.Equal(-1, Sign(Cmp.Compare(null, "1.0")));
        Assert.Equal(1, Sign(Cmp.Compare("1.0", null)));
    }

    [Fact]
    public void MavenEqualButDifferentlySpelledVersionsStillOrderDeterministically()
    {
        // Maven considers 1.0 and 1.0.0 equal; a comparer returning 0 for them would make the
        // rendered order depend on row arrival, and the ETag with it. The ordinal fallback is
        // what makes this total.
        int forward = Cmp.Compare("1.0", "1.0.0");
        int backward = Cmp.Compare("1.0.0", "1.0");

        Assert.NotEqual(0, forward);
        Assert.Equal(-Sign(forward), Sign(backward));
    }

    [Fact]
    public void UnparseableVersionsStillOrderDeterministically()
    {
        foreach (var (a, b) in new[] { ("", "x"), ("!!", "??"), ("20040616", "not-a-version") })
        {
            int forward = Cmp.Compare(a, b);
            Assert.Equal(-Sign(forward), Sign(Cmp.Compare(b, a)));
        }
    }

    [Fact]
    public void SortingIsStableAcrossInputOrderings()
    {
        // The property the ETag actually rests on: any permutation of the same set renders the
        // same sequence.
        string[] versions =
        [
            "1.0", "1.0.0", "1.10", "1.9", "1.0-SNAPSHOT", "1.0-alpha-1", "1.0-sp1",
            "2.0", "20040616", "1.2.3.4.5",
        ];

        string[] reference = versions.OrderBy(v => v, Cmp).ToArray();

        foreach (int seed in new[] { 1, 2, 3, 4, 5 })
        {
            // Deterministic shuffles, so a failure reproduces.
            string[] shuffled = versions
                .OrderBy(v => (v.Length * seed + v.GetHashCode(StringComparison.Ordinal)) % 97)
                .ToArray();
            Assert.Equal(reference, shuffled.OrderBy(v => v, Cmp).ToArray());
        }
    }

    [Fact]
    public void IsAntisymmetricAndTransitiveOverTheSet()
    {
        string[] versions = ["1.0-alpha", "1.0-beta", "1.0-rc", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.1", "1.10"];

        foreach (string a in versions)
        {
            foreach (string b in versions)
            {
                Assert.Equal(-Sign(Cmp.Compare(b, a)), Sign(Cmp.Compare(a, b)));
            }
        }

        string[] sorted = versions.OrderBy(v => v, Cmp).ToArray();
        for (int i = 0; i + 1 < sorted.Length; i++)
        {
            Assert.True(Sign(Cmp.Compare(sorted[i], sorted[i + 1])) <= 0);
        }
    }

    [Fact]
    public void InstanceIsShared()
    {
        Assert.Same(MavenVersionComparer.Instance, MavenVersionComparer.Instance);
    }
}
