using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class EcosystemVersionOrderingTests
{
    // ── npm (semver) ───────────────────────────────────────────────────────────

    [Fact]
    public void CountNewerStable_Npm_CountsOnlyStableVersionsNewerThanHeld()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "npm", new[] { "1.0.0", "1.1.0", "1.2.0", "2.0.0-beta.1", "2.0.0" });

        // Stable-only, so the prerelease is excluded from the list entirely.
        Assert.Equal(new[] { "2.0.0", "1.2.0", "1.1.0", "1.0.0" }, stable);

        Assert.Equal(3, EcosystemVersionOrdering.CountNewerStable("npm", stable, "1.0.0"));
        Assert.Equal(0, EcosystemVersionOrdering.CountNewerStable("npm", stable, "2.0.0"));
    }

    [Fact]
    public void CountNewerStable_Npm_HeldVersionCanBeAPrerelease()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending("npm", new[] { "1.0.0", "1.1.0", "1.2.0" });
        Assert.Equal(3, EcosystemVersionOrdering.CountNewerStable("npm", stable, "1.0.0-rc.1"));
    }

    [Fact]
    public void CountNewerStable_Npm_UnparseableHeldVersionReturnsNull()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending("npm", new[] { "1.0.0", "1.1.0" });
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("npm", stable, "not-a-version"));
    }

    // ── PyPI (PEP 440) ────────────────────────────────────────────────────────

    [Fact]
    public void CountNewerStable_PyPi_ExcludesPreAndDevReleases()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "pypi", new[] { "1.0.0", "1.1.0a1", "1.1.0.dev0", "1.1.0", "1.1.0.post1", "2.0.0" });

        Assert.Equal(new[] { "2.0.0", "1.1.0.post1", "1.1.0", "1.0.0" }, stable);
        Assert.Equal(3, EcosystemVersionOrdering.CountNewerStable("pypi", stable, "1.0.0"));
    }

    [Fact]
    public void CountNewerStable_PyPi_PostReleaseOutranksTheBaseRelease()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending("pypi", new[] { "1.0.0", "1.0.0.post1" });
        Assert.Equal(1, EcosystemVersionOrdering.CountNewerStable("pypi", stable, "1.0.0"));
        Assert.Equal(0, EcosystemVersionOrdering.CountNewerStable("pypi", stable, "1.0.0.post1"));
    }

    [Fact]
    public void OrderStableDescending_PyPi_LocalVersionIdentifierContainingDev_IsStillFinal()
    {
        // "+ubuntu.dev1" is a local version identifier, not a dev-release segment — a whole-string
        // "dev" substring scan would wrongly classify this as PhaseDev and drop it from the stable
        // list, even though it is a final release per PEP 440.
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "pypi", new[] { "1.0.0", "1.2.3+ubuntu.dev1" });

        Assert.Contains("1.2.3+ubuntu.dev1", stable);
        Assert.Equal(new[] { "1.2.3+ubuntu.dev1", "1.0.0" }, stable);
    }

    [Fact]
    public void CountNewerStable_PyPi_LocalVersionIdentifierContainingDev_CountsAsNewer()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "pypi", new[] { "1.0.0", "1.2.3+dev" });

        Assert.Equal(1, EcosystemVersionOrdering.CountNewerStable("pypi", stable, "1.0.0"));
    }

    [Fact]
    public void Compare_PyPi_PreReleaseDev_KeepsPreReleaseSubRankInsteadOfCollapsing()
    {
        // A dev-release OF a pre-release (e.g. "2.0.0b1.dev1") must still order the alpha/beta
        // distinction correctly — collapsing both to a bare "dev" rank would report them equal.
        int? alphaVsBetaDev = EcosystemVersionOrdering.Compare("pypi", "2.0.0a1.dev1", "2.0.0b1.dev1");
        Assert.NotNull(alphaVsBetaDev);
        Assert.True(alphaVsBetaDev < 0, "alpha-dev must sort below beta-dev, not compare equal.");
    }

    // ── NuGet (NuGet.Versioning) ──────────────────────────────────────────────

    [Fact]
    public void CountNewerStable_NuGet_ExcludesPrereleaseAndNormalizesCase()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "nuget", new[] { "1.0.0", "1.1.0-beta", "1.2.0", "2.0.0" });

        Assert.Equal(new[] { "2.0.0", "1.2.0", "1.0.0" }, stable);
        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable("nuget", stable, "1.0.0"));
    }

    // ── Maven (ComparableVersion-style) ───────────────────────────────────────

    [Fact]
    public void CountNewerStable_Maven_ExcludesSnapshotsAndOrdersNumerically()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "maven", new[] { "1.0", "1.1", "1.2-SNAPSHOT", "1.10", "2.0" });

        // 1.10 > 1.2-SNAPSHOT (excluded) and sorts after 1.1 numerically, not lexically.
        Assert.Equal(new[] { "2.0", "1.10", "1.1", "1.0" }, stable);
        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable("maven", stable, "1.1"));
    }

    [Fact]
    public void CountNewerStable_Maven_QualifierRanksBelowRelease()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending("maven", new[] { "1.0-alpha", "1.0-beta", "1.0" });
        // alpha < beta < release(empty) — all three are "stable" (none is -SNAPSHOT).
        Assert.Equal(new[] { "1.0", "1.0-beta", "1.0-alpha" }, stable);
        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable("maven", stable, "1.0-alpha"));
    }

    // ── Cross-cutting: NULL/unknown semantics ─────────────────────────────────

    [Fact]
    public void CountNewerStable_NullListReturnsNull()
    {
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("npm", null, "1.0.0"));
    }

    [Fact]
    public void CountNewerStable_EmptyListReturnsNull()
    {
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("npm", Array.Empty<string>(), "1.0.0"));
    }

    [Fact]
    public void CountNewerStable_UnsupportedEcosystemReturnsNull()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending("npm", new[] { "1.0.0" });
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("rpm", stable, "1.0.0"));
    }

    [Fact]
    public void CountNewerStable_AtLatestReturnsZero_NotUnknown()
    {
        // A known, up-to-date version is a real "0 behind" answer, distinct from an unknown count.
        var stable = EcosystemVersionOrdering.OrderStableDescending("npm", new[] { "1.0.0", "1.1.0" });
        Assert.Equal(0, EcosystemVersionOrdering.CountNewerStable("npm", stable, "1.1.0"));
    }

    [Fact]
    public void OrderStableDescending_UnsupportedEcosystemReturnsEmpty()
    {
        Assert.Empty(EcosystemVersionOrdering.OrderStableDescending("go", new[] { "v1.0.0" }));
    }

    // ── Compare (pairwise, native ordering) ───────────────────────────────────

    [Theory]
    [InlineData("npm", "1.2.3", "1.10.0", -1)]          // numeric, not lexicographic
    [InlineData("npm", "2.0.0-rc.1", "2.0.0", -1)]      // prerelease sorts below release
    [InlineData("npm", "1.0.0", "1.0.0", 0)]
    [InlineData("pypi", "1.9", "1.10", -1)]             // PEP 440 numeric segments
    [InlineData("pypi", "2.0.0rc1", "2.0.0", -1)]       // pre-release below final
    [InlineData("nuget", "1.0", "1.0.0", 0)]            // NuGet normalization: equal
    [InlineData("nuget", "1.0.0-beta", "1.0.0", -1)]
    [InlineData("maven", "1.0-alpha-1", "1.0", -1)]     // qualifier sorts below release
    [InlineData("maven", "1.0", "1.0.1", -1)]
    public void Compare_OrdersUnderNativeScheme(string ecosystem, string left, string right, int expectedSign)
    {
        int? result = EcosystemVersionOrdering.Compare(ecosystem, left, right);
        Assert.NotNull(result);
        Assert.Equal(expectedSign, Math.Sign(result.Value));
    }

    [Fact]
    public void Compare_UnsupportedEcosystemReturnsNull()
    {
        Assert.Null(EcosystemVersionOrdering.Compare("rpm", "1.0.0", "2.0.0"));
    }

    [Fact]
    public void Compare_UnparseableVersionReturnsNull_NeverEqual()
    {
        Assert.Null(EcosystemVersionOrdering.Compare("npm", "not-a-version", "1.0.0"));
        Assert.Null(EcosystemVersionOrdering.Compare("npm", "1.0.0", "not-a-version"));
    }
}
