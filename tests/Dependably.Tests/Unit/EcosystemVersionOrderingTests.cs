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

    private static int Sign(string ecosystem, string left, string right)
    {
        int? result = EcosystemVersionOrdering.Compare(ecosystem, left, right);
        Assert.NotNull(result);
        return Math.Sign(result.Value);
    }

    // ── SemVer precedence (npm, cargo, terraform, hex) ────────────────────────

    [Theory]
    [InlineData("npm", "2.0.0", "1.9.9", 1)]
    [InlineData("npm", "1.2.0", "1.1.9", 1)]
    [InlineData("npm", "1.0.1", "1.0.2", -1)]
    [InlineData("npm", "1.0.0", "1.0.0-alpha", 1)]
    [InlineData("npm", "1.0.0-alpha", "1.0.0-alpha", 0)]
    [InlineData("npm", "1.0.0-alpha", "1.0.0-beta", -1)]
    [InlineData("npm", "1.0.0-alpha", "1.0.0-alpha.1", -1)]
    [InlineData("npm", "1.0.0-rc.1.2", "1.0.0-rc.1", 1)]
    [InlineData("npm", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1)]
    [InlineData("npm", "1.0.0-alpha.beta", "1.0.0-alpha.1", 1)]
    [InlineData("npm", "1.0.0-rc.2", "1.0.0-rc.10", -1)]
    [InlineData("npm", "1.0.0-rc.007", "1.0.0-rc.7", 0)]
    [InlineData("npm", "1.0.0-99999999999999999999", "1.0.0-9999999999999999999", 1)]
    [InlineData("npm", "1.0.0-Beta", "1.0.0-alpha", -1)]
    [InlineData("npm", "1.0.0-alpha.", "1.0.0-alpha.1", 1)]
    [InlineData("npm", "v1.2.3", "1.2.3", 0)]
    [InlineData("npm", "V2.0.0", "1.0.0", 1)]
    [InlineData("npm", " 1.2.3 ", "1.2.3", 0)]
    [InlineData("npm", "1.2.3+build.5", "1.2.3+build.9", 0)]
    [InlineData("cargo", "0.9.0", "0.10.0", -1)]
    [InlineData("terraform", "3.0.0-beta.1", "3.0.0", -1)]
    [InlineData("hex", "1.0.0-rc.1", "1.0.0-rc.2", -1)]
    public void Compare_SemVerEcosystems_FollowSemverOrgPrecedence(string ecosystem, string left, string right, int expected)
    {
        Assert.Equal(expected, Sign(ecosystem, left, right));
        Assert.Equal(-expected, Sign(ecosystem, right, left));
    }

    [Theory]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("1.x.3")]
    [InlineData("-1.2.3")]
    [InlineData("1.2.3.")]
    [InlineData("99999999999.0.0")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("v")]
    public void Compare_SemVerEcosystems_MalformedVersionIsUnknown(string malformed)
    {
        Assert.Null(EcosystemVersionOrdering.Compare("npm", malformed, "1.0.0"));
        Assert.Null(EcosystemVersionOrdering.Compare("cargo", "1.0.0", malformed));
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("cargo")]
    [InlineData("terraform")]
    [InlineData("hex")]
    public void OrderStableDescending_SemVerEcosystems_DropPrereleasesAndGarbageButKeepTheRawSpelling(string ecosystem)
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            ecosystem, new[] { "v1.2.0", "1.10.0", "1.9.0", "2.0.0-rc.1", "junk", "1.0.0+build" });

        Assert.Equal(new[] { "1.10.0", "1.9.0", "v1.2.0", "1.0.0+build" }, stable);
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("cargo")]
    [InlineData("terraform")]
    [InlineData("hex")]
    public void CountNewerStable_SemVerEcosystems_IgnoreUnparseableEntriesInTheList(string ecosystem)
    {
        string[] list = new[] { "2.0.0", "garbage", "1.5.0", "1.0.0" };

        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable(ecosystem, list, "1.0.0"));
        Assert.Equal(1, EcosystemVersionOrdering.CountNewerStable(ecosystem, list, "1.5.0"));
        Assert.Null(EcosystemVersionOrdering.CountNewerStable(ecosystem, list, "garbage"));
    }

    // ── PEP 440 ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("1.0", "1.0.0", 0)]
    [InlineData("1.0.0", "1.0.0.0.0", 0)]
    [InlineData("1.10", "1.9", 1)]
    [InlineData("1.2.3.4", "1.2.3.5", -1)]
    [InlineData("1!0.1", "2.0", 1)]
    [InlineData("1.0a1", "1.0b1", -1)]
    [InlineData("1.0b1", "1.0rc1", -1)]
    [InlineData("1.0rc1", "1.0c1", 0)]
    [InlineData("1.0alpha1", "1.0a1", 0)]
    [InlineData("1.0beta2", "1.0b2", 0)]
    [InlineData("1.0preview1", "1.0rc1", 0)]
    [InlineData("1.0pre1", "1.0rc1", 0)]
    [InlineData("1.0a2", "1.0a10", -1)]
    [InlineData("1.0.dev1", "1.0a1", -1)]
    [InlineData("1.0.dev1", "1.0.dev2", -1)]
    [InlineData("1.0a1", "1.0", -1)]
    [InlineData("1.0", "1.0.post1", -1)]
    [InlineData("1.0.post1", "1.0.post2", -1)]
    [InlineData("1.0-1", "1.0.post1", 0)]
    [InlineData("1.0rc1.dev1", "1.0rc1", -1)]
    [InlineData("1.0+local.1", "1.0+local.2", 0)]
    [InlineData(" 1.0 ", "1.0", 0)]
    [InlineData("1.0.RC1", "1.0rc1", 0)]
    [InlineData("1.0a", "1.0a0", 0)]
    [InlineData("1.0rc", "1.0rc0", 0)]
    public void Compare_PyPi_FollowsPep440Precedence(string left, string right, int expected)
    {
        Assert.Equal(expected, Sign("pypi", left, right));
        Assert.Equal(-expected, Sign("pypi", right, left));
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData("1.0.0.")]
    [InlineData("1.0 final")]
    [InlineData("1..0")]
    public void Compare_PyPi_UnparseableVersionIsUnknown(string malformed)
    {
        Assert.Null(EcosystemVersionOrdering.Compare("pypi", malformed, "1.0"));
        Assert.Null(EcosystemVersionOrdering.Compare("pypi", "1.0", malformed));
    }

    [Fact]
    public void OrderStableDescending_PyPi_EpochDominatesAndPrereleaseDevAndGarbageAreDropped()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "pypi", new[] { "1.0", "1.0.post1", "1.0rc1", "0.9", "1!0.1", "junk", "1.0.dev1", "2.0b3.dev1" });

        Assert.Equal(new[] { "1!0.1", "1.0.post1", "1.0", "0.9" }, stable);
    }

    [Fact]
    public void CountNewerStable_PyPi_HeldPrereleaseCountsItsOwnFinalAsNewer()
    {
        string[] list = new[] { "2.0", "junk", "1.0", "0.9" };

        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable("pypi", list, "1.0rc1"));
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("pypi", list, "not a version"));
    }

    // ── NuGet ────────────────────────────────────────────────────────────────

    [Fact]
    public void OrderStableDescending_NuGet_NormalizesSpellingDropsPrereleaseAndGarbage()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "nuget", new[] { "1.0.0", "1.1.0-beta", "2.0.0-RC1", "3.0.0", "junk", "1.0.0.1", "2.0" });

        Assert.Equal(new[] { "3.0.0", "2.0.0", "1.0.0.1", "1.0.0" }, stable);
    }

    [Fact]
    public void CountNewerStable_NuGet_HeldPrereleaseAndUnparseableHeld()
    {
        string[] list = new[] { "2.0.0", "1.0.0" };

        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable("nuget", list, "1.0.0-beta"));
        Assert.Equal(0, EcosystemVersionOrdering.CountNewerStable("nuget", list, "2.0.0"));
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("nuget", list, "junk"));
    }

    [Fact]
    public void Compare_NuGet_PrereleaseLabelsOrderNumericallyAndUnparseableIsUnknown()
    {
        Assert.Equal(-1, Sign("nuget", "1.0.0-beta.2", "1.0.0-beta.11"));
        Assert.Equal(1, Sign("nuget", "1.0.0.1", "1.0.0"));
        Assert.Null(EcosystemVersionOrdering.Compare("nuget", "junk", "1.0.0"));
        Assert.Null(EcosystemVersionOrdering.Compare("nuget", "1.0.0", "junk"));
    }

    // ── Maven ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("1.0", "1.0.0", 0)]
    [InlineData("1", "1.0.0.0", 0)]
    [InlineData("1.10", "1.9", 1)]
    [InlineData("1.0-alpha", "1.0-beta", -1)]
    [InlineData("1.0-beta", "1.0-milestone", -1)]
    [InlineData("1.0-m", "1.0-milestone", 0)]
    [InlineData("1.0-m1", "1.0-rc1", -1)]
    [InlineData("1.0-rc1", "1.0-cr1", 0)]
    [InlineData("1.0-rc1", "1.0-snapshot", -1)]
    [InlineData("1.0-snapshot", "1.0", -1)]
    [InlineData("1.0-beta", "1.0", -1)]
    [InlineData("1.0-ga", "1.0", 0)]
    [InlineData("1.0-final", "1.0", 0)]
    [InlineData("1.0-sp1", "1.0", 1)]
    [InlineData("1.0-foo", "1.0-bar", 1)]
    [InlineData("1.0-foo", "1.0-rc1", 1)]
    [InlineData("1.0-abc", "1.0", 1)]
    [InlineData("1.0.1", "1.0-sp1", 1)]
    [InlineData("1.0-1", "1.0-alpha", 1)]
    [InlineData("1.0-RC1", "1.0-rc1", 0)]
    public void Compare_Maven_FollowsComparableVersionStyleQualifierRanks(string left, string right, int expected)
    {
        Assert.Equal(expected, Sign("maven", left, right));
        Assert.Equal(-expected, Sign("maven", right, left));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("---")]
    [InlineData("...")]
    public void Compare_Maven_VersionWithNoTokensIsUnknown(string malformed)
    {
        Assert.Null(EcosystemVersionOrdering.Compare("maven", malformed, "1.0"));
        Assert.Null(EcosystemVersionOrdering.Compare("maven", "1.0", malformed));
    }

    [Fact]
    public void OrderStableDescending_Maven_DropsSnapshotsCaseInsensitivelyAndTokenlessVersions()
    {
        var stable = EcosystemVersionOrdering.OrderStableDescending(
            "maven", new[] { "1.0", "1.0-SNAPSHOT", "2.0-snapshot", "1.0-sp1", "---", "", "1.0-RC1" });

        Assert.Equal(new[] { "1.0-sp1", "1.0", "1.0-RC1" }, stable);
    }

    [Fact]
    public void CountNewerStable_Maven_IgnoresUnparseableEntriesAndRejectsUnparseableHeld()
    {
        string[] list = new[] { "2.0", "---", "1.5", "1.0" };

        Assert.Equal(2, EcosystemVersionOrdering.CountNewerStable("maven", list, "1.0"));
        Assert.Null(EcosystemVersionOrdering.CountNewerStable("maven", list, "---"));
    }
}
