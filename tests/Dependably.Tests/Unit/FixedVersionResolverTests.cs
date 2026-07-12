using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class FixedVersionResolverTests
{
    private static OsvRangeEvent Introduced(string v) => new(v, null, null, null);
    private static OsvRangeEvent Fixed(string v) => new(null, v, null, null);
    private static OsvRangeEvent LastAffected(string v) => new(null, null, v, null);

    private static OsvAffectedDetail Entry(string? name, string? purl, params OsvRange[] ranges) =>
        new(new OsvAffectedPackageRef("npm", name, purl), ranges, null, null, null);

    private static OsvRange Semver(params OsvRangeEvent[] events) => new("SEMVER", null, events);

    [Fact]
    public void Resolve_PicksTheFixOfTheIntervalContainingTheInstalledVersion()
    {
        // Two vulnerable intervals with distinct fixes — the naive "first fixed event" answer
        // (1.8.1) is wrong for an installed 2.1.0; the containing interval's fix is 2.3.4.
        var affected = new[]
        {
            Entry("left-pad", "pkg:npm/left-pad",
                Semver(Introduced("1.0.0"), Fixed("1.8.1"), Introduced("2.0.0"), Fixed("2.3.4"))),
        };

        Assert.Equal("2.3.4", FixedVersionResolver.Resolve(affected, "npm", "left-pad", "2.1.0"));
        Assert.Equal("1.8.1", FixedVersionResolver.Resolve(affected, "npm", "left-pad", "1.5.0"));
    }

    [Fact]
    public void Resolve_InstalledOutsideEveryIntervalReturnsNull()
    {
        var affected = new[]
        {
            Entry("left-pad", "pkg:npm/left-pad", Semver(Introduced("1.0.0"), Fixed("1.8.1"))),
        };

        Assert.Null(FixedVersionResolver.Resolve(affected, "npm", "left-pad", "1.8.1")); // fixed bound is exclusive
        Assert.Null(FixedVersionResolver.Resolve(affected, "npm", "left-pad", "0.9.0")); // below introduced
    }

    [Fact]
    public void Resolve_IntroducedZeroMeansSinceTheBeginning()
    {
        var affected = new[]
        {
            Entry("left-pad", "pkg:npm/left-pad", Semver(Introduced("0"), Fixed("1.2.0"))),
        };

        Assert.Equal("1.2.0", FixedVersionResolver.Resolve(affected, "npm", "left-pad", "0.0.1"));
    }

    [Fact]
    public void Resolve_LastAffectedIntervalCarriesNoFix()
    {
        var affected = new[]
        {
            Entry("left-pad", "pkg:npm/left-pad", Semver(Introduced("1.0.0"), LastAffected("1.9.9"))),
        };

        Assert.Null(FixedVersionResolver.Resolve(affected, "npm", "left-pad", "1.5.0"));
    }

    [Fact]
    public void Resolve_GitRangesAreSkipped()
    {
        var affected = new[]
        {
            Entry("left-pad", "pkg:npm/left-pad",
                new OsvRange("GIT", "https://example.test/repo.git",
                    new[] { Introduced("0"), Fixed("deadbeef") }),
                Semver(Introduced("1.0.0"), Fixed("2.0.0"))),
        };

        Assert.Equal("2.0.0", FixedVersionResolver.Resolve(affected, "npm", "left-pad", "1.5.0"));
    }

    [Fact]
    public void Resolve_PrefersTheEntryMatchingThePackageName()
    {
        // A multi-package advisory: matching on name keeps another package's range from
        // answering for ours.
        var affected = new[]
        {
            Entry("other-pkg", "pkg:npm/other-pkg", Semver(Introduced("0"), Fixed("9.9.9"))),
            Entry("left-pad", "pkg:npm/left-pad", Semver(Introduced("0"), Fixed("2.0.0"))),
        };

        Assert.Equal("2.0.0", FixedVersionResolver.Resolve(affected, "npm", "left-pad", "1.0.0"));
    }

    [Fact]
    public void Resolve_FallsBackToAllEntriesWhenNoNameMatches()
    {
        // OSV name spellings can diverge from ours — resolution degrades to every entry
        // rather than vanishing.
        var affected = new[]
        {
            Entry("Left_Pad", "pkg:npm/Left_Pad", Semver(Introduced("0"), Fixed("2.0.0"))),
        };

        Assert.Equal("2.0.0", FixedVersionResolver.Resolve(affected, "npm", "leftpad", "1.0.0"));
    }

    [Fact]
    public void Resolve_MatchesOnThePurlNameTail()
    {
        var affected = new[]
        {
            Entry(null, "pkg:npm/left-pad", Semver(Introduced("0"), Fixed("2.0.0"))),
        };

        Assert.Equal("2.0.0", FixedVersionResolver.Resolve(affected, "npm", "left-pad", "1.0.0"));
    }

    [Fact]
    public void Resolve_UnsupportedEcosystemReturnsNull()
    {
        var affected = new[]
        {
            Entry("pkg", "pkg:rpm/pkg", Semver(Introduced("0"), Fixed("2.0.0"))),
        };

        Assert.Null(FixedVersionResolver.Resolve(affected, "rpm", "pkg", "1.0.0"));
    }

    [Fact]
    public void Resolve_UnparseableInstalledVersionReturnsNull()
    {
        var affected = new[]
        {
            Entry("left-pad", "pkg:npm/left-pad", Semver(Introduced("0"), Fixed("2.0.0"))),
        };

        Assert.Null(FixedVersionResolver.Resolve(affected, "npm", "left-pad", "not-a-version"));
    }

    [Fact]
    public void Resolve_NullOrEmptyAffectedReturnsNull()
    {
        Assert.Null(FixedVersionResolver.Resolve(null, "npm", "left-pad", "1.0.0"));
        Assert.Null(FixedVersionResolver.Resolve(Array.Empty<OsvAffectedDetail>(), "npm", "left-pad", "1.0.0"));
    }

    [Fact]
    public void Resolve_NuGetUsesNativeNormalization()
    {
        var affected = new[]
        {
            Entry("Some.Package", "pkg:nuget/Some.Package", Semver(Introduced("1.0"), Fixed("1.2.0"))),
        };

        // 1.0.0.0 == 1.0 under NuGet normalization; contained → fix resolves.
        Assert.Equal("1.2.0", FixedVersionResolver.Resolve(affected, "nuget", "Some.Package", "1.0.0.0"));
    }

    [Fact]
    public void Resolve_PyPiUsesPep440Ordering()
    {
        var affected = new[]
        {
            Entry("requests", "pkg:pypi/requests", Semver(Introduced("2.0"), Fixed("2.31.0"))),
        };

        // 2.9 < 2.31 under PEP 440 (numeric segments), > under lexicographic — native wins.
        Assert.Equal("2.31.0", FixedVersionResolver.Resolve(affected, "pypi", "requests", "2.9"));
    }
}
