using Dependably.Api;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Unit tests for <see cref="RpmController.ParseNevra"/>: <c>{name}-{version}-{release}.{arch}.rpm</c>
/// parsed from the right by locating the last '.', then the last '-', then the next last '-'.
/// </summary>
[Trait("Category", "Unit")]
public class RpmNevraParserTests
{
    [Theory]
    [InlineData("tree-2.1.1-1.fc40.x86_64.rpm", "tree", "2.1.1", "1.fc40", "x86_64")]
    [InlineData("bash-5.2.15-1.el9.x86_64.rpm", "bash", "5.2.15", "1.el9", "x86_64")]
    [InlineData("perl-AutoLoader-5.74-483.fc40.noarch.rpm", "perl-AutoLoader", "5.74", "483.fc40", "noarch")]
    public void ParseNevra_WellFormed_ExtractsNameVersionReleaseArch(
        string filename, string expectedName, string expectedVer, string expectedRel, string expectedArch)
    {
        var parsed = RpmController.ParseNevra(filename);
        Assert.NotNull(parsed);
        Assert.Equal(expectedName, parsed!.Value.Name);
        Assert.Equal(expectedVer, parsed.Value.Version);
        Assert.Equal(expectedRel, parsed.Value.Release);
        Assert.Equal(expectedArch, parsed.Value.Arch);
    }

    [Fact]
    public void ParseNevra_SimpleName_ExtractsExactSegments()
    {
        var parsed = RpmController.ParseNevra("tree-2.1.1-1.fc40.x86_64.rpm");
        Assert.NotNull(parsed);
        Assert.Equal("tree", parsed!.Value.Name);
        Assert.Equal("2.1.1", parsed.Value.Version);
        Assert.Equal("1.fc40", parsed.Value.Release);
        Assert.Equal("x86_64", parsed.Value.Arch);
    }

    [Fact]
    public void ParseNevra_EpochPrefixInVersion_ExtractsEpoch()
    {
        var parsed = RpmController.ParseNevra("tree-2:2.1.1-1.fc40.x86_64.rpm");
        Assert.NotNull(parsed);
        Assert.Equal(2, parsed!.Value.Epoch);
        Assert.Equal("2.1.1", parsed.Value.Version);
    }

    // A leading/trailing separator makes one of Name/Version/Release/Arch resolve to an empty
    // string. Every one of these must be rejected — a malformed NEVRA must never render an
    // empty-segment PURL (e.g. pkg:rpm/@1.0-1?arch=x86_64).
    [Theory]
    [InlineData("-1.0-1.x86_64.rpm")]      // leading '-' ⇒ empty Name
    [InlineData("name--1.x86_64.rpm")]     // adjacent dashes ⇒ empty Version
    [InlineData("name-1.0-.x86_64.rpm")]   // trailing '-' before dot ⇒ empty Release
    [InlineData("name-1.0-1..rpm")]        // trailing '.' ⇒ empty Arch
    [InlineData(".rpm")]                   // nothing but the extension
    [InlineData("name.rpm")]               // no '-' segments at all
    [InlineData("name-1.0.rpm")]           // only one '-' segment (missing release)
    public void ParseNevra_EmptyBoundarySegment_ReturnsNull(string filename)
    {
        Assert.Null(RpmController.ParseNevra(filename));
    }

    // The epoch-colon strip runs after the dash/dot boundary guards pass, so it needs its own
    // empty-Version guard: verDash sits strictly inside "pkg-1:" (never at a boundary), but
    // stripping the "1:" epoch prefix from the resulting "1:" Version leaves "" — an empty
    // Version that must never reach the PURL/cache_artifact coordinate.
    [Theory]
    [InlineData("pkg-1:-1.x86_64.rpm")]
    [InlineData("tree-0:-1.fc40.x86_64.rpm")]
    public void ParseNevra_EpochStripEmptiesVersion_ReturnsNull(string filename)
    {
        Assert.Null(RpmController.ParseNevra(filename));
    }

    [Fact]
    public void ParseNevra_WrongExtension_ReturnsNull()
    {
        Assert.Null(RpmController.ParseNevra("tree-2.1.1-1.fc40.x86_64.deb"));
    }

    [Fact]
    public void ParseNevra_IsCaseInsensitiveOnExtension()
    {
        var parsed = RpmController.ParseNevra("tree-2.1.1-1.fc40.x86_64.RPM");
        Assert.NotNull(parsed);
        Assert.Equal("tree", parsed!.Value.Name);
    }
}
