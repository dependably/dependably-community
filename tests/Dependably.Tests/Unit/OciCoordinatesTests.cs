using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class OciCoordinatesTests
{
    // ── Repository name validation ──────────────────────────────────────────────

    [Theory]
    [InlineData("library/ubuntu")]
    [InlineData("ubuntu")]
    [InlineData("acme/web/api")]
    [InlineData("foo.bar")]
    [InlineData("foo_bar")]
    [InlineData("foo-bar")]
    [InlineData("a")]
    public void IsValidRepositoryName_AcceptsLegal(string name)
        => Assert.True(OciCoordinatesParser.IsValidRepositoryName(name));

    [Theory]
    [InlineData("")]
    [InlineData("UPPER")]
    [InlineData("Library/Ubuntu")]
    [InlineData("/leading")]
    [InlineData("trailing/")]
    [InlineData("double//slash")]
    public void IsValidRepositoryName_RejectsIllegal(string name)
        => Assert.False(OciCoordinatesParser.IsValidRepositoryName(name));

    // ── Reference / digest validation ───────────────────────────────────────────

    [Theory]
    [InlineData("sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd")]
    [InlineData("sha512:00112233")]
    public void IsValidDigest_AcceptsLegal(string digest)
        => Assert.True(OciCoordinatesParser.IsValidDigest(digest));

    [Theory]
    [InlineData("notadigest")]
    [InlineData("sha1:abc")]
    [InlineData("sha256:")]
    [InlineData("sha256:ZZZZ")]
    public void IsValidDigest_RejectsIllegal(string digest)
        => Assert.False(OciCoordinatesParser.IsValidDigest(digest));

    [Theory]
    [InlineData("latest")]
    [InlineData("1.0.0")]
    [InlineData("v1.2.3-rc1")]
    [InlineData("stable_2024-01")]
    public void IsValidTag_AcceptsLegal(string tag)
        => Assert.True(OciCoordinatesParser.IsValidTag(tag));

    [Theory]
    [InlineData("")]
    [InlineData("-leading-dash")]
    public void IsValidTag_RejectsIllegal(string tag)
        => Assert.False(OciCoordinatesParser.IsValidTag(tag));

    [Fact]
    public void Parse_TagReference_MarkedNotDigest()
    {
        var c = OciCoordinatesParser.Parse("library/ubuntu", "latest");
        Assert.NotNull(c);
        Assert.False(c!.IsDigest);
        Assert.Equal("latest", c.Reference);
        // Tag references expose no digest components.
        Assert.Null(c.DigestAlgorithm);
        Assert.Null(c.DigestHex);
    }

    [Fact]
    public void Parse_DigestReference_MarkedAsDigest()
    {
        var digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var c = OciCoordinatesParser.Parse("library/ubuntu", digest);
        Assert.NotNull(c);
        Assert.True(c!.IsDigest);
        Assert.Equal("sha256", c.DigestAlgorithm);
        Assert.StartsWith("aaaa", c.DigestHex!);
    }
}
