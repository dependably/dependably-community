using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Parser must accept the canonical GNU coreutils format and reject obviously
/// malformed input. The integration path relies on these guarantees — a parse error
/// becomes a 422 to the operator, while a successful parse is treated as gospel.
/// </summary>
[Trait("Category", "Unit")]
public sealed class Sha256SumsParserTests
{
    [Fact]
    public void Empty_ReturnsEmptyMap()
    {
        Assert.Empty(Sha256SumsParser.Parse(""));
        Assert.Empty(Sha256SumsParser.Parse("   \n  \n"));
    }

    [Fact]
    public void TwoSpaceSeparator_CanonicalForm()
    {
        string text = """
            abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  acme-1.0.0.tgz
            0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  bravo-2.0.0.tar.gz
            """;
        var map = Sha256SumsParser.Parse(text);
        Assert.Equal(2, map.Count);
        Assert.Equal("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            map["acme-1.0.0.tgz"]);
        Assert.Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            map["bravo-2.0.0.tar.gz"]);
    }

    [Fact]
    public void TabSeparator_AlsoAccepted()
    {
        string text = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\tacme.nupkg";
        var map = Sha256SumsParser.Parse(text);
        Assert.Equal("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            map["acme.nupkg"]);
    }

    [Fact]
    public void FilenameWithSpaces_PreservedAfterFirstSeparator()
    {
        string text = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  weird name.whl";
        var map = Sha256SumsParser.Parse(text);
        Assert.Equal("weird name.whl", map.Keys.Single());
    }

    [Fact]
    public void CommentLines_Skipped()
    {
        string text = """
            # this is a comment
            abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  acme.tgz
            # another comment
            """;
        var map = Sha256SumsParser.Parse(text);
        Assert.Single(map);
    }

    [Fact]
    public void DigestLowercased()
    {
        string text = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  upper.tgz";
        var map = Sha256SumsParser.Parse(text);
        Assert.Equal("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            map["upper.tgz"]);
    }

    [Theory]
    [InlineData("abc  short.tgz", "64 hex characters")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdez  bad.tgz", "non-hex")]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "missing separator")]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  ", "filename is empty")]
    public void Malformed_Throws(string text, string expectedFragment)
    {
        var ex = Assert.Throws<InvalidDataException>(() => Sha256SumsParser.Parse(text));
        Assert.Contains(expectedFragment, ex.Message);
    }
}
