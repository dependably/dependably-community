using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Security")]
public class ReservedSlugsTests
{
    [Theory]
    [InlineData("acme")]
    [InlineData("foo-bar")]
    [InlineData("a")]
    [InlineData("widgets-co")]
    public void Normalize_ValidSlug_ReturnsSlug(string input)
    {
        Assert.Equal(input.ToLowerInvariant(), ReservedSlugs.Normalize(input));
    }

    [Theory]
    [InlineData("system")]
    [InlineData("admin")]
    [InlineData("api")]
    [InlineData("www")]
    [InlineData("default")]
    [InlineData("localhost")]
    [InlineData("ADMIN")]   // case-insensitive reserved match
    public void Normalize_BuiltinReserved_Rejected(string input)
    {
        Assert.Null(ReservedSlugs.Normalize(input));
    }

    [Theory]
    [InlineData("xn--abc")]      // punycode
    [InlineData("xn--80akhbyknj4f")]  // real IDN
    public void Normalize_Punycode_Rejected(string input)
    {
        Assert.Null(ReservedSlugs.Normalize(input));
    }

    [Theory]
    [InlineData("Foo")]
    [InlineData("FOO")]
    public void Normalize_LowercasesInput(string input)
    {
        Assert.Equal("foo", ReservedSlugs.Normalize(input));
    }

    [Theory]
    [InlineData("acme.")]     // trailing dot
    [InlineData("acme.\t")]   // trailing whitespace + dot
    [InlineData(" acme ")]    // surrounding whitespace
    public void Normalize_StripsTrailingDotAndWhitespace(string input)
    {
        Assert.Equal("acme", ReservedSlugs.Normalize(input));
    }

    [Theory]
    [InlineData("acme:8080")]  // host:port
    public void Normalize_StripsPort(string input)
    {
        Assert.Equal("acme", ReservedSlugs.Normalize(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("foo bar")]    // space inside
    [InlineData("foo_bar")]    // underscore not allowed
    [InlineData("foo$")]
    [InlineData("-acme")]      // leading hyphen
    [InlineData("acme-")]      // trailing hyphen
    [InlineData("acmé")]       // non-ASCII
    public void Normalize_InvalidCharsOrEdges_Rejected(string input)
    {
        Assert.Null(ReservedSlugs.Normalize(input));
    }

    [Fact]
    public void Normalize_TooLong_Rejected()
    {
        Assert.Null(ReservedSlugs.Normalize(new string('a', 64)));
    }

    [Fact]
    public void Normalize_AtMaxLength_Accepted()
    {
        var max = new string('a', 63);
        Assert.Equal(max, ReservedSlugs.Normalize(max));
    }

    [Fact]
    public void Normalize_ExtraReservedFromConfig_Rejected()
    {
        var extra = ReservedSlugs.ParseExtra("custom,operator,reserved");
        Assert.Null(ReservedSlugs.Normalize("custom", extra));
        Assert.Null(ReservedSlugs.Normalize("operator", extra));
        Assert.Equal("acme", ReservedSlugs.Normalize("acme", extra));
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData("", 0)]
    [InlineData("  ", 0)]
    [InlineData("foo,bar", 2)]
    [InlineData("foo, bar , baz", 3)]
    public void ParseExtra_HandlesEdgeCases(string? input, int expectedCount)
    {
        Assert.Equal(expectedCount, ReservedSlugs.ParseExtra(input).Count);
    }

    [Theory]
    [InlineData(":8080")]   // port-only input -> empty slug after port strip
    [InlineData(".:80")]    // trailing dot + port -> empty slug after strip
    public void Normalize_EmptyAfterPortStrip_Rejected(string input)
    {
        Assert.Null(ReservedSlugs.Normalize(input));
    }
}
