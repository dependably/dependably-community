using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public class LanguageCodesTests
{
    [Fact]
    public void Supported_ContainsExpectedLocales()
    {
        Assert.Equal(new[] { "en", "fr" }, LanguageCodes.Supported);
    }

    [Fact]
    public void Default_IsEnglish()
    {
        Assert.Equal("en", LanguageCodes.Default);
    }

    [Fact]
    public void Default_IsContainedInSupported()
    {
        Assert.Contains(LanguageCodes.Default, LanguageCodes.Supported);
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    public void IsSupported_KnownCode_ReturnsTrue(string code)
    {
        Assert.True(LanguageCodes.IsSupported(code));
    }

    [Theory]
    [InlineData("EN")]      // uppercase — IndexOf is case-sensitive
    [InlineData("Fr")]      // mixed case
    [InlineData("FR")]
    [InlineData("es")]      // unsupported locale
    [InlineData("de")]
    [InlineData("en-US")]   // BCP-47 with region
    [InlineData("")]        // empty
    [InlineData(" en")]     // leading whitespace
    [InlineData("en ")]     // trailing whitespace
    public void IsSupported_UnknownOrMismatchedCode_ReturnsFalse(string code)
    {
        Assert.False(LanguageCodes.IsSupported(code));
    }

    [Fact]
    public void IsSupported_Null_ReturnsFalse()
    {
        Assert.False(LanguageCodes.IsSupported(null!));
    }
}
