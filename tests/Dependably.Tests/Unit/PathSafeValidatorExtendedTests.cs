using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class PathSafeValidatorExtendedTests
{
    // The existing SecurityTests.cs covers empty, too-long, '..', '/', '\\', and '\0',
    // but not the trailing `char.IsControl` branch at line 28 — that only fires for
    // a control character that ISN'T a null byte (null is caught one branch earlier).
    [Theory]
    [InlineData("\t")]          // tab (U+0009)
    [InlineData("foo\tbar")]    // tab embedded
    [InlineData("foo\rbar")]    // carriage return (U+000D)
    [InlineData("foo\nbar")]    // line feed (U+000A)
    [InlineData("foobar")] // bell (U+0007)
    [InlineData("foobar")] // ESC (U+001B)
    [InlineData("foobar")] // DEL (U+007F)
    public void Validate_NonNullControlCharacter_FailsWithControlCharMessage(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");

        Assert.False(result.IsValid);
        Assert.Equal("field", result.FieldName);
        Assert.Equal("must not contain control characters", result.Message);
    }

    [Fact]
    public void Validate_ValidInput_ReturnsOkWithNullFieldAndMessage()
    {
        var result = PathSafeValidator.Validate("safe-package-name", "field");

        Assert.True(result.IsValid);
        Assert.Null(result.FieldName);
        Assert.Null(result.Message);
    }
}
