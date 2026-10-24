using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public sealed class NpmNameValidatorTests
{
    [Theory]
    [InlineData("left-pad")]
    [InlineData("lodash.merge")]
    [InlineData("is_number")]
    [InlineData("a")]
    [InlineData("7zip")]
    public void IsValidPlainName_AcceptsLowercaseUrlSafeNames(string name)
    {
        Assert.True(NpmNameValidator.IsValidPlainName(name));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Left-Pad")]
    [InlineData(".hidden")]
    [InlineData("_private")]
    [InlineData("-dash")]
    [InlineData("node_modules")]
    [InlineData("favicon.ico")]
    [InlineData("with space")]
    [InlineData("semi;colon")]
    [InlineData("slash/inside")]
    [InlineData("left-pad\n")]
    public void IsValidPlainName_RejectsReservedUppercaseAndUnsafeNames(string name)
    {
        Assert.False(NpmNameValidator.IsValidPlainName(name));
    }

    [Fact]
    public void IsValidPlainName_EnforcesTheTwoHundredFourteenCharacterBoundary()
    {
        Assert.True(NpmNameValidator.IsValidPlainName(new string('a', 214)));
        Assert.False(NpmNameValidator.IsValidPlainName(new string('a', 215)));
    }

    [Fact]
    public void IsValidPlainName_ReservedNamesAreOnlyReservedWhole()
    {
        Assert.True(NpmNameValidator.IsValidPlainName("node_modules-helper"));
        Assert.True(NpmNameValidator.IsValidPlainName("favicon.icon"));
    }

    [Theory]
    [InlineData("left-pad")]
    [InlineData("@babel/core")]
    [InlineData("@types/node")]
    [InlineData("@scope/lodash.merge")]
    public void IsValidFullName_AcceptsPlainAndSingleScopedNames(string name)
    {
        Assert.True(NpmNameValidator.IsValidFullName(name));
    }

    [Theory]
    [InlineData("")]
    [InlineData("@")]
    [InlineData("@babel")]
    [InlineData("@babel/")]
    [InlineData("@/core")]
    [InlineData("@babel/core/extra")]
    [InlineData("@Babel/core")]
    [InlineData("@babel/Core")]
    [InlineData("@.hidden/core")]
    [InlineData("@babel/_core")]
    [InlineData("@babel/node_modules")]
    [InlineData("babel/core")]
    [InlineData("Left-Pad")]
    public void IsValidFullName_RejectsMalformedScopesAndExtraSeparators(string name)
    {
        Assert.False(NpmNameValidator.IsValidFullName(name));
    }

    [Fact]
    public void IsValidFullName_NullIsRejected()
    {
        Assert.False(NpmNameValidator.IsValidFullName(null!));
    }

    [Fact]
    public void IsValidFullName_OverallLengthIsCappedIncludingTheScope()
    {
        string withinCap = "@" + new string('s', 10) + "/" + new string('a', 202);
        string overCap = "@" + new string('s', 10) + "/" + new string('a', 203);

        Assert.Equal(214, withinCap.Length);
        Assert.True(NpmNameValidator.IsValidFullName(withinCap));
        Assert.Equal(215, overCap.Length);
        Assert.False(NpmNameValidator.IsValidFullName(overCap));
    }
}
