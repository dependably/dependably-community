using Dependably.Protocol.Hex;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The hex.pm identity rules (<see cref="HexNaming"/>) applied to every package name and release
/// version the registry accepts: lower case names that start with a letter and stay within 100
/// characters, and strict SemVer 2.0 versions.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexNamingTests
{
    [Theory]
    [InlineData("a")]
    [InlineData("phoenix")]
    [InlineData("plug_cowboy")]
    [InlineData("ecto3")]
    public void Lower_case_name_starting_with_a_letter_is_valid(string name) =>
        Assert.True(HexNaming.IsValidPackageName(name));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Phoenix")]
    [InlineData("1phoenix")]
    [InlineData("_phoenix")]
    [InlineData("plug-cowboy")]
    [InlineData("plug.cowboy")]
    [InlineData("phoenix\n")]
    public void Name_outside_the_hex_rules_is_invalid(string? name) =>
        Assert.False(HexNaming.IsValidPackageName(name));

    [Fact]
    public void Name_is_capped_at_one_hundred_characters()
    {
        Assert.True(HexNaming.IsValidPackageName(new string('a', 100)));
        Assert.False(HexNaming.IsValidPackageName(new string('a', 101)));
    }

    [Theory]
    [InlineData("0.0.0")]
    [InlineData("1.2.3")]
    [InlineData("10.20.30")]
    [InlineData("1.0.0-rc.1")]
    [InlineData("1.0.0+build.5")]
    [InlineData("1.0.0-alpha.1+exp.sha.5114f85")]
    public void Strict_semver_version_is_valid(string version) =>
        Assert.True(HexNaming.IsValidVersion(version));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1.0")]
    [InlineData("v1.0.0")]
    [InlineData("01.0.0")]
    [InlineData("1.00.0")]
    [InlineData("1.0.0-")]
    [InlineData("1.0.0-rc..1")]
    [InlineData("1.0.0+")]
    [InlineData("1.0.0\n")]
    public void Version_that_is_not_strict_semver_is_invalid(string? version) =>
        Assert.False(HexNaming.IsValidVersion(version));
}
