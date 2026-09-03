using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// <c>metadata.config</c> as Mix and Rebar3 write it, read through the textual term codec into the
/// typed model the publish path validates and the registry index is built from.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexPackageMetadataTests
{
    private const string Decimal = """
        {<<"links">>,[{<<"GitHub">>,<<"https://github.com/ericmj/decimal">>}]}.
        {<<"name">>,<<"decimal">>}.
        {<<"version">>,<<"2.3.0">>}.
        {<<"description">>,<<"Arbitrary precision decimal arithmetic.">>}.
        {<<"elixir">>,<<"~> 1.8">>}.
        {<<"app">>,<<"decimal">>}.
        {<<"licenses">>,[<<"Apache-2.0">>]}.
        {<<"requirements">>,[]}.
        {<<"files">>,
         [<<"lib">>,<<"lib/decimal">>,<<"lib/decimal/error.ex">>,
          <<"lib/decimal/context.ex">>,<<"lib/decimal/macros.ex">>,
          <<"lib/decimal.ex">>,<<".formatter.exs">>,<<"mix.exs">>,<<"README.md">>,
          <<"LICENSE.txt">>,<<"CHANGELOG.md">>]}.
        {<<"build_tools">>,[<<"mix">>]}.

        """;

    [Fact]
    public void RealDecimalMetadata_Parses()
    {
        var meta = HexPackageMetadata.Parse(Decimal);

        Assert.Equal("decimal", meta.Name);
        Assert.Equal("2.3.0", meta.Version);
        Assert.Equal("decimal", meta.App);
        Assert.Equal("Arbitrary precision decimal arithmetic.", meta.Description);
        Assert.Equal(new[] { "Apache-2.0" }, meta.Licenses);
        Assert.Equal("https://github.com/ericmj/decimal", meta.Links["GitHub"]);
        Assert.Empty(meta.Requirements);
        Assert.Equal(new[] { "mix" }, meta.BuildTools);
        Assert.Equal("~> 1.8", meta.Elixir);
        Assert.Equal(11, meta.Files.Count);
    }

    [Fact]
    public void RealDecimalTarball_MetadataParsesFromTheTarballReader()
    {
        byte[] tar = File.ReadAllBytes(Path.Combine(FixtureManifest.FixturesRoot, "hex", "decimal-2.3.0.tar"));
        var parsed = HexTarball.Parse(tar, 64 * 1024 * 1024);

        var meta = HexPackageMetadata.Parse(parsed.MetadataText);

        Assert.Equal("decimal", meta.Name);
        Assert.Equal("2.3.0", meta.Version);
    }

    [Fact]
    public void CurrentRequirementsShape_ProplistKeyedByName_Parses()
    {
        var meta = HexPackageMetadata.Parse("""
            {<<"name">>,<<"demo">>}.
            {<<"version">>,<<"1.0.0">>}.
            {<<"requirements">>,[{<<"jason">>,[{<<"app">>,<<"jason">>},{<<"optional">>,false},{<<"requirement">>,<<"~> 1.0">>},{<<"repository">>,<<"hexpm">>}]},
                                  {<<"phoenix_html">>,[{<<"app">>,<<"phoenix_html">>},{<<"optional">>,true},{<<"requirement">>,<<">= 3.0.0 and < 5.0.0">>}]}]}.
            """);

        Assert.Equal(2, meta.Requirements.Count);
        var jason = meta.Requirements[0];
        Assert.Equal(("jason", "~> 1.0", false, "jason", "hexpm"), (jason.Name, jason.Requirement, jason.Optional, jason.App, jason.Repository));
        Assert.True(meta.Requirements[1].Optional);
        Assert.Null(meta.Requirements[1].Repository);

        // The index form drops the defaults hex.pm drops: app equal to the name, repository hexpm.
        var dep = jason.ToDependency();
        Assert.Equal(new HexDependency("jason", "~> 1.0"), dep);
        Assert.True(meta.Requirements[1].ToDependency().Optional);
    }

    [Fact]
    public void LegacyRequirementsShape_ListOfProplistsWithName_Parses()
    {
        var meta = HexPackageMetadata.Parse("""
            {<<"name">>,<<"demo">>}.
            {<<"version">>,<<"1.0.0">>}.
            {<<"requirements">>,[[{<<"name">>,<<"jason">>},{<<"app">>,<<"json_app">>},{<<"optional">>,false},{<<"requirement">>,<<"~> 1.0">>}]]}.
            """);

        var req = Assert.Single(meta.Requirements);
        Assert.Equal("jason", req.Name);
        Assert.Equal("json_app", req.App);
        Assert.Equal("json_app", req.ToDependency().App);
    }

    [Fact]
    public void MapShapedRequirements_Parses()
    {
        var meta = HexPackageMetadata.Parse("""
            {<<"name">>,<<"demo">>}.
            {<<"version">>,<<"1.0.0">>}.
            {<<"requirements">>,#{<<"jason">> => #{<<"app">> => <<"jason">>, <<"optional">> => true, <<"requirement">> => <<"~> 1.0">>}}}.
            """);

        var req = Assert.Single(meta.Requirements);
        Assert.Equal("~> 1.0", req.Requirement);
        Assert.True(req.Optional);
    }

    [Theory]
    [InlineData("{<<\"version\">>,<<\"1.0.0\">>}.", "missing name")]
    [InlineData("{<<\"name\">>,<<\"demo\">>}.", "missing version")]
    [InlineData("{<<\"name\">>,<<\"Demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.", "not a valid Hex package name")]
    [InlineData("{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0\">>}.", "not a valid SemVer")]
    [InlineData("{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n{<<\"app\">>,<<\"Bad App\">>}.", "OTP application name")]
    [InlineData("{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n{<<\"requirements\">>,[{<<\"jason\">>,[{<<\"app\">>,<<\"jason\">>}]}]}.", "no version requirement")]
    [InlineData("{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n{<<\"requirements\">>,<<\"nope\">>}.", "neither a list nor a map")]
    [InlineData("{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n{<<\"requirements\">>,[{<<\"Bad-Name\">>,[{<<\"requirement\">>,<<\"~> 1.0\">>}]}]}.", "invalid package")]
    [InlineData("this is not erlang", "not a readable Erlang term file")]
    public void InvalidMetadata_IsRefusedWithAReason(string text, string expectedFragment)
    {
        var ex = Assert.Throws<HexProtocolException>(() => HexPackageMetadata.Parse(text));
        Assert.Contains(expectedFragment, ex.Message);
    }

    [Theory]
    [InlineData("1.0.0", true)]
    [InlineData("0.0.1-rc.1", true)]
    [InlineData("2.0.0+build.5", true)]
    [InlineData("01.0.0", false)]
    [InlineData("1.0", false)]
    [InlineData("v1.0.0", false)]
    [InlineData("1.0.0\n", false)]
    public void VersionRule_IsStrictSemVer(string version, bool valid) =>
        Assert.Equal(valid, HexPackageMetadata.IsValidVersion(version));

    [Theory]
    [InlineData("decimal", true)]
    [InlineData("phoenix_html", true)]
    [InlineData("a1", true)]
    [InlineData("Decimal", false)]
    [InlineData("1abc", false)]
    [InlineData("has-dash", false)]
    [InlineData("has space", false)]
    [InlineData("name\n", false)]
    public void NameRule_MatchesHexPm(string name, bool valid) =>
        Assert.Equal(valid, HexPackageMetadata.IsValidName(name));

    [Fact]
    public void AppDefaultsToName_AndUnknownKeysAreIgnored()
    {
        var meta = HexPackageMetadata.Parse("""
            {<<"name">>,<<"demo">>}.
            {<<"version">>,<<"1.0.0">>}.
            {<<"maintainers">>,[<<"someone">>]}.
            {<<"extra">>,#{<<"x">> => 1}}.
            """);

        Assert.Equal("demo", meta.App);
        Assert.Empty(meta.Licenses);
        Assert.Empty(meta.Links);
        Assert.Null(meta.Elixir);
    }
}
