using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The line-level <c>Cargo.toml</c> readers (<see cref="CargoTomlReader"/>) shared by the licence
/// extractor and the publish-time coordinate cross-check. The scan must only ever surface keys from
/// the crate's own <c>[package]</c> table, and each line reader must refuse a value shape it does
/// not support rather than half-parse it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CargoTomlReaderTests
{
    [Theory]
    [InlineData("serde-1.0.0/Cargo.toml", true)]
    [InlineData("a/Cargo.toml", true)]
    [InlineData("Cargo.toml", false)]
    [InlineData("/Cargo.toml", false)]
    [InlineData("serde-1.0.0/vendor/Cargo.toml", false)]
    [InlineData("serde-1.0.0/Cargo.toml.orig", false)]
    [InlineData("serde-1.0.0/cargo.toml", false)]
    [InlineData("serde-1.0.0/", false)]
    public void IsRootCargoToml_matches_only_the_manifest_at_the_tarball_root(string entryName, bool expected) =>
        Assert.Equal(expected, CargoTomlReader.IsRootCargoToml(entryName));

    [Fact]
    public void ScanPackageTable_reports_only_string_keys_of_the_package_table()
    {
        const string text = """
            name = "outside-any-section"

            [package]
            # a comment line
            name = "serde"
            version = "1.0.0"   # trailing comment
            edition = 2021
            license = 'MIT'
            authors = ["A <a@example.com>", "B"]

            [package.metadata.docs.rs]
            name = "nested-table"

            [dependencies]
            license = "GPL-3.0"
            """;
        var seen = new List<string>();

        CargoTomlReader.ScanPackageTable(text, (key, value) => seen.Add($"{key}={value}"));

        Assert.Equal(new[] { "name=serde", "version=1.0.0" }, seen);
    }

    [Fact]
    public void ScanPackageTable_hands_package_string_arrays_to_the_array_callback()
    {
        const string text = """
            [package]
            name = "serde"
            authors = ["A <a@example.com>", "B"]

            [workspace]
            members = ["x", "y"]
            """;
        var keys = new List<string>();
        var arrays = new Dictionary<string, List<string>>();

        CargoTomlReader.ScanPackageTable(
            text,
            (key, value) => keys.Add($"{key}={value}"),
            (key, entries) => arrays[key] = entries);

        Assert.Equal("name=serde", Assert.Single(keys));
        Assert.Equal("authors", Assert.Single(arrays.Keys));
        Assert.Equal(new[] { "A <a@example.com>", "B" }, arrays["authors"]);
    }

    [Fact]
    public void ScanPackageTable_stops_at_a_malformed_section_header()
    {
        const string text = """
            [package]
            name = "serde"
            [broken
            version = "1.0.0"
            """;
        var seen = new List<string>();

        CargoTomlReader.ScanPackageTable(text, (key, value) => seen.Add($"{key}={value}"));

        Assert.Equal("name=serde", Assert.Single(seen));
    }

    [Fact]
    public void TryParseStringArrayAssignment_reads_a_single_line_array_and_drops_empty_entries()
    {
        bool parsed = CargoTomlReader.TryParseStringArrayAssignment(
            "keywords = ['serde', \"json\", \"\" ]", out string? key, out var entries);

        Assert.True(parsed);
        Assert.Equal("keywords", key);
        Assert.Equal(new[] { "serde", "json" }, entries);
    }

    [Theory]
    [InlineData("= [\"a\"]")]
    [InlineData("no assignment here")]
    [InlineData("keywords = \"serde\"")]
    [InlineData("keywords = [")]
    [InlineData("keywords = [\"a\",")]
    public void TryParseStringArrayAssignment_refuses_anything_but_a_single_line_array(string line)
    {
        bool parsed = CargoTomlReader.TryParseStringArrayAssignment(line, out string? key, out var entries);

        Assert.False(parsed);
        Assert.Null(key);
        Assert.Empty(entries);
    }

    [Theory]
    [InlineData("[package]", "package")]
    [InlineData("[ package ]", "package")]
    [InlineData("[package.metadata]", "package.metadata")]
    public void TryParseSectionHeader_extracts_the_section_name(string line, string expected)
    {
        bool parsed = CargoTomlReader.TryParseSectionHeader(line, out string? section);

        Assert.True(parsed);
        Assert.Equal(expected, section);
    }

    [Fact]
    public void TryParseSectionHeader_treats_an_unclosed_header_as_a_header_with_no_name()
    {
        bool parsed = CargoTomlReader.TryParseSectionHeader("[package", out string? section);

        Assert.True(parsed);
        Assert.Null(section);
    }

    [Theory]
    [InlineData("name = \"serde\"")]
    [InlineData("# [package]")]
    [InlineData("")]
    public void TryParseSectionHeader_rejects_non_header_lines(string line)
    {
        bool parsed = CargoTomlReader.TryParseSectionHeader(line, out string? section);

        Assert.False(parsed);
        Assert.Null(section);
    }

    [Theory]
    [InlineData("name = \"serde\"", "name", "serde")]
    [InlineData("name=\"serde\"", "name", "serde")]
    [InlineData("description = \"fast # not a comment\" # a comment", "description", "fast # not a comment")]
    [InlineData("readme = \"\"", "readme", "")]
    public void TryParseStringAssignment_reads_a_basic_string(string line, string expectedKey, string expectedValue)
    {
        bool parsed = CargoTomlReader.TryParseStringAssignment(line, out string? key, out string? value);

        Assert.True(parsed);
        Assert.Equal(expectedKey, key);
        Assert.Equal(expectedValue, value);
    }

    [Theory]
    [InlineData("license = 'MIT'")]
    [InlineData("edition = 2021")]
    [InlineData("authors = [\"A\"]")]
    [InlineData("name = \"unterminated")]
    [InlineData("= \"serde\"")]
    [InlineData("name")]
    public void TryParseStringAssignment_refuses_other_value_shapes(string line) =>
        Assert.False(CargoTomlReader.TryParseStringAssignment(line, out _, out _));

    [Theory]
    [InlineData("\"serde\"", "serde")]
    [InlineData("\"serde\" # comment", "serde")]
    [InlineData("\"\"", "")]
    [InlineData("\"", null)]
    [InlineData("'serde'", null)]
    [InlineData("serde", null)]
    [InlineData("", null)]
    public void UnquoteBasicString_returns_the_double_quoted_value_only(string value, string? expected) =>
        Assert.Equal(expected, CargoTomlReader.UnquoteBasicString(value));
}
