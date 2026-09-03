using System.Text.Json;
using Dependably.Infrastructure.Sbom;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The manifest dev-dependency marker: components[].properties[] entries from the CycloneDX
/// taxonomy (cdx:npm:package:development and its per-ecosystem siblings) parsed as true/false/
/// absent on <see cref="CycloneDxComponent.ManifestDevDeclared"/>.
///
/// <para>This is a lower-confidence signal than a reachability scanner's own verdict — see
/// <see cref="SbomIngestRepository"/> for how ingest keeps the two apart — but the parse itself
/// has to be right regardless: a producer's spelling that this parser fails to recognise is a
/// component that can never seed <c>dependency_scope</c> at all.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class CycloneDxManifestDevDeclaredTests
{
    private static CycloneDxComponent ParseOne(string componentJson)
    {
        string document = $$"""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "components": [ {{componentJson}} ]
            }
            """;
        var parsed = CycloneDxParser.Parse(JsonDocument.Parse(document).RootElement);
        return Assert.Single(parsed.Components);
    }

    [Theory]
    [InlineData("cdx:npm:package:development")]
    [InlineData("cdx:pypi:package:development")]
    [InlineData("cdx:gomod:package:development")]
    [InlineData("cdx:nuget:package:development")]
    public void ReadsTrueFromEveryTaxonomySpelling(string propertyName)
    {
        var component = ParseOne($$"""
            {
              "name": "x",
              "properties": [ { "name": "{{propertyName}}", "value": "true" } ]
            }
            """);

        Assert.Equal(true, component.ManifestDevDeclared);
    }

    [Fact]
    public void ReadsFalseAsARealNegativeNotAnAbsence()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "cdx:npm:package:development", "value": "false" } ]
            }
            """);

        Assert.Equal(false, component.ManifestDevDeclared);
    }

    [Fact]
    public void IsNullWhenNoTaxonomyPropertyIsPresent()
    {
        var component = ParseOne("""{ "name": "x" }""");

        Assert.Null(component.ManifestDevDeclared);
    }

    [Fact]
    public void IsNullWhenPropertiesArePresentButNoneMatchTheTaxonomy()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "cdx:npm:package:bundled", "value": "true" } ]
            }
            """);

        Assert.Null(component.ManifestDevDeclared);
    }

    // Value spelling a producer might reasonably vary casing on ("True", "TRUE") — must still
    // resolve, since a case-sensitive compare would silently drop a compliant producer's data.
    [Theory]
    [InlineData("True", true)]
    [InlineData("TRUE", true)]
    [InlineData("False", false)]
    [InlineData("FALSE", false)]
    public void MatchesTheValueCaseInsensitively(string value, bool expected)
    {
        var component = ParseOne($$"""
            {
              "name": "x",
              "properties": [ { "name": "cdx:npm:package:development", "value": "{{value}}" } ]
            }
            """);

        Assert.Equal(expected, component.ManifestDevDeclared);
    }

    // Neither "true" nor "false" — a producer's malformed value is silence, not a guess.
    [Fact]
    public void IsNullWhenTheValueIsNeitherTrueNorFalse()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "cdx:npm:package:development", "value": "yes" } ]
            }
            """);

        Assert.Null(component.ManifestDevDeclared);
    }

    // Two taxonomy entries on one component is malformed input; the first wins rather than being
    // reconciled, the same tolerance policy the parser uses everywhere else.
    [Fact]
    public void FirstMatchingPropertyWinsWhenMoreThanOneIsPresent()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [
                { "name": "cdx:npm:package:development", "value": "true" },
                { "name": "cdx:pypi:package:development", "value": "false" }
              ]
            }
            """);

        Assert.Equal(true, component.ManifestDevDeclared);
    }
}
