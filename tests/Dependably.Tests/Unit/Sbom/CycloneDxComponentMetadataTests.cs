using System.Text.Json;
using Dependably.Infrastructure.Sbom;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The component-presentation half of the CycloneDX parse: what a component entry says it is,
/// who wrote it, and where it lives.
///
/// <para>These fields are display-only, which is exactly why they are worth pinning: nothing
/// downstream fails when one is silently dropped, so a regression here is invisible until a
/// person opens a component panel and finds it empty. Each fact below fails if its field stops
/// being read, and the adversarial ones fail if a field is read too eagerly — a
/// <c>javascript:</c> reference that reaches an href, or a producer's prose stored unbounded.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class CycloneDxComponentMetadataTests
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

    [Fact]
    public void ReadsEveryPresentationFieldFromA16Component()
    {
        var component = ParseOne("""
            {
              "type": "library",
              "name": "left-pad",
              "version": "1.3.0",
              "group": "@scoped",
              "description": "String padding.",
              "copyright": "Copyright (c) 2016 Contributors",
              "authors": [ { "name": "Ada" }, { "name": "Grace" } ],
              "externalReferences": [
                { "type": "website", "url": "https://example.com/home" },
                { "type": "vcs", "url": "https://example.com/repo.git" },
                { "type": "issue-tracker", "url": "https://example.com/issues" },
                { "type": "distribution", "url": "https://example.com/dist.tgz" }
              ],
              "hashes": [ { "alg": "SHA-256", "content": "abc123" } ]
            }
            """);

        Assert.Equal("String padding.", component.Description);
        Assert.Equal("Copyright (c) 2016 Contributors", component.Copyright);
        Assert.Equal("@scoped", component.Group);
        // Several authors are joined rather than reduced to the first: dropping the rest would
        // misattribute the component to whoever the producer happened to list first.
        Assert.Equal("Ada, Grace", component.Author);
        Assert.Equal("https://example.com/home", component.WebsiteUrl);
        Assert.Equal("https://example.com/repo.git", component.VcsUrl);
        Assert.Equal("https://example.com/issues", component.IssueTrackerUrl);
        Assert.Equal("https://example.com/dist.tgz", component.DistributionUrl);
        Assert.Equal("""[{"alg":"SHA-256","content":"abc123"}]""", component.HashesJson);
    }

    /// <summary>
    /// cyclonedx-npm writes the 1.4-era <c>author</c> string while the .NET generator writes
    /// <c>authors[]</c>. Both producers publish into the same instance, so a parser that read
    /// only one shape would leave half of a real inventory attributed to nobody.
    /// </summary>
    [Theory]
    [InlineData("""{ "name": "x", "author": "Ada" }""", "Ada")]
    [InlineData("""{ "name": "x", "authors": [ { "name": "Ada" } ] }""", "Ada")]
    [InlineData("""{ "name": "x", "publisher": "Acme" }""", "Acme")]
    // authors[] outranks both: it is the current shape, and a document carrying it alongside a
    // legacy string means the string is the stale copy.
    [InlineData("""{ "name": "x", "authors": [ { "name": "Ada" } ], "author": "stale" }""", "Ada")]
    // publisher is the organization, so it answers only when no person is named.
    [InlineData("""{ "name": "x", "author": "Ada", "publisher": "Acme" }""", "Ada")]
    public void ResolvesAuthorAcrossProducerShapes(string componentJson, string expected) =>
        Assert.Equal(expected, ParseOne(componentJson).Author);

    [Fact]
    public void DropsExternalReferencesThatAreNotHttpUrls()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "externalReferences": [
                { "type": "website", "url": "javascript:alert(1)" },
                { "type": "vcs", "url": "/relative/path" },
                { "type": "issue-tracker", "url": "data:text/html,hi" }
              ]
            }
            """);

        // Every one of these reaches an href in the component panel. Filtering at ingest is what
        // makes that safe for every renderer at once rather than for whichever ones remembered.
        Assert.Null(component.WebsiteUrl);
        Assert.Null(component.VcsUrl);
        Assert.Null(component.IssueTrackerUrl);
    }

    [Fact]
    public void KeepsTheFirstReferenceOfARepeatedTypeAndIgnoresUnlinkedTypes()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "externalReferences": [
                { "type": "distribution", "url": "https://example.com/first.tgz" },
                { "type": "distribution", "url": "https://example.com/second.tgz" },
                { "type": "advisories", "url": "https://example.com/advisories" }
              ]
            }
            """);

        Assert.Equal("https://example.com/first.tgz", component.DistributionUrl);
        // A type with no column is not folded into another one; it survives in the stored blob.
        Assert.Null(component.WebsiteUrl);
    }

    private static CycloneDxComponent ParseOne17(string componentJson)
    {
        string document = $$"""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.7",
              "components": [ {{componentJson}} ]
            }
            """;
        var parsed = CycloneDxParser.Parse(JsonDocument.Parse(document).RootElement);
        return Assert.Single(parsed.Components);
    }

    [Fact]
    public void ReadsAVersionRangeComponentThatDeclaresNoVersion()
    {
        var component = ParseOne17("""
            {
              "type": "library",
              "name": "axios",
              "versionRange": "vers:npm/>=1.6.0|<2.0.0",
              "purl": "pkg:npm/axios"
            }
            """);

        // 1.7 admits versionRange INSTEAD of version, so a null version here is the document
        // being well-formed rather than a producer omitting a field.
        Assert.Equal("vers:npm/>=1.6.0|<2.0.0", component.VersionRange);
        Assert.Null(component.Version);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    public void ReadsIsExternalAsDeclared(string literal, bool expected)
    {
        var component = ParseOne17($$"""{ "name": "x", "isExternal": {{literal}} }""");

        Assert.Equal(expected, component.IsExternal);
    }

    [Fact]
    public void LeavesIsExternalNullWhenTheDocumentDoesNotDeclareIt()
    {
        // Null and false are different claims: every document below 1.7 is in the first group,
        // and collapsing them would assert "not external" about a component nothing examined.
        Assert.Null(ParseOne17("""{ "name": "x" }""").IsExternal);
        Assert.Null(ParseOne17("""{ "name": "x", "isExternal": "yes" }""").IsExternal);
    }

    [Fact]
    public void ReadsALicensesArrayThatMixesAnIdWithAnExpression()
    {
        var component = ParseOne17("""
            {
              "name": "Dapper",
              "licenses": [
                { "license": { "id": "Apache-2.0" } },
                { "expression": "MIT OR BSD-3-Clause" }
              ]
            }
            """);

        // 1.6 admitted only one form per array; 1.7 allows both in one. Each entry is read on its
        // own terms, so neither form is dropped for the other being present.
        Assert.Equal("Apache-2.0 OR MIT OR BSD-3-Clause", component.LicenseSpdx);
    }

    [Fact]
    public void KeepsAHashAlgorithmItDoesNotRecognise()
    {
        var component = ParseOne17("""
            { "name": "x", "hashes": [ { "alg": "Streebog-256", "content": "abc123" } ] }
            """);

        // The algorithm set is open and grew in 1.7. Nothing here is a trust input, so an
        // unrecognised algorithm round-trips rather than being filtered to nothing.
        Assert.Contains("Streebog-256", component.HashesJson);
    }

    [Fact]
    public void ClipsProseRatherThanRefusingTheDocument()
    {
        string longText = new('a', 5000);
        var component = ParseOne($$"""
            { "name": "x", "description": "{{longText}}", "copyright": "{{longText}}" }
            """);

        // A 50k-component document could otherwise widen every row without tripping the byte cap
        // that governs the document as a whole. Refusing would be worse: the field is display-only.
        Assert.Equal(1000, component.Description!.Length);
        Assert.Equal(400, component.Copyright!.Length);
        Assert.Equal(400, ParseOne17($$"""{ "name": "x", "versionRange": "{{longText}}" }""")
            .VersionRange!.Length);
    }

    [Fact]
    public void DropsAnOversizedHashSetWholeRatherThanEmittingTruncatedJson()
    {
        string entries = string.Join(",", Enumerable.Range(0, 200)
            .Select(i => $$"""{ "alg": "SHA-512", "content": "{{new string('f', 128)}}{{i}}" }"""));
        var component = ParseOne($$"""{ "name": "x", "hashes": [ {{entries}} ] }""");

        // The column is read back as JSON. Clipping would produce a value no reader can parse,
        // which is worse than a reader finding nothing.
        Assert.Null(component.HashesJson);
    }

    [Fact]
    public void LeavesEveryFieldNullWhenTheProducerOmitsThem()
    {
        var component = ParseOne("""{ "name": "bare", "version": "1.0.0" }""");

        Assert.Null(component.Description);
        Assert.Null(component.Author);
        Assert.Null(component.Copyright);
        Assert.Null(component.Group);
        Assert.Null(component.WebsiteUrl);
        Assert.Null(component.HashesJson);
        Assert.Null(component.VersionRange);
        Assert.Null(component.IsExternal);
    }
}
