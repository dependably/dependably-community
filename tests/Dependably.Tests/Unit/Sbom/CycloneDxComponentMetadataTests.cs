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
    /// only one shape would leave half of a real inventory attributed to nobody. manufacturer is
    /// the last fallback, per CycloneDX's own schema documenting it as authors[]'s
    /// automated-creation analogue.
    /// </summary>
    [Theory]
    [InlineData("""{ "name": "x", "author": "Ada" }""", "Ada")]
    [InlineData("""{ "name": "x", "authors": [ { "name": "Ada" } ] }""", "Ada")]
    // publisher/supplier are a distinct CISA element (Component Producer) from Component Author,
    // so neither is EVER a fallback for Author — a component naming only an organization as its
    // supplier has no author.
    [InlineData("""{ "name": "x", "publisher": "Acme" }""", null)]
    [InlineData("""{ "name": "x", "supplier": { "name": "Acme" } }""", null)]
    // authors[] outranks the legacy string: it is the current shape, and a document carrying it
    // alongside a legacy string means the string is the stale copy.
    [InlineData("""{ "name": "x", "authors": [ { "name": "Ada" } ], "author": "stale" }""", "Ada")]
    [InlineData("""{ "name": "x", "author": "Ada", "publisher": "Acme" }""", "Ada")]
    // manufacturer.name is read ONLY when neither authors[] nor author named anyone.
    [InlineData("""{ "name": "x", "manufacturer": { "name": "Automated Builders Inc" } }""", "Automated Builders Inc")]
    [InlineData("""{ "name": "x", "author": "Ada", "manufacturer": { "name": "Automated Builders Inc" } }""", "Ada")]
    [InlineData(
        """{ "name": "x", "authors": [ { "name": "Ada" } ], "manufacturer": { "name": "Automated Builders Inc" } }""",
        "Ada")]
    public void ResolvesAuthorAcrossProducerShapes(string componentJson, string? expected) =>
        Assert.Equal(expected, ParseOne(componentJson).Author);

    /// <summary>
    /// D10 (Component Producer): <c>supplier.name</c> (present in the schema since CycloneDX 1.2)
    /// is preferred, falling back to the older <c>publisher</c> string for a producer that still
    /// only emits that; neither is ever derived from authors[]/author — a component naming a
    /// person has no producer — and <c>manufacturer</c> is NEVER read here (see
    /// <see cref="ManufacturerFeedsAuthorNeverProducer"/>).
    /// </summary>
    [Theory]
    [InlineData("""{ "name": "x", "publisher": "Acme" }""", "Acme")]
    [InlineData("""{ "name": "x", "supplier": { "name": "Acme" } }""", "Acme")]
    // supplier wins when a document carries both — the awkward, adversarial case, not the
    // representative one: the two name DIFFERENT organizations, so a fixture that just happened
    // to agree would prove nothing about precedence.
    [InlineData(
        """{ "name": "x", "supplier": { "name": "Modern Supplier Co" }, "publisher": "Legacy Publisher Inc" }""",
        "Modern Supplier Co")]
    [InlineData("""{ "name": "x", "author": "Ada" }""", null)]
    [InlineData("""{ "name": "x", "authors": [ { "name": "Ada" } ] }""", null)]
    [InlineData("""{ "name": "x", "manufacturer": { "name": "Acme" } }""", null)]
    public void ResolvesProducerAcrossSupplierAndPublisherShapes(string componentJson, string? expected) =>
        Assert.Equal(expected, ParseOne(componentJson).Producer);

    /// <summary>
    /// Adversarial twin for the producer/author split: a component whose supplier and authors[]
    /// NAME DIFFERENT ENTITIES must resolve a producer distinct from its author. A fixture where
    /// the two happen to be equal proves nothing — that is the exact shape the old collapsed
    /// column would also have satisfied.
    /// </summary>
    [Fact]
    public void ProducerAndAuthorAreIndependentWhenTheDocumentNamesDifferentEntities()
    {
        var component = ParseOne("""
            { "name": "x", "authors": [ { "name": "Ada Lovelace" } ], "supplier": { "name": "Acme Corp" } }
            """);

        Assert.Equal("Ada Lovelace", component.Author);
        Assert.Equal("Acme Corp", component.Producer);
        Assert.NotEqual(component.Author, component.Producer);
    }

    /// <summary>
    /// manufacturer and supplier are DIFFERENT CISA-recognized concepts (who created it vs. who
    /// supplied it) and CycloneDX keeps them apart the same way — this pins that a component
    /// naming BOTH, with different organizations, resolves manufacturer into Author and supplier
    /// into Producer rather than either bleeding into the other.
    /// </summary>
    [Fact]
    public void ManufacturerFeedsAuthorNeverProducer()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "manufacturer": { "name": "Automated Builders Inc" },
              "supplier": { "name": "Modern Supplier Co" }
            }
            """);

        Assert.Equal("Automated Builders Inc", component.Author);
        Assert.Equal("Modern Supplier Co", component.Producer);
    }

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
        Assert.Null(component.Producer);
        Assert.Null(component.Copyright);
        Assert.Null(component.Group);
        Assert.Null(component.WebsiteUrl);
        Assert.Null(component.HashesJson);
        Assert.Null(component.VersionRange);
        Assert.Null(component.IsExternal);
        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    // ── CISA X4/P4a read-back: a dependably-exported document, re-uploaded ─────────────────────

    [Fact]
    public void ReadsDependablyProducerStatusBackAsAnExplicitUnknownMarker()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "dependably:producer-status", "value": "unknown" } ]
            }
            """);

        Assert.Equal("""["producer"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void ReadsBothDependablyStatusPropertiesBackTogether()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [
                { "name": "dependably:producer-status", "value": "unknown" },
                { "name": "dependably:license-status", "value": "unknown" }
              ]
            }
            """);

        Assert.Equal("""["producer","license"]""", component.ExplicitUnknownFieldsJson);
    }

    // #706: two of the six dependably:*-status duty-field properties an export ever writes were
    // read back before this fix (producer/license); version-status/identifier-status were emitted
    // but silently dropped, so a dependably-exported document re-uploaded to another dependably
    // instance scored D12/D13 as silent gaps rather than the explicitly-unknown practice it
    // actually demonstrated.

    [Fact]
    public void ReadsDependablyVersionStatusBackAsAnExplicitUnknownMarker()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "dependably:version-status", "value": "unknown" } ]
            }
            """);

        Assert.Equal("""["version"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void ReadsDependablyIdentifierStatusBackAsAnExplicitUnknownMarker()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "dependably:identifier-status", "value": "unknown" } ]
            }
            """);

        Assert.Equal("""["identifier"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void ReadsAllFourDependablyStatusPropertiesBackTogether_InDeclarationOrder()
    {
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [
                { "name": "dependably:producer-status", "value": "unknown" },
                { "name": "dependably:license-status", "value": "unknown" },
                { "name": "dependably:version-status", "value": "unknown" },
                { "name": "dependably:identifier-status", "value": "unknown" }
              ]
            }
            """);

        Assert.Equal(
            """["producer","license","version","identifier"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void DoesNotReadDependablyHashOrToolVersionStatusBackAsAComponentExplicitUnknownMarker()
    {
        // hash-status is deliberately not tracked in this component-scoped vocabulary at all (see
        // SbomExplicitUnknownFields's class doc comment); tool-version-status is a document-level
        // property carried on the metadata.tools entry, not a component's own properties[] — see
        // CycloneDxDocumentToolVersionTests. Neither is a member of
        // CycloneDxParser.ExplicitUnknownPropertyNames, so a component-level occurrence of either
        // (a malformed document, or a producer misusing the name) must never be mistaken for one.
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [
                { "name": "dependably:hash-status", "value": "unknown" },
                { "name": "dependably:tool-version-status", "value": "unknown" }
              ]
            }
            """);

        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void IgnoresAnUnrecognisedPropertyValue_ForADependablyStatusProperty()
    {
        // Only "unknown"/"withheld" — DependablyExportProperties.AbsenceReason's own vocabulary —
        // are ever written by the exporter; anything else is not this registry's own marker.
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "dependably:producer-status", "value": "maybe" } ]
            }
            """);

        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void IgnoresAnyOtherProducersPropertyNames_NeverInventingAMechanismForPlainCycloneDx()
    {
        // A third-party property that happens to carry the string "unknown" must never be
        // mistaken for this registry's own vocabulary — only the two exact property names count.
        var component = ParseOne("""
            {
              "name": "x",
              "properties": [ { "name": "cdx:some-other-tool:status", "value": "unknown" } ]
            }
            """);

        Assert.Null(component.ExplicitUnknownFieldsJson);
    }
}
