using System.Text.Json;
using Dependably.Infrastructure.Sbom;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// SPDX 2.3 parsed into the same <see cref="CycloneDxComponent"/> / <see cref="CycloneDxDocument"/>
/// shape <see cref="CycloneDxParser"/> writes — see <see cref="SpdxParser"/>'s own doc comment for
/// why that is the whole point of the design. Field-level pinning lives here; the end-to-end
/// upload path and the CycloneDX/SPDX parity assertion live in
/// <c>Integration/SpdxIngestTests.cs</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SpdxParserTests
{
    private static string Document(string packagesJson, string extra = "") => $$"""
        {
          "spdxVersion": "SPDX-2.3",
          "dataLicense": "CC0-1.0",
          "SPDXID": "SPDXRef-DOCUMENT",
          "name": "doc",
          "documentNamespace": "https://example.com/spdx/doc",
          "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
          "packages": [ {{packagesJson}} ]
          {{extra}}
        }
        """;

    private static CycloneDxComponent ParseOne(string packageJson)
    {
        var parsed = SpdxParser.Parse(JsonDocument.Parse(Document(packageJson)).RootElement);
        return Assert.Single(parsed.Components);
    }

    [Fact]
    public void IsSpdx_IsTrueForAnSpdxVersionMarker()
    {
        var root = JsonDocument.Parse(Document("""{ "name": "x", "SPDXID": "SPDXRef-Package-x" }""")).RootElement;
        Assert.True(SpdxParser.IsSpdx(root));
    }

    [Fact]
    public void IsSpdx_IsFalseForACycloneDxDocument()
    {
        var root = JsonDocument.Parse("""{ "bomFormat": "CycloneDX", "specVersion": "1.6" }""").RootElement;
        Assert.False(SpdxParser.IsSpdx(root));
    }

    [Fact]
    public void Parse_RejectsASpdxVersionOutsideTheAcceptedSet()
    {
        string document = """
            {
              "spdxVersion": "SPDX-2.2",
              "SPDXID": "SPDXRef-DOCUMENT",
              "packages": []
            }
            """;

        var ex = Assert.Throws<SbomParseException>(
            () => SpdxParser.Parse(JsonDocument.Parse(document).RootElement));
        Assert.Equal(SbomParseFailure.UnsupportedSpecVersion, ex.Failure);
        Assert.Equal("SPDX-2.2", ex.Diagnostic);
    }

    [Fact]
    public void Parse_ReadsNameVersionAndPurlFromThePackageManagerExternalRef()
    {
        var component = ParseOne("""
            {
              "name": "left-pad",
              "SPDXID": "SPDXRef-Package-left-pad",
              "versionInfo": "1.3.0",
              "downloadLocation": "NOASSERTION",
              "externalRefs": [
                { "referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:left-pad:left-pad:1.3.0:*:*:*:*:*:*:*" },
                { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0" }
              ]
            }
            """);

        Assert.Equal("left-pad", component.Name);
        Assert.Equal("1.3.0", component.Version);
        Assert.Equal("pkg:npm/left-pad@1.3.0", component.Purl);
    }

    [Fact]
    public void Parse_ReadsDescriptionCopyrightAndHomepageAsWebsiteUrl()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x",
              "downloadLocation": "NOASSERTION",
              "description": "String padding to a specified length.",
              "copyrightText": "Copyright (c) 2014-2018 Ada Lovelace",
              "homepage": "https://example.com/left-pad"
            }
            """);

        Assert.Equal("String padding to a specified length.", component.Description);
        Assert.Equal("Copyright (c) 2014-2018 Ada Lovelace", component.Copyright);
        Assert.Equal("https://example.com/left-pad", component.WebsiteUrl);
    }

    [Fact]
    public void Parse_RecordsNoDescriptionCopyrightOrHomepageWhenUnasserted()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "copyrightText": "NOASSERTION", "homepage": "NOASSERTION"
            }
            """);

        Assert.Null(component.Description);
        Assert.Null(component.Copyright);
        Assert.Null(component.WebsiteUrl);
    }

    [Fact]
    public void Parse_SkipsAPackageWithNoName()
    {
        var parsed = SpdxParser.Parse(JsonDocument.Parse(
            Document("""{ "SPDXID": "SPDXRef-Package-noname", "downloadLocation": "NOASSERTION" }""")).RootElement);
        Assert.Empty(parsed.Components);
    }

    [Theory]
    [InlineData("Organization: Example Org", "Example Org")]
    [InlineData("Person: Ada Lovelace", "Ada Lovelace")]
    [InlineData("Organization: Example Org (ops@example.com)", "Example Org")]
    [InlineData("Person: Ada Lovelace (ada@example.com)", "Ada Lovelace")]
    [InlineData("NOASSERTION", null)]
    public void Parse_ReadsSupplierAsComponentProducer_StrippingTheEntityPrefix(string raw, string? expected)
    {
        var component = ParseOne($$"""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "supplier": "{{raw}}"
            }
            """);

        Assert.Equal(expected, component.Producer);
    }

    [Fact]
    public void Parse_ReadsOriginatorAsComponentAuthor_NeverCollapsingItIntoProducer()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "supplier": "Organization: Distributor Co",
              "originator": "Person: Ada Lovelace"
            }
            """);

        Assert.Equal("Distributor Co", component.Producer);
        Assert.Equal("Ada Lovelace", component.Author);
    }

    [Fact]
    public void Parse_PrefersLicenseConcludedOverDeclared()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseConcluded": "Apache-2.0", "licenseDeclared": "MIT"
            }
            """);

        Assert.Equal("Apache-2.0", component.LicenseSpdx);
    }

    [Fact]
    public void Parse_FallsBackToLicenseDeclaredWhenConcludedIsUnasserted()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT"
            }
            """);

        Assert.Equal("MIT", component.LicenseSpdx);
    }

    [Fact]
    public void Parse_RecordsNoLicenceWhenBothFieldsAreUnasserted()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseConcluded": "NOASSERTION", "licenseDeclared": "NONE"
            }
            """);

        Assert.Null(component.LicenseSpdx);
    }

    // ── CISA X4/P4a: explicit-unknown-vs-silent-absence (the #688 constraint) ──────────────────

    [Fact]
    public void Parse_RecordsExplicitUnknownForLicense_WhenBothFieldsAreExplicitlyUnasserted()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseConcluded": "NOASSERTION", "licenseDeclared": "NONE"
            }
            """);

        Assert.Null(component.LicenseSpdx);
        Assert.Equal("""["license"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_RecordsExplicitUnknownForLicense_WhenOnlyConcludedIsExplicitlyUnasserted()
    {
        // licenseDeclared is never mentioned at all — isolates concludedUnasserted from
        // declaredUnasserted, so a mutant that drops either half of the OR is caught.
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseConcluded": "NOASSERTION"
            }
            """);

        Assert.Null(component.LicenseSpdx);
        Assert.Equal("""["license"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_RecordsExplicitUnknownForLicense_WhenOnlyDeclaredIsExplicitlyUnasserted()
    {
        // licenseConcluded is never mentioned at all — isolates declaredUnasserted from
        // concludedUnasserted, the other half of the same OR.
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseDeclared": "NONE"
            }
            """);

        Assert.Null(component.LicenseSpdx);
        Assert.Equal("""["license"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_DoesNotRecordExplicitUnknownForLicense_WhenNeitherFieldWasMentionedAtAll()
    {
        // Silent absence: the document never wrote licenseConcluded or licenseDeclared at all,
        // which must read differently from a document that wrote NOASSERTION for them —
        // exactly the distinction #688's constraint exists to capture.
        var component = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION" }
            """);

        Assert.Null(component.LicenseSpdx);
        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_DoesNotRecordExplicitUnknownForLicense_WhenAConcreteValueWasResolved()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "licenseConcluded": "Apache-2.0"
            }
            """);

        Assert.Equal("Apache-2.0", component.LicenseSpdx);
        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_RecordsExplicitUnknownForProducer_WhenSupplierIsExplicitlyNoAssertion()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "supplier": "NOASSERTION"
            }
            """);

        Assert.Null(component.Producer);
        Assert.Equal("""["producer"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_DoesNotRecordExplicitUnknownForProducer_WhenSupplierWasNeverMentioned()
    {
        var component = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION" }
            """);

        Assert.Null(component.Producer);
        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_RecordsBothExplicitUnknownFields_WhenSupplierAndLicenceAreBothNoAssertion()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "supplier": "NOASSERTION",
              "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION"
            }
            """);

        Assert.Equal("""["producer","license"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_DoesNotRecordExplicitUnknownForAuthor_WhichIsNotAScoredDutyField()
    {
        // originator (Author) carries NOASSERTION the same way supplier does, but Component
        // Author is not one of CISA X4's "indicate unknown" duty fields, so the flag must never
        // fire for it.
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "originator": "NOASSERTION"
            }
            """);

        Assert.Null(component.Author);
        Assert.Null(component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void Parse_ReadsChecksumsIntoTheSameShapeCycloneDxHashesUse()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "checksums": [
                { "algorithm": "SHA256", "checksumValue": "abc123" },
                { "algorithm": "SHA1", "checksumValue": "def456" }
              ]
            }
            """);

        Assert.Equal(
            """[{"alg":"SHA256","content":"abc123"},{"alg":"SHA1","content":"def456"}]""",
            component.HashesJson);
    }

    [Fact]
    public void Parse_MapsDownloadLocationToDistributionUrlWhenItIsARealHttpUrl()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x",
              "downloadLocation": "https://example.com/x-1.0.0.tgz"
            }
            """);

        Assert.Equal("https://example.com/x-1.0.0.tgz", component.DistributionUrl);
    }

    [Fact]
    public void Parse_DropsANonHttpDownloadLocationRatherThanStoringIt()
    {
        var component = ParseOne("""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x",
              "downloadLocation": "git+https://example.com/x.git"
            }
            """);

        // git+https is not a URI scheme IsHttpUrl accepts; the field is dropped rather than
        // storing a value the component page would try to render as a plain http(s) link.
        Assert.Null(component.DistributionUrl);
    }

    [Theory]
    [InlineData("APPLICATION", "application")]
    [InlineData("FRAMEWORK", "framework")]
    [InlineData("LIBRARY", "library")]
    [InlineData("CONTAINER", "container")]
    [InlineData("OPERATING-SYSTEM", "operating-system")]
    [InlineData("DEVICE", "device")]
    [InlineData("FIRMWARE", "firmware")]
    [InlineData("FILE", "file")]
    // SPDX admits four purposes CycloneDX's closed component.type enum has no member for at all.
    // Passing any of them through (even lower-cased) makes every subsequent export of the
    // project version invalid CycloneDX — SbomExportService writes component_type verbatim with
    // no enum guard of its own. Unmapped reads as no assertion, not an invalid one.
    [InlineData("SOURCE", null)]
    [InlineData("ARCHIVE", null)]
    [InlineData("INSTALL", null)]
    [InlineData("OTHER", null)]
    // A purpose no SPDX 2.3 document may declare — future-proofing against the same "invent a
    // spelling that happens to collide with something" risk a bare lower-case would have had.
    [InlineData("SOMETHING-SPDX-4.0-INVENTS", null)]
    public void Parse_MapsPrimaryPackagePurposeOntoACycloneDxTypeOrNull(string purpose, string? expectedType)
    {
        var component = ParseOne($$"""
            {
              "name": "x", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
              "primaryPackagePurpose": "{{purpose}}"
            }
            """);

        Assert.Equal(expectedType, component.Type);
    }

    [Fact]
    public void Parse_ExcludesTheDescribedPackageFromComponentsAndUsesItAsRoot()
    {
        string document = """
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo-app",
              "documentNamespace": "https://example.com/spdx/demo-app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "documentDescribes": ["SPDXRef-Package-demo-app"],
              "packages": [
                { "name": "demo-app", "SPDXID": "SPDXRef-Package-demo-app", "versionInfo": "2.0.0", "downloadLocation": "NOASSERTION" },
                { "name": "left-pad", "SPDXID": "SPDXRef-Package-left-pad", "versionInfo": "1.3.0", "downloadLocation": "NOASSERTION" }
              ]
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);

        var component = Assert.Single(parsed.Components);
        Assert.Equal("left-pad", component.Name);
        Assert.NotNull(parsed.Root);
        Assert.Equal("demo-app", parsed.Root!.Name);
        Assert.Equal("2.0.0", parsed.Root.Version);
    }

    [Fact]
    public void Parse_ResolvesTheDescribedPackageFromADescribesRelationship_WhenDocumentDescribesIsAbsent()
    {
        string document = """
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo-app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "packages": [
                { "name": "demo-app", "SPDXID": "SPDXRef-Package-demo-app", "versionInfo": "2.0.0", "downloadLocation": "NOASSERTION" },
                { "name": "left-pad", "SPDXID": "SPDXRef-Package-left-pad", "versionInfo": "1.3.0", "downloadLocation": "NOASSERTION" }
              ],
              "relationships": [
                { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-demo-app", "relationshipType": "DESCRIBES" }
              ]
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);

        Assert.Equal("demo-app", parsed.Root!.Name);
        Assert.Equal("left-pad", Assert.Single(parsed.Components).Name);
    }

    [Theory]
    [InlineData("DEPENDS_ON", "SPDXRef-Package-demo-app", "SPDXRef-Package-left-pad")]
    [InlineData("DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    // The six scoped DEPENDENCY_OF forms SPDX 2.3 also defines carry the identical "is a
    // dependency of" semantics as the base DEPENDENCY_OF, only scoped to a build phase — each
    // reads as a genuine dependency edge, the same direction as the base form, not the six
    // unrelated relationship types ReadRelationships still leaves unmapped.
    [InlineData("BUILD_DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    [InlineData("RUNTIME_DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    [InlineData("DEV_DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    [InlineData("OPTIONAL_DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    [InlineData("PROVIDED_DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    [InlineData("TEST_DEPENDENCY_OF", "SPDXRef-Package-left-pad", "SPDXRef-Package-demo-app")]
    public void Parse_FoldsBothDependsOnAndItsInverseOntoTheSameParentToChildAdjacency(
        string relationshipType, string spdxElementId, string relatedSpdxElement)
    {
        string document = $$"""
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo-app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "documentDescribes": ["SPDXRef-Package-demo-app"],
              "packages": [
                { "name": "demo-app", "SPDXID": "SPDXRef-Package-demo-app", "versionInfo": "2.0.0", "downloadLocation": "NOASSERTION" },
                { "name": "left-pad", "SPDXID": "SPDXRef-Package-left-pad", "versionInfo": "1.3.0", "downloadLocation": "NOASSERTION" }
              ],
              "relationships": [
                { "spdxElementId": "{{spdxElementId}}", "relatedSpdxElement": "{{relatedSpdxElement}}", "relationshipType": "{{relationshipType}}" }
              ]
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);

        // Regardless of which relationship spelling the document used, the resolved adjacency
        // always reads "demo-app depends on left-pad" — the parent -> child direction
        // SbomDependencyGraph.Resolve walks from the root.
        var dependsOn = Assert.Single(parsed.Dependencies);
        Assert.Equal("SPDXRef-Package-demo-app", dependsOn.Key);
        Assert.Equal(new[] { "SPDXRef-Package-left-pad" }, dependsOn.Value);
    }

    [Fact]
    public void Parse_ReadsContainsIntoContainmentDeclared_NeverIntoTheDependencyGraph()
    {
        // A judgment call (see ReadContainedRefs's own doc comment): CONTAINS satisfies D17 the
        // same way DEPENDS_ON does — CISA's Relationship attribute is defined as inclusion, not
        // depth — because a container/OS-level SBOM whose relationships[] is entirely CONTAINS
        // (no DEPENDS_ON/DEPENDENCY_OF at all — exactly this shape) would otherwise leave every
        // component reading as though the document declared no relationship at all, which is
        // false: it declared exactly this. But it is read into ContainmentDeclared, a D17-only
        // signal — NEVER into the dependency graph itself (Dependencies stays empty here), so it
        // can never mint a false direct/transitive depth claim a containment edge never made.
        string document = """
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo-app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "packages": [
                { "name": "left-pad", "SPDXID": "SPDXRef-Package-left-pad", "versionInfo": "1.3.0", "downloadLocation": "NOASSERTION" }
              ],
              "relationships": [
                { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-left-pad", "relationshipType": "CONTAINS" }
              ]
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);

        Assert.Empty(parsed.Dependencies);
        Assert.True(Assert.Single(parsed.Components).ContainmentDeclared);
    }

    [Fact]
    public void Parse_NeverOverwritesAGenuineMultiHopDependsOnChainWithARootLevelContainsEdge()
    {
        // The hard case: the root CONTAINS libssl AND libcrypto directly (a container/OS scanner
        // commonly declares every held package as a root-level CONTAINS target), but the document
        // ALSO declares a genuine two-hop chain — app (the root) DEPENDS_ON libssl DEPENDS_ON
        // libcrypto. libcrypto is a declared TRANSITIVE dependency; the root's own CONTAINS edge
        // straight to it must never make it read as a direct one. Both get D17 credit via
        // ContainmentDeclared, but the DEPENDS_ON-family adjacency — the one SbomDependencyGraph's
        // BFS actually walks — must contain ONLY the real chain.
        string document = """
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "documentDescribes": ["SPDXRef-Package-app"],
              "packages": [
                { "name": "app", "SPDXID": "SPDXRef-Package-app", "downloadLocation": "NOASSERTION" },
                { "name": "libssl", "SPDXID": "SPDXRef-Package-libssl", "downloadLocation": "NOASSERTION" },
                { "name": "libcrypto", "SPDXID": "SPDXRef-Package-libcrypto", "downloadLocation": "NOASSERTION" }
              ],
              "relationships": [
                { "spdxElementId": "SPDXRef-Package-app", "relatedSpdxElement": "SPDXRef-Package-libssl", "relationshipType": "CONTAINS" },
                { "spdxElementId": "SPDXRef-Package-app", "relatedSpdxElement": "SPDXRef-Package-libcrypto", "relationshipType": "CONTAINS" },
                { "spdxElementId": "SPDXRef-Package-app", "relatedSpdxElement": "SPDXRef-Package-libssl", "relationshipType": "DEPENDS_ON" },
                { "spdxElementId": "SPDXRef-Package-libssl", "relatedSpdxElement": "SPDXRef-Package-libcrypto", "relationshipType": "DEPENDS_ON" }
              ]
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);

        // The dependency-graph adjacency has exactly the two real DEPENDS_ON edges — no
        // root-to-libcrypto shortcut, however directly the root's own CONTAINS edge names it.
        Assert.Equal(2, parsed.Dependencies.Count);
        Assert.Equal(new[] { "SPDXRef-Package-libssl" }, parsed.Dependencies["SPDXRef-Package-app"]);
        Assert.Equal(new[] { "SPDXRef-Package-libcrypto" }, parsed.Dependencies["SPDXRef-Package-libssl"]);

        var positions = SbomDependencyGraph.Resolve(parsed);
        Assert.Equal("direct", positions["SPDXRef-Package-libssl"].Kind);
        // The whole point: libcrypto is TWO hops from the root via the real chain, never
        // "direct" despite the root's own CONTAINS edge straight to it.
        Assert.Equal("transitive", positions["SPDXRef-Package-libcrypto"].Kind);

        // Both non-root components still get D17 credit via ContainmentDeclared, independent of
        // the graph — pinned directly rather than only inferred from the graph assertions above.
        Assert.All(parsed.Components, c => Assert.True(c.ContainmentDeclared));
    }

    [Fact]
    public void Parse_IgnoresOtherRelationshipTypesForTheDependencyGraph()
    {
        // DESCRIBES/GENERATED_FROM/etc. are not composition or dependency edges at all — folding
        // them in would not be the same judgment call CONTAINS is, it would be wrong.
        string document = """
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo-app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "packages": [
                { "name": "left-pad", "SPDXID": "SPDXRef-Package-left-pad", "versionInfo": "1.3.0", "downloadLocation": "NOASSERTION" }
              ],
              "relationships": [
                { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-left-pad", "relationshipType": "GENERATED_FROM" }
              ]
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);
        Assert.Empty(parsed.Dependencies);
    }

    [Theory]
    [InlineData("Tool: syft-1.46.0", "syft", "1.46.0")]
    [InlineData("Tool: cyclonedx-cli-0.28.1", "cyclonedx-cli", "0.28.1")]
    [InlineData("Tool: no-version-suffix", "no-version-suffix", null)]
    public void Parse_ReadsTheFirstToolCreatorAndSplitsItsNameFromItsVersion(
        string creator, string expectedName, string? expectedVersion)
    {
        string document = $$"""
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "doc",
              "creationInfo": { "creators": [ "Organization: Someone", "{{creator}}" ], "created": "2026-08-01T10:10:00Z" },
              "packages": []
            }
            """;

        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);
        Assert.Equal(expectedName, parsed.ToolName);
        Assert.Equal(expectedVersion, parsed.ToolVersion);
    }
}
