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

    // ── malformed and edge-case documents ────────────────────────────────────────────────────

    private static CycloneDxDocument ParseRaw(string document) =>
        SpdxParser.Parse(JsonDocument.Parse(document).RootElement);

    // A document with caller-chosen creationInfo/packages/trailing members; the trailing members
    // string must begin with a comma when non-empty.
    private static string Doc(string creationInfo, string packages, string trailing = "") =>
        "{\"spdxVersion\":\"SPDX-2.3\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"doc\"" +
        (creationInfo.Length == 0 ? "" : ",\"creationInfo\":" + creationInfo) +
        ",\"packages\":[" + packages + "]" + trailing + "}";

    [Theory]
    [InlineData("[]")]
    [InlineData("\"SPDX-2.3\"")]
    [InlineData("null")]
    public void Parse_RootThatIsNotAnObject_IsMalformed_AndNotRecognisedAsSpdx(string raw)
    {
        var ex = Assert.Throws<SbomParseException>(() => ParseRaw(raw));

        Assert.Equal(SbomParseFailure.Malformed, ex.Failure);
        Assert.False(SpdxParser.IsSpdx(JsonDocument.Parse(raw).RootElement));
    }

    [Theory]
    [InlineData("""{"SPDXID":"SPDXRef-DOCUMENT","packages":[]}""")]
    [InlineData("""{"spdxVersion":2.3,"packages":[]}""")]
    [InlineData("""{"spdxVersion":"   ","packages":[]}""")]
    public void Parse_MissingOrNonStringSpdxVersion_IsMalformed(string raw)
    {
        var ex = Assert.Throws<SbomParseException>(() => ParseRaw(raw));

        Assert.Equal(SbomParseFailure.Malformed, ex.Failure);
    }

    [Theory]
    [InlineData("SPDX-3.0", true)]
    [InlineData("SPDX-2.2", true)]
    [InlineData("spdx-2.3", false)]
    [InlineData("CycloneDX", false)]
    public void IsSpdx_MatchesTheSpdxPrefixCaseSensitively(string version, bool expected)
    {
        var root = JsonDocument.Parse("{\"spdxVersion\":\"" + version + "\"}").RootElement;

        Assert.Equal(expected, SpdxParser.IsSpdx(root));
    }

    [Fact]
    public void Parse_WithoutCreationInfo_HasNoTool()
    {
        var parsed = ParseRaw(Doc(creationInfo: "", packages: ""));

        Assert.Null(parsed.ToolName);
        Assert.Null(parsed.ToolVersion);
    }

    [Theory]
    [InlineData("""{"creators":["Organization: Acme", "Person: Jane"]}""", null, null)]
    [InlineData("""{"creators":[7, null, "Tool: trivy-0.50.0"]}""", "trivy", "0.50.0")]
    [InlineData("""{"creators":["Tool: noversion"]}""", "noversion", null)]
    [InlineData("""{"creators":["Tool: trailing-"]}""", "trailing-", null)]
    [InlineData("""{"creators":["Tool: my-tool-v2-beta"]}""", "my-tool-v2-beta", null)]
    [InlineData("""{"creators":["tool: syft-1.0"]}""", null, null)]
    [InlineData("""{"created":"2026-08-01T10:10:00Z"}""", null, null)]
    public void Parse_ToolCreator_IsTheFirstCaseSensitiveToolEntryWithADigitLedVersionSegment(
        string creationInfo, string? expectedName, string? expectedVersion)
    {
        var parsed = ParseRaw(Doc(creationInfo, packages: ""));

        Assert.Equal(expectedName, parsed.ToolName);
        Assert.Equal(expectedVersion, parsed.ToolVersion);
    }

    private const string TwoPackages =
        "{\"name\":\"subject\",\"SPDXID\":\"SPDXRef-subject\"},{\"name\":\"left-pad\",\"SPDXID\":\"SPDXRef-left-pad\"}";

    [Fact]
    public void Parse_DocumentDescribes_SkipsNonStringAndBlankEntriesToTheFirstRealOne()
    {
        var parsed = ParseRaw(Doc("", TwoPackages, ",\"documentDescribes\":[7,null,\"   \",\"SPDXRef-subject\"]"));

        Assert.Equal("subject", parsed.Root!.Name);
        Assert.Equal("left-pad", Assert.Single(parsed.Components).Name);
    }

    [Fact]
    public void Parse_DocumentDescribesWithOnlyUnusableEntries_FallsBackToTheDescribesRelationship()
    {
        var parsed = ParseRaw(Doc("", TwoPackages,
            ",\"documentDescribes\":[\"   \"],\"relationships\":[" +
            "{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relatedSpdxElement\":\"SPDXRef-subject\",\"relationshipType\":\"DESCRIBES\"}]"));

        Assert.Equal("subject", parsed.Root!.Name);
    }

    [Fact]
    public void Parse_DescribesRelationship_IgnoresOtherSubjectsMalformedEntriesAndTargetlessEdges()
    {
        var parsed = ParseRaw(Doc("", TwoPackages,
            ",\"relationships\":[" +
            "\"not-an-object\"," +
            "{\"spdxElementId\":\"SPDXRef-other-doc\",\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"DESCRIBES\"}," +
            "{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relationshipType\":\"DESCRIBES\"}," +
            "{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"CONTAINS\"}," +
            "{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relatedSpdxElement\":\"SPDXRef-subject\",\"relationshipType\":\"DESCRIBES\"}]"));

        Assert.Equal("subject", parsed.Root!.Name);
        Assert.Equal("left-pad", Assert.Single(parsed.Components).Name);
    }

    [Fact]
    public void Parse_DescribesRelationshipWithNoSourceElement_IsAccepted()
    {
        var parsed = ParseRaw(Doc("", TwoPackages,
            ",\"relationships\":[{\"relatedSpdxElement\":\"SPDXRef-subject\",\"relationshipType\":\"DESCRIBES\"}]"));

        Assert.Equal("subject", parsed.Root!.Name);
    }

    [Fact]
    public void Parse_NothingDescribed_LeavesEveryPackageAComponent()
    {
        var parsed = ParseRaw(Doc("", TwoPackages));

        Assert.Null(parsed.Root);
        Assert.Equal(2, parsed.Components.Count);
    }

    [Fact]
    public void Parse_SkipsNonObjectPackages()
    {
        var parsed = ParseRaw(Doc("", "7,\"left-pad\",null,{\"name\":\"left-pad\",\"SPDXID\":\"SPDXRef-left-pad\"}"));

        Assert.Equal("left-pad", Assert.Single(parsed.Components).Name);
    }

    [Fact]
    public void Parse_Purl_SkipsAnExternalRefWithoutALocatorAndOtherPackageManagerTypes()
    {
        var component = ParseOne("""
            {
              "name": "left-pad", "SPDXID": "SPDXRef-left-pad",
              "externalRefs": [
                { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl" },
                { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "npm", "referenceLocator": "left-pad@1.3.0" },
                { "referenceCategory": "OTHER", "referenceType": "purl", "referenceLocator": "pkg:npm/wrong@1" },
                { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0" },
                { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/second@2" }
              ]
            }
            """);

        Assert.Equal("pkg:npm/left-pad@1.3.0", component.Purl);
    }

    [Fact]
    public void Parse_AdditionalIdentifiers_CoverCpeSwhAndGitoid_AndDropEverythingElse()
    {
        string tooLong = "cpe:2.3:a:" + new string('x', 400);
        var component = ParseOne(
            "{\"name\":\"openssl\",\"SPDXID\":\"SPDXRef-openssl\",\"externalRefs\":[" +
            "{\"referenceCategory\":\"SECURITY\",\"referenceType\":\"cpe22Type\",\"referenceLocator\":\"cpe:/a:openssl:openssl:3.0.7\"}," +
            "{\"referenceCategory\":\"SECURITY\",\"referenceType\":\"cpe23Type\"}," +
            "{\"referenceCategory\":\"SECURITY\",\"referenceType\":\"cpe23Type\",\"referenceLocator\":\"" + tooLong + "\"}," +
            "{\"referenceCategory\":\"SECURITY\",\"referenceType\":\"advisory\",\"referenceLocator\":\"https://example.com/advisory\"}," +
            "{\"referenceCategory\":\"PERSISTENT-ID\",\"referenceType\":\"swh\",\"referenceLocator\":\"swh:1:cnt:abc\"}," +
            "{\"referenceCategory\":\"PERSISTENT-ID\",\"referenceType\":\"gitoid\",\"referenceLocator\":\"gitoid:blob:sha1:def\"}," +
            "{\"referenceCategory\":\"PERSISTENT-ID\",\"referenceType\":\"other\",\"referenceLocator\":\"ignored\"}]}");

        Assert.Equal(
            """[{"kind":"cpe","value":"cpe:/a:openssl:openssl:3.0.7"},{"kind":"swhid","value":"swh:1:cnt:abc"},{"kind":"omnibor","value":"gitoid:blob:sha1:def"}]""",
            component.AdditionalIdentifiersJson);
    }

    [Fact]
    public void Parse_EntityWithAnUnterminatedParenthetical_IsKeptWhole()
    {
        var component = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-x", "supplier": "Person: Jane (unterminated", "originator": "Acme Corp" }
            """);

        Assert.Equal("Jane (unterminated", component.Producer);
        Assert.Equal("Acme Corp", component.Author);
    }

    [Fact]
    public void Parse_ToolPrefixedOriginator_LosesThePrefix()
    {
        var component = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-x", "originator": "Tool: bazel-7.0.0" }
            """);

        Assert.Equal("bazel-7.0.0", component.Author);
    }

    [Fact]
    public void Parse_LinkedUrls_RequireHttpAndAreClipped()
    {
        string longUrl = "https://example.com/" + new string('a', 500);
        var ftp = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-x", "homepage": "ftp://example.com/x", "downloadLocation": "git+https://github.com/a/b.git" }
            """);
        Assert.Null(ftp.WebsiteUrl);
        Assert.Null(ftp.DistributionUrl);

        var plainHttp = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-x", "homepage": "http://example.com/x", "downloadLocation": "NONE" }
            """);
        Assert.Equal("http://example.com/x", plainHttp.WebsiteUrl);
        Assert.Null(plainHttp.DistributionUrl);

        var clipped = ParseOne("{\"name\":\"x\",\"SPDXID\":\"SPDXRef-x\",\"homepage\":\"" + longUrl + "\"}");
        Assert.Equal(longUrl[..400], clipped.WebsiteUrl);
    }

    [Fact]
    public void Parse_TextFields_AreClippedAtTheirBounds()
    {
        var component = ParseOne(
            "{\"name\":\"x\",\"SPDXID\":\"SPDXRef-x\",\"description\":\"" + new string('d', 1001) +
            "\",\"copyrightText\":\"" + new string('c', 401) + "\"}");

        Assert.Equal(1000, component.Description!.Length);
        Assert.Equal(400, component.Copyright!.Length);
    }

    [Fact]
    public void Parse_Checksums_DropEntriesMissingAnAlgorithmOrValue_AndOversizedSetsWhole()
    {
        var component = ParseOne("""
            { "name": "x", "SPDXID": "SPDXRef-x", "checksums": [
                { "algorithm": "SHA256", "checksumValue": "abc" }, { "algorithm": "SHA1" }, { "checksumValue": "zzz" } ] }
            """);
        Assert.Equal("""[{"alg":"SHA256","content":"abc"}]""", component.HashesJson);

        var noneValid = ParseOne("""{ "name": "x", "SPDXID": "SPDXRef-x", "checksums": [ { "algorithm": "SHA1" } ] }""");
        Assert.Null(noneValid.HashesJson);

        string many = string.Join(",", Enumerable.Range(0, 20).Select(i =>
            "{\"algorithm\":\"SHA512\",\"checksumValue\":\"" + new string('a', 128) + "\"}"));
        var oversized = ParseOne("{\"name\":\"x\",\"SPDXID\":\"SPDXRef-x\",\"checksums\":[" + many + "]}");
        Assert.Null(oversized.HashesJson);
    }

    [Fact]
    public void Parse_Relationships_BuildAdjacencyOnlyFromWellFormedDependencyEdges()
    {
        var parsed = ParseRaw(Doc("", TwoPackages + ",{\"name\":\"is-odd\",\"SPDXID\":\"SPDXRef-is-odd\"}",
            ",\"relationships\":[" +
            "\"not-an-object\"," +
            "{\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"DEPENDS_ON\"}," +
            "{\"spdxElementId\":\"SPDXRef-subject\",\"relationshipType\":\"DEPENDS_ON\"}," +
            "{\"spdxElementId\":\"SPDXRef-subject\",\"relatedSpdxElement\":\"SPDXRef-left-pad\"}," +
            "{\"spdxElementId\":\"SPDXRef-subject\",\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"GENERATED_FROM\"}," +
            "{\"spdxElementId\":\"SPDXRef-subject\",\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"DEPENDS_ON\"}," +
            "{\"spdxElementId\":\"SPDXRef-is-odd\",\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"BUILD_DEPENDENCY_OF\"}]"));

        Assert.Equal(2, parsed.Dependencies.Count);
        Assert.Equal(new[] { "SPDXRef-left-pad" }, parsed.Dependencies["SPDXRef-subject"]);
        Assert.Equal(new[] { "SPDXRef-is-odd" }, parsed.Dependencies["SPDXRef-left-pad"]);
    }

    [Theory]
    [InlineData("DEPENDENCY_OF")]
    [InlineData("BUILD_DEPENDENCY_OF")]
    [InlineData("RUNTIME_DEPENDENCY_OF")]
    [InlineData("DEV_DEPENDENCY_OF")]
    [InlineData("OPTIONAL_DEPENDENCY_OF")]
    [InlineData("PROVIDED_DEPENDENCY_OF")]
    [InlineData("TEST_DEPENDENCY_OF")]
    public void Parse_EveryDependencyOfForm_ReadsTheTargetAsParentAndTheSourceAsChild(string relationshipType)
    {
        var parsed = ParseRaw(Doc("", TwoPackages,
            ",\"relationships\":[{\"spdxElementId\":\"SPDXRef-left-pad\",\"relatedSpdxElement\":\"SPDXRef-subject\"," +
            "\"relationshipType\":\"" + relationshipType + "\"}]"));

        Assert.Equal(new[] { "SPDXRef-left-pad" }, Assert.Single(parsed.Dependencies).Value);
        Assert.Equal("SPDXRef-subject", Assert.Single(parsed.Dependencies).Key);
    }

    [Fact]
    public void Parse_ContainsEdges_IgnoreMalformedEntriesAndPackagesWithNoSpdxId()
    {
        var parsed = ParseRaw(Doc("", "{\"name\":\"anonymous\"},{\"name\":\"left-pad\",\"SPDXID\":\"SPDXRef-left-pad\"}",
            ",\"relationships\":[" +
            "7," +
            "{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relationshipType\":\"CONTAINS\"}," +
            "{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relatedSpdxElement\":\"SPDXRef-left-pad\",\"relationshipType\":\"CONTAINS\"}]"));

        Assert.False(parsed.Components.Single(c => c.Name == "anonymous").ContainmentDeclared);
        Assert.True(parsed.Components.Single(c => c.Name == "left-pad").ContainmentDeclared);
    }

    [Fact]
    public void Parse_PackageCountAtTheCeiling_IsAccepted_AndOneMoreIsRefused()
    {
        int ceiling = SbomDocumentLimits.MaxComponents;
        static string Packages(int count) => string.Join(",", Enumerable.Repeat("{\"name\":\"p\"}", count));

        Assert.Equal(ceiling, ParseRaw(Doc("", Packages(ceiling))).Components.Count);

        var ex = Assert.Throws<SbomParseException>(() => ParseRaw(Doc("", Packages(ceiling + 1))));
        Assert.Equal(SbomParseFailure.TooManyComponents, ex.Failure);
        Assert.Equal(ceiling.ToString(System.Globalization.CultureInfo.InvariantCulture), ex.Diagnostic);
    }
}
