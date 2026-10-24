using System.Text.Json;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Tests.Unit;

/// <summary>
/// The pure half of document ingest: purl canonicalization, the OpenVEX vocabulary mapping, the
/// dependency-graph walk, and the three parsers' tolerance rules. Each of these is a place where
/// a wrong answer is silent — a purl keyed two ways splits one package into two rows, and a
/// dropped vocabulary value turns a triage decision into an untriaged one — so they are pinned
/// here rather than only through the end-to-end path.
/// </summary>
public sealed class SbomDocumentParsingTests
{
    private static JsonElement Json(string raw) => JsonDocument.Parse(raw).RootElement;

    // ── purl keying ──────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("pkg:npm/lodash@4.17.21", "pkg:npm/lodash", "4.17.21")]
    [InlineData("pkg:npm/%40babel/core@7.24.7", "pkg:npm/@babel/core", "7.24.7")]
    [InlineData("pkg:pypi/Charset_Normalizer@2.1.1", "pkg:pypi/charset-normalizer", "2.1.1")]
    [InlineData("pkg:nuget/Newtonsoft.Json@12.0.3", "pkg:nuget/newtonsoft.json", "12.0.3")]
    [InlineData("pkg:maven/org.apache/commons-lang3@3.12.0", "pkg:maven/org.apache/commons-lang3", "3.12.0")]
    [InlineData("pkg:rpm/openssl@3.0.7?arch=x86_64", "pkg:rpm/openssl", "3.0.7")]
    [InlineData("pkg:golang/github.com/gin-gonic/gin@v1.9.1", "pkg:golang/github.com/gin-gonic/gin", "v1.9.1")]
    [InlineData("pkg:npm/lodash", "pkg:npm/lodash", null)]
    public void PurlKey_CanonicalizesAcrossTheSpellingsThirdPartiesUse(
        string purl, string expectedKey, string? expectedVersion)
    {
        var identity = SbomPurlKey.TryParse(purl);

        Assert.NotNull(identity);
        Assert.Equal(expectedKey, identity!.Key);
        Assert.Equal(expectedVersion, identity.Version);
    }

    [Fact]
    public void PurlKey_IsIdenticalWithAndWithoutQualifiersOrSubpath()
    {
        // The reachability scanner fingerprints a version-less purl and an SBOM writes a
        // qualified one; if these disagreed, every RPM statement would read as unmatched.
        string bare = SbomPurlKey.TryParse("pkg:rpm/openssl@3.0.7")!.Key;
        string qualified = SbomPurlKey.TryParse("pkg:rpm/openssl@3.0.7?arch=x86_64&distro=rhel")!.Key;
        string subpathed = SbomPurlKey.TryParse("pkg:rpm/openssl@3.0.7#/usr/lib")!.Key;

        Assert.Equal(bare, qualified);
        Assert.Equal(bare, subpathed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("lodash@1.0.0")]
    [InlineData("pkg:npm")]
    [InlineData("pkg:/lodash@1.0.0")]
    public void PurlKey_RefusesWhatIsNotAPurl(string candidate) =>
        Assert.Null(SbomPurlKey.TryParse(candidate));

    [Fact]
    public void PurlKey_PassesAnUnmappedTypeThroughLowercased()
    {
        // A component whose type this registry does not host is still inventory.
        var identity = SbomPurlKey.TryParse("pkg:SWIFT/Alamofire@5.8.0");

        Assert.NotNull(identity);
        Assert.Equal("swift", identity!.Ecosystem);
        Assert.Equal("pkg:swift/Alamofire", identity.Key);
    }

    // ── VEX vocabulary ───────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("not_affected", "not_affected")]
    [InlineData("affected", "exploitable")]
    [InlineData("fixed", "resolved")]
    [InlineData("under_investigation", "in_triage")]
    [InlineData("something_new", null)]
    [InlineData(null, null)]
    public void OpenVexStatus_MapsOntoTheColumnVocabulary(string? status, string? expected) =>
        Assert.Equal(expected, VexVocabulary.FromOpenVexStatus(status));

    [Theory]
    [InlineData("component_not_present", "code_not_present")]
    [InlineData("vulnerable_code_not_present", "code_not_present")]
    [InlineData("vulnerable_code_not_in_execute_path", "code_not_reachable")]
    [InlineData("vulnerable_code_cannot_be_controlled_by_adversary", "requires_configuration")]
    [InlineData("inline_mitigations_already_exist", "protected_by_mitigating_control")]
    [InlineData("invented_by_a_producer", null)]
    public void OpenVexJustification_MapsOntoTheColumnVocabulary(string justification, string? expected) =>
        Assert.Equal(expected, VexVocabulary.FromOpenVexJustification(justification));

    [Fact]
    public void VexVocabulary_DropsAValueTheColumnConstraintWouldReject()
    {
        // Storing it would fail the insert and lose the whole document over one producer's
        // spelling; dropping it loses one field of one statement.
        Assert.Null(VexVocabulary.NormalizeState("mitigated"));
        Assert.Equal("not_affected", VexVocabulary.NormalizeState("not_affected"));
        Assert.Null(VexVocabulary.NormalizeResponse("ignore"));
        Assert.Equal("will_not_fix", VexVocabulary.NormalizeResponse("will_not_fix"));
    }

    // ── CycloneDX parse ──────────────────────────────────────────────────────────────────────

    private const string MinimalBom = """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "metadata": {
            "tools": { "components": [ { "name": "syft", "version": "1.2.3" } ] },
            "component": { "type": "application", "bom-ref": "app@1", "name": "app", "version": "1" }
          },
          "components": [
            { "type": "library", "bom-ref": "a", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
              "scope": "required", "licenses": [ { "license": { "id": "MIT" } } ] },
            { "type": "library", "bom-ref": "b", "name": "b", "version": "2", "purl": "pkg:npm/b@2",
              "scope": "invented", "licenses": [ { "expression": "MIT" }, { "license": { "id": "Apache-2.0" } } ] },
            { "type": "library", "name": "no-purl", "version": "3" }
          ],
          "dependencies": [
            { "ref": "app@1", "dependsOn": [ "a" ] },
            { "ref": "a", "dependsOn": [ "b" ] },
            { "ref": "b", "dependsOn": [] }
          ]
        }
        """;

    [Fact]
    public void CycloneDx_ReadsInventoryToolingAndTheGraph()
    {
        var document = CycloneDxParser.Parse(Json(MinimalBom));

        Assert.Equal("1.6", document.SpecVersion);
        Assert.Equal("syft", document.ToolName);
        Assert.Equal("1.2.3", document.ToolVersion);
        Assert.Equal("application", document.Root!.Type);
        Assert.Equal(3, document.Components.Count);
        Assert.Equal(3, document.Dependencies.Count);
    }

    [Fact]
    public void CycloneDx_KeepsOnlyAScopeTheColumnAdmits()
    {
        var document = CycloneDxParser.Parse(Json(MinimalBom));

        Assert.Equal("required", document.Components[0].Scope);
        Assert.Null(document.Components[1].Scope);
    }

    [Fact]
    public void CycloneDx_FoldsSeveralDeclaredLicencesIntoOneExpression()
    {
        var document = CycloneDxParser.Parse(Json(MinimalBom));

        Assert.Equal("MIT", document.Components[0].LicenseSpdx);
        Assert.Equal("MIT OR Apache-2.0", document.Components[1].LicenseSpdx);
        Assert.Null(document.Components[2].LicenseSpdx);
    }

    [Fact]
    public void CycloneDx_ReadsBothShapesOfMetadataTools()
    {
        var arrayForm = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.4",
              "metadata": { "tools": [ { "vendor": "CycloneDX", "name": "cyclonedx-python", "version": "3.11.7" } ] },
              "components": []
            }
            """));

        Assert.Equal("cyclonedx-python", arrayForm.ToolName);
        Assert.Equal("3.11.7", arrayForm.ToolVersion);
    }

    // #706: dependably:tool-version-status=unknown is written on the ORIGINAL producing tool's own
    // metadata.tools entry (SbomExportService.BuildToolsMetadata), never on dependably's own — a
    // dependably export re-ingested here must read the marker back rather than scoring D8 as a
    // silent gap.

    [Fact]
    public void CycloneDx_ReadsToolVersionExplicitlyUnknown_FromTheArrayFormToolEntry()
    {
        var document = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.4",
              "metadata": {
                "tools": [
                  {
                    "name": "cyclonedx-python",
                    "properties": [ { "name": "dependably:tool-version-status", "value": "unknown" } ]
                  }
                ]
              },
              "components": []
            }
            """));

        Assert.Equal("cyclonedx-python", document.ToolName);
        Assert.Null(document.ToolVersion);
        Assert.True(document.ToolVersionExplicitlyUnknown);
    }

    [Fact]
    public void CycloneDx_ReadsToolVersionExplicitlyUnknown_FromTheObjectFormToolEntry()
    {
        var document = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "metadata": {
                "tools": {
                  "components": [
                    {
                      "name": "syft",
                      "properties": [ { "name": "dependably:tool-version-status", "value": "unknown" } ]
                    }
                  ]
                }
              },
              "components": []
            }
            """));

        Assert.Equal("syft", document.ToolName);
        Assert.Null(document.ToolVersion);
        Assert.True(document.ToolVersionExplicitlyUnknown);
    }

    [Fact]
    public void CycloneDx_LeavesToolVersionExplicitlyUnknownFalse_WhenTheToolSimplyOmittedAVersion()
    {
        // The ordinary, unambiguous silent-absence case: no dependably:tool-version-status
        // property at all — a third-party document that never demonstrated the vocabulary.
        var document = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "metadata": { "tools": { "components": [ { "name": "syft" } ] } },
              "components": []
            }
            """));

        Assert.Equal("syft", document.ToolName);
        Assert.Null(document.ToolVersion);
        Assert.False(document.ToolVersionExplicitlyUnknown);
    }

    [Fact]
    public void CycloneDx_LeavesToolVersionExplicitlyUnknownFalse_WhenAVersionIsActuallyNamed()
    {
        // MinimalBom's tool entry carries no properties[] at all — the ordinary, unambiguous case
        // (no marker, a real version) that leaves ToolVersionExplicitlyUnknown at its default.
        var document = CycloneDxParser.Parse(Json(MinimalBom));

        Assert.False(document.ToolVersionExplicitlyUnknown);
    }

    [Fact]
    public void CycloneDx_ExtractsBothToolVersionAndTheMarker_WhenADocumentAsymmetricallyCarriesBoth()
    {
        // The marker and a real version are mutually exclusive on export (BuildToolsMetadata), so
        // a document carrying both is malformed input a real producer should not emit — but this
        // parser reads defensively, and D8's actual real-version-wins precedence is enforced at
        // the SCORER (SbomConformanceScorer.ScoreToolVersion checks document.ToolVersion before
        // ToolVersionExplicitlyUnknown), not here. This pins only what THIS layer must still do
        // correctly: extract both facts as the document literally states them, verbatim, so the
        // scorer has the real values to arbitrate between.
        var document = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "metadata": {
                "tools": {
                  "components": [
                    {
                      "name": "syft",
                      "version": "1.46.0",
                      "properties": [ { "name": "dependably:tool-version-status", "value": "unknown" } ]
                    }
                  ]
                }
              },
              "components": []
            }
            """));

        Assert.Equal("syft", document.ToolName);
        Assert.Equal("1.46.0", document.ToolVersion);
        Assert.True(document.ToolVersionExplicitlyUnknown);
    }

    [Theory]
    [InlineData("1.4")]
    [InlineData("1.5")]
    [InlineData("1.6")]
    [InlineData("1.7")]
    public void CycloneDx_AcceptsEverySupportedSpecVersion(string specVersion)
    {
        string raw = $$"""{"bomFormat":"CycloneDX","specVersion":"{{specVersion}}","components":[]}""";

        Assert.Equal(specVersion, CycloneDxParser.Parse(Json(raw)).SpecVersion);
    }

    [Theory]
    [InlineData("1.3")]
    [InlineData("1.8")]
    [InlineData("2.0")]
    public void CycloneDx_RefusesASpecVersionOutsideTheSupportedRange(string specVersion)
    {
        string raw = $$"""{"bomFormat":"CycloneDX","specVersion":"{{specVersion}}","components":[]}""";

        var thrown = Assert.Throws<SbomParseException>(() => CycloneDxParser.Parse(Json(raw)));
        Assert.Equal(SbomParseFailure.UnsupportedSpecVersion, thrown.Failure);
        Assert.Equal(specVersion, thrown.Diagnostic);
    }

    [Fact]
    public void CycloneDx_RefusesADocumentThatIsNotACycloneDxBom()
    {
        var thrown = Assert.Throws<SbomParseException>(
            () => CycloneDxParser.Parse(Json("""{"version":"2.1.0","runs":[]}""")));

        Assert.Equal(SbomParseFailure.WrongDocumentKind, thrown.Failure);
    }

    [Fact]
    public void CycloneDx_SkipsAComponentWithNoName()
    {
        // name is the one mandatory component field; a row with none has no identity to merge on.
        var document = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "components": [ { "type": "library", "purl": "pkg:npm/x@1" }, { "type": "library", "name": "y" } ]
            }
            """));

        Assert.Equal("y", Assert.Single(document.Components).Name);
    }

    [Fact]
    public void CycloneDx_ReadsEmbeddedAnalysisStatements()
    {
        var document = CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [],
              "vulnerabilities": [
                { "id": "CVE-2021-1", "affects": [ { "ref": "pkg:npm/a@1" } ],
                  "analysis": { "state": "not_affected", "justification": "code_not_reachable",
                                "response": [ "will_not_fix" ], "detail": "unused" } }
              ]
            }
            """));

        var statement = Assert.Single(document.Statements);
        Assert.Equal("CVE-2021-1", statement.VulnId);
        Assert.Equal("pkg:npm/a@1", Assert.Single(statement.ProductRefs));
        Assert.Equal("not_affected", statement.State);
        Assert.Equal("will_not_fix", statement.Response);
    }

    // ── dependency graph ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void DependencyGraph_PlacesEachComponentByItsShortestRouteFromTheApplication()
    {
        var positions = SbomDependencyGraph.Resolve(CycloneDxParser.Parse(Json(MinimalBom)));

        // Keyed by bom-ref, but the path itself is written in purls — see
        // DependencyGraph_RecordsThePathAsPurlsWhenBomRefsAreOpaque for why.
        Assert.Equal("direct", positions["a"].Kind);
        Assert.Equal("""["pkg:npm/a@1"]""", positions["a"].PathJson);
        Assert.Equal("transitive", positions["b"].Kind);
        Assert.Equal("""["pkg:npm/a@1","pkg:npm/b@2"]""", positions["b"].PathJson);
    }

    [Fact]
    public void DependencyGraph_CallsAnUnplacedComponentUnknownRatherThanTransitive()
    {
        var positions = SbomDependencyGraph.Resolve(CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "metadata": { "component": { "type": "application", "bom-ref": "app@1", "name": "app", "version": "1" } },
              "components": [ { "type": "library", "bom-ref": "orphan", "name": "orphan", "version": "1" } ],
              "dependencies": [ { "ref": "app@1", "dependsOn": [] } ]
            }
            """)));

        Assert.Equal("graph-unknown", positions["orphan"].Kind);
        Assert.Null(positions["orphan"].PathJson);
    }

    [Fact]
    public void DependencyGraph_RecordsThePathAsPurlsWhenBomRefsAreOpaque()
    {
        // Maven and container scanners routinely emit bom-refs that are not purls. The stored path
        // has to survive that: it is read back by the export, which names components by purl, and
        // it outlives the document whose bom-refs are only meaningful inside it.
        var positions = SbomDependencyGraph.Resolve(CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "metadata": { "component": { "type": "application", "bom-ref": "root-0", "name": "app", "version": "1" } },
              "components": [
                { "type": "library", "bom-ref": "comp-1", "name": "eslint", "version": "8.57.0",
                  "purl": "pkg:npm/eslint@8.57.0" },
                { "type": "library", "bom-ref": "comp-2", "name": "minimist", "version": "1.2.5",
                  "purl": "pkg:npm/minimist@1.2.5" }
              ],
              "dependencies": [
                { "ref": "root-0", "dependsOn": [ "comp-1" ] },
                { "ref": "comp-1", "dependsOn": [ "comp-2" ] }
              ]
            }
            """)));

        Assert.Equal("direct", positions["comp-1"].Kind);
        Assert.Equal("transitive", positions["comp-2"].Kind);
        Assert.Equal("[\u0022pkg:npm/eslint@8.57.0\u0022]", positions["comp-1"].PathJson);
        Assert.Equal(
            "[\u0022pkg:npm/eslint@8.57.0\u0022,\u0022pkg:npm/minimist@1.2.5\u0022]",
            positions["comp-2"].PathJson);
        Assert.DoesNotContain("comp-", positions["comp-2"].PathJson);
    }

    [Fact]
    public void DependencyGraph_ClaimsNothingWhenTheDocumentDeclaredNoGraph()
    {
        var positions = SbomDependencyGraph.Resolve(CycloneDxParser.Parse(Json("""
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "components": [ { "type": "library", "bom-ref": "a", "name": "a", "version": "1" } ]
            }
            """)));

        Assert.Empty(positions);
    }

    // ── OpenVEX parse ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void OpenVex_IsDetectedByItsContextAndReadsBothIdSpellings()
    {
        string raw = """
            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "statements": [
                { "vulnerability": { "name": "CVE-1" }, "status": "not_affected",
                  "justification": "vulnerable_code_not_in_execute_path",
                  "products": [ { "@id": "pkg:npm/a@1" } ] },
                { "vulnerability": "CVE-2", "status": "affected",
                  "action_statement": "Upgrade.", "products": [ "pkg:npm/b@2" ] }
              ]
            }
            """;

        Assert.True(OpenVexParser.IsOpenVex(Json(raw)));
        var document = OpenVexParser.Parse(Json(raw));

        Assert.Equal(2, document.Statements.Count);
        Assert.Equal("CVE-1", document.Statements[0].VulnId);
        Assert.Equal("not_affected", document.Statements[0].State);
        Assert.Equal("code_not_reachable", document.Statements[0].Justification);
        Assert.Equal("exploitable", document.Statements[1].State);
        Assert.Equal("Upgrade.", document.Statements[1].Detail);
        Assert.Equal("pkg:npm/b@2", Assert.Single(document.Statements[1].ProductRefs));
    }

    [Fact]
    public void OpenVex_IsNotConfusedWithACycloneDxVex()
    {
        string cycloneDx = """{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[]}""";

        Assert.False(OpenVexParser.IsOpenVex(Json(cycloneDx)));
        Assert.True(CycloneDxParser.IsCycloneDx(Json(cycloneDx)));
    }

    // ── SARIF parse ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Sarif_ReadsTheReachabilityProducerContract()
    {
        var document = SarifParser.Parse(Json("""
            {
              "version": "2.1.0",
              "runs": [ {
                "tool": { "driver": { "name": "sbom-reach", "semanticVersion": "0.2.0" } },
                "results": [ {
                  "ruleId": "CVE-2021-44906",
                  "message": { "text": "minimist@1.2.5 is vulnerable." },
                  "partialFingerprints": { "sbomReach/v1": "abc" },
                  "suppressions": [ { "kind": "external", "justification": "Accepted VEX." } ],
                  "properties": {
                    "purl": "pkg:npm/minimist@1.2.5",
                    "reachability": "reachable", "confidence": "high",
                    "dependencyScope": "dev", "sbomScope": "required",
                    "dependencyKind": "transitive",
                    "dependencyPath": [ "pkg:npm/eslint@8.57.0", "pkg:npm/minimist@1.2.5" ],
                    "runtimePresent": true, "diagnostics": [ "x" ], "recommendation": "Upgrade.",
                    "security-severity": "9.8", "severityScoreOrigin": "asserted"
                  } } ] } ]
            }
            """));

        Assert.Equal("sbom-reach", document.ToolName);
        Assert.Equal("0.2.0", document.ToolVersion);
        var result = Assert.Single(document.Results);
        Assert.Equal("reachable", result.Reachability);
        Assert.Equal("high", result.Confidence);
        Assert.Equal("dev", result.DependencyScope);
        Assert.Equal("required", result.SbomScope);
        Assert.Equal("transitive", result.DependencyKind);
        Assert.Equal(2, result.DependencyPath.Count);
        Assert.Equal(9.8, result.SecuritySeverity);
        Assert.Equal("asserted", result.SeverityOrigin);
        Assert.Equal("abc", result.Fingerprint);
        Assert.True(result.Suppressed);
        Assert.Equal("Accepted VEX.", result.SuppressionJustification);
    }

    [Fact]
    public void Sarif_IgnoresTheRetiredMergedScopeKey()
    {
        // The producer split `scope` into dependencyScope and sbomScope. Reading the old key
        // would put a CycloneDX scope value into the dev/prod column, whose constraint rejects it.
        var document = SarifParser.Parse(Json("""
            {"version":"2.1.0","runs":[{"results":[
              {"ruleId":"CVE-1","properties":{"scope":"dev"}}]}]}
            """));

        var result = Assert.Single(document.Results);
        Assert.Null(result.DependencyScope);
        Assert.Null(result.SbomScope);
    }

    [Fact]
    public void Sarif_ToleratesAProducerCarryingNoneOfTheBags()
    {
        var document = SarifParser.Parse(Json("""
            {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
              {"ruleId":"js.audit.open-redirect","level":"warning",
               "message":{"text":"res.redirect receives user input."}}]}]}
            """));

        var result = Assert.Single(document.Results);
        Assert.Equal("js.audit.open-redirect", result.RuleId);
        Assert.Null(result.Purl);
        Assert.Null(result.Reachability);
        Assert.False(result.Suppressed);
        Assert.Empty(result.DependencyPath);
    }

    [Fact]
    public void Sarif_AcceptsSecuritySeverityAsABareNumber()
    {
        var document = SarifParser.Parse(Json("""
            {"version":"2.1.0","runs":[{"results":[
              {"ruleId":"CVE-1","properties":{"security-severity":7.5}}]}]}
            """));

        Assert.Equal(7.5, Assert.Single(document.Results).SecuritySeverity);
    }

    [Fact]
    public void Sarif_DropsAValueOutsideAColumnVocabulary()
    {
        var document = SarifParser.Parse(Json("""
            {"version":"2.1.0","runs":[{"results":[
              {"ruleId":"CVE-1","properties":{"reachability":"probably","confidence":"certain",
               "dependencyScope":"prod","dependencyKind":"peer"}}]}]}
            """));

        var result = Assert.Single(document.Results);
        Assert.Null(result.Reachability);
        Assert.Null(result.Confidence);
        Assert.Null(result.DependencyScope);
        Assert.Null(result.DependencyKind);
    }

    [Fact]
    public void Sarif_SkipsAResultWithNoRuleId()
    {
        var document = SarifParser.Parse(Json("""
            {"version":"2.1.0","runs":[{"results":[{"message":{"text":"no rule"}},{"ruleId":"CVE-1"}]}]}
            """));

        Assert.Equal("CVE-1", Assert.Single(document.Results).RuleId);
    }

    [Theory]
    [InlineData("2.0.0")]
    [InlineData("2.2.0")]
    public void Sarif_RefusesAVersionOtherThan210(string version)
    {
        string raw = $$"""{"version":"{{version}}","runs":[]}""";

        var thrown = Assert.Throws<SbomParseException>(() => SarifParser.Parse(Json(raw)));
        Assert.Equal(SbomParseFailure.UnsupportedSpecVersion, thrown.Failure);
    }

    [Fact]
    public void Sarif_RefusesADocumentThatIsNotASarifLog()
    {
        var thrown = Assert.Throws<SbomParseException>(
            () => SarifParser.Parse(Json("""{"bomFormat":"CycloneDX","specVersion":"1.6"}""")));

        Assert.Equal(SbomParseFailure.WrongDocumentKind, thrown.Failure);
    }

    // ── CycloneDX: malformed and edge-case documents ─────────────────────────────────────────

    private static CycloneDxDocument ParseBom(string componentsJson = "", string extra = "") =>
        CycloneDxParser.Parse(Json(
            "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[" + componentsJson + "]" + extra + "}"));

    private static CycloneDxComponent ParseComponent(string componentJson) =>
        Assert.Single(ParseBom(componentJson).Components);

    private static CycloneDxDocument ParseBomWithMetadata(string metadataJson) =>
        ParseBom(extra: ",\"metadata\":" + metadataJson);

    [Theory]
    [InlineData("[]")]
    [InlineData("\"CycloneDX\"")]
    [InlineData("null")]
    public void CycloneDx_RootThatIsNotAnObject_IsMalformedAndIsNotRecognised(string raw)
    {
        var thrown = Assert.Throws<SbomParseException>(() => CycloneDxParser.Parse(Json(raw)));

        Assert.Equal(SbomParseFailure.Malformed, thrown.Failure);
        Assert.False(CycloneDxParser.IsCycloneDx(Json(raw)));
    }

    [Theory]
    [InlineData("""{"bomFormat":"CycloneDX","components":[]}""")]
    [InlineData("""{"bomFormat":"CycloneDX","specVersion":1.6,"components":[]}""")]
    [InlineData("""{"bomFormat":"CycloneDX","specVersion":"  ","components":[]}""")]
    public void CycloneDx_MissingOrNonStringSpecVersion_IsMalformed(string raw)
    {
        var thrown = Assert.Throws<SbomParseException>(() => CycloneDxParser.Parse(Json(raw)));

        Assert.Equal(SbomParseFailure.Malformed, thrown.Failure);
    }

    [Theory]
    [InlineData("""{"tools":[]}""", null, null)]
    [InlineData("""{"tools":["not-an-object",{"name":"trivy","version":"0.50.0"}]}""", "trivy", "0.50.0")]
    [InlineData("""{"tools":"syft"}""", null, null)]
    [InlineData("""{"tools":{}}""", null, null)]
    [InlineData("""{"tools":{"components":[],"services":[{"name":"scanner","version":"2.1"}]}}""", "scanner", "2.1")]
    [InlineData("""{"tools":{"components":["x",{"name":"syft"}]}}""", "syft", null)]
    [InlineData("""{"tools":{"components":[{"version":"1.0"}],"services":[{"name":"later"}]}}""", null, "1.0")]
    [InlineData("""{"lifecycles":[]}""", null, null)]
    public void CycloneDx_ToolIsTheFirstObjectEntryOfWhicheverShapeTheProducerUsed(
        string metadataJson, string? expectedName, string? expectedVersion)
    {
        var document = ParseBomWithMetadata(metadataJson);

        Assert.Equal(expectedName, document.ToolName);
        Assert.Equal(expectedVersion, document.ToolVersion);
        Assert.False(document.ToolVersionExplicitlyUnknown);
    }

    [Theory]
    [InlineData("withheld", true)]
    [InlineData("unknown", true)]
    [InlineData("known", false)]
    public void CycloneDx_ToolVersionMarker_IsReadFromTheMatchingPropertyOnly(string value, bool expected)
    {
        string status = Dependably.Infrastructure.DependablyExportProperties.ToolVersionStatus;
        var document = ParseBomWithMetadata(
            "{\"tools\":[{\"name\":\"syft\",\"properties\":[" +
            "{\"value\":\"unknown\"}," +
            "{\"name\":\"" + status + "\"}," +
            "{\"name\":\"dependably:something-else\",\"value\":\"unknown\"}," +
            "{\"name\":\"" + status + "\",\"value\":\"" + value + "\"}]}]}");

        Assert.Equal(expected, document.ToolVersionExplicitlyUnknown);
    }

    [Fact]
    public void CycloneDx_SkipsNonObjectAndBlankNameComponents_KeepingTheRest()
    {
        var document = ParseBom("42, null, \"left-pad\", {\"name\":\"  \"}, {\"name\":\"left-pad\",\"version\":\"1.3.0\"}");

        var component = Assert.Single(document.Components);
        Assert.Equal("left-pad", component.Name);
        Assert.Equal("1.3.0", component.Version);
    }

    [Fact]
    public void CycloneDx_ClipsPresentationFieldsAtTheirBounds_ButNeverBelow()
    {
        string description = new('d', 1001);
        string text = new('t', 401);
        var component = ParseComponent(
            "{\"name\":\"lodash\",\"description\":\"" + description + "\",\"author\":\"" + text + "\"," +
            "\"copyright\":\"" + text + "\",\"group\":\"" + text + "\",\"versionRange\":\"" + text + "\"," +
            "\"publisher\":\"" + text + "\"}");

        Assert.Equal(1000, component.Description!.Length);
        Assert.Equal(400, component.Author!.Length);
        Assert.Equal(400, component.Copyright!.Length);
        Assert.Equal(400, component.Group!.Length);
        Assert.Equal(400, component.VersionRange!.Length);
        Assert.Equal(400, component.Producer!.Length);

        var atBound = ParseComponent("{\"name\":\"lodash\",\"description\":\"" + new string('d', 1000) + "\"}");
        Assert.Equal(1000, atBound.Description!.Length);
    }

    [Fact]
    public void CycloneDx_ExternalReferences_KeepOnlyTheFirstHttpLinkOfEachLinkedType()
    {
        var component = ParseComponent("""
            {
              "name": "lodash",
              "externalReferences": [
                { "type": "website", "url": "http://lodash.com" },
                { "type": "website", "url": "https://second.example" },
                { "type": "vcs", "url": "git+https://github.com/lodash/lodash.git" },
                { "type": "vcs", "url": "https://github.com/lodash/lodash" },
                { "type": "issue-tracker", "url": "javascript:alert(1)" },
                { "type": "issue-tracker", "url": "https://github.com/lodash/lodash/issues" },
                { "type": "distribution", "url": "/relative/path" },
                { "type": "distribution", "url": "data:text/html,x" },
                { "type": "documentation", "url": "https://docs.example" },
                { "type": "vcs" },
                { "url": "https://nowhere.example" }
              ]
            }
            """);

        Assert.Equal("http://lodash.com", component.WebsiteUrl);
        Assert.Equal("https://github.com/lodash/lodash", component.VcsUrl);
        Assert.Equal("https://github.com/lodash/lodash/issues", component.IssueTrackerUrl);
        Assert.Null(component.DistributionUrl);
    }

    [Fact]
    public void CycloneDx_ExternalReferenceUrl_IsClippedToTheTextBound()
    {
        string url = "https://example.com/" + new string('a', 500);
        var component = ParseComponent("{\"name\":\"x\",\"externalReferences\":[{\"type\":\"website\",\"url\":\"" + url + "\"}]}");

        Assert.Equal(url[..400], component.WebsiteUrl);
    }

    [Fact]
    public void CycloneDx_Hashes_DropEntriesMissingAnAlgorithmOrContent()
    {
        var component = ParseComponent("""
            { "name": "x", "hashes": [
                { "alg": "SHA-256", "content": "abc" }, { "alg": "SHA-1" }, { "content": "zzz" } ] }
            """);

        Assert.Equal("""[{"alg":"SHA-256","content":"abc"}]""", component.HashesJson);
        Assert.Null(ParseComponent("""{ "name": "x", "hashes": [ { "alg": "SHA-1" } ] }""").HashesJson);
    }

    [Fact]
    public void CycloneDx_HashSetTooLargeForTheColumn_IsDroppedWholeRatherThanTruncatedIntoInvalidJson()
    {
        string hashes = string.Join(",", Enumerable.Range(0, 20).Select(i =>
            "{\"alg\":\"SHA-512\",\"content\":\"" + new string((char)('a' + (i % 6)), 128) + "\"}"));

        var component = ParseComponent("{\"name\":\"x\",\"hashes\":[" + hashes + "]}");

        Assert.Null(component.HashesJson);
    }

    [Fact]
    public void CycloneDx_NameOnlyLicence_IsFlaggedNamedAndKeepsAnHttpUrl()
    {
        var component = ParseComponent("""
            { "name": "x", "licenses": [ "MIT", { "foo": 1 },
                { "license": { "id": "  ", "name": "Custom EULA", "url": "https://example.com/eula" } } ] }
            """);

        Assert.Equal("Custom EULA", component.LicenseSpdx);
        Assert.True(component.LicenseNamed);
        Assert.Equal("https://example.com/eula", component.LicenseUrl);
    }

    [Theory]
    [InlineData("""{ "license": { "name": "Custom EULA", "url": "javascript:alert(1)" } }""", "Custom EULA", true)]
    [InlineData("""{ "license": { "name": "Custom EULA" } }""", "Custom EULA", true)]
    [InlineData("""{ "license": { "id": "Apache-2.0", "name": "ignored" } }""", "Apache-2.0", false)]
    [InlineData("""{ "expression": "MIT OR Apache-2.0" }""", "MIT OR Apache-2.0", false)]
    public void CycloneDx_SingleLicenceEntry_NeverCarriesAUrlUnlessItIsANameWithAnHttpOne(
        string entry, string expectedSpdx, bool expectedNamed)
    {
        var component = ParseComponent("{\"name\":\"x\",\"licenses\":[" + entry + "]}");

        Assert.Equal(expectedSpdx, component.LicenseSpdx);
        Assert.Equal(expectedNamed, component.LicenseNamed);
        Assert.Null(component.LicenseUrl);
    }

    [Theory]
    [InlineData("""{ "license": { "name": "   " } }""")]
    [InlineData("""{ "expression": "   " }""")]
    [InlineData("""{ "license": 7 }""")]
    [InlineData("""7""")]
    public void CycloneDx_LicenceEntriesThatResolveToNothing_LeaveTheLicenceUnrecorded(string entry)
    {
        var component = ParseComponent("{\"name\":\"x\",\"licenses\":[" + entry + "]}");

        Assert.Null(component.LicenseSpdx);
        Assert.Null(component.LicenseNamed);
        Assert.Null(component.LicenseUrl);
    }

    [Fact]
    public void CycloneDx_SeveralLicenceEntries_AreFoldedWithOrAndNeverCarryANameOrUrl()
    {
        var duplicated = ParseComponent("""{ "name": "x", "licenses": [ {"expression":"MIT"}, {"expression":"MIT"} ] }""");
        Assert.Equal("MIT", duplicated.LicenseSpdx);
        Assert.False(duplicated.LicenseNamed);

        var nameThenId = ParseComponent("""
            { "name": "x", "licenses": [
                { "license": { "name": "Custom EULA", "url": "https://example.com/eula" } },
                { "license": { "id": "MIT" } } ] }
            """);
        Assert.Equal("Custom EULA OR MIT", nameThenId.LicenseSpdx);
        Assert.False(nameThenId.LicenseNamed);
        Assert.Null(nameThenId.LicenseUrl);
    }

    [Fact]
    public void CycloneDx_ManifestDevMarker_SkipsUnrecognisedPropertiesAndNonBooleanValues()
    {
        var declaredDev = ParseComponent("""
            { "name": "x", "properties": [
                { "value": "true" },
                { "name": "other:property", "value": "true" },
                { "name": "cdx:npm:package:development", "value": "maybe" },
                { "name": "cdx:pypi:package:development", "value": "FALSE" },
                { "name": "cdx:gomod:package:development", "value": "true" } ] }
            """);
        Assert.False(declaredDev.ManifestDevDeclared);

        var upperTrue = ParseComponent("""
            { "name": "x", "properties": [ { "name": "cdx:nuget:package:development", "value": "True" } ] }
            """);
        Assert.True(upperTrue.ManifestDevDeclared);

        var unknownOnly = ParseComponent("""
            { "name": "x", "properties": [ { "name": "cdx:npm:package:development", "value": "maybe" } ] }
            """);
        Assert.Null(unknownOnly.ManifestDevDeclared);
    }

    [Fact]
    public void CycloneDx_ExplicitUnknownMarkers_RequireANameAndAnUnknownOrWithheldValue_AndAreDeduplicated()
    {
        string producer = Dependably.Infrastructure.DependablyExportProperties.ProducerStatus;
        string license = Dependably.Infrastructure.DependablyExportProperties.LicenseStatus;
        var component = ParseComponent(
            "{\"name\":\"x\",\"properties\":[" +
            "{\"value\":\"unknown\"}," +
            "{\"name\":\"" + license + "\"}," +
            "{\"name\":\"" + license + "\",\"value\":\"known\"}," +
            "{\"name\":\"" + producer + "\",\"value\":\"withheld\"}," +
            "{\"name\":\"" + producer + "\",\"value\":\"unknown\"}]}");

        Assert.Equal("""["producer"]""", component.ExplicitUnknownFieldsJson);
    }

    [Fact]
    public void CycloneDx_AdditionalIdentifiers_IgnoreNonStringEntriesAndOverlongValues()
    {
        string tooLong = "swh:1:cnt:" + new string('a', 400);
        var component = ParseComponent(
            "{\"name\":\"x\",\"swhid\":[\"swh:1:cnt:abc\",7,null,\"" + tooLong + "\"],\"omniborId\":\"not-an-array\"," +
            "\"externalReferences\":[{\"type\":\"other\",\"url\":\"urn:uuid:123e4567-e89b-12d3-a456-426614174000\"}," +
            "{\"type\":\"other\",\"url\":\"https://example.com\"},{\"type\":\"other\"}]," +
            "\"pedigree\":{\"commits\":[{\"uid\":\"a1b2c3\"},{\"url\":\"https://example.com/c\"}]}}");

        Assert.Equal(
            """[{"kind":"swhid","value":"swh:1:cnt:abc"},{"kind":"commit-hash","value":"a1b2c3"},{"kind":"uuid","value":"urn:uuid:123e4567-e89b-12d3-a456-426614174000"}]""",
            component.AdditionalIdentifiersJson);
    }

    [Fact]
    public void CycloneDx_Lifecycles_KeepDefinedPhasesAndFreeFormNames_AndSkipEverythingElse()
    {
        var document = ParseBomWithMetadata("""
            { "lifecycles": [
                "build",
                { "phase": "build" },
                { "phase": "weird-phase", "name": "Custom Phase", "description": "desc" },
                { "name": "   " },
                { "description": "orphan" },
                { "phase": "operations" } ] }
            """);

        Assert.Equal(
            """[{"phase":"build"},{"name":"Custom Phase","description":"desc"},{"phase":"operations"}]""",
            document.LifecyclesJson);
    }

    [Fact]
    public void CycloneDx_Lifecycles_AreNullWhenAbsentEmptyOrTooLargeForTheColumn()
    {
        Assert.Null(ParseBom().LifecyclesJson);
        Assert.Null(ParseBomWithMetadata("""{ "component": { "name": "app" } }""").LifecyclesJson);
        Assert.Null(ParseBomWithMetadata("""{ "lifecycles": [ { "name": "  " } ] }""").LifecyclesJson);

        string many = string.Join(",", Enumerable.Range(0, 30).Select(i =>
            "{\"name\":\"" + new string('p', 100) + i + "\"}"));
        Assert.Null(ParseBomWithMetadata("{\"lifecycles\":[" + many + "]}").LifecyclesJson);
    }

    [Fact]
    public void CycloneDx_Lifecycles_ClipTheirTextFields()
    {
        string name = new('n', 450);
        string description = new('d', 1200);
        var document = ParseBomWithMetadata(
            "{\"lifecycles\":[{\"name\":\"" + name + "\",\"description\":\"" + description + "\"}]}");

        using var parsed = JsonDocument.Parse(document.LifecyclesJson!);
        var entry = parsed.RootElement[0];
        Assert.Equal(400, entry.GetProperty("name").GetString()!.Length);
        Assert.Equal(1000, entry.GetProperty("description").GetString()!.Length);
    }

    [Fact]
    public void CycloneDx_Dependencies_SkipMalformedEntriesAndNonStringTargets()
    {
        var document = ParseBom(extra: """
            ,"dependencies": [
                "x",
                { "dependsOn": [ "a" ] },
                { "ref": "   ", "dependsOn": [ "a" ] },
                { "ref": "a", "dependsOn": [ "b", 7, null, "c" ] },
                { "ref": "leaf" } ]
            """);

        Assert.Equal(2, document.Dependencies.Count);
        Assert.Equal(new[] { "b", "c" }, document.Dependencies["a"]);
        Assert.Empty(document.Dependencies["leaf"]);
    }

    [Fact]
    public void CycloneDx_Statements_SkipMalformedEntriesAndKeepOnlyUsableAffectsRefs()
    {
        var document = ParseBom(extra: """
            ,"vulnerabilities": [
                "x",
                { "affects": [ { "ref": "pkg:npm/a@1" } ] },
                { "id": "   " },
                { "id": "CVE-2024-1",
                  "affects": [ "str", { "ref": "  " }, { "ref": "pkg:npm/a@1" }, { "noref": 1 } ],
                  "analysis": { "state": "exploitable", "response": "update" } },
                { "id": "CVE-2024-2" } ]
            """);

        Assert.Equal(2, document.Statements.Count);
        var first = document.Statements[0];
        Assert.Equal("CVE-2024-1", first.VulnId);
        Assert.Equal("pkg:npm/a@1", Assert.Single(first.ProductRefs));
        Assert.Equal("exploitable", first.State);
        Assert.Equal("update", first.Response);
        Assert.Null(first.Justification);
        Assert.Null(first.Detail);

        var second = document.Statements[1];
        Assert.Equal("CVE-2024-2", second.VulnId);
        Assert.Empty(second.ProductRefs);
        Assert.Null(second.State);
        Assert.Null(second.Justification);
        Assert.Null(second.Response);
        Assert.Null(second.Detail);
    }

    private static string RepeatedComponents(int count) =>
        string.Join(",", Enumerable.Repeat("{\"name\":\"c\"}", count));

    [Fact]
    public void CycloneDx_ComponentCountAtTheCeiling_IsAccepted_AndOneMoreIsRefused()
    {
        int ceiling = SbomDocumentLimits.MaxComponents;

        Assert.Equal(ceiling, ParseBom(RepeatedComponents(ceiling)).Components.Count);

        var thrown = Assert.Throws<SbomParseException>(() => ParseBom(RepeatedComponents(ceiling + 1)));
        Assert.Equal(SbomParseFailure.TooManyComponents, thrown.Failure);
        Assert.Equal(ceiling.ToString(System.Globalization.CultureInfo.InvariantCulture), thrown.Diagnostic);
    }

    [Fact]
    public void CycloneDx_StatementCeiling_IsChargedPerNamedComponent()
    {
        int ceiling = SbomDocumentLimits.MaxComponentStatements;
        static string Vulnerability(int affects) =>
            ",\"vulnerabilities\":[{\"id\":\"CVE-2024-1\",\"affects\":[" +
            string.Join(",", Enumerable.Repeat("{\"ref\":\"a\"}", affects)) + "]}]";

        Assert.Single(ParseBom(extra: Vulnerability(ceiling)).Statements);

        var thrown = Assert.Throws<SbomParseException>(() => ParseBom(extra: Vulnerability(ceiling + 1)));
        Assert.Equal(SbomParseFailure.TooManyStatements, thrown.Failure);
        Assert.Equal(ceiling.ToString(System.Globalization.CultureInfo.InvariantCulture), thrown.Diagnostic);
    }

    // ── dependency graph: unrooted, renamed and cyclic graphs ────────────────────────────────

    [Fact]
    public void DependencyGraph_WithEdgesButNoRootComponent_PlacesEveryComponentAsUnknown()
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"a\",\"name\":\"a\",\"version\":\"1\"}",
            ",\"dependencies\":[{\"ref\":\"app\",\"dependsOn\":[\"a\"]}]"));

        Assert.Equal("graph-unknown", positions["a"].Kind);
        Assert.Null(positions["a"].PathJson);
    }

    [Fact]
    public void DependencyGraph_RootWithNeitherBomRefNorName_LeavesTheGraphUnrooted()
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"a\",\"name\":\"a\",\"version\":\"1\"}",
            ",\"metadata\":{\"component\":{\"type\":\"application\"}},\"dependencies\":[{\"ref\":\"app\",\"dependsOn\":[\"a\"]}]"));

        Assert.Equal("graph-unknown", positions["a"].Kind);
    }

    [Theory]
    [InlineData("""{"name":"app","version":"1.2.0"}""", "app@1.2.0")]
    [InlineData("""{"name":"app"}""", "app")]
    [InlineData("""{"bom-ref":"missing-from-graph","name":"app","version":"1.2.0"}""", "app@1.2.0")]
    public void DependencyGraph_RootNamedInTheGraphByNameAndVersion_IsStillFound(string rootJson, string graphRef)
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"a\",\"name\":\"a\",\"version\":\"1\"}",
            ",\"metadata\":{\"component\":" + rootJson + "},\"dependencies\":[{\"ref\":\"" + graphRef + "\",\"dependsOn\":[\"a\"]}]"));

        Assert.Equal("direct", positions["a"].Kind);
        Assert.Equal("""["a@1"]""", positions["a"].PathJson);
    }

    [Fact]
    public void DependencyGraph_RootBomRefAbsentFromTheGraphAndNoComposedMatch_PlacesEverythingAsUnknown()
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"a\",\"name\":\"a\",\"version\":\"1\"}",
            ",\"metadata\":{\"component\":{\"bom-ref\":\"root-0\",\"name\":\"app\",\"version\":\"9\"}}," +
            "\"dependencies\":[{\"ref\":\"somebody-else\",\"dependsOn\":[\"a\"]}]"));

        Assert.Equal("graph-unknown", positions["a"].Kind);
    }

    [Fact]
    public void DependencyGraph_CyclesAndDiamonds_TakeTheShortestRouteAndTerminate()
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"a\",\"name\":\"a\",\"version\":\"1\"}," +
            "{\"bom-ref\":\"b\",\"name\":\"b\",\"version\":\"2\"}," +
            "{\"bom-ref\":\"c\",\"name\":\"c\",\"version\":\"3\"}",
            ",\"metadata\":{\"component\":{\"bom-ref\":\"app\",\"name\":\"app\"}}," +
            "\"dependencies\":[" +
            "{\"ref\":\"app\",\"dependsOn\":[\"a\",\"b\"]}," +
            "{\"ref\":\"a\",\"dependsOn\":[\"b\",\"c\",\"app\"]}," +
            "{\"ref\":\"b\",\"dependsOn\":[\"a\"]}," +
            "{\"ref\":\"c\",\"dependsOn\":[]}]"));

        Assert.Equal("direct", positions["a"].Kind);
        Assert.Equal("direct", positions["b"].Kind);
        Assert.Equal("transitive", positions["c"].Kind);
        Assert.Equal("""["a@1","c@3"]""", positions["c"].PathJson);
    }

    [Fact]
    public void DependencyGraph_PathIdentities_FallBackFromPurlToNameAtVersionToName()
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"p\",\"name\":\"p\",\"version\":\"1\",\"purl\":\"pkg:npm/p@1\"}," +
            "{\"bom-ref\":\"v\",\"name\":\"versioned\",\"version\":\"2.0\"}," +
            "{\"bom-ref\":\"n\",\"name\":\"bare\"}," +
            "{\"bom-ref\":\"leaf\",\"name\":\"leaf\"}",
            ",\"metadata\":{\"component\":{\"bom-ref\":\"app\",\"name\":\"app\"}}," +
            "\"dependencies\":[{\"ref\":\"app\",\"dependsOn\":[\"p\"]},{\"ref\":\"p\",\"dependsOn\":[\"v\"]}," +
            "{\"ref\":\"v\",\"dependsOn\":[\"n\"]},{\"ref\":\"n\",\"dependsOn\":[\"leaf\"]}]"));

        Assert.Equal("""["pkg:npm/p@1","versioned@2.0","bare","leaf"]""", positions["leaf"].PathJson);
        Assert.Equal("transitive", positions["leaf"].Kind);
    }

    [Fact]
    public void DependencyGraph_UndeclaredRefsKeepTheirRawSpelling_AndComponentsWithNoRefAreOmitted()
    {
        var positions = SbomDependencyGraph.Resolve(ParseBom(
            "{\"bom-ref\":\"real\",\"name\":\"real\",\"version\":\"1\",\"purl\":\"pkg:npm/real@1\"}," +
            "{\"name\":\"anonymous\",\"version\":\"1\"}," +
            "{\"name\":\"by-purl\",\"purl\":\"pkg:npm/by-purl@3\"}",
            ",\"metadata\":{\"component\":{\"bom-ref\":\"app\",\"name\":\"app\"}}," +
            "\"dependencies\":[{\"ref\":\"app\",\"dependsOn\":[\"ghost\",\"pkg:npm/by-purl@3\"]}," +
            "{\"ref\":\"ghost\",\"dependsOn\":[\"real\"]}]"));

        Assert.Equal(2, positions.Count);
        Assert.DoesNotContain("anonymous", positions.Keys);
        Assert.Equal("""["ghost","pkg:npm/real@1"]""", positions["real"].PathJson);
        Assert.Equal("direct", positions["pkg:npm/by-purl@3"].Kind);
        Assert.Equal("""["pkg:npm/by-purl@3"]""", positions["pkg:npm/by-purl@3"].PathJson);
    }

    // ── OpenVEX: malformed and edge-case documents ───────────────────────────────────────────

    [Theory]
    [InlineData("[]")]
    [InlineData("\"https://openvex.dev/ns\"")]
    [InlineData("""{"statements":[]}""")]
    [InlineData("""{"@context":7}""")]
    [InlineData("""{"@context":"https://example.com/openvex"}""")]
    [InlineData("""{"@context":"HTTPS://OPENVEX.DEV/ns"}""")]
    public void OpenVex_DocumentWithoutTheOpenVexContext_IsNotRecognised_AndParseRefusesIt(string raw)
    {
        Assert.False(OpenVexParser.IsOpenVex(Json(raw)));

        var thrown = Assert.Throws<SbomParseException>(() => OpenVexParser.Parse(Json(raw)));
        Assert.Equal(SbomParseFailure.WrongDocumentKind, thrown.Failure);
    }

    [Fact]
    public void OpenVex_SkipsStatementsThatNameNoUsableVulnerability()
    {
        var document = OpenVexParser.Parse(Json("""
            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "tooling": "vexctl",
              "statements": [
                "not-an-object",
                { "status": "affected" },
                { "vulnerability": {} },
                { "vulnerability": { "name": "   " } },
                { "vulnerability": 7 },
                { "vulnerability": { "@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-9" }, "status": "fixed" }
              ]
            }
            """));

        Assert.Equal("vexctl", document.ToolName);
        var statement = Assert.Single(document.Statements);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-9", statement.VulnId);
        Assert.Equal("resolved", statement.State);
    }

    [Fact]
    public void OpenVex_ProductsAcceptStringsAndObjectsOfEitherSpelling_AndDropEverythingElse()
    {
        var document = OpenVexParser.Parse(Json("""
            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "statements": [ { "vulnerability": "CVE-2024-1", "status": "affected",
                "products": [
                  "pkg:npm/lodash@4.17.21",
                  "   ",
                  { "@id": "pkg:npm/left-pad@1.3.0" },
                  { "purl": "pkg:pypi/requests@2.31.0" },
                  { "@id": "  ", "purl": "pkg:pypi/flask@3.0.0" },
                  { "name": "no-identifier" },
                  42,
                  null ] } ]
            }
            """));

        Assert.Equal(
            new[] { "pkg:npm/lodash@4.17.21", "pkg:npm/left-pad@1.3.0", "pkg:pypi/requests@2.31.0", "pkg:pypi/flask@3.0.0" },
            Assert.Single(document.Statements).ProductRefs);
    }

    [Fact]
    public void OpenVex_DetailPrefersTheActionStatement_AndFallsBackToTheImpactStatement()
    {
        var document = OpenVexParser.Parse(Json("""
            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "statements": [
                { "vulnerability": "CVE-1", "status": "affected", "action_statement": "Upgrade.", "impact_statement": "Exposed." },
                { "vulnerability": "CVE-2", "status": "not_affected", "impact_statement": "Not reachable." },
                { "vulnerability": "CVE-3", "status": "unheard_of" }
              ]
            }
            """));

        Assert.Equal("Upgrade.", document.Statements[0].Detail);
        Assert.Equal("Not reachable.", document.Statements[1].Detail);
        Assert.Null(document.Statements[2].Detail);
        Assert.Null(document.Statements[2].State);
        Assert.Null(document.ToolName);
    }

    private static OpenVexDocument ParseVex(IEnumerable<string> statements) =>
        OpenVexParser.Parse(Json(
            "{\"@context\":\"https://openvex.dev/ns/v0.2.0\",\"statements\":[" + string.Join(",", statements) + "]}"));

    [Fact]
    public void OpenVex_StatementCeiling_ChargesOnePerProductAndOnePerProductlessStatement()
    {
        int ceiling = SbomDocumentLimits.MaxComponentStatements;

        Assert.Equal(ceiling, ParseVex(Enumerable.Repeat("{\"vulnerability\":\"CVE-1\"}", ceiling)).Statements.Count);

        var tooManyStatements = Assert.Throws<SbomParseException>(
            () => ParseVex(Enumerable.Repeat("{\"vulnerability\":\"CVE-1\"}", ceiling + 1)));
        Assert.Equal(SbomParseFailure.TooManyStatements, tooManyStatements.Failure);
        Assert.Equal(ceiling.ToString(System.Globalization.CultureInfo.InvariantCulture), tooManyStatements.Diagnostic);

        string products = string.Join(",", Enumerable.Repeat("\"pkg:npm/a@1\"", ceiling + 1));
        var tooManyProducts = Assert.Throws<SbomParseException>(
            () => ParseVex(new[] { "{\"vulnerability\":\"CVE-1\",\"products\":[" + products + "]}" }));
        Assert.Equal(SbomParseFailure.TooManyStatements, tooManyProducts.Failure);
    }
}
