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
}
