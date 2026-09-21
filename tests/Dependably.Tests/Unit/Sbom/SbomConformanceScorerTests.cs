using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Pins <see cref="SbomConformanceScorer"/>'s governing rule — a state may only reflect what the
/// SUPPLIER did or did not do — and the five-state model that rule requires: Present, Absent
/// (silent), ExplicitlyUnknown (SPDX's <c>NOASSERTION</c>/<c>NONE</c>, or dependably's own
/// vocabulary read back), NotApplicable (the format/version has no mechanism), and NotAssessed
/// (dependably's own parser or storage bound could not tell, or does not try). Pinned against
/// both hand-built scenarios per rule here and a real Syft-produced document in
/// <see cref="SbomConformanceScorerFixtureTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomConformanceScorerTests
{
    private static ProjectDocument Document(
        string format = "cyclonedx-json",
        string? specVersion = "1.6",
        string? toolName = null,
        string? toolVersion = null,
        string? lifecycles = null,
        string? signatureStatus = null,
        bool toolVersionExplicitlyUnknown = false) => new()
        {
            Id = "doc-1",
            Format = format,
            SpecVersion = specVersion,
            ToolName = toolName,
            ToolVersion = toolVersion,
            Lifecycles = lifecycles,
            SignatureStatus = signatureStatus,
            ToolVersionExplicitlyUnknown = toolVersionExplicitlyUnknown,
        };

    private static SbomComponentRow Component(
        string name = "left-pad",
        string? purl = "pkg:npm/left-pad@1.3.0",
        string? version = "1.3.0",
        string? versionRange = null,
        string? licenseSpdx = null,
        string? componentProducer = null,
        string? componentHashes = null,
        string? additionalIdentifiers = null,
        string? dependencyKind = null,
        string? explicitUnknownFields = null) => new()
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
            Purl = purl,
            Version = version,
            VersionRange = versionRange,
            LicenseSpdx = licenseSpdx,
            ComponentProducer = componentProducer,
            ComponentHashes = componentHashes,
            AdditionalIdentifiers = additionalIdentifiers,
            DependencyKind = dependencyKind,
            ExplicitUnknownFields = explicitUnknownFields,
        };

    private static SbomElementVerdict Find(SbomConformanceScorecard scorecard, string elementId) =>
        Assert.Single(scorecard.Elements, e => e.ElementId == elementId);

    // ── D1/D2/D6/D9: dependably does not parse these at ingest ─────────────────────────────────

    [Theory]
    [InlineData(SbomConformanceScorer.SbomAuthor)]
    [InlineData(SbomConformanceScorer.SbomAuthorSignature)]
    [InlineData(SbomConformanceScorer.SbomTimestamp)]
    [InlineData(SbomConformanceScorer.SbomVersion)]
    public void Score_MarksUnparsedMetadataElementsNotAssessed(string elementId)
    {
        var scorecard = SbomConformanceScorer.Score(Document(), []);
        Assert.Equal(SbomElementState.NotAssessed, Find(scorecard, elementId).State);
    }

    // ── D2: SBOM Author Signature — every arm discriminated, so an inversion cannot pass ────────

    [Fact]
    public void Score_MarksAuthorSignaturePresent_WhenVerified()
    {
        var scorecard = SbomConformanceScorer.Score(Document(signatureStatus: "verified"), []);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    [Fact]
    public void Score_MarksAuthorSignatureAbsent_WhenCryptographicallyInvalid()
    {
        // 'failed' is a cryptographically invalid signature — the supplier's own failure.
        var scorecard = SbomConformanceScorer.Score(Document(signatureStatus: "failed"), []);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    [Fact]
    public void Score_MarksAuthorSignatureAbsent_WhenUnsignedOnACycloneDxDocument()
    {
        var scorecard = SbomConformanceScorer.Score(Document(format: "cyclonedx-json", signatureStatus: "unsigned"), []);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    [Fact]
    public void Score_MarksAuthorSignatureNotAssessed_WhenUnanchored()
    {
        // 'unanchored' (SbomSignatureVerdict.UnanchoredStatus) is THIS REGISTRY's own trust-store
        // gap — no pinned anchor for the document's claimed keyId — never a claim the supplier
        // failed to sign, so it under-claims to NotAssessed rather than Absent.
        var scorecard = SbomConformanceScorer.Score(Document(signatureStatus: "unanchored"), []);
        Assert.Equal(SbomElementState.NotAssessed, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    [Fact]
    public void Score_MarksAuthorSignatureNotAssessed_WhenNull()
    {
        var scorecard = SbomConformanceScorer.Score(Document(signatureStatus: null), []);
        Assert.Equal(SbomElementState.NotAssessed, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    [Fact]
    public void Score_MarksAuthorSignatureNotApplicable_ForAnSpdxDocument_RegardlessOfPersistedStatus()
    {
        // SbomController's admission check persists 'unsigned' for EVERY non-CycloneDX upload
        // under warn/block (format-switching must not evade the policy — see
        // SbomAuthorSignatureIngestTests.SpdxDocument_UnderBlock_IsScoredAsUnsigned_NotExempt),
        // but SPDX defines no signature carrier at all, so the SCORE must read NotApplicable
        // regardless of what got persisted — the pattern ScoreGenerationContext already applies
        // to D5.
        var scorecard = SbomConformanceScorer.Score(
            Document(format: "spdx-json", specVersion: "SPDX-2.3", signatureStatus: "unsigned"), []);
        Assert.Equal(SbomElementState.NotApplicable, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    [Theory]
    [InlineData("verified", SbomElementState.Present)]
    [InlineData("failed", SbomElementState.Absent)]
    [InlineData("unsigned", SbomElementState.Absent)]
    [InlineData("unanchored", SbomElementState.NotAssessed)]
    [InlineData(null, SbomElementState.NotAssessed)]
    public void Score_DiscriminatesEveryD2Arm_TheInversionCannotPass(string? signatureStatus, SbomElementState expected)
    {
        // Every arm asserted against every OTHER arm's expected value in one theory: swapping any
        // two outcomes (the inversion this test exists to catch — Verified=>Absent,
        // Failed=>Present, Unsigned=>Present) fails at least one row.
        var scorecard = SbomConformanceScorer.Score(Document(signatureStatus: signatureStatus), []);
        Assert.Equal(expected, Find(scorecard, SbomConformanceScorer.SbomAuthorSignature).State);
    }

    // ── D3/D4: always present on a stored sbom row ──────────────────────────────────────────────

    [Fact]
    public void Score_MarksFormatNameAndFormatVersionPresent()
    {
        var scorecard = SbomConformanceScorer.Score(Document(), []);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomDataFormatName).State);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomDataFormatVersion).State);
    }

    // ── D5: Generation Context — format/version asymmetry, never a supplier verdict on a storage
    //        bound we cannot distinguish from genuine silence ─────────────────────────────────────

    [Fact]
    public void Score_MarksGenerationContextPresent_WhenCycloneDxDocumentDeclaresLifecycles()
    {
        var scorecard = SbomConformanceScorer.Score(Document(lifecycles: """[{"phase":"build"}]"""), []);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomGenerationContext).State);
    }

    [Fact]
    public void Score_MarksGenerationContextNotAssessed_WhenA15PlusCycloneDxDocumentHasNoStoredLifecycles()
    {
        // CycloneDxParser drops an over-length lifecycles array to NULL on the same bound that
        // turns a real assertion into silence, and project_documents carries no marker telling
        // "declared none" apart from "dropped for length" — so this must never read as Absent.
        var scorecard = SbomConformanceScorer.Score(Document(specVersion: "1.6", lifecycles: null), []);
        Assert.Equal(SbomElementState.NotAssessed, Find(scorecard, SbomConformanceScorer.SbomGenerationContext).State);
    }

    [Fact]
    public void Score_MarksGenerationContextNotApplicable_ForACycloneDx14Document()
    {
        // metadata.lifecycles is a CycloneDX 1.5+ field. A 1.4 document cannot carry it regardless
        // of supplier intent — a format-VERSION fact, not a gap.
        var scorecard = SbomConformanceScorer.Score(Document(specVersion: "1.4", lifecycles: null), []);
        Assert.Equal(SbomElementState.NotApplicable, Find(scorecard, SbomConformanceScorer.SbomGenerationContext).State);
    }

    [Fact]
    public void Score_MarksGenerationContextNotApplicable_ForAnSpdxDocument()
    {
        // SPDX 2.3 has no lifecycle-equivalent element — a structural format fact, never Absent.
        var scorecard = SbomConformanceScorer.Score(Document(format: "spdx-json", specVersion: "SPDX-2.3"), []);
        Assert.Equal(SbomElementState.NotApplicable, Find(scorecard, SbomConformanceScorer.SbomGenerationContext).State);
    }

    // ── D7/D8: Tool Name / Tool Version ─────────────────────────────────────────────────────────

    [Fact]
    public void Score_MarksToolNameAndVersionPresent_WhenBothAreNamed()
    {
        var scorecard = SbomConformanceScorer.Score(Document(toolName: "syft", toolVersion: "1.46.0"), []);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomToolName).State);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }

    [Fact]
    public void Score_MarksToolNameAbsentAndToolVersionNotApplicable_WhenNoToolIsNamedAtAll()
    {
        var scorecard = SbomConformanceScorer.Score(Document(), []);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.SbomToolName).State);
        // No tool named means D8 has no subject — distinct from a named tool that omitted its
        // own version, which reads Absent instead (next test).
        Assert.Equal(SbomElementState.NotApplicable, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }

    [Fact]
    public void Score_MarksToolVersionAbsent_WhenToolIsNamedButItsVersionIsNot()
    {
        var scorecard = SbomConformanceScorer.Score(Document(toolName: "syft", toolVersion: null), []);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }

    [Fact]
    public void Score_MarksToolVersionExplicitlyUnknown_WhenTheNamedToolsEntryExplicitlySaidSo()
    {
        // #706: dependably:tool-version-status=unknown, read back onto
        // ProjectDocument.ToolVersionExplicitlyUnknown — a dependably export re-ingested here must
        // read as the explicit P4b practice, not a silent D8 gap.
        var scorecard = SbomConformanceScorer.Score(
            Document(toolName: "cyclonedx-python", toolVersion: null, toolVersionExplicitlyUnknown: true), []);
        Assert.Equal(SbomElementState.ExplicitlyUnknown, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }

    [Fact]
    public void Score_IgnoresToolVersionExplicitlyUnknown_WhenNoToolIsNamedAtAll()
    {
        // The flag can never fire without a tool name (CycloneDxParser only sets it on the same
        // entry it read the name from), but the scorer's own precedence is pinned directly: no
        // subject for D8 still outranks the flag.
        var scorecard = SbomConformanceScorer.Score(
            Document(toolName: null, toolVersionExplicitlyUnknown: true), []);
        Assert.Equal(SbomElementState.NotApplicable, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }

    [Fact]
    public void Score_MarksToolVersionPresent_WhenARealVersionIsNamed_EvenIfTheMarkerAlsoFired()
    {
        // The marker and a real version are mutually exclusive on export (BuildToolsMetadata), so
        // a document asserting both is malformed input a real producer should not emit — but the
        // SCORER, not the parser, is where D8's real-value-wins precedence is actually enforced
        // (ScoreToolVersion checks ToolVersion before ToolVersionExplicitlyUnknown), so it is
        // pinned here directly rather than only inferred from CycloneDxParser's own extraction
        // test.
        var scorecard = SbomConformanceScorer.Score(
            Document(toolName: "syft", toolVersion: "1.46.0", toolVersionExplicitlyUnknown: true), []);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }

    // ── D10-D17: component rollups ──────────────────────────────────────────────────────────────

    [Fact]
    public void Score_RollsUpComponentProducer_CountingPresentExplicitUnknownAndAbsentSeparately()
    {
        var components = new[]
        {
            Component(componentProducer: "Example Org"),
            Component(componentProducer: null, explicitUnknownFields: """["producer"]"""),
            Component(componentProducer: null),
        };

        var scorecard = SbomConformanceScorer.Score(Document(), components);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentProducer);

        Assert.Equal(3, verdict.Total);
        Assert.Equal(1, verdict.PresentCount);
        Assert.Equal(1, verdict.ExplicitUnknownCount);
        Assert.Equal(1, verdict.AbsentCount);
        // A genuine silent absence survives in the count, so the rollup state is Absent even
        // though most of the set is accounted for.
        Assert.Equal(SbomElementState.Absent, verdict.State);
    }

    [Fact]
    public void Score_MarksProducerRollupPresent_WhenEveryComponentIsAccountedForEitherWay()
    {
        var components = new[]
        {
            Component(componentProducer: "Example Org"),
            Component(componentProducer: null, explicitUnknownFields: """["producer"]"""),
        };

        var scorecard = SbomConformanceScorer.Score(Document(), components);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentProducer);

        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Score_MarksComponentNamePresent_ForEveryStoredComponent()
    {
        var scorecard = SbomConformanceScorer.Score(Document(), [Component(), Component(name: "right-pad")]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentName);

        Assert.Equal(2, verdict.Total);
        Assert.Equal(2, verdict.PresentCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Score_CountsAVersionRangeAsPresent_NotAbsent()
    {
        var scorecard = SbomConformanceScorer.Score(
            Document(), [Component(version: null, versionRange: "^3.0.0 || ^4.0.0")]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentVersion);

        Assert.Equal(1, verdict.PresentCount);
        Assert.Equal(0, verdict.AbsentCount);
    }

    [Fact]
    public void Score_CountsNeitherVersionNorRange_AsAbsent_WhenTheDocumentNeverDemonstratedTheVocabulary()
    {
        // Silent absence, NOT dependably's own explicit-unknown readback (explicitUnknownFields
        // is null): the ordinary, unambiguous case, still Absent after #706's fix — only a
        // component whose SOURCE DOCUMENT explicitly marked this duty field unknown (next test)
        // reads differently.
        var scorecard = SbomConformanceScorer.Score(
            Document(), [Component(version: null, versionRange: null, explicitUnknownFields: null)]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentVersion);

        Assert.Equal(0, verdict.PresentCount);
        Assert.Equal(0, verdict.ExplicitUnknownCount);
        Assert.Equal(1, verdict.AbsentCount);
    }

    [Fact]
    public void Score_CountsNeitherVersionNorRange_AsExplicitlyUnknown_WhenDependablysOwnVersionStatusWasReadBack()
    {
        // #706: dependably:version-status=unknown, read back into
        // SbomExplicitUnknownFields.Version — a dependably export re-ingested here must not score
        // as a silent D12 gap.
        var scorecard = SbomConformanceScorer.Score(
            Document(),
            [Component(version: null, versionRange: null, explicitUnknownFields: """["version"]""")]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentVersion);

        Assert.Equal(0, verdict.PresentCount);
        Assert.Equal(1, verdict.ExplicitUnknownCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Score_CountsAnAdditionalIdentifierAsPresent_ForAPurlLessComponent()
    {
        var scorecard = SbomConformanceScorer.Score(
            Document(),
            [Component(purl: null, additionalIdentifiers: """[{"kind":"cpe","value":"cpe:2.3:a:x:x:1:*:*:*:*:*:*:*"}]""")]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentIdentifiers);

        Assert.Equal(1, verdict.PresentCount);
    }

    [Fact]
    public void Score_CountsNoPurlAndNoAdditionalIdentifier_AsAbsent_WhenTheDocumentNeverDemonstratedTheVocabulary()
    {
        // Silent absence, NOT dependably's own explicit-unknown readback — still Absent after
        // #706's fix (see the ComponentVersion twin above for the full reasoning).
        var scorecard = SbomConformanceScorer.Score(
            Document(), [Component(purl: null, additionalIdentifiers: null, explicitUnknownFields: null)]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentIdentifiers);

        Assert.Equal(0, verdict.ExplicitUnknownCount);
        Assert.Equal(1, verdict.AbsentCount);
    }

    [Fact]
    public void Score_CountsNoPurlAndNoAdditionalIdentifier_AsExplicitlyUnknown_WhenDependablysOwnIdentifierStatusWasReadBack()
    {
        // #706: dependably:identifier-status=unknown, read back into
        // SbomExplicitUnknownFields.Identifier.
        var scorecard = SbomConformanceScorer.Score(
            Document(),
            [Component(purl: null, additionalIdentifiers: null, explicitUnknownFields: """["identifier"]""")]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentIdentifiers);

        Assert.Equal(0, verdict.PresentCount);
        Assert.Equal(1, verdict.ExplicitUnknownCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Score_MirrorsHashValueAndHashAlgorithmFromTheSameColumn_AndNeverReadsNullAsAbsent()
    {
        // Neither parser carries a marker distinguishing "no hash asserted" from "dropped for
        // exceeding the length bound" — a NULL column must read NotAssessed, never Absent, until
        // that marker exists.
        var components = new[]
        {
            Component(componentHashes: """[{"alg":"SHA-256","content":"abc"}]"""),
            Component(componentHashes: null),
        };

        var scorecard = SbomConformanceScorer.Score(Document(), components);
        var value = Find(scorecard, SbomConformanceScorer.ComponentHashValue);
        var algorithm = Find(scorecard, SbomConformanceScorer.ComponentHashAlgorithm);

        Assert.Equal(1, value.PresentCount);
        Assert.Equal(0, value.AbsentCount);
        Assert.Equal(1, value.NotAssessedCount);
        Assert.Equal(SbomElementState.Present, value.State);
        Assert.Equal(value.PresentCount, algorithm.PresentCount);
        Assert.Equal(value.NotAssessedCount, algorithm.NotAssessedCount);
    }

    [Fact]
    public void Score_MarksHashValueNotAssessed_WhenEveryComponentHasNoStoredHash()
    {
        var scorecard = SbomConformanceScorer.Score(Document(), [Component(componentHashes: null)]);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentHashValue);

        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(1, verdict.NotAssessedCount);
        Assert.Equal(SbomElementState.NotAssessed, verdict.State);
    }

    [Fact]
    public void Score_RollsUpComponentLicense_CountingExplicitUnknownSeparatelyFromSilentAbsence()
    {
        var components = new[]
        {
            Component(licenseSpdx: "MIT"),
            Component(licenseSpdx: null, explicitUnknownFields: """["license"]"""),
            Component(licenseSpdx: null),
        };

        var scorecard = SbomConformanceScorer.Score(Document(format: "spdx-json"), components);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentLicense);

        Assert.Equal(1, verdict.PresentCount);
        Assert.Equal(1, verdict.ExplicitUnknownCount);
        Assert.Equal(1, verdict.AbsentCount);
    }

    [Fact]
    public void Score_CountsGraphUnknownDependencyKind_AsNotAssessed_NeverAsASupplierAbsence()
    {
        // graph-unknown is SbomDependencyGraph's own fallback for a root THIS REGISTRY'S OWN walk
        // could not reach — a routing limitation, not a claim the supplier declared nothing. Only
        // a component the graph never mentions at all (null) is a genuine, unexcused silence.
        var components = new[]
        {
            Component(dependencyKind: "direct"),
            Component(dependencyKind: "graph-unknown"),
            Component(dependencyKind: null),
        };

        var scorecard = SbomConformanceScorer.Score(Document(), components);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentDependencyRelationship);

        Assert.Equal(1, verdict.PresentCount);
        Assert.Equal(1, verdict.NotAssessedCount);
        Assert.Equal(1, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Absent, verdict.State);
    }

    [Fact]
    public void Score_MarksDependencyRelationshipNotAssessed_WhenEveryComponentIsGraphUnknown()
    {
        // The real Syft fixture's exact shape: DESCRIBES roots at the scanned directory, which
        // carries no DEPENDS_ON/DEPENDENCY_OF edge of its own, so the walk reaches nothing and
        // every component is graph-unknown. This registry's own root-resolution limitation must
        // not read as "the supplier declared no relationships".
        var components = new[] { Component(dependencyKind: "graph-unknown"), Component(dependencyKind: "graph-unknown") };
        var scorecard = SbomConformanceScorer.Score(Document(), components);
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentDependencyRelationship);

        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(2, verdict.NotAssessedCount);
        Assert.Equal(SbomElementState.NotAssessed, verdict.State);
    }

    // ── P2 Coverage — no minimum depth (the 2021 floor this practice replaces) ──────────────────

    [Fact]
    public void Score_MarksCoverageAbsent_ForAZeroComponentDocument()
    {
        var scorecard = SbomConformanceScorer.Score(Document(), []);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.Coverage).State);
    }

    [Fact]
    public void Score_MarksCoveragePresent_ForAFlatFullyDirectInventory_NoMinimumDepthIsRequired()
    {
        // CISA's 2026 Coverage practice names NO minimum depth — a genuinely flat application
        // whose every dependency is direct satisfies it exactly as well as a deep one. Scoring
        // this Absent would implement the 2021 "Depth" floor the cited clause abolished.
        var components = new[] { Component(dependencyKind: "direct"), Component(dependencyKind: "direct") };
        var scorecard = SbomConformanceScorer.Score(Document(), components);
        var verdict = Find(scorecard, SbomConformanceScorer.Coverage);

        Assert.Equal(2, verdict.PresentCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Score_MarksCoveragePresent_WhenAtLeastOneComponentIsClassifiedTransitive()
    {
        var components = new[] { Component(dependencyKind: "direct"), Component(dependencyKind: "transitive") };
        var scorecard = SbomConformanceScorer.Score(Document(), components);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.Coverage).State);
    }

    [Fact]
    public void Score_MarksCoverageNotAssessed_WhenEveryComponentIsGraphUnknown()
    {
        var components = new[] { Component(dependencyKind: "graph-unknown") };
        var scorecard = SbomConformanceScorer.Score(Document(), components);
        Assert.Equal(SbomElementState.NotAssessed, Find(scorecard, SbomConformanceScorer.Coverage).State);
    }

    [Fact]
    public void Score_MarksCoverageAbsent_WhenNoComponentHasAnyDeclaredRelationshipAtAll()
    {
        var components = new[] { Component(dependencyKind: null) };
        var scorecard = SbomConformanceScorer.Score(Document(), components);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.Coverage).State);
    }

    // ── P4 Explicit Unknowns ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Score_MarksExplicitUnknownsPresent_ForAFlawlessDocument_VacuouslySatisfyingP4a()
    {
        // P4a is conditional: "WHEN a required field is absent, state whether it is unknown or
        // withheld." A document with no unexcused Producer/Licence absence never triggers the
        // duty, so it is satisfied vacuously — regardless of format.
        var scorecard = SbomConformanceScorer.Score(
            Document(format: "cyclonedx-json"),
            [Component(componentProducer: "Example Org", licenseSpdx: "MIT")]);
        var verdict = Find(scorecard, SbomConformanceScorer.ExplicitUnknowns);

        Assert.Equal(SbomElementState.Present, verdict.State);
        Assert.Equal(0, verdict.AbsentCount);
    }

    [Fact]
    public void Score_MarksExplicitUnknownsNotApplicable_ForAPlainCycloneDxDocumentWithAGap()
    {
        // A gap exists (no producer, no licence) and the document never demonstrates ANY
        // dependably: vocabulary use — plain CycloneDX has no generic mechanism a third-party
        // producer could plausibly have used, so this is a format limitation, never Absent.
        var scorecard = SbomConformanceScorer.Score(
            Document(format: "cyclonedx-json"), [Component(componentProducer: null, licenseSpdx: null)]);
        Assert.Equal(SbomElementState.NotApplicable, Find(scorecard, SbomConformanceScorer.ExplicitUnknowns).State);
    }

    [Fact]
    public void Score_MarksExplicitUnknownsAbsent_ForACycloneDxDocumentThatDemonstratedTheVocabularyButNotEverywhere()
    {
        // Once a CycloneDX document demonstrates dependably's own vocabulary anywhere, it has
        // proven the mechanism was available to it — a REMAINING silent gap is then attributable
        // to the supplier the same way an unused NOASSERTION is.
        var components = new[]
        {
            Component(componentProducer: null, licenseSpdx: null, explicitUnknownFields: """["producer"]"""),
            Component(componentProducer: null, licenseSpdx: null),
        };
        var scorecard = SbomConformanceScorer.Score(Document(format: "cyclonedx-json"), components);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.ExplicitUnknowns).State);
    }

    [Fact]
    public void Score_MarksExplicitUnknownsAbsent_ForAnSpdxDocumentThatNeverUsedNoAssertion()
    {
        var scorecard = SbomConformanceScorer.Score(
            Document(format: "spdx-json"), [Component(componentProducer: null, licenseSpdx: null)]);
        Assert.Equal(SbomElementState.Absent, Find(scorecard, SbomConformanceScorer.ExplicitUnknowns).State);
    }

    [Fact]
    public void Score_MarksExplicitUnknownsPresent_ForAnSpdxDocumentThatUsedNoAssertionForEveryGap()
    {
        var scorecard = SbomConformanceScorer.Score(
            Document(format: "spdx-json"),
            [Component(componentProducer: null, licenseSpdx: null, explicitUnknownFields: """["producer","license"]""")]);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.ExplicitUnknowns).State);
    }

    // ── P5/P6 ────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Score_MarksFrequencyAndMachineProcessablePresent_ForAnyStoredDocument()
    {
        var scorecard = SbomConformanceScorer.Score(Document(), []);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.Frequency).State);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.MachineProcessable).State);
    }

    // ── Scorecard shape ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Score_EmitsExactlyOneVerdictPerElementInElementOrder_WithMatchingComponentTotal()
    {
        var components = new[] { Component(), Component(name: "right-pad") };
        var scorecard = SbomConformanceScorer.Score(Document(), components);

        Assert.Equal(SbomConformanceScorer.ElementOrder, scorecard.Elements.Select(e => e.ElementId));
        Assert.Equal(2, scorecard.ComponentTotal);
    }
}
