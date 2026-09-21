using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Scores <c>spdx-2.3-npm-syft.json</c> — the checked-in fixture that is verbatim <c>syft dir:.</c>
/// output (Anchore Syft 1.46.0), not a hand-built document — through the real
/// <see cref="SpdxParser"/>, the real <see cref="SbomDependencyGraph"/>, and
/// <see cref="SbomConformanceScorer"/>. Field-by-field rule pinning against synthetic scenarios
/// lives in <see cref="SbomConformanceScorerTests"/>; this file exists to check the three
/// collaborate correctly against a document dependably did not author, and asserts specific named
/// elements rather than a total, per the brief that authorized this class.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomConformanceScorerFixtureTests
{
    private static SbomConformanceScorecard ScoreFixture()
    {
        string path = Path.Combine(FixtureManifest.SbomFixturesRoot, "spdx-2.3-npm-syft.json");
        var root = JsonDocument.Parse(File.ReadAllText(path)).RootElement;
        var parsed = SpdxParser.Parse(root);
        var positions = SbomDependencyGraph.Resolve(parsed);

        var components = parsed.Components.Select(c =>
        {
            string? reference = c.BomRef ?? c.Purl;
            var position = reference is not null && positions.TryGetValue(reference, out var found)
                ? found
                : new SbomGraphPosition(null, null);
            return new SbomComponentRow
            {
                Id = reference ?? c.Name,
                Name = c.Name,
                Purl = c.Purl,
                Version = c.Version,
                VersionRange = c.VersionRange,
                LicenseSpdx = c.LicenseSpdx,
                ComponentProducer = c.Producer,
                ComponentHashes = c.HashesJson,
                AdditionalIdentifiers = c.AdditionalIdentifiersJson,
                DependencyKind = position.Kind,
                ExplicitUnknownFields = c.ExplicitUnknownFieldsJson,
                ContainmentDeclared = c.ContainmentDeclared,
            };
        }).ToList();

        var document = new ProjectDocument
        {
            Id = "fixture-doc",
            Format = "spdx-json",
            SpecVersion = parsed.SpecVersion,
            ToolName = parsed.ToolName,
            ToolVersion = parsed.ToolVersion,
        };

        return SbomConformanceScorer.Score(document, components);
    }

    private static SbomElementVerdict Find(SbomConformanceScorecard scorecard, string elementId) =>
        Assert.Single(scorecard.Elements, e => e.ElementId == elementId);

    [Fact]
    public void Fixture_HasThreeComponents_ExcludingTheDirectoryRoot()
    {
        // 4 packages in the raw document; SPDXRef-DocumentRoot-Directory-. is the DESCRIBES
        // subject and is excluded from Components, matching CycloneDX's metadata.component split.
        var scorecard = ScoreFixture();
        Assert.Equal(3, scorecard.ComponentTotal);
    }

    [Fact]
    public void Fixture_ScoresComponentProducerAsFullyExplicitlyUnknown()
    {
        // Every package's own supplier is spelled "NOASSERTION" — CISA-conformant honesty, not a
        // gap, so AbsentCount must be zero even though nothing carries a real producer.
        var verdict = Find(ScoreFixture(), SbomConformanceScorer.ComponentProducer);
        Assert.Equal(3, verdict.Total);
        Assert.Equal(0, verdict.PresentCount);
        Assert.Equal(3, verdict.ExplicitUnknownCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Fixture_ScoresComponentLicense_TwoDeclaredOneExplicitlyUnknown()
    {
        // chalk and the sample root package both fall back to licenseDeclared="MIT" after
        // licenseConcluded="NOASSERTION"; lodash asserts NOASSERTION on both fields.
        var verdict = Find(ScoreFixture(), SbomConformanceScorer.ComponentLicense);
        Assert.Equal(3, verdict.Total);
        Assert.Equal(2, verdict.PresentCount);
        Assert.Equal(1, verdict.ExplicitUnknownCount);
        Assert.Equal(0, verdict.AbsentCount);
    }

    [Fact]
    public void Fixture_ScoresComponentIdentifiersAndVersionAsFullyPresent()
    {
        var identifiers = Find(ScoreFixture(), SbomConformanceScorer.ComponentIdentifiers);
        Assert.Equal(3, identifiers.PresentCount);
        Assert.Equal(0, identifiers.AbsentCount);

        var version = Find(ScoreFixture(), SbomConformanceScorer.ComponentVersion);
        Assert.Equal(3, version.PresentCount);
        Assert.Equal(0, version.AbsentCount);
    }

    [Fact]
    public void Fixture_ScoresComponentHashValueNotAssessed_NeverAsASupplierAbsence()
    {
        // Syft's dir: source with filesAnalyzed=false never populates checksums[] — but this
        // parser has no marker distinguishing that from an over-length array dropped for
        // exceeding the stored bound, so the honest verdict is NotAssessed, never Absent.
        var verdict = Find(ScoreFixture(), SbomConformanceScorer.ComponentHashValue);
        Assert.Equal(0, verdict.PresentCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(3, verdict.NotAssessedCount);
        Assert.Equal(SbomElementState.NotAssessed, verdict.State);
    }

    [Fact]
    public void Fixture_ScoresDependencyRelationshipPresent_ViaContainmentDeclared_NeverByFabricatingDepth()
    {
        // DEPENDS_ON/DEPENDENCY_OF alone is rooted one level below the DESCRIBES target (the
        // scanned directory) — every component still reads dependency_kind = graph-unknown, this
        // registry's own routing limitation on THAT walk, unchanged from before CONTAINS was
        // read at all (see the DependencyKind assertion below). But the same real fixture also
        // declares CONTAINS from that directory root to all three packages (Syft's actual dir:
        // output), which SpdxParser.ReadContainedRefs reads SEPARATELY into ContainmentDeclared —
        // a D17-only signal that upgrades graph-unknown to Present without ever touching
        // dependency_kind/dependency_path, so no false direct/transitive claim is minted.
        var scorecard = ScoreFixture();
        var verdict = Find(scorecard, SbomConformanceScorer.ComponentDependencyRelationship);
        Assert.Equal(3, verdict.PresentCount);
        Assert.Equal(0, verdict.AbsentCount);
        Assert.Equal(0, verdict.NotAssessedCount);
        Assert.Equal(SbomElementState.Present, verdict.State);
    }

    [Fact]
    public void Fixture_ScoresCoverageNotAssessed_BecauseCoverageStaysBlindToContainment()
    {
        // P2 Coverage is a depth/completeness practice and deliberately does NOT get
        // ContainmentDeclared credit — it reuses the unchanged ClassifyGraphPosition, so this
        // fixture's graph-unknown dependency_kind (see the D17 test above) still reads
        // NotAssessed here, exactly as it did before CONTAINS was read at all.
        Assert.Equal(SbomElementState.NotAssessed, Find(ScoreFixture(), SbomConformanceScorer.Coverage).State);
    }

    [Fact]
    public void Fixture_ScoresExplicitUnknownsPresent_BecauseTheDocumentActuallyUsesNoAssertion()
    {
        Assert.Equal(SbomElementState.Present, Find(ScoreFixture(), SbomConformanceScorer.ExplicitUnknowns).State);
    }

    [Fact]
    public void Fixture_ScoresGenerationContextNotApplicable_BecauseSpdxHasNoLifecycleElement()
    {
        Assert.Equal(SbomElementState.NotApplicable, Find(ScoreFixture(), SbomConformanceScorer.SbomGenerationContext).State);
    }

    [Fact]
    public void Fixture_ScoresToolNameAndVersionPresent_FromTheRealCreatorsString()
    {
        // creationInfo.creators includes "Tool: syft-1.46.0".
        var scorecard = ScoreFixture();
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomToolName).State);
        Assert.Equal(SbomElementState.Present, Find(scorecard, SbomConformanceScorer.SbomToolVersion).State);
    }
}
