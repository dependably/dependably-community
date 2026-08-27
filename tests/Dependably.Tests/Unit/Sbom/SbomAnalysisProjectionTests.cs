using Dependably.Api;
using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The filter/sort/rollup matrix over the in-memory merge, asserted against a frozen fixture set
/// mirroring the shared SBOM/VEX/SARIF documents: a dev-scope transitive npm component, a runtime
/// reachable one, a PyPI component a VEX statement marks not_affected, a NuGet component the SBOM
/// scopes 'excluded', a component that declares no licence at all, and an analysis row naming a
/// product the SBOM does not list.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomAnalysisProjectionTests
{
    private static readonly DateTimeOffset Scanned = new(2026, 3, 4, 5, 6, 7, TimeSpan.Zero);
    private static readonly DateTimeOffset Triaged = new(2026, 3, 5, 6, 7, 8, TimeSpan.Zero);

    // ── Fixture ──────────────────────────────────────────────────────────────

    private static List<AnalysisComponentRow> Components() =>
    [
        Component("c-minimist", "pkg:npm/minimist@1.2.5", "npm", "minimist", "1.2.5",
            dependencyScope: "dev", dependencyKind: "transitive", license: "MIT",
            dependencyPath: """["pkg:npm/eslint@8.57.0","pkg:npm/minimist@1.2.5"]"""),
        Component("c-qs", "pkg:npm/qs@6.10.2", "npm", "qs", "6.10.2",
            dependencyScope: "runtime", dependencyKind: "direct", license: "BSD-3-Clause"),
        Component("c-requests", "pkg:pypi/requests@2.28.1", "pypi", "requests", "2.28.1",
            dependencyScope: "runtime", dependencyKind: "direct", license: "Apache-2.0"),
        Component("c-charset", "pkg:pypi/charset-normalizer@2.1.1", "pypi", "charset-normalizer", "2.1.1",
            dependencyScope: "unknown", dependencyKind: "transitive", license: null),
        Component("c-serilog", "pkg:nuget/serilog@2.12.0", "nuget", "serilog", "2.12.0",
            dependencyScope: "unknown", dependencyKind: "direct", license: "Apache-2.0",
            sbomScope: "excluded"),
    ];

    private static List<AnalysisAdvisoryRow> Advisories() =>
    [
        // Dev-scope, medium score, analyzer never saw it called.
        new() { ComponentId = "c-minimist", VulnId = "v1", OsvId = "GHSA-xvch-5gv4-984h",
                Aliases = """["CVE-2021-44906"]""", Severity = "CRITICAL", CvssScore = 9.8 },
        // Runtime, high score, reachable — the promotion case.
        new() { ComponentId = "c-qs", VulnId = "v2", OsvId = "GHSA-hrpp-h998-j3pp",
                Aliases = """["CVE-2022-24999"]""", Severity = "HIGH", CvssScore = 7.5 },
        // The one a VEX statement suppresses.
        new() { ComponentId = "c-requests", VulnId = "v3", OsvId = "GHSA-j8r2-6x86-q33q",
                Aliases = """["CVE-2023-32681"]""", Severity = "MEDIUM", CvssScore = 6.1 },
        // No score at all — the UNSCORED bucket.
        new() { ComponentId = "c-charset", VulnId = "v4", OsvId = "GHSA-unsc-0000-0000",
                Aliases = null, Severity = null, CvssScore = null },
    ];

    private static List<AnalysisVexRow> AnalysisRows() =>
    [
        // Cited by its CVE alias while the advisory row is keyed by GHSA — the in-memory match.
        new() { PurlKey = "pkg:npm/minimist", VulnKey = "CVE-2021-44906",
                Reachability = "not-observed", Confidence = "high", UpdatedAt = Scanned },
        new() { PurlKey = "pkg:npm/qs", VulnKey = "CVE-2022-24999",
                Reachability = "reachable", Confidence = "high", UpdatedAt = Scanned },
        new() { PurlKey = "pkg:pypi/requests", VulnKey = "CVE-2023-32681",
                VexState = "not_affected", VexJustification = "code_not_reachable",
                VexSource = "upload", UpdatedAt = Scanned },
        // Names a product this version's SBOM does not list.
        new() { PurlKey = "pkg:npm/event-stream", VulnKey = "GHSA-mh6f-8j2x-4483",
                VexState = "exploitable", VexSource = "upload",
                UpdatedBy = "user-1", UpdatedAt = Triaged },
    ];

    private static List<AnalysisFindingRow> Findings() =>
    [
        new() { ComponentId = "c-qs", Arm = "cvss", VulnKey = "CVE-2022-24999", Detail = """{"threshold":7.0}""" },
        new() { ComponentId = "c-charset", Arm = "license", LicenseSpdx = null, Detail = """{"reason":"undeclared"}""" },
    ];

    private static AnalysisPage Run(AnalysisQuery query) =>
        SbomAnalysisProjection.Build(
            new AnalysisRows(Components(), Advisories(), AnalysisRows(), Findings()),
            NoRegistryFacts, "violation", query);

    private static AnalysisQuery Query(
        string sort = "priority", string dir = "desc", string? q = null, string? scope = null,
        string? sev = null, string? reach = null, string? registry = null, bool violations = false,
        bool suppressed = false, int page = 1, int limit = 50) =>
        new(page, limit, sort, dir, q, scope, sev, reach, registry, violations, suppressed);

    /// <summary>
    /// The registry cross-link answering nothing at all — every component reads as either absent
    /// or, where it carries no coordinate, unknown. The fixtures that care supply their own.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, ComponentRegistryFacts> NoRegistryFacts =
        new Dictionary<string, ComponentRegistryFacts>(StringComparer.Ordinal);

    // ── Priority derivation over the fixture ─────────────────────────────────

    [Fact]
    public void Priority_IsDerivedFromTheJoinedFacts()
    {
        var result = Run(Query(suppressed: true));
        var byId = result.Items.ToDictionary(i => i.ComponentId, StringComparer.Ordinal);

        // 9.8 → Attend, then not-observed demotes to Track.
        Assert.Equal(EffectivePriority.Track, Only(byId["c-minimist"]).EffectivePriority);
        // 7.5 → Attend, then reachable promotes to Act.
        Assert.Equal(EffectivePriority.Act, Only(byId["c-qs"]).EffectivePriority);
        // not_affected is final.
        Assert.Equal(EffectivePriority.Suppressed, Only(byId["c-requests"]).EffectivePriority);
        // No score: Track, flagged unscored.
        Assert.Equal(EffectivePriority.Track, Only(byId["c-charset"]).EffectivePriority);
        Assert.True(Only(byId["c-charset"]).Unscored);
    }

    [Fact]
    public void AliasCitedStatement_BindsToTheGhsaKeyedAdvisory()
    {
        var result = Run(Query(suppressed: true));
        var advisory = Only(result.Items.Single(i => i.ComponentId == "c-minimist"));

        // The statement cites the CVE; the advisory row is keyed by the GHSA. Both are reported,
        // and the vulnKey the triage editor writes back is the one the statement is stored under.
        Assert.Equal("CVE-2021-44906", advisory.VulnKey);
        Assert.Equal("GHSA-xvch-5gv4-984h", advisory.OsvId);
        Assert.Equal("not-observed", advisory.Reachability);
    }

    [Fact]
    public void PurlKey_IsTheVersionLessCanonicalPurl()
    {
        var result = Run(Query(suppressed: true));
        Assert.Equal("pkg:npm/minimist", result.Items.Single(i => i.ComponentId == "c-minimist").PurlKey);
        Assert.Equal("pkg:pypi/charset-normalizer", result.Items.Single(i => i.ComponentId == "c-charset").PurlKey);
    }

    // ── Scope semantics (CONTRACT D1) ────────────────────────────────────────

    [Fact]
    public void ScopeProd_ExcludesDevAndSbomExcluded_ButKeepsUnknown()
    {
        var result = Run(Query(scope: "prod", suppressed: true));
        var ids = result.Items.Select(i => i.ComponentId).ToList();

        Assert.DoesNotContain("c-minimist", ids);  // dependency_scope = dev
        Assert.DoesNotContain("c-serilog", ids);   // sbom_scope = excluded
        Assert.Contains("c-qs", ids);
        Assert.Contains("c-requests", ids);
        // Unclassified is not the same as dev: it stays visible and labeled.
        Assert.Contains("c-charset", ids);
    }

    [Fact]
    public void ScopeDev_IsExactlyTheDevDependencyScope()
    {
        var result = Run(Query(scope: "dev", suppressed: true));
        Assert.Equal(["c-minimist"], result.Items.Select(i => i.ComponentId));
    }

    [Fact]
    public void ScopeAll_ReturnsEveryComponent()
    {
        Assert.Equal(5, Run(Query(suppressed: true)).Total);
    }

    // ── Filters ──────────────────────────────────────────────────────────────

    [Fact]
    public void SearchFilter_MatchesNameAndPurl()
    {
        Assert.Equal(["c-minimist"], Run(Query(q: "MINIM", suppressed: true)).Items.Select(i => i.ComponentId));
        Assert.Equal(["c-serilog"], Run(Query(q: "pkg:nuget/", suppressed: true)).Items.Select(i => i.ComponentId));
        Assert.Empty(Run(Query(q: "nothing-matches", suppressed: true)).Items);
    }

    [Fact]
    public void SeverityFilter_ReadsTheRollupBuckets()
    {
        Assert.Equal(["c-minimist"], Run(Query(sev: "critical", suppressed: true)).Items.Select(i => i.ComponentId));
        Assert.Equal(["c-qs"], Run(Query(sev: "high", suppressed: true)).Items.Select(i => i.ComponentId));
        Assert.Equal(["c-charset"], Run(Query(sev: "unscored", suppressed: true)).Items.Select(i => i.ComponentId));
    }

    [Fact]
    public void SeverityFilter_HidesAComponentWhoseOnlyMatchIsSuppressed()
    {
        // requests carries one MEDIUM advisory, suppressed by a VEX statement. With suppressed off
        // it must not answer a medium filter — otherwise the row count and the rollup disagree.
        Assert.Empty(Run(Query(sev: "medium")).Items);
        Assert.Equal(["c-requests"], Run(Query(sev: "medium", suppressed: true)).Items.Select(i => i.ComponentId));
    }

    [Fact]
    public void ReachabilityFilter_SelectsOnTheStatementValue()
    {
        Assert.Equal(["c-qs"], Run(Query(reach: "reachable", suppressed: true)).Items.Select(i => i.ComponentId));
        Assert.Equal(["c-minimist"], Run(Query(reach: "not-observed", suppressed: true)).Items.Select(i => i.ComponentId));
    }

    [Fact]
    public void ViolationsFilter_SelectsComponentsCarryingAFinding()
    {
        var ids = Run(Query(violations: true, suppressed: true)).Items.Select(i => i.ComponentId).ToList();
        Assert.Equal(2, ids.Count);
        Assert.Contains("c-qs", ids);
        // The licence arm names no advisory, so the component is the only place its finding can
        // land — and the violations filter still has to find it.
        Assert.Contains("c-charset", ids);
    }

    [Fact]
    public void LicenceArmFinding_IsCarriedOnTheComponentNotAnAdvisory()
    {
        var charset = Run(Query(suppressed: true)).Items.Single(i => i.ComponentId == "c-charset");
        Assert.Equal("license", Assert.Single(charset.PolicyViolations).Arm);
        Assert.Empty(Only(charset).PolicyViolations);
    }

    [Fact]
    public void AdvisoryFinding_IsMatchedThroughTheAliasSet()
    {
        var qs = Run(Query(suppressed: true)).Items.Single(i => i.ComponentId == "c-qs");
        Assert.Equal("cvss", Assert.Single(Only(qs).PolicyViolations).Arm);
    }

    // ── Sorting ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("desc", new[] { "c-qs", "c-charset", "c-minimist", "c-requests", "c-serilog" })]
    [InlineData("asc", new[] { "c-requests", "c-serilog", "c-charset", "c-minimist", "c-qs" })]
    public void PrioritySort_RanksActAboveTrackAboveNothing(string dir, string[] expected)
    {
        // With suppressed advisories hidden, requests and serilog contribute no visible advisory and
        // rank below the Track rows; the tiebreak is the component name, ascending, both directions.
        var result = Run(Query(sort: "priority", dir: dir));
        Assert.Equal(expected, result.Items.Select(i => i.ComponentId));
    }

    [Fact]
    public void SeveritySort_RanksCriticalFirst()
    {
        var result = Run(Query(sort: "severity", dir: "desc", suppressed: true));
        Assert.Equal("c-minimist", result.Items[0].ComponentId);
    }

    [Fact]
    public void NameSort_IsOrdinalAndReversible()
    {
        var ascending = Run(Query(sort: "name", dir: "asc", suppressed: true)).Items.Select(i => i.Name).ToList();
        var descending = Run(Query(sort: "name", dir: "desc", suppressed: true)).Items.Select(i => i.Name).ToList();
        Assert.Equal(ascending.AsEnumerable().Reverse(), descending);
        Assert.Equal("charset-normalizer", ascending[0]);
    }

    [Fact]
    public void ScopeSort_GroupsByTheDependencyScope()
    {
        var result = Run(Query(sort: "scope", dir: "asc", suppressed: true));
        Assert.Equal("dev", result.Items[0].DependencyScope);
    }

    [Fact]
    public void Paging_CutsTheSortedSetAndReportsTheFilteredTotal()
    {
        var first = Run(Query(sort: "name", dir: "asc", limit: 2, page: 1, suppressed: true));
        var second = Run(Query(sort: "name", dir: "asc", limit: 2, page: 2, suppressed: true));

        Assert.Equal(5, first.Total);
        Assert.Equal(2, first.Items.Count);
        Assert.Equal(2, second.Items.Count);
        Assert.Empty(first.Items.Select(i => i.ComponentId).Intersect(second.Items.Select(i => i.ComponentId)));
    }

    [Fact]
    public void Paging_PastTheEndIsEmptyNotAnError()
    {
        var result = Run(Query(page: 99, suppressed: true));
        Assert.Empty(result.Items);
        Assert.Equal(5, result.Total);
    }

    // ── Rollup ───────────────────────────────────────────────────────────────

    [Fact]
    public void Rollup_CountsScopesAcrossTheWholeVersion()
    {
        // Deliberately read through a narrowing filter: the rollup is the version's header and must
        // not move when someone types in the search box.
        var rollup = Run(Query(q: "minim")).Rollup;

        Assert.Equal(5, rollup.ComponentTotal);
        Assert.Equal(3, rollup.ProdCount);           // qs, requests, charset-normalizer
        Assert.Equal(1, rollup.DevCount);            // minimist
        Assert.Equal(2, rollup.UnknownScopeCount);   // charset-normalizer, serilog
        Assert.Equal(0, rollup.UnscannableCount);    // every fixture component carries a scannable purl
        Assert.Equal("violation", rollup.PolicyStatus);
        Assert.Equal(2, rollup.ViolationCount);
    }

    /// <summary>
    /// The policy rollup excuses a component no advisory query could ever answer for, so the count
    /// of those components is reported here rather than silently dropped: an unanswerable
    /// component is a fact about the SBOM the operator still needs to see.
    /// </summary>
    [Fact]
    public void Rollup_CountsComponentsNoAdvisoryQueryCanAnswerFor()
    {
        var components = Components();
        components.Add(Component(
            "c-blob", purl: null, ecosystem: null, purlName: "vendored-blob.so", version: "1.0.0",
            dependencyScope: "unknown", dependencyKind: "direct", license: "MIT"));
        components.Add(Component(
            "c-base-image", "pkg:oci/base@sha256%3Aabc", "oci", "base", "1.0.0",
            dependencyScope: "runtime", dependencyKind: "direct", license: null));

        var rollup = SbomAnalysisProjection.Build(
            new AnalysisRows(components, Advisories(), AnalysisRows(), Findings()),
            NoRegistryFacts, "violation", Query()).Rollup;

        Assert.Equal(7, rollup.ComponentTotal);
        Assert.Equal(2, rollup.UnscannableCount);
    }

    /// <summary>
    /// Policy exempts a component the SBOM's own producer marked <c>scope='excluded'</c> from the
    /// four vulnerability arms — an exemption that is otherwise invisible, so the rollup counts
    /// it the same honest-uncertainty way it counts <see cref="AnalysisRollup.UnscannableCount"/>.
    /// The fixture's <c>c-serilog</c> component (excluded, but carries a real scannable purl) is
    /// the discriminator between the two counts: it must land in ScopeSuppressedCount and not in
    /// UnscannableCount, which a mutant merging the two axes into one count would fail to keep
    /// apart the moment either fixture component were removed.
    /// </summary>
    [Fact]
    public void Rollup_CountsComponentsTheSbomMarkedExcludedFromTheBuild_SeparatelyFromUnscannable()
    {
        var rollup = Run(Query()).Rollup;

        Assert.Equal(1, rollup.ScopeSuppressedCount);
        Assert.Equal(0, rollup.UnscannableCount);
    }

    // ── Inherited triage ─────────────────────────────────────────────────────

    /// <summary>
    /// A statement whose provenance predates the version it is now rendered against was carried
    /// forward from an earlier release rather than decided for this one — the exact concern
    /// Dependency-Track's opt-in gating exists for. No comparison point (the default every caller
    /// before this feature landed still passes) never claims a row is inherited.
    /// </summary>
    [Fact]
    public void Advisory_Inherited_TrueWhenStatementPredatesTheVersionsOwnCreation()
    {
        var versionCreatedAfterTriage = Triaged.AddDays(1);
        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(Components(), Advisories(), AnalysisRows(), Findings()),
            NoRegistryFacts, "violation", Query(suppressed: true), versionCreatedAfterTriage);

        // c-minimist's statement was recorded at `Scanned`, which predates the version.
        var minimist = page.Items.Single(i => i.ComponentId == "c-minimist");
        Assert.True(Only(minimist).Inherited);
    }

    [Fact]
    public void Advisory_Inherited_FalseWhenStatementIsNotOlderThanTheVersion()
    {
        var versionCreatedBeforeTriage = Scanned.AddSeconds(-1);
        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(Components(), Advisories(), AnalysisRows(), Findings()),
            NoRegistryFacts, "violation", Query(suppressed: true), versionCreatedBeforeTriage);

        var minimist = page.Items.Single(i => i.ComponentId == "c-minimist");
        Assert.False(Only(minimist).Inherited);
    }

    [Fact]
    public void Advisory_Inherited_FalseWhenNoComparisonPointIsSupplied()
    {
        // The default every pre-existing caller (and every other test in this file) still uses.
        var minimist = Run(Query(suppressed: true)).Items.Single(i => i.ComponentId == "c-minimist");
        Assert.False(Only(minimist).Inherited);
    }

    [Fact]
    public void Orphan_Inherited_TrueWhenStatementPredatesTheVersionsOwnCreation()
    {
        var versionCreatedAfterTriage = Triaged.AddDays(1);
        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(Components(), Advisories(), AnalysisRows(), Findings()),
            NoRegistryFacts, "violation", Query(), versionCreatedAfterTriage);

        var orphan = Assert.Single(page.Orphans);
        Assert.True(orphan.Inherited);
    }

    [Fact]
    public void Rollup_ExcludesSuppressedFromSeverityCountsByDefault()
    {
        var hidden = Run(Query()).Rollup;
        Assert.Equal(0, hidden.SeverityCounts["medium"]);
        Assert.Equal(1, hidden.SeverityCounts["critical"]);
        Assert.Equal(1, hidden.SeverityCounts["high"]);
        Assert.Equal(1, hidden.SeverityCounts["unscored"]);

        var shown = Run(Query(suppressed: true)).Rollup;
        Assert.Equal(1, shown.SeverityCounts["medium"]);
    }

    [Fact]
    public void Rollup_AlwaysReportsTheSuppressedPriorityBucket()
    {
        // The suppressed bucket is what makes the hidden count visible; it is reported whether or
        // not the caller asked to see the rows.
        var rollup = Run(Query()).Rollup;
        Assert.Equal(1, rollup.PriorityCounts[EffectivePriority.Act]);
        Assert.Equal(2, rollup.PriorityCounts[EffectivePriority.Track]);
        Assert.Equal(1, rollup.PriorityCounts[EffectivePriority.Suppressed]);
    }

    [Fact]
    public void Rollup_LicenceCountsCoverTheWholeVersion()
    {
        var counts = Run(Query(scope: "dev")).Rollup.LicenseCounts;

        Assert.Equal(5, counts.Total);
        Assert.Equal(4, counts.Declared);
        Assert.Equal(1, counts.Undeclared);
        Assert.Equal(2, counts.ByIdentifier["Apache-2.0"]);
        Assert.Equal(1, counts.ByIdentifier["MIT"]);
        Assert.False(counts.ByIdentifier.ContainsKey("GPL-3.0-only"));
    }

    [Fact]
    public void Rollup_LastScanAt_IsTheNewestComponentStamp()
    {
        var components = Components();
        components[0].VulnCheckedAt = Scanned;
        components[1].VulnCheckedAt = Scanned.AddHours(2);

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, Advisories(), AnalysisRows(), Findings()),
            NoRegistryFacts, "pass", Query());
        Assert.Equal(Scanned.AddHours(2), page.Rollup.LastScanAt);
    }

    [Fact]
    public void Rollup_LastScanAt_IsNullWhenNothingHasBeenScanned()
    {
        Assert.Null(Run(Query()).Rollup.LastScanAt);
    }

    // ── Orphans ──────────────────────────────────────────────────────────────

    [Fact]
    public void OrphanAnalysis_SurfacesStatementsWithNoMatchingComponent()
    {
        var orphan = Assert.Single(Run(Query()).Orphans);
        Assert.Equal("pkg:npm/event-stream", orphan.PurlKey);
        Assert.Equal("GHSA-mh6f-8j2x-4483", orphan.VulnKey);
        Assert.Equal("exploitable", orphan.VexState);
        Assert.Equal("user-1", orphan.VexUpdatedBy);
        Assert.Equal(Triaged, orphan.VexUpdatedAt);
    }

    [Fact]
    public void OrphanAnalysis_IsNotAffectedByTheRowFilters()
    {
        // The orphan section is a completeness guarantee, not a view of the page. Narrowing the
        // table must not make a statement disappear.
        Assert.Single(Run(Query(scope: "dev", sev: "critical")).Orphans);
    }

    [Fact]
    public void StatementCitingAnUnlinkedAdvisory_LandsOnItsComponentNotInTheOrphanList()
    {
        // The product purl matched a component; only the advisory is unknown to the scanner. That
        // is a component-level fact rendered with no score, not an orphan.
        var rows = AnalysisRows();
        rows.Add(new AnalysisVexRow
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-9999-0001",
            VexState = "in_triage",
            VexSource = "manual",
            UpdatedAt = Triaged,
        });

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(Components(), Advisories(), rows, Findings()),
            NoRegistryFacts, null, Query());
        var qs = page.Items.Single(i => i.ComponentId == "c-qs");

        var synthesized = qs.Advisories.Single(x => x.VulnKey == "CVE-9999-0001");
        Assert.Null(synthesized.OsvId);
        Assert.Null(synthesized.Cvss);
        Assert.True(synthesized.Unscored);
        Assert.Equal(SbomAnalysisProjection.UnscoredBucket, synthesized.SeverityBucket);
        Assert.Single(page.Orphans);
    }

    // ── New signal wiring at the real call site (#612) ───────────────────────

    /// <summary>
    /// c-charset carries no OSV score. With an NVD overlay score wired onto the same advisory row,
    /// the real <c>BuildAdvisory</c> call site now resolves the NVD fallback rather than leaving the
    /// advisory permanently unscored — the bucket still reflects c-charset's own dependency-graph
    /// position (transitive, in the shared fixture), which demotes the NVD-sourced Attend base down
    /// to Track, but <see cref="AnalysisAdvisoryView.Unscored"/> now correctly reads false.
    /// </summary>
    [Fact]
    public void NvdScore_FeedsThePriorityThroughTheRealCallSite()
    {
        var advisories = Advisories();
        advisories.Single(a => a.ComponentId == "c-charset").NvdScore = 9.1;

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(Components(), advisories, AnalysisRows(), Findings()),
            NoRegistryFacts, "violation", Query(suppressed: true));

        var charset = Only(page.Items.Single(i => i.ComponentId == "c-charset"));
        Assert.Equal(EffectivePriority.Track, charset.EffectivePriority);
        Assert.False(charset.Unscored);
    }

    /// <summary>
    /// A single isolated advisory that fires the ransomware arm without KEV membership — the
    /// combination the stored-data comment on <c>SetKevAsync</c> says never occurs, kept isolated
    /// from the shared fixture so it proves the arm itself rather than piggy-backing on KEV.
    /// </summary>
    [Fact]
    public void KevRansomware_FeedsThePriorityThroughTheRealCallSite_IndependentlyOfKev()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-solo", "pkg:npm/solo@1.0.0", "npm", "solo", "1.0.0",
                dependencyScope: "runtime", dependencyKind: "direct", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new()
            {
                ComponentId = "c-solo", VulnId = "v-solo", OsvId = "GHSA-solo-0000-0000",
                Severity = "LOW", CvssScore = 2.0, IsKev = false, IsKevRansomware = true,
            },
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, [], []), NoRegistryFacts, null, Query());

        var solo = Only(page.Items.Single(i => i.ComponentId == "c-solo"));
        Assert.Equal(EffectivePriority.Act, solo.EffectivePriority);
    }

    /// <summary>SSVC active exploitation is an observation-grade signal; it forces Act on its own.</summary>
    [Fact]
    public void SsvcActive_FeedsThePriorityThroughTheRealCallSite()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-solo", "pkg:npm/solo@1.0.0", "npm", "solo", "1.0.0",
                dependencyScope: "runtime", dependencyKind: "direct", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new()
            {
                ComponentId = "c-solo", VulnId = "v-solo", OsvId = "GHSA-solo-0000-0000",
                Severity = "LOW", CvssScore = 2.0, SsvcExploitation = "active",
            },
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, [], []), NoRegistryFacts, null, Query());

        var solo = Only(page.Items.Single(i => i.ComponentId == "c-solo"));
        Assert.Equal(EffectivePriority.Act, solo.EffectivePriority);
    }

    /// <summary>A top-decile EPSS percentile forces Act even on a low-CVSS, non-KEV advisory.</summary>
    [Fact]
    public void EpssPercentile_FeedsThePriorityThroughTheRealCallSite()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-solo", "pkg:npm/solo@1.0.0", "npm", "solo", "1.0.0",
                dependencyScope: "runtime", dependencyKind: "direct", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new()
            {
                ComponentId = "c-solo", VulnId = "v-solo", OsvId = "GHSA-solo-0000-0000",
                Severity = "LOW", CvssScore = 2.0, EpssPercentile = 0.95,
            },
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, [], []), NoRegistryFacts, null, Query());

        var solo = Only(page.Items.Single(i => i.ComponentId == "c-solo"));
        Assert.Equal(EffectivePriority.Act, solo.EffectivePriority);
    }

    /// <summary>CISA Vulnrichment SSVC "poc" floors a demoted advisory back up at Attend.</summary>
    [Fact]
    public void SsvcPoc_FeedsThePriorityThroughTheRealCallSite_AndFloorsAtAttend()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-solo", "pkg:npm/solo@1.0.0", "npm", "solo", "1.0.0",
                dependencyScope: "dev", dependencyKind: "transitive", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new()
            {
                ComponentId = "c-solo", VulnId = "v-solo", OsvId = "GHSA-solo-0000-0000",
                Severity = "MEDIUM", CvssScore = 6.0, SsvcExploitation = "poc",
            },
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, [], []), NoRegistryFacts, null, Query());

        // Track base (6.0 < 7.0), dev+transitive demote further — poc still floors it back to Attend.
        var solo = Only(page.Items.Single(i => i.ComponentId == "c-solo"));
        Assert.Equal(EffectivePriority.Attend, solo.EffectivePriority);
    }

    /// <summary>
    /// Dependency kind/scope are read from the real <see cref="AnalysisComponentRow"/>, not from a
    /// synthetic fixture: c-minimist (transitive, dev) and a fresh direct/runtime twin at the same
    /// CVSS and no reachability statement land in different buckets.
    /// </summary>
    [Fact]
    public void DependencyKindAndScope_FeedFromTheRealComponentRow()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-transitive-dev", "pkg:npm/a@1.0.0", "npm", "a", "1.0.0",
                dependencyScope: "dev", dependencyKind: "transitive", license: "MIT"),
            Component("c-direct-runtime", "pkg:npm/b@1.0.0", "npm", "b", "1.0.0",
                dependencyScope: "runtime", dependencyKind: "direct", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new() { ComponentId = "c-transitive-dev", VulnId = "v-a", OsvId = "GHSA-a-0000-0000", CvssScore = 7.0 },
            new() { ComponentId = "c-direct-runtime", VulnId = "v-b", OsvId = "GHSA-b-0000-0000", CvssScore = 7.0 },
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, [], []), NoRegistryFacts, null, Query());
        var byId = page.Items.ToDictionary(i => i.ComponentId, StringComparer.Ordinal);

        // Attend base (7.0), transitive (-1) and dev (-1) demote to Track.
        Assert.Equal(EffectivePriority.Track, Only(byId["c-transitive-dev"]).EffectivePriority);
        // Attend base, direct/runtime contribute no adjustment.
        Assert.Equal(EffectivePriority.Attend, Only(byId["c-direct-runtime"]).EffectivePriority);
    }

    /// <summary>
    /// The install-script/reachability discriminator, exercised through the real call site: the
    /// registry cross-link (<see cref="ComponentRegistryFacts.HasInstallScriptThisVersion"/>) is
    /// what supplies <c>HasInstallScript</c> on the projects plane, not a component or advisory
    /// column. Track base (5.0), not-observed reachability suppressed by the install-script flag,
    /// plus the install-script promotion itself — naive additive cancellation would net zero and
    /// stay at Track; the correct suppression nets +1 and promotes to Attend.
    /// </summary>
    [Fact]
    public void InstallScriptFromRegistryCrossLink_SuppressesTheNotObservedDemotion()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-script", "pkg:npm/scripty@1.0.0", "npm", "scripty", "1.0.0",
                dependencyScope: "runtime", dependencyKind: "direct", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new() { ComponentId = "c-script", VulnId = "v-script", OsvId = "GHSA-script-0000-0000", CvssScore = 5.0 },
        };
        var analysisRows = new List<AnalysisVexRow>
        {
            new() { PurlKey = "pkg:npm/scripty", VulnKey = "GHSA-script-0000-0000", Reachability = "not-observed" },
        };
        var registryFacts = new Dictionary<string, ComponentRegistryFacts>(StringComparer.Ordinal)
        {
            ["c-script"] = new ComponentRegistryFacts(
                Hosted: true, Cached: false, UpstreamLatestVersion: null,
                BlockedThisVersion: false, BlockedAnyVersion: false,
                DeprecatedThisVersion: false, DeprecatedAnyVersion: false,
                HasInstallScriptThisVersion: true),
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, analysisRows, []), registryFacts, null, Query());

        var script = Only(page.Items.Single(i => i.ComponentId == "c-script"));
        Assert.Equal(EffectivePriority.Attend, script.EffectivePriority);
    }

    /// <summary>Without the registry cross-link entry, the same fixture demotes normally.</summary>
    [Fact]
    public void NoRegistryCrossLink_TheNotObservedDemotionIsNotSuppressed()
    {
        var components = new List<AnalysisComponentRow>
        {
            Component("c-script", "pkg:npm/scripty@1.0.0", "npm", "scripty", "1.0.0",
                dependencyScope: "runtime", dependencyKind: "direct", license: "MIT"),
        };
        var advisories = new List<AnalysisAdvisoryRow>
        {
            new() { ComponentId = "c-script", VulnId = "v-script", OsvId = "GHSA-script-0000-0000", CvssScore = 9.0 },
        };
        var analysisRows = new List<AnalysisVexRow>
        {
            new() { PurlKey = "pkg:npm/scripty", VulnKey = "GHSA-script-0000-0000", Reachability = "not-observed" },
        };

        var page = SbomAnalysisProjection.Build(
            new AnalysisRows(components, advisories, analysisRows, []), NoRegistryFacts, null, Query());

        var script = Only(page.Items.Single(i => i.ComponentId == "c-script"));
        Assert.Equal(EffectivePriority.Track, script.EffectivePriority);
    }

    // ── Parsing helpers ──────────────────────────────────────────────────────

    [Fact]
    public void DependencyPath_IsPassedThroughAsTheStoredArray()
    {
        var minimist = Run(Query(suppressed: true)).Items.Single(i => i.ComponentId == "c-minimist");
        Assert.NotNull(minimist.DependencyPath);
        Assert.Equal(2, minimist.DependencyPath!.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("{\"not\":\"an array\"}")]
    public void DependencyPath_MalformedYieldsNothingRatherThanThrowing(string? stored)
    {
        Assert.Null(SbomAnalysisProjection.ParseJsonArray(stored));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("[[[")]
    [InlineData("{\"aliases\":[]}")]
    public void Aliases_MalformedYieldNothingRatherThanThrowing(string? stored)
    {
        Assert.Empty(SbomAnalysisProjection.ParseAliases(stored));
    }

    [Fact]
    public void SplitSpdx_SeparatesACompoundExpression()
    {
        Assert.Equal(
            ["MIT", "Apache-2.0"],
            SbomAnalysisProjection.SplitSpdx("(MIT OR Apache-2.0)").OrderByDescending(x => x, StringComparer.Ordinal));
        Assert.Empty(SbomAnalysisProjection.SplitSpdx(null));
    }

    // ── Fixture helpers ──────────────────────────────────────────────────────

    private static AnalysisAdvisoryView Only(AnalysisComponentView component) =>
        Assert.Single(component.Advisories);

    private static AnalysisComponentRow Component(
        string id, string? purl, string? ecosystem, string purlName, string version,
        string dependencyScope, string dependencyKind, string? license,
        string? sbomScope = null, string? dependencyPath = null) => new()
        {
            Id = id,
            Purl = purl,
            Ecosystem = ecosystem,
            PurlName = purlName,
            Version = version,
            Name = purlName,
            ComponentType = "library",
            SbomScope = sbomScope,
            DependencyScope = dependencyScope,
            DependencyKind = dependencyKind,
            DependencyPath = dependencyPath,
            LicenseSpdx = license,
        };
}
