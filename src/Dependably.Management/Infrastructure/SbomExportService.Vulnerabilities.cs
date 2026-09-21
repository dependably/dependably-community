using System.Globalization;
using System.Text.Json.Nodes;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;

namespace Dependably.Infrastructure;

/// <summary>
/// The dependency-graph and vulnerability half of <see cref="SbomExportService"/>: the
/// <c>dependencies[]</c> and <c>vulnerabilities[]</c> arrays, and the per-vulnerability
/// <c>dependably:</c> signal properties that disclose what this registry does and does not know
/// about each advisory.
///
/// <para>Separated from the document assembly by file only — one partial class, one lifetime.</para>
/// </summary>
public sealed partial class SbomExportService
{
    /// <summary>
    /// Reconstructs a closed <c>dependencies[]</c> adjacency graph from each component's own
    /// <see cref="ComponentRow.DependencyPath"/> — the JSON array of purls from the dependency
    /// root to the component itself (inclusive of its own ref). Consecutive elements of one
    /// component's path are direct edges; the root is the implicit ancestor of every path's first
    /// element. A component with no stored path is treated as a direct child of the root. Every
    /// ref that is ever named — root, every component, and any ancestor a path mentions without
    /// itself being an uploaded component — gets its own <c>dependencies[]</c> entry, so the graph
    /// has no dangling edges.
    /// </summary>
    private static JsonArray BuildDependenciesArray(
        string rootRef, IReadOnlyList<ComponentRow> components, string? refPrefix = null)
    {
        var order = new List<string> { rootRef };
        var childrenOf = new Dictionary<string, List<string>>(StringComparer.Ordinal) { [rootRef] = [] };

        void EnsureNode(string r)
        {
            if (!childrenOf.ContainsKey(r))
            {
                childrenOf[r] = [];
                order.Add(r);
            }
        }

        void AddEdge(string parent, string child)
        {
            EnsureNode(parent);
            EnsureNode(child);
            if (!childrenOf[parent].Contains(child))
            {
                childrenOf[parent].Add(child);
            }
        }

        // Path elements are stored as bare purls, so an aggregate has to namespace them the same
        // way the component bom-refs are — otherwise the graph names refs no component declares,
        // and two projects sharing a transitive dependency merge into one node.
        string Namespaced(string bareRef) => refPrefix is null ? bareRef : $"{refPrefix}/{bareRef}";

        foreach (var c in components)
        {
            string selfRef = RefOf(c, refPrefix);
            EnsureNode(selfRef);

            var path = ParseStringArray(c.DependencyPath);
            if (path.Count == 0)
            {
                AddEdge(rootRef, selfRef);
                continue;
            }

            AddEdge(rootRef, Namespaced(path[0]));
            for (int i = 0; i < path.Count - 1; i++)
            {
                AddEdge(Namespaced(path[i]), Namespaced(path[i + 1]));
            }
        }

        var arr = new JsonArray();
        foreach (string r in order)
        {
            var dependsOn = new JsonArray();
            foreach (string child in childrenOf[r])
            {
                dependsOn.Add(JsonValue.Create(child));
            }

            arr.Add(new JsonObject { ["ref"] = r, ["dependsOn"] = dependsOn });
        }

        return arr;
    }

    private static JsonArray BuildVulnerabilitiesArray(
        IReadOnlyList<ComponentVulnRow> vulnRows, IReadOnlyList<AnalysisRow> analysisRows,
        IReadOnlyDictionary<string, bool> installScriptByComponentId,
        IReadOnlyDictionary<string, int> affectedAppsByOsvId,
        string? refPrefix = null)
    {
        // Keyed with the same SbomVulnKeyComparer SbomPolicyRepository.ResolveVexState uses — one
        // comparison rule for vuln_key so an analysis block suppressed in the analysis view is
        // suppressed in the exported document too, never the reverse — without rewriting the
        // stored spelling of an advisory id.
        var analysisByKey = analysisRows.ToDictionary(
            a => (a.PurlKey, a.VulnKey), SbomVulnKeyComparer.Instance);

        var arr = new JsonArray();
        foreach (var v in vulnRows)
        {
            // The analysis rows are keyed by SbomPurlKey on the way in; re-deriving the key any
            // other way here drops the suppressing analysis block off exactly the scoped,
            // mixed-case and underscored coordinates canonicalization exists for.
            string? purlKey = SbomPurlKey.ForComponent(v.Ecosystem, v.PurlName, v.ComponentPurl);
            var analysis = purlKey is null
                ? null
                : FindAnalysis(analysisByKey, purlKey, v.OsvId, v.Aliases);

            var entry = new JsonObject
            {
                ["bom-ref"] = $"vuln-{v.OsvId}-{v.ComponentId}",
                ["id"] = v.OsvId,
                ["source"] = BuildSource(v.OsvId),
            };

            var ratings = BuildRatings(v.Severity, v.CvssScore);
            if (ratings is not null)
            {
                entry["ratings"] = ratings;
            }

            var analysisObj = BuildAnalysis(analysis);
            if (analysisObj is not null)
            {
                entry["analysis"] = analysisObj;
            }

            // Points at the component's bom-ref, which in an aggregate is the namespaced one —
            // an un-prefixed affects ref would resolve to whichever project's copy came first.
            entry["affects"] = new JsonArray(new JsonObject
            {
                ["ref"] = refPrefix is null ? v.ComponentPurl : $"{refPrefix}/{v.ComponentPurl}",
            });

            entry["properties"] = BuildVulnProperties(
                new VulnSignalFacts(
                    v.CvssScore,
                    v.NvdScore,
                    v.NvdCheckedAt,
                    v.NvdAssertedAt,
                    v.IsKev,
                    v.IsKevRansomware,
                    v.KevDueDate,
                    v.KevDateAdded,
                    v.KevRequiredAction,
                    v.KevCwes,
                    v.KevNotes,
                    v.EpssScore,
                    v.EpssPercentile,
                    v.SsvcExploitation,
                    v.SsvcAutomatable,
                    v.SsvcTechnicalImpact,
                    v.SsvcCheckedAt,
                    v.SsvcAssertedAt,
                    v.DependencyKind,
                    v.DependencyScope,
                    installScriptByComponentId.GetValueOrDefault(v.ComponentId),
                    affectedAppsByOsvId.GetValueOrDefault(v.OsvId),
                    v.IsMalicious),
                analysis?.VexState,
                analysis?.Reachability);

            arr.Add(entry);
        }

        return arr;
    }

    // ── Signal-property assembly, shared by every producer ───────────────────

    /// <summary>
    /// Every input <see cref="EffectivePriority.Derive"/> and the per-vulnerability property
    /// vocabulary need for one (component, advisory) pair, gathered from whichever producer's own
    /// row shapes so <see cref="BuildVulnProperties"/> has exactly one implementation shared by the
    /// VDR, collection, and standalone-VEX producers — the thing the fixture set that pairs them
    /// pins.
    /// </summary>
    private readonly record struct VulnSignalFacts(
        double? Cvss,
        double? NvdScore,
        string? NvdCheckedAt,
        string? NvdAssertedAt,
        bool IsKev,
        bool? IsKevRansomware,
        string? KevDueDate,
        string? KevDateAdded,
        string? KevRequiredAction,
        string? KevCwes,
        string? KevNotes,
        double? Epss,
        double? EpssPercentile,
        string? SsvcExploitation,
        string? SsvcAutomatable,
        string? SsvcTechnicalImpact,
        string? SsvcCheckedAt,
        string? SsvcAssertedAt,
        string? DependencyKind,
        string? DependencyScope,
        bool HasInstallScript,
        int AffectedApplications,
        bool IsMalicious);

    /// <summary>
    /// Builds the <c>properties[]</c> array for one vulnerability entry: the derived priority
    /// bucket (computed fresh here, per <see cref="EffectivePriority"/>'s never-materialize
    /// invariant) plus every exploitation/decision-support signal the platform holds for it.
    /// Fail-closed throughout: an absent signal is emitted as an explicit unknown value or
    /// omitted property, never a value a consumer could mistake for verified-benign.
    /// </summary>
    private static JsonArray BuildVulnProperties(VulnSignalFacts f, string? vexState, string? reachability)
    {
        // HasStaleEnrichment is unused by Derive's rule text (see EffectivePriority's own doc
        // comment), so it stays at VulnFacts' unknown default here — the same posture
        // SbomAnalysisProjection.BuildAdvisory takes for the live analysis surface.
        var vulnFacts = VulnFacts.None with
        {
            Cvss = f.Cvss,
            NvdScore = f.NvdScore,
            IsKev = f.IsKev,
            IsKevRansomware = f.IsKevRansomware,
            IsMalicious = f.IsMalicious,
            Epss = f.Epss,
            EpssPercentile = f.EpssPercentile,
            SsvcExploitation = f.SsvcExploitation,
        };
        var verdict = EffectivePriority.Derive(PriorityFacts.ForProjectsPlane(
            vulnFacts, vexState, reachability, f.DependencyKind, f.DependencyScope, f.HasInstallScript));

        var props = new JsonArray
        {
            Prop(DependablyExportProperties.Priority, verdict.Bucket),
            Prop(DependablyExportProperties.Unscored, BoolValue(verdict.Unscored)),
            Prop(DependablyExportProperties.Kev, BoolValue(f.IsKev)),
            Prop(DependablyExportProperties.KevRansomware, TriStateValue(f.IsKevRansomware)),
            Prop(DependablyExportProperties.SsvcExploitation, f.SsvcExploitation ?? DependablyExportProperties.UnknownValue),
            Prop(DependablyExportProperties.AffectedApplications, f.AffectedApplications.ToString(CultureInfo.InvariantCulture)),
        };

        if (f.KevDueDate is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevDueDate, f.KevDueDate));
        }

        if (f.KevDateAdded is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevDateAdded, f.KevDateAdded));
        }

        if (f.KevRequiredAction is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevRequiredAction, f.KevRequiredAction));
        }

        if (f.KevCwes is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevCwes, f.KevCwes));
        }

        if (f.KevNotes is not null)
        {
            props.Add(Prop(DependablyExportProperties.CisaKevNotes, f.KevNotes));
        }

        if (f.EpssPercentile is not null)
        {
            props.Add(Prop(DependablyExportProperties.EpssPercentile, f.EpssPercentile.Value.ToString(CultureInfo.InvariantCulture)));
        }

        if (f.SsvcAutomatable is not null)
        {
            props.Add(Prop(DependablyExportProperties.SsvcAutomatable, f.SsvcAutomatable));
        }

        if (f.SsvcTechnicalImpact is not null)
        {
            props.Add(Prop(DependablyExportProperties.SsvcTechnicalImpact, f.SsvcTechnicalImpact));
        }

        if (f.NvdScore is not null)
        {
            props.Add(Prop(DependablyExportProperties.NvdScore, f.NvdScore.Value.ToString(CultureInfo.InvariantCulture)));
        }

        // Raw freshness timestamps, never a computed stale/fresh boolean — the operator's staleness
        // horizon is a policy judgment this export surface does not own; the consumer compares the
        // timestamp to its own cutoff. A stale reading is exported as-is (never suppressed just
        // because it is old), the same "stale input is not absent input" posture ARCH-block-gate
        // states for the gate itself. Omitted only when there is no signal at all to date.
        string? nvdCheckedAt = EffectiveFreshness(f.NvdCheckedAt, f.NvdAssertedAt);
        if (nvdCheckedAt is not null)
        {
            props.Add(Prop(DependablyExportProperties.NvdCheckedAt, nvdCheckedAt));
        }

        string? ssvcCheckedAt = EffectiveFreshness(f.SsvcCheckedAt, f.SsvcAssertedAt);
        if (ssvcCheckedAt is not null)
        {
            props.Add(Prop(DependablyExportProperties.SsvcCheckedAt, ssvcCheckedAt));
        }

        return props;
    }

    /// <summary>
    /// <c>COALESCE(assertedAt, checkedAt)</c> — the same left-operand shape
    /// <c>VulnerabilityRepository</c>'s own gate-signal freshness queries evaluate against the
    /// operator's staleness cutoff, mirrored here (not reused — this file writes its own queries
    /// per the fleet contract) because the export boundary needs the same "as-of" preference
    /// without needing the cutoff comparison itself. Null when <paramref name="checkedAt"/> is
    /// null: no signal was ever checked, which is a different, unambiguous absence, not a
    /// staleness question <paramref name="assertedAt"/> alone could answer.
    /// </summary>
    private static string? EffectiveFreshness(string? checkedAt, string? assertedAt) =>
        checkedAt is null ? null : (assertedAt ?? checkedAt);
}
