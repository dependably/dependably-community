using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol;

namespace Dependably.Api;

/// <summary>
/// Merges one project version's stored facts into the analysis payload: components joined to their
/// advisories, advisories joined to the VEX/reachability statements recorded against them, policy
/// findings attached where they belong, and <see cref="EffectivePriority"/> derived per advisory.
///
/// <para>Pure and synchronous — every input arrives as an already-loaded list, so the whole merge
/// is assertable against frozen fixtures without a database.</para>
///
/// <para><b>Why the merge is in memory.</b> An analysis row is keyed by advisory <em>id as the
/// document cited it</em>, which is routinely a CVE while the advisory feed keys the same finding
/// under a GHSA. Resolving one to the other means reading <c>vulnerabilities.aliases</c>, an
/// unindexed JSON array; a SQL join on it does not exist. Effective priority is likewise derived
/// from four columns across three tables and is never materialized. Sorting by priority and
/// filtering by "has a violation on a visible advisory" therefore both need the merged view before
/// a page can be cut.</para>
///
/// <para><b>Rollup scope.</b> The rollup describes the whole version, not the filtered page — the
/// UI renders it as a header that must not move when someone types in the search box. The one
/// filter it honours is <c>suppressed</c>: severity counts exclude advisories a VEX statement has
/// suppressed unless the caller asked to see them, so the counts and the rows agree.</para>
/// </summary>
public static partial class SbomAnalysisProjection
{
    /// <summary>Largest page a caller may request.</summary>
    public const int MaxPageSize = 200;

    /// <summary>Page size applied when the caller names none.</summary>
    public const int DefaultPageSize = 50;

    /// <summary>Sort keys the endpoint accepts.</summary>
    public static readonly IReadOnlySet<string> SortKeys =
        new HashSet<string>(StringComparer.Ordinal) { "priority", "name", "version", "severity", "scope" };

    /// <summary>Scope filters the endpoint accepts. <c>all</c> is also what an omitted value means.</summary>
    public static readonly IReadOnlySet<string> ScopeFilters =
        new HashSet<string>(StringComparer.Ordinal) { "all", "prod", "dev" };

    /// <summary>Severity buckets the endpoint accepts as a filter, matching the rollup's own buckets.</summary>
    public static readonly IReadOnlySet<string> SeverityBuckets =
        new HashSet<string>(StringComparer.Ordinal) { "critical", "high", "medium", "low", "unscored" };

    /// <summary>Reachability values the endpoint accepts as a filter.</summary>
    public static readonly IReadOnlySet<string> ReachabilityFilters =
        new HashSet<string>(StringComparer.Ordinal) { "reachable", "not-observed", "unknown", "imported-not-called" };

    /// <summary>The bucket an advisory nobody scored is counted in — its own, never folded into "low".</summary>
    public const string UnscoredBucket = "unscored";

    [GeneratedRegex(@"\s+(?:AND|OR|WITH)\s+", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SpdxOperatorRegex();

    /// <summary>
    /// Builds the whole payload body for one version. <paramref name="versionCreatedAt"/> is the
    /// comparison point for the "inherited triage" signal:
    /// <see cref="Dependably.Infrastructure.ProjectRepository"/>'s
    /// <c>CarryForwardManualTriageAsync</c> seeds a freshly created version's manual VEX rows from
    /// its predecessor's, preserving their original <c>updated_by</c>/<c>updated_at</c> rather than
    /// restamping them, so a statement whose <c>UpdatedAt</c> predates this version's own creation
    /// was not decided <em>for</em> this release — it is rendered as inherited rather than as a
    /// fresh decision. Null (no version record to compare against, the shape every existing caller
    /// before this feature landed still passes) never claims a row is inherited: the absence of a
    /// comparison point is not evidence of one.
    /// </summary>
    public static AnalysisPage Build(
        AnalysisRows rows,
        IReadOnlyDictionary<string, ComponentRegistryFacts> registryFacts,
        string? policyStatus,
        AnalysisQuery query,
        DateTimeOffset? versionCreatedAt = null)
    {
        var (components, advisories, analysisRows, findings) = rows;

        var advisoriesByComponent = advisories
            .GroupBy(a => a.ComponentId, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<AnalysisAdvisoryRow>)g.ToList(), StringComparer.Ordinal);
        var findingsByComponent = findings
            .GroupBy(f => f.ComponentId, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<AnalysisFindingRow>)g.ToList(), StringComparer.Ordinal);
        var analysisByPurlKey = analysisRows
            .GroupBy(r => r.PurlKey, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<AnalysisVexRow>)g.ToList(), StringComparer.Ordinal);

        var claimedAnalysisRows = new HashSet<(string PurlKey, string VulnKey)>();
        var views = new List<AnalysisComponentView>(components.Count);
        foreach (var component in components)
        {
            views.Add(BuildComponent(
                component, advisoriesByComponent, findingsByComponent, analysisByPurlKey,
                registryFacts.GetValueOrDefault(component.Id), claimedAnalysisRows, versionCreatedAt));
        }

        // Analysis rows nobody claimed name a product this version's SBOM does not list. They are
        // surfaced in their own section rather than dropped: a VEX statement or a SARIF result
        // nobody can see is one nobody can correct.
        var orphans = analysisRows
            .Where(r => !claimedAnalysisRows.Contains((r.PurlKey, r.VulnKey)))
            .OrderBy(r => r.PurlKey, StringComparer.Ordinal)
            .ThenBy(r => r.VulnKey, StringComparer.Ordinal)
            .Select(r => BuildOrphan(r, versionCreatedAt))
            .ToList();

        var rollup = BuildRollup(components, views, findings, policyStatus, query.IncludeSuppressed);

        var filtered = views.Where(v => Matches(v, query)).ToList();
        var sorted = Sort(filtered, query);
        int offset = Math.Max(0, (query.Page - 1) * query.Limit);
        var page = sorted.Skip(offset).Take(query.Limit).ToList();

        return new AnalysisPage(rollup, page, orphans, filtered.Count);
    }

    private static AnalysisComponentView BuildComponent(
        AnalysisComponentRow component,
        IReadOnlyDictionary<string, IReadOnlyList<AnalysisAdvisoryRow>> advisoriesByComponent,
        IReadOnlyDictionary<string, IReadOnlyList<AnalysisFindingRow>> findingsByComponent,
        IReadOnlyDictionary<string, IReadOnlyList<AnalysisVexRow>> analysisByPurlKey,
        ComponentRegistryFacts? registryFacts,
        HashSet<(string PurlKey, string VulnKey)> claimedAnalysisRows,
        DateTimeOffset? versionCreatedAt)
    {
        string? purlKey = PurlKeyFor(component);
        var componentFindings = findingsByComponent.TryGetValue(component.Id, out var f)
            ? f : Array.Empty<AnalysisFindingRow>();
        var candidateAnalysis = purlKey is not null && analysisByPurlKey.TryGetValue(purlKey, out var rows)
            ? rows : Array.Empty<AnalysisVexRow>();
        var linked = advisoriesByComponent.TryGetValue(component.Id, out var a)
            ? a : Array.Empty<AnalysisAdvisoryRow>();

        var advisoryViews = new List<AnalysisAdvisoryView>(linked.Count);
        var matchedForThisComponent = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var advisory in linked)
        {
            var identifiers = IdentifiersOf(advisory);
            var statement = candidateAnalysis.FirstOrDefault(r => identifiers.Contains(r.VulnKey));
            if (statement is not null)
            {
                claimedAnalysisRows.Add((statement.PurlKey, statement.VulnKey));
                matchedForThisComponent.Add(statement.VulnKey);
            }

            string vulnKey = statement?.VulnKey ?? advisory.OsvId;
            advisoryViews.Add(BuildAdvisory(
                vulnKey, advisory, identifiers, statement, componentFindings, versionCreatedAt, component, registryFacts));
        }

        // A statement citing an advisory the scanner never linked to this component still belongs on
        // the component — its product purl matched. It is rendered from the statement alone, with no
        // score, which is exactly the "we were told about this, nobody scored it" case the UNSCORED
        // bucket exists for.
        foreach (var statement in candidateAnalysis)
        {
            if (matchedForThisComponent.Contains(statement.VulnKey))
            {
                continue;
            }

            claimedAnalysisRows.Add((statement.PurlKey, statement.VulnKey));
            advisoryViews.Add(BuildAdvisory(
                statement.VulnKey, advisory: null,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { statement.VulnKey },
                statement, componentFindings, versionCreatedAt, component, registryFacts));
        }

        advisoryViews.Sort(static (x, y) =>
        {
            int byPriority = EffectivePriority.RankOf(y.EffectivePriority).CompareTo(EffectivePriority.RankOf(x.EffectivePriority));
            return byPriority != 0 ? byPriority : string.CompareOrdinal(x.VulnKey, y.VulnKey);
        });

        bool isDev = string.Equals(component.DependencyScope, "dev", StringComparison.Ordinal);
        bool isExcluded = string.Equals(component.SbomScope, "excluded", StringComparison.Ordinal);

        var resolvedMetadata = ComponentMetadataResolver.Resolve(component, registryFacts);

        return new AnalysisComponentView
        {
            ComponentId = component.Id,
            Purl = component.Purl,
            PurlKey = purlKey,
            Name = component.Name,
            Version = component.Version,
            Ecosystem = component.Ecosystem,
            PurlName = component.PurlName,
            ComponentType = component.ComponentType,
            SbomScope = component.SbomScope,
            DependencyScope = component.DependencyScope,
            IsProd = !isDev && !isExcluded,
            IsDev = isDev,
            DependencyKind = component.DependencyKind,
            DependencyPath = ParseJsonArray(component.DependencyPath),
            LicenseSpdx = component.LicenseSpdx,
            // The registry's own record of the package wins over the uploaded document's
            // description of it, field by field — see ComponentMetadataResolver.
            Description = resolvedMetadata.Description,
            Author = resolvedMetadata.Author,
            WebsiteUrl = resolvedMetadata.WebsiteUrl,
            VcsUrl = resolvedMetadata.VcsUrl,
            MetadataSource = resolvedMetadata.Source,
            // No registry equivalent exists for these, so they are the document's alone.
            Copyright = component.Copyright,
            Group = component.ComponentGroup,
            IssueTrackerUrl = component.IssueTrackerUrl,
            DistributionUrl = component.DistributionUrl,
            Hashes = ParseJsonArray(component.ComponentHashes),
            Registry = SbomRegistryView.For(
                component.Ecosystem, component.PurlName, component.Version, registryFacts),
            Advisories = advisoryViews,
            PolicyViolations = componentFindings
                .Select(x => new AnalysisPolicyViolationView(x.Arm, x.Detail, x.VulnKey, x.LicenseSpdx))
                .ToList(),
        };
    }

    private static AnalysisAdvisoryView BuildAdvisory(
        string vulnKey,
        AnalysisAdvisoryRow? advisory,
        IReadOnlySet<string> identifiers,
        AnalysisVexRow? statement,
        IReadOnlyList<AnalysisFindingRow> componentFindings,
        DateTimeOffset? versionCreatedAt,
        AnalysisComponentRow component,
        ComponentRegistryFacts? registryFacts)
    {
        // HasStaleEnrichment is unused by Derive's rule text, so it stays at VulnFacts' unknown
        // default here rather than reaching further into `advisory`.
        var verdict = EffectivePriority.Derive(PriorityFacts.ForProjectsPlane(
            VulnFacts.None with
            {
                Cvss = advisory?.CvssScore,
                NvdScore = advisory?.NvdScore,
                IsKev = advisory?.IsKev ?? false,
                IsKevRansomware = advisory?.IsKevRansomware,
                IsMalicious = advisory?.IsMalicious ?? false,
                Epss = advisory?.EpssScore,
                EpssPercentile = advisory?.EpssPercentile,
                SsvcExploitation = advisory?.SsvcExploitation,
            },
            statement?.VexState,
            statement?.Reachability,
            component.DependencyKind,
            component.DependencyScope,
            registryFacts?.HasInstallScriptThisVersion ?? false));

        return new AnalysisAdvisoryView
        {
            VulnKey = vulnKey,
            OsvId = advisory?.OsvId,
            Aliases = advisory is null ? Array.Empty<string>() : ParseAliases(advisory.Aliases),
            Severity = advisory?.Severity,
            Cvss = advisory?.CvssScore,
            IsKev = advisory?.IsKev ?? false,
            IsKevRansomware = advisory?.IsKevRansomware,
            Epss = advisory?.EpssScore,
            EffectivePriority = verdict.Bucket,
            Unscored = verdict.Unscored,
            VexState = statement?.VexState,
            VexJustification = statement?.VexJustification,
            VexResponse = statement?.VexResponse,
            VexDetail = statement?.VexDetail,
            VexSource = statement?.VexSource,
            VexUpdatedBy = statement?.UpdatedBy,
            VexUpdatedAt = statement?.UpdatedAt,
            Reachability = statement?.Reachability,
            Confidence = statement?.Confidence,
            SarifSuppressed = statement?.SarifSuppressed ?? false,
            SecuritySeverity = statement?.SecuritySeverity,
            SeverityOrigin = statement?.SeverityOrigin,
            Inherited = IsInherited(statement, versionCreatedAt),
            SeverityBucket = SeverityBucketOf(advisory?.Severity, verdict.Unscored),
            PolicyViolations = componentFindings
                .Where(x => x.VulnKey is not null
                            && (identifiers.Contains(x.VulnKey)
                                || string.Equals(x.VulnKey, vulnKey, StringComparison.OrdinalIgnoreCase)))
                .Select(x => new AnalysisPolicyViolationView(x.Arm, x.Detail, x.VulnKey, x.LicenseSpdx))
                .ToList(),
        };
    }

    private static AnalysisOrphanView BuildOrphan(AnalysisVexRow row, DateTimeOffset? versionCreatedAt) => new()
    {
        PurlKey = row.PurlKey,
        VulnKey = row.VulnKey,
        VexState = row.VexState,
        VexJustification = row.VexJustification,
        VexResponse = row.VexResponse,
        VexDetail = row.VexDetail,
        VexSource = row.VexSource,
        VexUpdatedBy = row.UpdatedBy,
        VexUpdatedAt = row.UpdatedAt,
        Reachability = row.Reachability,
        Confidence = row.Confidence,
        SarifSuppressed = row.SarifSuppressed,
        SecuritySeverity = row.SecuritySeverity,
        SeverityOrigin = row.SeverityOrigin,
        Inherited = IsInherited(row, versionCreatedAt),
    };

    /// <summary>
    /// True when a VEX/reachability statement's <c>UpdatedAt</c> predates the project version it
    /// is now rendered against — the signal that <c>ProjectRepository.CarryForwardManualTriageAsync</c>
    /// carried manual triage forward onto a new version rather than an operator having decided it
    /// for this release. Null
    /// <paramref name="versionCreatedAt"/> (no comparison point supplied) and a null
    /// <paramref name="statement"/> both answer false: the absence of a fact is never rendered as
    /// the fact itself.
    /// </summary>
    private static bool IsInherited(AnalysisVexRow? statement, DateTimeOffset? versionCreatedAt) =>
        statement is not null && versionCreatedAt is { } createdAt && statement.UpdatedAt < createdAt;

    private static AnalysisRollup BuildRollup(
        IReadOnlyList<AnalysisComponentRow> components,
        IReadOnlyList<AnalysisComponentView> views,
        IReadOnlyList<AnalysisFindingRow> findings,
        string? policyStatus,
        bool includeSuppressed)
    {
        var (severityCounts, priorityCounts) = CountAdvisories(views, includeSuppressed);
        var (licenseIdentifiers, undeclared) = CountLicences(components);

        DateTimeOffset? lastScanAt = components
            .Where(c => c.VulnCheckedAt is not null)
            .Select(c => c.VulnCheckedAt!.Value)
            .DefaultIfEmpty()
            .Max();
        if (lastScanAt == default(DateTimeOffset))
        {
            lastScanAt = null;
        }

        return new AnalysisRollup(
            ComponentTotal: components.Count,
            ProdCount: views.Count(v => v.IsProd),
            DevCount: views.Count(v => v.IsDev),
            UnknownScopeCount: components.Count(c => string.Equals(c.DependencyScope, "unknown", StringComparison.Ordinal)),
            UnscannableCount: components.Count(c => !SbomScannableComponents.IsScannable(c.Ecosystem, c.Purl)),
            ScopeSuppressedCount: components.Count(c =>
                string.Equals(c.SbomScope, SbomPolicyEvaluator.ExcludedSbomScope, StringComparison.Ordinal)),
            RegistryCounts: new AnalysisRegistryCounts(
                InRegistry: views.Count(v => v.Registry.Presence == RegistryPresence.Present),
                NotInRegistry: views.Count(v => v.Registry.Presence == RegistryPresence.Absent),
                Unknown: views.Count(v => v.Registry.Presence == RegistryPresence.Unknown)),
            SeverityCounts: severityCounts,
            PriorityCounts: priorityCounts,
            LicenseCounts: new AnalysisLicenseCounts(
                Total: components.Count,
                Declared: components.Count - undeclared,
                Undeclared: undeclared,
                ByIdentifier: licenseIdentifiers
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase)),
            PolicyStatus: policyStatus,
            ViolationCount: findings.Count,
            LastScanAt: lastScanAt);
    }

    /// <summary>
    /// The severity and effective-priority histograms. Priority counts every advisory including the
    /// suppressed ones — that bucket is one of the four — while severity honours the caller's
    /// include-suppressed choice, because a suppressed finding is not part of the risk picture the
    /// severity chart states.
    /// </summary>
    private static (Dictionary<string, int> Severity, Dictionary<string, int> Priority) CountAdvisories(
        IReadOnlyList<AnalysisComponentView> views, bool includeSuppressed)
    {
        var severityCounts = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["critical"] = 0,
            ["high"] = 0,
            ["medium"] = 0,
            ["low"] = 0,
            [UnscoredBucket] = 0,
        };
        var priorityCounts = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [EffectivePriority.Act] = 0,
            [EffectivePriority.Attend] = 0,
            [EffectivePriority.Track] = 0,
            [EffectivePriority.Suppressed] = 0,
        };

        foreach (var advisory in views.SelectMany(v => v.Advisories))
        {
            if (priorityCounts.TryGetValue(advisory.EffectivePriority, out int seenSoFar))
            {
                priorityCounts[advisory.EffectivePriority] = seenSoFar + 1;
            }

            if (!advisory.IsSuppressed || includeSuppressed)
            {
                severityCounts[advisory.SeverityBucket]++;
            }
        }

        return (severityCounts, priorityCounts);
    }

    /// <summary>
    /// How many components carry each SPDX identifier, and how many declare none at all. A compound
    /// expression counts once per identifier it names.
    /// </summary>
    private static (Dictionary<string, int> ByIdentifier, int Undeclared) CountLicences(
        IReadOnlyList<AnalysisComponentRow> components)
    {
        var byIdentifier = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int undeclared = 0;

        foreach (var component in components)
        {
            var identifiers = SplitSpdx(component.LicenseSpdx);
            if (identifiers.Count == 0)
            {
                undeclared++;
                continue;
            }

            foreach (string identifier in identifiers)
            {
                byIdentifier[identifier] = byIdentifier.GetValueOrDefault(identifier) + 1;
            }
        }

        return (byIdentifier, undeclared);
    }

    private static bool Matches(AnalysisComponentView view, AnalysisQuery query)
    {
        if (query.Q is { Length: > 0 } needle
            && !Contains(view.Name, needle) && !Contains(view.Purl, needle))
        {
            return false;
        }

        if (string.Equals(query.Scope, "prod", StringComparison.Ordinal) && !view.IsProd)
        {
            return false;
        }

        if (string.Equals(query.Scope, "dev", StringComparison.Ordinal) && !view.IsDev)
        {
            return false;
        }

        if (query.ViolationsOnly && view.PolicyViolations.Count == 0)
        {
            return false;
        }

        if (query.Registry is { Length: > 0 } registry
            && !string.Equals(view.Registry.Presence, registry, StringComparison.Ordinal))
        {
            return false;
        }

        // The severity and reachability filters read the advisories the caller can actually see, so a
        // component whose only high-severity advisory has been suppressed drops out of a sev=high
        // page exactly as it drops out of the rollup's high count.
        var visible = view.Advisories.Where(x => query.IncludeSuppressed || !x.IsSuppressed).ToList();

        bool severityMatches = query.Sev is not { Length: > 0 } severity
            || visible.Any(x => string.Equals(x.SeverityBucket, severity, StringComparison.Ordinal));
        bool reachMatches = query.Reach is not { Length: > 0 } reach
            || visible.Any(x => string.Equals(
                EffectivePriority.NormalizeReachability(x.Reachability), reach, StringComparison.Ordinal));

        return severityMatches && reachMatches;
    }

    private static bool Contains(string? haystack, string needle) =>
        haystack is not null && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private static List<AnalysisComponentView> Sort(List<AnalysisComponentView> views, AnalysisQuery query)
    {
        bool descending = string.Equals(query.Dir, "desc", StringComparison.Ordinal);
        Comparison<AnalysisComponentView> primary = query.Sort switch
        {
            "name" => (x, y) => string.CompareOrdinal(x.Name, y.Name),
            "version" => (x, y) => string.CompareOrdinal(x.Version ?? "", y.Version ?? ""),
            "scope" => (x, y) => string.CompareOrdinal(x.DependencyScope, y.DependencyScope),
            "severity" => (x, y) => SeverityRank(x, query.IncludeSuppressed).CompareTo(SeverityRank(y, query.IncludeSuppressed)),
            _ => (x, y) => PriorityRank(x, query.IncludeSuppressed).CompareTo(PriorityRank(y, query.IncludeSuppressed)),
        };

        var sorted = new List<AnalysisComponentView>(views);
        // The tiebreak stays ascending regardless of direction: two rows with the same priority must
        // land in the same relative order on every request, or a reader paging through the table
        // sees a row twice and never sees another.
        sorted.Sort((x, y) =>
        {
            int result = primary(x, y);
            if (result != 0)
            {
                return descending ? -result : result;
            }

            int byName = string.CompareOrdinal(x.Name, y.Name);
            return byName != 0 ? byName : string.CompareOrdinal(x.ComponentId, y.ComponentId);
        });
        return sorted;
    }

    private static int PriorityRank(AnalysisComponentView view, bool includeSuppressed) =>
        view.Advisories
            .Where(x => includeSuppressed || !x.IsSuppressed)
            .Select(x => EffectivePriority.RankOf(x.EffectivePriority))
            .DefaultIfEmpty(0)
            .Max();

    private static int SeverityRank(AnalysisComponentView view, bool includeSuppressed) =>
        view.Advisories
            .Where(x => includeSuppressed || !x.IsSuppressed)
            .Select(x => SeverityBucketRank(x.SeverityBucket))
            .DefaultIfEmpty(0)
            .Max();

    private static int SeverityBucketRank(string bucket) => bucket switch
    {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    };

    /// <summary>
    /// The bucket an advisory is counted in. Unscored wins over a declared band: an advisory whose
    /// feed carries a label but no score is an open question, and reporting it as "high" would
    /// claim a precision nobody produced.
    /// </summary>
    public static string SeverityBucketOf(string? severity, bool unscored)
    {
        if (unscored || string.IsNullOrWhiteSpace(severity))
        {
            return UnscoredBucket;
        }

        string lowered = severity.Trim().ToLowerInvariant();
        return SeverityBuckets.Contains(lowered) ? lowered : UnscoredBucket;
    }

    /// <summary>
    /// The version-less canonical purl an analysis row is keyed by. Null when the component
    /// declared no purl, or one whose type has no registry mapping — such a component can carry
    /// inventory and licence facts but never a VEX statement, because there is nothing to key one
    /// on.
    /// </summary>
    public static string? PurlKeyFor(AnalysisComponentRow component) =>
        SbomPurlKey.ForComponent(component.Ecosystem, component.PurlName, component.Purl);

    /// <summary>Every id this advisory answers to: its own OSV id plus every alias it records.</summary>
    private static IReadOnlySet<string> IdentifiersOf(AnalysisAdvisoryRow advisory)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { advisory.OsvId };
        foreach (string alias in ParseAliases(advisory.Aliases))
        {
            set.Add(alias);
        }

        return set;
    }

    /// <summary>
    /// Alias ids from the stored JSON array. A malformed value yields none rather than throwing —
    /// the column is written by an upstream feed, and one bad row must not take the page down.
    /// </summary>
    public static IReadOnlyList<string> ParseAliases(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<string>();
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// The stored dependency-path JSON, re-emitted as-is. Entries may be plain purl strings or
    /// richer objects depending on the producer, so the node is passed through rather than coerced;
    /// a value that is not an array at all yields none.
    /// </summary>
    // Null is not an empty path — it is "this component recorded no dependency path at all",
    // which the payload carries as a null field. Returning `[]` would tell the SPA the graph was
    // walked and found nothing, which is a different fact.
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "null distinguishes 'no recorded path' from 'an empty path' on the wire.")]
    public static JsonArray? ParseJsonArray(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(json) as JsonArray;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// The distinct SPDX identifiers a declared expression names. A compound expression is split on
    /// its operators so a licence blocklist can be matched per identifier, which is the same split
    /// the licence policy evaluator applies.
    /// </summary>
    public static IReadOnlyCollection<string> SplitSpdx(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
        {
            return Array.Empty<string>();
        }

        var identifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string part in SpdxOperatorRegex().Split(expression))
        {
            string trimmed = part.Replace("(", "").Replace(")", "").Trim();
            if (trimmed.Length > 0)
            {
                identifiers.Add(trimmed);
            }
        }

        return identifiers;
    }
}

/// <summary>
/// The four row sets one analysis page is projected from, bundled so <see cref="SbomAnalysisProjection.Build"/>
/// keeps a signature a reader can hold: they are always loaded together, for one project version,
/// and none of them means anything without the others.
/// </summary>
public sealed record AnalysisRows(
    IReadOnlyList<AnalysisComponentRow> Components,
    IReadOnlyList<AnalysisAdvisoryRow> Advisories,
    IReadOnlyList<AnalysisVexRow> Analysis,
    IReadOnlyList<AnalysisFindingRow> Findings);

/// <summary>Validated filter/pagination state for one analysis read.</summary>
public sealed record AnalysisQuery(
    int Page,
    int Limit,
    string Sort,
    string Dir,
    string? Q,
    string? Scope,
    string? Sev,
    string? Reach,
    string? Registry,
    bool ViolationsOnly,
    bool IncludeSuppressed);

/// <summary>
/// Version-wide registry cross-link tally, summing to the component total.
///
/// <para><see cref="NotInRegistry"/> is the blind-spot count: a real coordinate this registry has
/// never served, so nothing it enforces — block state, licence policy, provenance, the advisory
/// scan — has ever applied to those bytes. <see cref="Unknown"/> is kept separate rather than
/// folded in, because a component with no purl is a question the registry cannot be asked, and
/// answering it "never vetted" would inflate the number an operator is meant to act on.</para>
/// </summary>
public sealed record AnalysisRegistryCounts(int InRegistry, int NotInRegistry, int Unknown);

/// <summary>The merged body of one analysis read: header rollup, the page of rows, and the orphans.</summary>
public sealed record AnalysisPage(
    AnalysisRollup Rollup,
    IReadOnlyList<AnalysisComponentView> Items,
    IReadOnlyList<AnalysisOrphanView> Orphans,
    int Total);

/// <summary>
/// Version-wide header counts. Never narrowed by the row filters.
/// <see cref="RegistryCounts"/> is the registry cross-link tally — most usefully its
/// <see cref="AnalysisRegistryCounts.NotInRegistry"/> arm, the components the application ships
/// that this registry has never served and therefore never gated.
/// <see cref="UnscannableCount"/> is how many components no advisory query can ever answer for
/// (no purl, no ecosystem, or an ecosystem OSV publishes no feed for). Those rows are excluded
/// from the policy rollup's unscanned arm, so the count is reported here rather than dropped —
/// an unanswerable component is a fact about the SBOM, not a verdict about the version.
/// </summary>
public sealed record AnalysisRollup(
    int ComponentTotal,
    int ProdCount,
    int DevCount,
    int UnknownScopeCount,
    int UnscannableCount,
    // Components the SBOM's own producer marked scope='excluded' — bytes that do not ship in the
    // assembled deliverable, so the four vulnerability arms exempt them (the licence arm still
    // evaluates them; see Dependably.Protocol.SbomPolicyEvaluator). Reported beside
    // UnscannableCount in the same honest-uncertainty style: the exemption is otherwise
    // invisible, and a component nothing scored for a documented reason is a different fact than
    // one nothing scored at all.
    int ScopeSuppressedCount,
    AnalysisRegistryCounts RegistryCounts,
    IReadOnlyDictionary<string, int> SeverityCounts,
    IReadOnlyDictionary<string, int> PriorityCounts,
    AnalysisLicenseCounts LicenseCounts,
    string? PolicyStatus,
    int ViolationCount,
    DateTimeOffset? LastScanAt);

/// <summary>
/// Version-wide licence tally. <see cref="Undeclared"/> is reported beside the identifier counts
/// because a component that declared no licence is an open question, not a clean result.
/// </summary>
public sealed record AnalysisLicenseCounts(
    int Total,
    int Declared,
    int Undeclared,
    IReadOnlyDictionary<string, int> ByIdentifier);

/// <summary>One component row of the analysis page.</summary>
public sealed class AnalysisComponentView
{
    public string ComponentId { get; init; } = "";
    public string? Purl { get; init; }
    /// <summary>Version-less canonical purl — the key a triage write is addressed by.</summary>
    public string? PurlKey { get; init; }
    public string Name { get; init; } = "";
    public string? Version { get; init; }
    public string? Ecosystem { get; init; }
    public string? PurlName { get; init; }
    public string? ComponentType { get; init; }
    public string? SbomScope { get; init; }
    public string DependencyScope { get; init; } = "unknown";
    public bool IsProd { get; init; }
    public bool IsDev { get; init; }
    public string? DependencyKind { get; init; }
    public JsonArray? DependencyPath { get; init; }
    public string? LicenseSpdx { get; init; }
    /// <summary>
    /// Presentation metadata the component's own SBOM entry carried. Every field is display-only
    /// and null for a component whose producer omitted it — and null for every row written before
    /// ingest recorded these, until that document is re-merged.
    /// </summary>
    public string? Description { get; init; }
    public string? Author { get; init; }
    public string? Copyright { get; init; }
    public string? Group { get; init; }
    public string? WebsiteUrl { get; init; }
    public string? VcsUrl { get; init; }
    public string? IssueTrackerUrl { get; init; }
    public string? DistributionUrl { get; init; }
    /// <summary>components[].hashes as parsed JSON, or null. Display and export only.</summary>
    public JsonArray? Hashes { get; init; }
    /// <summary>
    /// Which source answered for the four fields both planes can describe: <c>registry</c>,
    /// <c>sbom</c>, <c>mixed</c>, or null when neither carried anything. Rendered so a reader can
    /// tell a fact this instance observed from one an uploaded document asserted.
    /// </summary>
    public string? MetadataSource { get; init; }
    /// <summary>What this tenant's own registry knows about the component's coordinate.</summary>
    public ComponentRegistryView Registry { get; init; } = ComponentRegistryView.Unknown;
    public IReadOnlyList<AnalysisAdvisoryView> Advisories { get; init; } = Array.Empty<AnalysisAdvisoryView>();
    /// <summary>Every finding on this component, including the licence arm, which names no advisory.</summary>
    public IReadOnlyList<AnalysisPolicyViolationView> PolicyViolations { get; init; } =
        Array.Empty<AnalysisPolicyViolationView>();
}

/// <summary>One advisory recorded against a component, with its derived bucket.</summary>
public sealed class AnalysisAdvisoryView
{
    public string VulnKey { get; init; } = "";
    public string? OsvId { get; init; }
    public IReadOnlyList<string> Aliases { get; init; } = Array.Empty<string>();
    public string? Severity { get; init; }
    public double? Cvss { get; init; }
    public bool IsKev { get; init; }
    /// <summary>Tri-state: see <see cref="Dependably.Infrastructure.VulnFacts.IsKevRansomware"/> for the null/false distinction.</summary>
    public bool? IsKevRansomware { get; init; }
    public double? Epss { get; init; }
    public string EffectivePriority { get; init; } = "";
    public bool Unscored { get; init; }
    /// <summary>Which rollup bucket this advisory is counted in.</summary>
    public string SeverityBucket { get; init; } = SbomAnalysisProjection.UnscoredBucket;
    public string? VexState { get; init; }
    public string? VexJustification { get; init; }
    public string? VexResponse { get; init; }
    public string? VexDetail { get; init; }
    public string? VexSource { get; init; }
    public string? VexUpdatedBy { get; init; }
    public DateTimeOffset? VexUpdatedAt { get; init; }
    public string? Reachability { get; init; }
    public string? Confidence { get; init; }
    public bool SarifSuppressed { get; init; }
    public double? SecuritySeverity { get; init; }
    public string? SeverityOrigin { get; init; }
    /// <summary>
    /// True when this statement's provenance predates the project version it is rendered
    /// against — a decision carried forward from an earlier release rather than made for this
    /// one. See <see cref="SbomAnalysisProjection.IsInherited"/>.
    /// </summary>
    public bool Inherited { get; init; }
    public IReadOnlyList<AnalysisPolicyViolationView> PolicyViolations { get; init; } =
        Array.Empty<AnalysisPolicyViolationView>();

    /// <summary>True when a VEX statement put this advisory in the suppressed bucket.</summary>
    public bool IsSuppressed =>
        string.Equals(EffectivePriority, Dependably.Infrastructure.EffectivePriority.Suppressed, StringComparison.Ordinal);
}

/// <summary>One policy verdict: which arm fired, and over what.</summary>
public sealed record AnalysisPolicyViolationView(string Arm, string? Detail, string? VulnKey, string? LicenseSpdx);

/// <summary>An analysis row naming a product this version's SBOM does not list.</summary>
public sealed class AnalysisOrphanView
{
    public string PurlKey { get; init; } = "";
    public string VulnKey { get; init; } = "";
    public string? VexState { get; init; }
    public string? VexJustification { get; init; }
    public string? VexResponse { get; init; }
    public string? VexDetail { get; init; }
    public string? VexSource { get; init; }
    public string? VexUpdatedBy { get; init; }
    public DateTimeOffset? VexUpdatedAt { get; init; }
    public string? Reachability { get; init; }
    public string? Confidence { get; init; }
    public bool SarifSuppressed { get; init; }
    public double? SecuritySeverity { get; init; }
    public string? SeverityOrigin { get; init; }
    /// <summary>See <see cref="AnalysisAdvisoryView.Inherited"/>.</summary>
    public bool Inherited { get; init; }
}
