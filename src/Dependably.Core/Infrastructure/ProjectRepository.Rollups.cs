using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// The read-time subtree rollups a collection page renders, and the row types they load. One
/// set of queries answers a whole page however many collections it holds: the tree is walked a
/// level at a time, the per-project facts are fetched in batches, and the folding is pure over
/// the dictionaries that produced.
/// </summary>
public sealed partial class ProjectRepository
{
    /// <summary>
    /// Every descendant project of each given collection, keyed by that collection, walked one
    /// level per query. Collections nest, so the frontier is re-seeded with the collections found
    /// at each level until it empties or <see cref="MaxTreeDepth"/> is reached.
    ///
    /// A recursive CTE would do this in one round trip; it is deliberately not used. The anchor
    /// would be seeded in one org and the recursive term follows <c>parent_id</c>, so a single
    /// mis-scoped join condition silently walks into another tenant's tree — a class of bug the
    /// level-at-a-time form cannot express, because every query names <c>org_id</c> on its own.
    /// The depth of a folder tree someone maintains by hand is single digits, so the round trips
    /// are bounded by that rather than by the number of projects.
    /// </summary>
    private static async Task<Dictionary<string, List<string>>> DescendantProjectsAsync(
        DbConnection conn, string orgId, IReadOnlyCollection<string> collectionIds, CancellationToken ct)
    {
        if (collectionIds.Count == 0)
        {
            return [];
        }

        var (parentOf, projectIds) = await DescendTreeAsync(conn, orgId, collectionIds, ct);
        return GroupByOwningCollection(collectionIds, parentOf, projectIds);
    }

    /// <summary>
    /// Walks down from the given collections one level at a time. Returns the childId -> parentId
    /// map accumulated across every level — so a project found three levels down can be walked back
    /// up to whichever page collection owns it — and every non-collection descendant reached.
    /// </summary>
    private static async Task<(Dictionary<string, string> ParentOf, List<string> ProjectIds)> DescendTreeAsync(
        DbConnection conn, string orgId, IReadOnlyCollection<string> collectionIds, CancellationToken ct)
    {
        var parentOf = new Dictionary<string, string>(StringComparer.Ordinal);
        var projectIds = new List<string>();
        var frontier = collectionIds.Distinct(StringComparer.Ordinal).ToList();
        var visited = new HashSet<string>(frontier, StringComparer.Ordinal);

        for (int depth = 0; frontier.Count > 0 && depth < MaxTreeDepth; depth++)
        {
            var children = (await conn.QueryAsync<ProjectTreeRow>(new CommandDefinition(
                """
                SELECT c.id AS Id, c.parent_id AS ParentId, c.kind AS Kind
                FROM projects c
                WHERE c.org_id = @orgId AND c.parent_id IN @frontier
                """,
                new { orgId, frontier }, cancellationToken: ct))).AsList();

            var next = new List<string>();
            foreach (var child in children)
            {
                // A cycle cannot be created through the API, but this reads whatever the table
                // holds; the visited set makes an existing one terminate instead of looping.
                if (child.ParentId is null || !visited.Add(child.Id))
                {
                    continue;
                }

                parentOf[child.Id] = child.ParentId;
                if (string.Equals(child.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
                {
                    next.Add(child.Id);
                }
                else
                {
                    projectIds.Add(child.Id);
                }
            }

            frontier = next;
        }

        return (parentOf, projectIds);
    }

    /// <summary>
    /// Attributes each descendant project to the page collection that owns it by climbing parent
    /// links. Bounded by the same depth the descent was, so a chain the descent could not have
    /// produced still terminates here.
    /// </summary>
    private static Dictionary<string, List<string>> GroupByOwningCollection(
        IReadOnlyCollection<string> collectionIds,
        Dictionary<string, string> parentOf,
        List<string> projectIds)
    {
        var roots = new HashSet<string>(collectionIds, StringComparer.Ordinal);
        var result = collectionIds.Distinct(StringComparer.Ordinal)
            .ToDictionary(id => id, _ => new List<string>(), StringComparer.Ordinal);

        foreach (string projectId in projectIds)
        {
            string? cursor = parentOf.GetValueOrDefault(projectId);
            for (int hop = 0; cursor is not null && hop < MaxTreeDepth; hop++)
            {
                if (roots.Contains(cursor))
                {
                    result[cursor].Add(projectId);
                    break;
                }

                cursor = parentOf.GetValueOrDefault(cursor);
            }
        }

        return result;
    }

    /// <summary>
    /// The <c>is_latest</c> version of each given project, absent from the result for a project
    /// holding no version at all — which the callers read as "never evaluated", not as a pass.
    /// </summary>
    private static async Task<Dictionary<string, LatestVersionRow>> LatestVersionsAsync(
        DbConnection conn, string orgId, IReadOnlyCollection<string> projectIds, CancellationToken ct)
    {
        if (projectIds.Count == 0)
        {
            return [];
        }

        var rows = await conn.QueryAsync<LatestVersionRow>(new CommandDefinition(
            """
            SELECT v.project_id AS ProjectId, v.id AS VersionId, v.version AS VersionLabel,
                   v.policy_status AS PolicyStatus
            FROM project_versions v
            WHERE v.org_id = @orgId AND v.project_id IN @projectIds AND v.is_latest = 1
            """,
            new { orgId, projectIds }, cancellationToken: ct));

        return rows.ToDictionary(r => r.ProjectId, r => r, StringComparer.Ordinal);
    }

    /// <summary>
    /// Sums one already-loaded set of descendant projects into the rollup a collection renders.
    /// Pure over the dictionaries the caller fetched, so the whole page costs one set of queries
    /// however many collections it holds.
    /// </summary>
    private static ProjectSubtreeRollup Fold(
        IReadOnlyList<string> descendantProjectIds,
        IReadOnlyDictionary<string, LatestVersionRow> latest,
        IReadOnlyDictionary<string, int> componentCounts,
        IReadOnlyDictionary<string, SeverityCounts> severityCounts,
        IReadOnlyDictionary<string, DateTimeOffset> lastUploads)
    {
        var rollup = new ProjectSubtreeRollup { ProjectCount = descendantProjectIds.Count };
        var statuses = new List<string?>(descendantProjectIds.Count);

        foreach (string projectId in descendantProjectIds)
        {
            var version = latest.GetValueOrDefault(projectId);
            statuses.Add(version?.PolicyStatus);

            if (ProjectPolicyRollup.Worst([version?.PolicyStatus]) is null)
            {
                rollup.UnevaluatedProjectCount++;
            }

            if (version is not null)
            {
                rollup.ComponentCount += componentCounts.GetValueOrDefault(version.VersionId);
                var counts = severityCounts.GetValueOrDefault(version.VersionId);
                if (counts is not null)
                {
                    rollup.SeverityCounts.Critical += counts.Critical;
                    rollup.SeverityCounts.High += counts.High;
                    rollup.SeverityCounts.Medium += counts.Medium;
                    rollup.SeverityCounts.Low += counts.Low;
                    rollup.SeverityCounts.Unscored += counts.Unscored;
                    rollup.SeverityCounts.KevCount += counts.KevCount;
                }
            }

            if (lastUploads.TryGetValue(projectId, out var stamp) &&
                (rollup.LastUploadAt is null || stamp > rollup.LastUploadAt))
            {
                rollup.LastUploadAt = stamp;
            }
        }

        rollup.PolicyStatus = ProjectPolicyRollup.Worst(statuses);
        return rollup;
    }

    private static async Task<Dictionary<string, int>> ComponentCountsAsync(
        DbConnection conn, string orgId, IReadOnlyCollection<string> versionIds, CancellationToken ct)
    {
        if (versionIds.Count == 0)
        {
            return [];
        }

        var rows = await conn.QueryAsync<ComponentCountRow>(new CommandDefinition(
            """
            SELECT c.project_version_id AS ProjectVersionId, COUNT(*) AS ComponentCount
            FROM sbom_components c
            WHERE c.org_id = @orgId AND c.project_version_id IN @versionIds
            GROUP BY c.project_version_id
            """,
            new { orgId, versionIds }, cancellationToken: ct));

        return rows.ToDictionary(r => r.ProjectVersionId, r => r.ComponentCount, StringComparer.Ordinal);
    }

    // Counts component-advisory pairs, not distinct advisories: one advisory affecting three
    // components is three things to fix, which is what the list's severity chips are read as.
    // sbom_component_vulns carries no org_id of its own — it is reached only through
    // sbom_components, whose org_id is the filter below.
    //
    // A VEX statement in one of EffectivePriority.SuppressingVexStates is excluded here the same
    // way the version-detail rollup excludes it by default — otherwise a fully triaged project
    // shows red chips on this list and zero on its own detail page, which trains an operator to
    // distrust the list. The match is by purl_key (project_vuln_analysis's key) against every id
    // the advisory answers to (its OSV id plus every alias), mirroring how the detail rollup binds
    // a statement to an advisory it may have cited under a different identifier. The same
    // suppression governs SeverityCounts.KevCount, projected from the same joined row (v.is_kev):
    // a VEX-suppressed advisory must not light up the KEV signal any more than it lights up a
    // severity bucket.
    private static async Task<Dictionary<string, SeverityCounts>> SeverityCountsAsync(
        DbConnection conn, string orgId, IReadOnlyCollection<string> versionIds, CancellationToken ct)
    {
        if (versionIds.Count == 0)
        {
            return [];
        }

        var rows = (await conn.QueryAsync<SeverityVulnRow>(new CommandDefinition(
            """
            SELECT c.project_version_id AS ProjectVersionId, c.ecosystem AS Ecosystem,
                   c.purl_name AS PurlName, c.purl AS Purl, v.osv_id AS OsvId,
                   v.aliases AS Aliases, v.severity AS Severity, v.is_kev AS IsKev
            FROM sbom_components c
            JOIN sbom_component_vulns cv ON cv.component_id = c.id
            JOIN vulnerabilities v ON v.id = cv.vuln_id
            WHERE c.org_id = @orgId AND c.project_version_id IN @versionIds
            """,
            new { orgId, versionIds }, cancellationToken: ct))).AsList();

        var suppressed = (await conn.QueryAsync<SuppressingAnalysisRow>(new CommandDefinition(
            """
            SELECT project_version_id AS ProjectVersionId, purl_key AS PurlKey, vuln_key AS VulnKey
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id IN @versionIds
              AND vex_state IN ('not_affected','false_positive','resolved')
            """,
            new { orgId, versionIds }, cancellationToken: ct))).AsList();

        var suppressedByVersionPurl = new Dictionary<(string VersionId, string PurlKey), HashSet<string>>();
        foreach (var s in suppressed)
        {
            var key = (s.ProjectVersionId, s.PurlKey);
            if (!suppressedByVersionPurl.TryGetValue(key, out var vulnKeys))
            {
                vulnKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                suppressedByVersionPurl[key] = vulnKeys;
            }

            vulnKeys.Add(s.VulnKey);
        }

        var counts = new Dictionary<string, SeverityCounts>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (suppressedByVersionPurl.Count > 0 && IsVexSuppressed(row, suppressedByVersionPurl))
            {
                continue;
            }

            if (!counts.TryGetValue(row.ProjectVersionId, out var bucket))
            {
                bucket = new SeverityCounts();
                counts[row.ProjectVersionId] = bucket;
            }

            bucket.Add(row.Severity, 1);
            if (row.IsKev)
            {
                bucket.KevCount++;
            }
        }

        return counts;
    }

    private static bool IsVexSuppressed(
        SeverityVulnRow row,
        IReadOnlyDictionary<(string VersionId, string PurlKey), HashSet<string>> suppressedByVersionPurl)
    {
        string? purlKey = SbomPurlKey.ForComponent(row.Ecosystem, row.PurlName, row.Purl);
        return purlKey is not null
            && suppressedByVersionPurl.TryGetValue((row.ProjectVersionId, purlKey), out var suppressedVulnKeys)
            && (suppressedVulnKeys.Contains(row.OsvId)
                || ParseAliasesOrEmpty(row.Aliases).Any(suppressedVulnKeys.Contains));
    }

    // A malformed alias array yields none rather than throwing — the column is written by an
    // upstream feed, and one bad row must not take the projects list down.
    private static IReadOnlyList<string> ParseAliasesOrEmpty(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static async Task<Dictionary<string, DateTimeOffset>> LastUploadsAsync(
        DbConnection conn, string orgId, IReadOnlyCollection<string> projectIds, CancellationToken ct)
    {
        if (projectIds.Count == 0)
        {
            return [];
        }

        var rows = await conn.QueryAsync<LastUploadRow>(new CommandDefinition(
            """
            SELECT v.project_id AS ProjectId, MAX(d.uploaded_at) AS LastUploadAt
            FROM project_documents d
            JOIN project_versions v ON v.id = d.project_version_id AND v.org_id = @orgId
            WHERE d.org_id = @orgId AND v.project_id IN @projectIds
            GROUP BY v.project_id
            """,
            new { orgId, projectIds }, cancellationToken: ct));

        return rows.Where(r => r.LastUploadAt is not null)
                   .ToDictionary(r => r.ProjectId, r => r.LastUploadAt!.Value, StringComparer.Ordinal);
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ComponentCountRow
    {
        public string ProjectVersionId { get; set; } = "";
        public int ComponentCount { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class SeverityVulnRow
    {
        public string ProjectVersionId { get; set; } = "";
        public string? Ecosystem { get; set; }
        public string? PurlName { get; set; }
        public string? Purl { get; set; }
        public string OsvId { get; set; } = "";
        public string? Aliases { get; set; }
        public string? Severity { get; set; }
        public bool IsKev { get; set; }
    }

    private sealed class SuppressingAnalysisRow
    {
        public string ProjectVersionId { get; set; } = "";
        public string PurlKey { get; set; } = "";
        public string VulnKey { get; set; } = "";
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class LastUploadRow
    {
        public string ProjectId { get; set; } = "";
        public DateTimeOffset? LastUploadAt { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ProjectTreeRow
    {
        public string Id { get; set; } = "";
        public string? ParentId { get; set; }
        public string Kind { get; set; } = ProjectKinds.Project;
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class LatestVersionRow
    {
        public string ProjectId { get; set; } = "";
        public string VersionId { get; set; } = "";
        public string VersionLabel { get; set; } = "";

        /// <summary>Null means never evaluated — see <see cref="ProjectPolicyRollup"/>.</summary>
        public string? PolicyStatus { get; set; }
    }
}
