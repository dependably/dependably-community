using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// Persistence for the projects plane: the application/collection tree, its versions, and the
/// read-time rollups the projects surfaces render.
///
/// Two invariants are enforced here rather than in the schema, because both are cross-row facts a
/// CHECK cannot express:
/// <list type="bullet">
///   <item>a project's parent must be <c>kind='collection'</c>; and</item>
///   <item>a collection holds no versions, so it is never a resolution or upload target.</item>
/// </list>
///
/// "Latest" is the <c>is_latest</c> flag and nothing else — never a version label compared as a
/// number. Promotion clears the flag and sets it again inside one transaction; the partial unique
/// index <c>idx_project_versions_latest</c> is what makes a double-latest impossible at commit, so
/// two concurrent promoters cannot both win and the loser retries against the committed state.
/// </summary>
public sealed partial class ProjectRepository
{
    /// <summary>The version-id path segment that resolves to the project's <c>is_latest</c> row.</summary>
    public const string LatestVersionAlias = "latest";

    /// <summary>
    /// Bound on the clear-then-set promotion retry. A promoter loses to a concurrent one either on
    /// the partial unique index (Postgres) or on the write lock (SQLite); both are resolved by
    /// re-reading the committed state, which the next attempt does.
    /// </summary>
    private const int MaxPromotionAttempts = 8;

    /// <summary>Bound on the resolve-or-create retry, which loses the same two races on insert.</summary>
    private const int MaxResolveAttempts = 4;

    /// <summary>
    /// Bound on every walk up the parent chain (breadcrumb reads, relocation cycle checks). The
    /// tree is nested collections, so real depths are single digits; the bound exists so a chain
    /// that a bug or a lost race has made cyclic terminates the walk instead of spinning.
    /// </summary>
    private const int MaxTreeDepth = 64;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public ProjectRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    // ── Reads ────────────────────────────────────────────────────────────────────────────────

    /// <summary>Loads one project by id, scoped to <paramref name="orgId"/>. Null when absent.</summary>
    public async Task<Project?> GetAsync(string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await GetAsync(conn, null, orgId, projectId);
    }

    /// <summary>
    /// Loads one project by its name within a parent scope. <paramref name="parentId"/> null means
    /// the root scope, which is a distinct namespace from any collection's children.
    /// </summary>
    public async Task<Project?> GetByNameAsync(
        string orgId, string? parentId, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await GetByNameAsync(conn, null, orgId, parentId, name);
    }

    /// <summary>
    /// One page of the org's projects, flattened, each row carrying the rollup the list renders.
    /// The rollup is read-time and describes the project's <c>is_latest</c> version: a project with
    /// no latest version reports a null version label, a zero component count and empty severity
    /// counts.
    ///
    /// A **collection sums its whole subtree** rather than reporting the zeros it holds itself.
    /// Collections have no versions, so read literally every folder row would say "0 components,
    /// no findings, not scanned" — which is not merely uninformative but actively misleading on
    /// the one row an operator scans first. Each descendant project contributes its own
    /// <c>is_latest</c> version; the depth is walked one level per query rather than by a recursive
    /// CTE, so <c>org_id</c> is re-asserted at every hop and the walk cannot follow a
    /// <c>parent_id</c> out of the tenant.
    ///
    /// <paramref name="q"/> is a case-insensitive substring match on the project name. Unfiltered
    /// (<paramref name="q"/> null or blank), the page holds root-level projects only — a child's
    /// row belongs under its parent, which is what the UI's grouped/indented rendering assumes and
    /// what <c>total</c> here counts. A search matches at any depth, because a match nested three
    /// collections deep must still surface; the caller groups the flat, possibly out-of-order
    /// result by parent.
    /// </summary>
    /// <summary>
    /// The <c>sort=</c> values the list accepts, mapped to the SQL that orders by them. A closed
    /// allowlist rather than interpolated caller text, and it is deliberately the same set as the
    /// sortable headers the UI draws — keeping the two in step is what makes the accepted surface
    /// reviewable. An unrecognised value falls back to <c>name</c> rather than erroring, so a
    /// stale bookmark still renders.
    ///
    /// Only columns the paged query can actually order by appear here. Components, findings and a
    /// collection's rolled-up verdict are computed per page AFTER the rows are selected, so
    /// sorting on them would order one page against itself and disagree with the pager's total —
    /// the failure the "a page of a queue is not the queue" rule exists to prevent. They are
    /// therefore not offered as sortable headers either.
    /// </summary>
    private static readonly Dictionary<string, string> ListSortColumns = new(StringComparer.Ordinal)
    {
        ["name"] = "LOWER(p.name)",
        ["latest"] = "lv.version",
        ["policy"] = "lv.policy_status",
    };

    /// <summary>The sort applied when the caller names none, or names one that is not allowed.</summary>
    public const string DefaultListSort = "name";

    /// <summary>The sort keys <c>ListAsync</c> honours, for the API's own validation surface.</summary>
    public static IReadOnlyCollection<string> ListSortKeys => ListSortColumns.Keys;

    public async Task<(IReadOnlyList<ProjectListRow> Items, int Total)> ListAsync(
        string orgId, string? q, int limit, int offset, string? sort = null, string? dir = null,
        CancellationToken ct = default)
    {
        string namePattern = LikeContainsPattern(q);
        int rootOnly = string.IsNullOrWhiteSpace(q) ? 1 : 0;

        // Both fragments come from the closed ListSortColumns allowlist and a two-value direction
        // check, never from caller text — see the marker on the query that splices them.
        string orderColumn = ListSortColumns.GetValueOrDefault(sort ?? "", ListSortColumns[DefaultListSort]);
        string orderDir = string.Equals(dir, "desc", StringComparison.OrdinalIgnoreCase) ? "DESC" : "ASC";
        // p.id is the tiebreaker on every sort, so a page boundary never splits or repeats a row
        // when two rows share the sorted value.
        string orderBy = $"ORDER BY {orderColumn} {orderDir}, p.id";

        await using var conn = await _db.OpenAsync(ct);

        int total = await conn.ExecuteScalarAsync<int>(
            new CommandDefinition(
                """
                SELECT COUNT(*) FROM projects p
                WHERE p.org_id = @orgId AND LOWER(p.name) LIKE @namePattern ESCAPE '\'
                  AND (@rootOnly = 0 OR p.parent_id IS NULL)
                """,
                new { orgId, namePattern, rootOnly }, cancellationToken: ct));

        // rawsql: the only interpolated fragment is {orderBy}, built above from the closed
        // ListSortColumns allowlist plus a two-value direction check — never from caller text.
        // ORDER BY cannot take a bound parameter, so this is the shape a whitelisted sort takes.
        var rows = (await conn.QueryAsync<ProjectListRow>(
            new CommandDefinition(
                $"""
                SELECT p.id AS Id, p.name AS Name, p.kind AS Kind, p.classifier AS Classifier,
                       p.parent_id AS ParentId, parent.name AS ParentName, p.is_active AS IsActive,
                       lv.id AS LatestVersionId, lv.version AS LatestVersion,
                       lv.policy_status AS PolicyStatus
                FROM projects p
                LEFT JOIN projects parent
                       ON parent.id = p.parent_id AND parent.org_id = p.org_id
                LEFT JOIN project_versions lv
                       ON lv.project_id = p.id AND lv.org_id = p.org_id AND lv.is_latest = 1
                WHERE p.org_id = @orgId AND LOWER(p.name) LIKE @namePattern ESCAPE '\'
                  AND (@rootOnly = 0 OR p.parent_id IS NULL)
                {orderBy}
                LIMIT @limit OFFSET @offset
                """,
                new { orgId, namePattern, rootOnly, limit, offset }, cancellationToken: ct))).AsList();

        if (rows.Count == 0)
        {
            return (rows, total);
        }

        // Every collection on the page expands to the projects beneath it, so one set of
        // aggregate queries covers the page's own rows and every row they summarize.
        var collectionIds = rows
            .Where(r => string.Equals(r.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
            .Select(r => r.Id).ToList();
        var descendants = await DescendantProjectsAsync(conn, orgId, collectionIds, ct);

        var projectIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            projectIds.Add(row.Id);
        }

        foreach (var subtree in descendants.Values)
        {
            projectIds.UnionWith(subtree);
        }

        var latest = await LatestVersionsAsync(conn, orgId, projectIds, ct);
        var versionIds = latest.Values.Select(v => v.VersionId).ToList();

        var componentCounts = await ComponentCountsAsync(conn, orgId, versionIds, ct);
        var severityCounts = await SeverityCountsAsync(conn, orgId, versionIds, ct);
        var lastUploads = await LastUploadsAsync(conn, orgId, projectIds, ct);

        foreach (var row in rows)
        {
            if (string.Equals(row.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
            {
                var rollup = Fold(
                    descendants.GetValueOrDefault(row.Id) ?? [],
                    latest, componentCounts, severityCounts, lastUploads);

                row.ComponentCount = rollup.ComponentCount;
                row.SeverityCounts = rollup.SeverityCounts;
                row.PolicyStatus = rollup.PolicyStatus;
                row.LastUploadAt = rollup.LastUploadAt;
                row.SubtreeProjectCount = rollup.ProjectCount;
                row.SubtreeUnevaluatedProjectCount = rollup.UnevaluatedProjectCount;
                continue;
            }

            if (row.LatestVersionId is not null)
            {
                row.ComponentCount = componentCounts.GetValueOrDefault(row.LatestVersionId);
                row.SeverityCounts = severityCounts.GetValueOrDefault(row.LatestVersionId)
                    ?? new SeverityCounts();
            }

            row.LastUploadAt = lastUploads.TryGetValue(row.Id, out var stamp) ? stamp : null;
        }

        return (rows, total);
    }

    /// <summary>
    /// Lightweight name search for the global type-ahead: no rollup joins, just enough to render a
    /// result row and link into the project. Matches both projects and collections, across the
    /// whole tree (not root-only, unlike <see cref="ListAsync"/>'s browse mode) — a type-ahead
    /// searches for a name, not a browse level.
    /// </summary>
    public async Task<IReadOnlyList<ProjectSearchRow>> SearchByNameAsync(
        string orgId, string query, int limit, CancellationToken ct = default)
    {
        string namePattern = LikeContainsPattern(query);
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ProjectSearchRow>(new CommandDefinition(
            """
            SELECT p.id AS Id, p.name AS Name, p.kind AS Kind
            FROM projects p
            WHERE p.org_id = @orgId AND LOWER(p.name) LIKE @namePattern ESCAPE '\'
            ORDER BY p.name, p.id
            LIMIT @limit
            """,
            new { orgId, namePattern, limit }, cancellationToken: ct));
        return rows.AsList();
    }

    /// <summary>
    /// The versions of one project, newest first, each with its own component count. Empty for a
    /// collection, which holds no versions by construction.
    /// </summary>
    public async Task<IReadOnlyList<ProjectVersionSummary>> ListVersionsAsync(
        string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = (await conn.QueryAsync<ProjectVersionSummary>(
            new CommandDefinition(
                """
                SELECT v.id AS Id, v.version AS Version, v.is_latest AS IsLatest,
                       v.is_active AS IsActive,
                       v.policy_status AS PolicyStatus, v.created_at AS CreatedAt
                FROM project_versions v
                WHERE v.org_id = @orgId AND v.project_id = @projectId
                ORDER BY v.created_at DESC, v.id
                """,
                new { orgId, projectId }, cancellationToken: ct))).AsList();

        if (rows.Count == 0)
        {
            return rows;
        }

        var counts = await ComponentCountsAsync(conn, orgId, rows.Select(r => r.Id).ToList(), ct);
        foreach (var row in rows)
        {
            row.ComponentCount = counts.GetValueOrDefault(row.Id);
        }

        return rows;
    }

    /// <summary>
    /// The direct children of a collection, each carrying the same rollup its own row would show
    /// on the projects list: a plain project reports its <c>is_latest</c> version, and a child
    /// collection reports the sum of everything beneath it. Reading the same way at both levels is
    /// what lets someone drill into a folder and see the parent's total account for itself.
    /// </summary>
    public async Task<IReadOnlyList<ProjectChildSummary>> ListChildrenAsync(
        string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = (await conn.QueryAsync<ProjectChildSummary>(
            new CommandDefinition(
                """
                SELECT c.id AS Id, c.name AS Name, c.kind AS Kind, c.is_active AS IsActive,
                       lv.id AS LatestVersionId, lv.version AS LatestVersion,
                       lv.policy_status AS PolicyStatus
                FROM projects c
                LEFT JOIN project_versions lv
                       ON lv.project_id = c.id AND lv.org_id = c.org_id AND lv.is_latest = 1
                WHERE c.org_id = @orgId AND c.parent_id = @projectId
                ORDER BY LOWER(c.name), c.id
                """,
                new { orgId, projectId }, cancellationToken: ct))).AsList();

        if (rows.Count == 0)
        {
            return rows;
        }

        var childCollectionIds = rows
            .Where(r => string.Equals(r.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
            .Select(r => r.Id).ToList();
        var descendants = await DescendantProjectsAsync(conn, orgId, childCollectionIds, ct);

        var projectIds = new HashSet<string>(rows.Select(r => r.Id), StringComparer.Ordinal);
        foreach (var subtree in descendants.Values)
        {
            projectIds.UnionWith(subtree);
        }

        var latest = await LatestVersionsAsync(conn, orgId, projectIds, ct);
        var componentCounts = await ComponentCountsAsync(
            conn, orgId, latest.Values.Select(v => v.VersionId).ToList(), ct);
        var severityCounts = await SeverityCountsAsync(
            conn, orgId, latest.Values.Select(v => v.VersionId).ToList(), ct);
        var lastUploads = await LastUploadsAsync(conn, orgId, projectIds, ct);

        foreach (var row in rows)
        {
            if (string.Equals(row.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
            {
                var rollup = Fold(
                    descendants.GetValueOrDefault(row.Id) ?? [],
                    latest, componentCounts, severityCounts, lastUploads);
                row.ComponentCount = rollup.ComponentCount;
                row.SeverityCounts = rollup.SeverityCounts;
                row.PolicyStatus = rollup.PolicyStatus;
                continue;
            }

            if (row.LatestVersionId is not null)
            {
                row.ComponentCount = componentCounts.GetValueOrDefault(row.LatestVersionId);
                row.SeverityCounts = severityCounts.GetValueOrDefault(row.LatestVersionId)
                    ?? new SeverityCounts();
            }
        }

        return rows;
    }

    /// <summary>
    /// Every project beneath a collection, at any depth, with the identity an export needs to
    /// name each one. Ordered by path so a rendered document is stable between calls rather than
    /// reshuffling with whatever order the walk happened to visit.
    ///
    /// Returns null when the id is not a collection this org holds, which the caller renders as a
    /// 404 — distinct from an empty list, which is a real but empty folder.
    /// </summary>
    public async Task<IReadOnlyList<ProjectSubtreeEntry>?> ListSubtreeProjectsAsync(
        string orgId, string collectionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var collection = await GetAsync(conn, null, orgId, collectionId);
        if (collection is null ||
            !string.Equals(collection.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
        {
            return null;
        }

        var descendants = await DescendantProjectsAsync(conn, orgId, [collectionId], ct);
        var projectIds = descendants.GetValueOrDefault(collectionId) ?? [];
        if (projectIds.Count == 0)
        {
            return Array.Empty<ProjectSubtreeEntry>();
        }

        var latest = await LatestVersionsAsync(conn, orgId, projectIds, ct);

        var rows = (await conn.QueryAsync<ProjectSubtreeEntry>(new CommandDefinition(
            """
            SELECT p.id AS ProjectId, p.name AS Name, p.classifier AS Classifier
            FROM projects p
            WHERE p.org_id = @orgId AND p.id IN @projectIds
            ORDER BY LOWER(p.name), p.id
            """,
            new { orgId, projectIds }, cancellationToken: ct))).AsList();

        foreach (var row in rows)
        {
            // Absent for a project nobody has uploaded an SBOM for. The export renders it as an
            // empty entry rather than dropping it: a document that silently omits a project the
            // folder contains is the misleading-completeness failure the whole selection rule
            // exists to avoid.
            var version = latest.GetValueOrDefault(row.ProjectId);
            row.ProjectVersionId = version?.VersionId;
            row.VersionLabel = version?.VersionLabel;
        }

        return rows;
    }

    /// <summary>
    /// The subtree rollup for one collection — what its own detail page reports about everything
    /// beneath it. Returns null when the id is not a collection this org holds, so the caller can
    /// tell "no rollup applies" from "an empty folder", which reports zeros and a null verdict.
    /// </summary>
    public async Task<ProjectSubtreeRollup?> GetSubtreeRollupAsync(
        string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var project = await GetAsync(conn, null, orgId, projectId);
        if (project is null ||
            !string.Equals(project.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
        {
            return null;
        }

        var descendants = await DescendantProjectsAsync(conn, orgId, [projectId], ct);
        var projectIds = descendants.GetValueOrDefault(projectId) ?? [];
        if (projectIds.Count == 0)
        {
            return new ProjectSubtreeRollup();
        }

        var latest = await LatestVersionsAsync(conn, orgId, projectIds, ct);
        var versionIds = latest.Values.Select(v => v.VersionId).ToList();

        return Fold(
            projectIds,
            latest,
            await ComponentCountsAsync(conn, orgId, versionIds, ct),
            await SeverityCountsAsync(conn, orgId, versionIds, ct),
            await LastUploadsAsync(conn, orgId, projectIds, ct));
    }

    /// <summary>
    /// The project's ancestors, root first, excluding the project itself. Empty for a root-level
    /// project and for a project id this org does not hold.
    ///
    /// Walked one level at a time rather than through a recursive CTE: the chain is a handful of
    /// rows deep, every hop re-asserts <c>org_id</c> (a CTE seeded in one org could otherwise
    /// follow a <c>parent_id</c> into another), and the visited set plus
    /// <see cref="MaxTreeDepth"/> make a cyclic chain terminate rather than hang.
    /// </summary>
    public async Task<IReadOnlyList<ProjectPathEntry>> ListAncestorsAsync(
        string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var self = await GetAsync(conn, null, orgId, projectId);
        if (self is null)
        {
            return [];
        }

        var chain = new List<ProjectPathEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal) { self.Id };

        string? cursor = self.ParentId;
        while (cursor is not null && chain.Count < MaxTreeDepth && seen.Add(cursor))
        {
            ct.ThrowIfCancellationRequested();
            var ancestor = await GetAsync(conn, null, orgId, cursor);
            if (ancestor is null)
            {
                break;
            }

            chain.Add(new ProjectPathEntry { Id = ancestor.Id, Name = ancestor.Name });
            cursor = ancestor.ParentId;
        }

        chain.Reverse();
        return chain;
    }

    /// <summary>
    /// Every collection the org holds, flat and capped at <paramref name="limit"/>. The relocation
    /// picker needs the whole set at once — it renders each target as a full path — which is why
    /// this is not the paged, root-only shape <see cref="ListAsync"/> returns.
    /// </summary>
    public async Task<IReadOnlyList<ProjectCollectionRow>> ListCollectionsAsync(
        string orgId, int limit, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return (await conn.QueryAsync<ProjectCollectionRow>(
            new CommandDefinition(
                """
                SELECT c.id AS Id, c.name AS Name, c.parent_id AS ParentId
                FROM projects c
                WHERE c.org_id = @orgId AND c.kind = 'collection'
                ORDER BY LOWER(c.name), c.id
                LIMIT @limit
                """,
                new { orgId, limit }, cancellationToken: ct))).AsList();
    }

    /// <summary>Loads one version by id, scoped to its org and project. Null when absent.</summary>
    public async Task<ProjectVersion?> GetVersionAsync(
        string orgId, string projectId, string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await GetVersionAsync(conn, null, orgId, projectId, versionId);
    }

    /// <summary>
    /// Resolves a <c>{versionId}</c> path segment to a concrete version id. The literal
    /// <see cref="LatestVersionAlias"/> resolves through the <c>is_latest</c> flag; anything else is
    /// treated as an id and verified against the org and project. Null when nothing matches — which
    /// is what keeps a cross-org id indistinguishable from an absent one at the API boundary.
    /// </summary>
    public async Task<string?> ResolveVersionIdAsync(
        string orgId, string projectId, string versionIdOrLatest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await ResolveVersionIdAsync(conn, null, orgId, projectId, versionIdOrLatest);
    }

    /// <summary>
    /// Every <c>project_documents.blob_key</c> reachable from this project's subtree, including
    /// descendant collections' projects. Callers enumerate these BEFORE deleting the rows: the
    /// metadata row is the blob's only reference, so once the cascade has run there is nothing left
    /// to read the key from.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListDocumentBlobKeysForProjectAsync(
        string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return (await conn.QueryAsync<string>(
            new CommandDefinition(
                """
                WITH RECURSIVE tree(id) AS (
                    SELECT p.id FROM projects p WHERE p.org_id = @orgId AND p.id = @projectId
                    UNION ALL
                    SELECT c.id FROM projects c
                    JOIN tree t ON c.parent_id = t.id
                    WHERE c.org_id = @orgId
                )
                SELECT d.blob_key
                FROM project_documents d
                JOIN project_versions v ON v.id = d.project_version_id AND v.org_id = @orgId
                JOIN tree t ON t.id = v.project_id
                WHERE d.org_id = @orgId
                """,
                new { orgId, projectId }, cancellationToken: ct))).AsList();
    }

    /// <summary>Every <c>project_documents.blob_key</c> belonging to one version.</summary>
    public async Task<IReadOnlyList<string>> ListDocumentBlobKeysForVersionAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return (await conn.QueryAsync<string>(
            new CommandDefinition(
                """
                SELECT d.blob_key
                FROM project_documents d
                WHERE d.org_id = @orgId AND d.project_version_id = @projectVersionId
                """,
                new { orgId, projectVersionId }, cancellationToken: ct))).AsList();
    }

    // ── Internals ────────────────────────────────────────────────────────────────────────────

    private static async Task<Project?> GetAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string projectId)
        => await conn.QuerySingleOrDefaultAsync<Project>(
            """
            SELECT p.id AS Id, p.org_id AS OrgId, p.parent_id AS ParentId, p.kind AS Kind,
                   p.name AS Name, p.classifier AS Classifier, p.description AS Description,
                   p.is_active AS IsActive,
                   p.created_by AS CreatedBy, p.created_at AS CreatedAt
            FROM projects p
            WHERE p.org_id = @orgId AND p.id = @projectId
            """,
            new { orgId, projectId }, tx);

    // Two partial unique indexes give the root scope and each collection's scope their own name
    // namespace, so the lookup branches on the same NULL/NOT NULL distinction they do —
    // `parent_id = @parentId` never matches a NULL parent_id under SQL's three-valued logic.
    private static async Task<Project?> GetByNameAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string? parentId, string name)
        => parentId is null
            ? await conn.QuerySingleOrDefaultAsync<Project>(
                """
                SELECT p.id AS Id, p.org_id AS OrgId, p.parent_id AS ParentId, p.kind AS Kind,
                       p.name AS Name, p.classifier AS Classifier, p.description AS Description,
                       p.is_active AS IsActive,
                       p.created_by AS CreatedBy, p.created_at AS CreatedAt
                FROM projects p
                WHERE p.org_id = @orgId AND p.parent_id IS NULL AND p.name = @name
                """,
                new { orgId, name }, tx)
            : await conn.QuerySingleOrDefaultAsync<Project>(
                """
                SELECT p.id AS Id, p.org_id AS OrgId, p.parent_id AS ParentId, p.kind AS Kind,
                       p.name AS Name, p.classifier AS Classifier, p.description AS Description,
                       p.is_active AS IsActive,
                       p.created_by AS CreatedBy, p.created_at AS CreatedAt
                FROM projects p
                WHERE p.org_id = @orgId AND p.parent_id = @parentId AND p.name = @name
                """,
                new { orgId, parentId, name }, tx);

    private static async Task<ProjectVersion?> GetVersionAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string projectId, string versionId)
        => await conn.QuerySingleOrDefaultAsync<ProjectVersion>(
            """
            SELECT v.id AS Id, v.org_id AS OrgId, v.project_id AS ProjectId, v.version AS Version,
                   v.is_latest AS IsLatest, v.is_active AS IsActive, v.policy_status AS PolicyStatus,
                   v.created_by AS CreatedBy, v.created_at AS CreatedAt
            FROM project_versions v
            WHERE v.org_id = @orgId AND v.project_id = @projectId AND v.id = @versionId
            """,
            new { orgId, projectId, versionId }, tx);

    private static async Task<string?> ResolveVersionIdAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string projectId, string versionIdOrLatest)
        => string.Equals(versionIdOrLatest, LatestVersionAlias, StringComparison.OrdinalIgnoreCase)
            ? await conn.QuerySingleOrDefaultAsync<string?>(
                """
                SELECT v.id FROM project_versions v
                WHERE v.org_id = @orgId AND v.project_id = @projectId AND v.is_latest = 1
                """,
                new { orgId, projectId }, tx)
            : await conn.QuerySingleOrDefaultAsync<string?>(
                """
                SELECT v.id FROM project_versions v
                WHERE v.org_id = @orgId AND v.project_id = @projectId AND v.id = @versionId
                """,
                new { orgId, projectId, versionId = versionIdOrLatest }, tx);

    /// <summary>
    /// A lowercased LIKE pattern matching any name containing <paramref name="q"/>, or every name
    /// when it is absent. The wildcards inside the caller's text are escaped so a search for
    /// <c>100%</c> matches that literal rather than every project.
    /// </summary>
    private static string LikeContainsPattern(string? q)
    {
        if (string.IsNullOrWhiteSpace(q))
        {
            return "%";
        }

        // Escaping via LikePattern; the blank-input convention differs deliberately — this
        // predicate has no `@pattern IS NULL OR` guard, so "no filter" is "%", not null.
        return "%" + LikePattern.Escape(q.Trim().ToLowerInvariant()) + "%";
    }
}
