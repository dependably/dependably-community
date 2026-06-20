using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Queries for Cargo sparse index metadata persisted per version. Each row in
/// <c>cargo_metadata</c> stores the full newline-delimited JSON index line for one crate
/// version, as defined by the Cargo sparse registry specification. Tenant-scoped via JOIN
/// through <c>package_versions</c> → <c>packages</c> on <c>org_id</c> for hosted rows;
/// global-plane (proxy) rows are scoped via <c>tenant_artifact_access</c>.
/// </summary>
public sealed class CargoMetadataRepository
{
    private readonly IMetadataStore _db;

    public CargoMetadataRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Returns all stored index lines for a crate, one per version, in insertion order.
    /// Includes lines from both the hosted path (<c>package_versions</c>) and the
    /// global-plane path (<c>cache_artifact</c> + <c>tenant_artifact_access</c>).
    /// Lines are deduplicated by version when a version appears in both planes
    /// (local wins over global-plane for the same version).
    /// </summary>
    public async Task<IReadOnlyList<string>> GetIndexLinesAsync(
        string orgId, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Tenant gate: packages.org_id = @orgId ensures no cross-tenant leakage.
        var rows = await conn.QueryAsync<string>(
            """
            SELECT cm.index_line
            FROM cargo_metadata cm
            JOIN package_versions pv ON pv.id = cm.version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'cargo'
              AND p.name = @name
            ORDER BY pv.created_at, pv.id
            """,
            new { orgId, name });

        // Also fetch global-plane index lines for proxy versions cached after the P3b flip.
        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var globalRows = await conn.QueryAsync<string>(
            """
            SELECT cm.index_line
            FROM cargo_metadata cm
            JOIN cache_artifact ca ON ca.id = cm.cache_artifact_id
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE cm.owner_kind = 'cache_artifact'
              AND ca.ecosystem = 'cargo'
              AND ca.name = @name
            ORDER BY ca.first_cached_at, ca.id
            """,
            new { orgId, name });

        var localList = rows.ToList();
        var globalList = globalRows.ToList();
        if (globalList.Count == 0)
        {
            return localList;
        }

        // Merge: local lines take precedence on version collision.
        return localList.Count == 0
            ? globalList
            : MergeIndexLines(localList, globalList);
    }

    // Merges local and global-plane index lines: local rows shadow any global-plane row
    // for the same version. The local set is preserved in order; global-only versions
    // are appended after local ones.
    private static List<string> MergeIndexLines(
        List<string> localLines, List<string> globalLines)
    {
        var localVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in localLines)
        {
            string? vers = ParseVersionFromIndexLine(line);
            if (vers is not null)
            {
                localVersions.Add(vers);
            }
        }

        var result = new List<string>(localLines.Count + globalLines.Count);
        result.AddRange(localLines);
        foreach (string line in globalLines)
        {
            string? vers = ParseVersionFromIndexLine(line);
            if (vers is null || !localVersions.Contains(vers))
            {
                result.Add(line);
            }
        }
        return result;
    }

    private static string? ParseVersionFromIndexLine(string line)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(line);
            return doc.RootElement.TryGetProperty("vers", out var v) ? v.GetString() : null;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Inserts or replaces the stored sparse-index line for a published crate version.
    /// Keyed on <c>version_id</c> (UNIQUE), so a re-publish of the same coordinate refreshes
    /// the line in place. The caller owns tenant scoping: <paramref name="versionId"/> is
    /// produced by the publish pipeline for an org-scoped package row, so the row this
    /// upsert touches is already confined to the publishing tenant.
    /// </summary>
    public async Task UpsertIndexLineAsync(string versionId, string indexLine, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: version_id is an FK to an org-scoped package_versions row created by the
        // publish pipeline for the current tenant; the cargo_metadata row inherits that scope.
        await conn.ExecuteAsync(
            """
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES (@versionId, @indexLine, 'package_version')
            ON CONFLICT (version_id) WHERE owner_kind = 'package_version' DO UPDATE SET index_line = excluded.index_line
            """,
            new { versionId, indexLine });
    }

    /// <summary>
    /// Inserts or updates the sparse-index line for a proxy crate version stored in the global
    /// cache plane. Keyed on <c>cache_artifact_id</c> (unique per owner_kind='cache_artifact')
    /// so a concurrent first-fetch race resolves to a single row. Called after the
    /// <c>cache_artifact</c> row is recorded so the FK is already satisfied.
    /// </summary>
    // xtenant: cache_artifact is global; id comes from CacheAccessRecorder so no arbitrary
    // cross-tenant row is reachable.
    public async Task UpsertIndexLineForCacheArtifactAsync(
        string cacheArtifactId, string indexLine, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind)
            VALUES (@caId, @indexLine, 'cache_artifact')
            ON CONFLICT (cache_artifact_id) WHERE owner_kind = 'cache_artifact'
            DO UPDATE SET index_line = excluded.index_line
            """,
            new { caId = cacheArtifactId, indexLine });
    }

    /// <summary>
    /// Returns the stored index line for one crate version, or null when no metadata row
    /// exists. Tenant-scoped via the JOIN to <c>packages.org_id</c> so a caller in one org
    /// cannot read another org's index line by guessing the (name, version) pair.
    /// </summary>
    public async Task<string?> GetIndexLineAsync(
        string orgId, string name, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Tenant gate: packages.org_id = @orgId ensures no cross-tenant leakage.
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT cm.index_line
            FROM cargo_metadata cm
            JOIN package_versions pv ON pv.id = cm.version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'cargo'
              AND p.name = @name
              AND pv.version = @version
            """,
            new { orgId, name, version });
    }

    /// <summary>
    /// Replaces the stored index line for one crate version. Used by the yank/unyank path to
    /// rewrite the line's <c>yanked</c> flag after the <c>package_versions.yanked</c> column is
    /// flipped. Tenant-scoped via the JOIN to <c>packages.org_id</c>.
    /// </summary>
    public async Task UpdateIndexLineAsync(
        string orgId, string name, string version, string indexLine, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Tenant gate: the UPDATE's row set is constrained to package_versions whose package
        // belongs to @orgId, so a cross-tenant (name, version) collision cannot be rewritten.
        await conn.ExecuteAsync(
            """
            UPDATE cargo_metadata
            SET index_line = @indexLine
            WHERE version_id IN (
                SELECT pv.id
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId
                  AND p.ecosystem = 'cargo'
                  AND p.name = @name
                  AND pv.version = @version
            )
            """,
            new { orgId, name, version, indexLine });
    }
}
