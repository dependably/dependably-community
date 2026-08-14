using Dapper;
using Dependably.Protocol;

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
    ///
    /// A global-plane line's <c>cksum</c> is stored once, against the shared
    /// <c>cache_artifact</c> row, from whichever tenant reached the coordinate first — while
    /// <c>cksum</c> is a required field the sparse-index spec has no "absent" form for, so it
    /// cannot simply be omitted the way npm's optional <c>dist.integrity</c> is. Cargo's
    /// <c>cksum</c> and this tenant's own bound <c>content_hash</c> are the same digest (SHA-256
    /// hex of the <c>.crate</c> file), so a tenant whose own fetch diverged from the shared row is
    /// served a line rewritten to carry its own hash — the value the <c>GetCrateAsync</c> download
    /// route actually verifies and streams against — rather than the other tenant's.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetIndexLinesAsync(
        string orgId, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Tenant gate: packages.org_id = @orgId ensures no cross-tenant leakage.
        var rows = await conn.QueryAsync<string>(
            // plane-ok: PV-plane index lines; global-plane lines are UNIONed via the sibling cache_artifact SELECT in this method.
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
        // Alongside each line, the tenant's own bound content hash (TenantContentHash, from
        // tenant_artifact_access — null when this tenant has no binding) and the shared row's
        // content hash so a diverging tenant's line can be rewritten to its own cksum below.
        // Bare column selects, not COALESCE — an expression column has no declared SQLite type
        // affinity, which Microsoft.Data.Sqlite reports to Dapper as byte[] and breaks buffered
        // multi-row materialization; the fallback to the shared hash is resolved in C# instead.
        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var globalRows = await conn.QueryAsync<GlobalIndexLineRow>(
            """
            SELECT cm.index_line     AS IndexLine,
                   taa.content_hash  AS TenantContentHash,
                   ca.content_hash   AS SharedContentHash
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
        var globalList = globalRows.Select(RewriteCksumForTenant).ToList();
        if (globalList.Count == 0)
        {
            return localList;
        }

        // Merge: local lines take precedence on version collision.
        return localList.Count == 0
            ? globalList
            : MergeIndexLines(localList, globalList);
    }

    private sealed class GlobalIndexLineRow
    {
        public string IndexLine { get; init; } = "";
        public string? TenantContentHash { get; init; }
        public string? SharedContentHash { get; init; }
    }

    /// <summary>
    /// Rewrites a global-plane index line's <c>cksum</c> to this tenant's own bound content hash
    /// when it diverges from the shared <c>cache_artifact</c> row's hash the stored line was
    /// originally built from. Both hashes must be known for the comparison to mean anything: a
    /// tenant with no binding is being served the shared blob (nothing to rewrite), and an
    /// un-backfilled row with no shared hash yet leaves the stored line alone. A line that fails
    /// to parse as JSON (should not happen — every stored line is written by
    /// <see cref="CargoPublishMetadata.ToIndexLine"/> or <c>BuildProxyIndexLine</c>) is returned
    /// unchanged rather than dropped, so an unexpected shape degrades to the pre-fix behaviour
    /// instead of vanishing from the index.
    /// </summary>
    private static string RewriteCksumForTenant(GlobalIndexLineRow row)
    {
        string? ownHash = row.TenantContentHash ?? row.SharedContentHash;
        bool diverges = !string.IsNullOrEmpty(row.TenantContentHash)
            && !string.IsNullOrEmpty(row.SharedContentHash)
            && !string.Equals(row.TenantContentHash, row.SharedContentHash, StringComparison.OrdinalIgnoreCase);
        if (!diverges)
        {
            return row.IndexLine;
        }

        try
        {
            if (System.Text.Json.Nodes.JsonNode.Parse(row.IndexLine) is System.Text.Json.Nodes.JsonObject obj)
            {
                obj["cksum"] = ownHash;
                return obj.ToJsonString(CargoPublishJsonContext.CompactOptions);
            }
        }
        catch (System.Text.Json.JsonException)
        {
            // Fall through — return the stored line verbatim.
        }

        return row.IndexLine;
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
            // plane-ok: single index-line lookup keyed to the PV-plane version the yank path resolved; proxy lines are keyed by cache_artifact_id.
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
