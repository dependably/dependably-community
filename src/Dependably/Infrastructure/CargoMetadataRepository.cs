using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Queries for Cargo sparse index metadata persisted per version. Each row in
/// <c>cargo_metadata</c> stores the full newline-delimited JSON index line for one crate
/// version, as defined by the Cargo sparse registry specification. Tenant-scoped via JOIN
/// through <c>package_versions</c> → <c>packages</c> on <c>org_id</c>.
/// </summary>
public sealed class CargoMetadataRepository
{
    private readonly IMetadataStore _db;

    public CargoMetadataRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Returns all stored index lines for a crate, one per version, in insertion order.
    /// The lines are concatenated (newline-separated) by the controller to form the sparse
    /// index file served at the crate's index path.
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
        return rows.ToList();
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
            INSERT INTO cargo_metadata (version_id, index_line)
            VALUES (@versionId, @indexLine)
            ON CONFLICT (version_id) DO UPDATE SET index_line = excluded.index_line
            """,
            new { versionId, indexLine });
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
