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
    /// Upserts the index line for a version. On conflict (same version_id) the existing line
    /// is replaced, which handles re-fetches of the same upstream version gracefully.
    /// </summary>
    public async Task UpsertIndexLineAsync(
        string versionId, string indexLine, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO cargo_metadata (version_id, index_line)
            VALUES (@versionId, @indexLine)
            ON CONFLICT (version_id) DO UPDATE SET index_line = excluded.index_line
            """,
            new { versionId, indexLine });
    }
}
