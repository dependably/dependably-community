using System.Data;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Persistence for <c>package_version_tombstone</c>: the version-granular record that a
/// <c>(org, ecosystem, purl_name, version)</c> coordinate has been hard-deleted from the hosted
/// plane. The row outlives both the <c>package_versions</c> row and its parent <c>packages</c>
/// row, so the coordinate is still known once nothing else remembers it.
///
/// This is the read side. The write side lives inside
/// <see cref="PackageRepository.DeleteVersionAsync"/>'s transaction — the tombstone and the
/// delete have to commit together, or a crash between them would drop the coordinate silently —
/// and executes <see cref="RecordSql"/> so both sides share one SQL definition.
///
/// Distinct from <see cref="NameBindingRepository"/>: a name binding is name-granular and answers
/// "which principal owns this name"; a tombstone is version-granular and answers "have these
/// coordinates already been spent".
/// </summary>
public sealed class VersionTombstoneRepository
{
    /// <summary>
    /// Upsert executed by the version-delete transaction. Re-deleting a coordinate that was
    /// republished under a permissive policy refreshes the row rather than conflicting, so
    /// <c>deleted_at</c>/<c>content_hash</c> always describe the most recent deletion.
    /// </summary>
    internal const string RecordSql =
        """
        INSERT INTO package_version_tombstone
            (id, org_id, ecosystem, purl_name, version, content_hash, deleted_at)
        VALUES (@id, @orgId, @ecosystem, @purlName, @version, @contentHash, @deletedAt)
        ON CONFLICT (org_id, ecosystem, purl_name, version) DO UPDATE
        SET content_hash = excluded.content_hash, deleted_at = excluded.deleted_at
        """;

    /// <summary>The (org, ecosystem, purl_name, version) coordinate a tombstone row keys on.</summary>
    internal readonly record struct VersionCoordinate(string OrgId, string Ecosystem, string PurlName, string Version);

    private readonly IMetadataStore _db;

    public VersionTombstoneRepository(IMetadataStore db) { _db = db; }

    /// <summary>
    /// <see langword="true"/> when the coordinate has been hard-deleted at least once in this org.
    /// Read by the publish dedup gate before any artifact bytes are written.
    /// </summary>
    public async Task<bool> ExistsAsync(
        string orgId, string ecosystem, string purlName, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // SQLite surfaces EXISTS as 0/1, Postgres as boolean — Dapper maps both to bool.
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS (
                SELECT 1 FROM package_version_tombstone
                WHERE org_id = @orgId AND ecosystem = @ecosystem
                  AND purl_name = @purlName AND version = @version)
            """,
            new { orgId, ecosystem, purlName, version });
    }

    /// <summary>
    /// Returns the recorded tombstone for a coordinate, or null when it has never been deleted.
    /// </summary>
    public async Task<VersionTombstone?> GetAsync(
        string orgId, string ecosystem, string purlName, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<VersionTombstone>(
            """
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, purl_name AS PurlName,
                   version AS Version, content_hash AS ContentHash, deleted_at AS DeletedAt
            FROM package_version_tombstone
            WHERE org_id = @orgId AND ecosystem = @ecosystem
              AND purl_name = @purlName AND version = @version
            """,
            new { orgId, ecosystem, purlName, version });
    }

    /// <summary>
    /// Records a tombstone on an already-open connection/transaction. Called from the
    /// version-delete transaction so the tombstone commits with the delete.
    /// </summary>
    internal static Task RecordAsync(
        IDbConnection conn, IDbTransaction tx, VersionCoordinate coordinate, string? contentHash, string deletedAt)
        => conn.ExecuteAsync(
            RecordSql,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = coordinate.OrgId,
                ecosystem = coordinate.Ecosystem,
                purlName = coordinate.PurlName,
                version = coordinate.Version,
                contentHash,
                deletedAt,
            },
            tx);
}

/// <summary>A recorded hard-delete of a hosted version coordinate.</summary>
public sealed class VersionTombstone
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string PurlName { get; init; } = "";
    public string Version { get; init; } = "";
    public string? ContentHash { get; init; }
    public string DeletedAt { get; init; } = "";
}
