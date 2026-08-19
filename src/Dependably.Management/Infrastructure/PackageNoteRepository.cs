using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Standing operator annotations on a package coordinate. Two needs share this shape: the
/// rationale recorded when someone rules on a package whose licence is conditional, and a general
/// compliance note left on a package regardless of any gate decision.
///
/// <para>Rows are keyed by (ecosystem, name, version) rather than an FK to <c>package_versions</c>
/// because proxied artifacts live on the global <c>cache_artifact</c> plane and have no version
/// row — a coordinate key covers both planes, which an FK to either one could not. A NULL version
/// scopes the note to every version of the package.</para>
///
/// <para><c>quarantine.note</c> is unchanged and still records the decision made on a blocked
/// artifact; this is the surface for everything that never reached a block.</para>
/// </summary>
public sealed class PackageNoteRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public PackageNoteRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>Notes for one package. When <paramref name="version"/> is supplied the result
    /// carries both the version's own notes and the package-wide (NULL-version) ones, because a
    /// package-wide note is by definition about this version too — a version view that hid them
    /// would be the surface most likely to miss the note that mattered.</summary>
    public async Task<IReadOnlyList<PackageNote>> ListAsync(
        string orgId, string ecosystem, string name, string? version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<PackageNote>(
            """
            SELECT pn.id          AS Id,
                   pn.org_id      AS OrgId,
                   pn.ecosystem   AS Ecosystem,
                   pn.name        AS Name,
                   pn.version     AS Version,
                   pn.note        AS Note,
                   pn.created_by  AS CreatedBy,
                   u.email        AS CreatedByLabel,
                   pn.created_at  AS CreatedAt,
                   pn.updated_at  AS UpdatedAt
            FROM package_note pn
            LEFT JOIN users u ON u.id = pn.created_by
            WHERE pn.org_id = @orgId AND pn.ecosystem = @ecosystem AND pn.name = @name
              AND (@version IS NULL OR pn.version IS NULL OR pn.version = @version)
            ORDER BY pn.created_at DESC
            """,
            new { orgId, ecosystem, name, version });
        return rows.ToList();
    }

    public async Task<PackageNote> AddAsync(
        string orgId, string ecosystem, string name, string? version, string note, string? createdBy,
        CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_note
                (id, org_id, ecosystem, name, version, note, created_by, created_at, updated_at)
            VALUES (@id, @orgId, @ecosystem, @name, @version, @note, @createdBy, @now, @now)
            """,
            new { id, orgId, ecosystem, name, version, note, createdBy, now });

        return new PackageNote
        {
            Id = id,
            OrgId = orgId,
            Ecosystem = ecosystem,
            Name = name,
            Version = version,
            Note = note,
            CreatedBy = createdBy,
            CreatedAt = _time.GetUtcNow(),
            UpdatedAt = _time.GetUtcNow()
        };
    }

    /// <summary>Rewrites a note's text. Returns false when the id does not name a row in this
    /// org — the org_id predicate is what stops a note id leaked from another tenant being
    /// editable here.</summary>
    public async Task<bool> UpdateAsync(
        string orgId, string id, string note, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            """
            UPDATE package_note SET note = @note, updated_at = @now
             WHERE id = @id AND org_id = @orgId
            """,
            new { orgId, id, note, now = _time.GetUtcNow().ToUtcIso() });
        return affected > 0;
    }

    public async Task<bool> DeleteAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            "DELETE FROM package_note WHERE id = @id AND org_id = @orgId",
            new { orgId, id });
        return affected > 0;
    }
}
