using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Read-only access to the seeded <c>spdx_license</c> reference table. Writes live in
/// <see cref="SpdxLicenseSeeder"/>; this repo only serves the picker + member detail views.
/// </summary>
public sealed class SpdxLicenseRepository
{
    private readonly IMetadataStore _db;

    public SpdxLicenseRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Returns SPDX licenses, optionally filtered by a substring query against identifier or
    /// name (case-insensitive). Deprecated identifiers are excluded by default since they
    /// shouldn't surface as new policy entries; admins opt in for backfill cases.
    /// </summary>
    public async Task<IReadOnlyList<SpdxLicense>> ListAsync(
        string? query, bool includeDeprecated, int limit = 200, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var filter = string.IsNullOrWhiteSpace(query) ? null : $"%{query.Trim()}%";

        var rows = await conn.QueryAsync<SpdxLicense>(
            """
            SELECT identifier      AS Identifier,
                   name            AS Name,
                   is_osi_approved AS IsOsiApproved,
                   is_fsf_libre    AS IsFsfLibre,
                   is_deprecated   AS IsDeprecated,
                   reference_url   AS ReferenceUrl,
                   copyleft        AS Copyleft
            FROM spdx_license
            WHERE (@includeDeprecated = 1 OR is_deprecated = 0)
              AND (@filter IS NULL OR identifier LIKE @filter COLLATE NOCASE OR name LIKE @filter COLLATE NOCASE)
            ORDER BY
              -- Exact-prefix matches first when filtering, otherwise alphabetical.
              CASE WHEN @filter IS NULL THEN 0
                   WHEN identifier LIKE @prefix COLLATE NOCASE THEN 0
                   ELSE 1 END,
              identifier
            LIMIT @limit
            """,
            new { filter, prefix = filter is null ? null : $"{query!.Trim()}%", includeDeprecated = includeDeprecated ? 1 : 0, limit });

        return rows.ToList();
    }

    public async Task<SpdxLicense?> GetAsync(string identifier, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<SpdxLicense>(
            """
            SELECT identifier      AS Identifier,
                   name            AS Name,
                   is_osi_approved AS IsOsiApproved,
                   is_fsf_libre    AS IsFsfLibre,
                   is_deprecated   AS IsDeprecated,
                   reference_url   AS ReferenceUrl,
                   copyleft        AS Copyleft
            FROM spdx_license
            WHERE identifier = @identifier
            """,
            new { identifier });
    }

    /// <summary>Returns reference rows for the given identifiers, keyed by identifier.
    /// Used by policy-list endpoints to hydrate allow/block entries with full SPDX detail.</summary>
    public async Task<IReadOnlyDictionary<string, SpdxLicense>> GetManyAsync(
        IEnumerable<string> identifiers, CancellationToken ct = default)
    {
        var ids = identifiers.Distinct(StringComparer.Ordinal).ToList();
        if (ids.Count == 0) return new Dictionary<string, SpdxLicense>();

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<SpdxLicense>(
            """
            SELECT identifier      AS Identifier,
                   name            AS Name,
                   is_osi_approved AS IsOsiApproved,
                   is_fsf_libre    AS IsFsfLibre,
                   is_deprecated   AS IsDeprecated,
                   reference_url   AS ReferenceUrl,
                   copyleft        AS Copyleft
            FROM spdx_license
            WHERE identifier IN @ids
            """,
            new { ids });

        return rows.ToDictionary(r => r.Identifier, StringComparer.Ordinal);
    }
}
