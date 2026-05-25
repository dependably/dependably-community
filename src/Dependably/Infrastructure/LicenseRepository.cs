using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// CRUD for package_version_licenses, license_allowlist, and license_blocklist tables.
/// </summary>
public sealed class LicenseRepository
{
    private readonly IMetadataStore _db;

    public LicenseRepository(IMetadataStore db) => _db = db;

    // ── Package version licenses ──────────────────────────────────────────────

    public async Task<IReadOnlyList<PackageVersionLicense>> GetForVersionAsync(
        string packageVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by package_version_id (caller-org-scoped); FK chains to packages.org_id.
        var rows = await conn.QueryAsync<PackageVersionLicense>(
            """
            SELECT id as Id, package_version_id as PackageVersionId,
                   license_spdx as LicenseSpdx, source as Source,
                   created_at as CreatedAt
            FROM package_version_licenses
            WHERE package_version_id = @packageVersionId
            ORDER BY license_spdx
            """,
            new { packageVersionId });
        return rows.ToList();
    }

    public async Task SetLicensesAsync(
        string packageVersionId,
        IEnumerable<string> spdxIds,
        string source,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Upsert each SPDX identifier; ignore duplicates from same source
        foreach (var spdx in spdxIds)
        {
            // xtenant: INSERT pinned to caller-supplied package_version_id (org-scoped via FK).
            await conn.ExecuteAsync(
                """
                INSERT INTO package_version_licenses (id, package_version_id, license_spdx, source)
                VALUES (@id, @pvId, @spdx, @source)
                ON CONFLICT(package_version_id, license_spdx) DO NOTHING
                """,
                new { id = Guid.NewGuid().ToString("N"), pvId = packageVersionId, spdx, source });
        }
    }

    public async Task<ILookup<string, string>> GetSpdxForVersionsAsync(
        IEnumerable<string> versionIds, CancellationToken ct = default)
    {
        var ids = versionIds.ToList();
        if (ids.Count == 0) return Enumerable.Empty<VersionLicenseRow>().ToLookup(r => r.VersionId, r => r.Spdx);
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by an IN list of package_version_ids (each caller-org-scoped).
        var rows = await conn.QueryAsync<VersionLicenseRow>(
            """
            SELECT package_version_id as VersionId, license_spdx as Spdx
            FROM package_version_licenses
            WHERE package_version_id IN @ids
            ORDER BY license_spdx
            """,
            new { ids });
        return rows.ToLookup(r => r.VersionId, r => r.Spdx);
    }

    private sealed record VersionLicenseRow(string VersionId, string Spdx);

    // ── License allowlist ─────────────────────────────────────────────────────

    public async Task<IReadOnlyList<LicenseAllowlistEntry>> GetAllowlistAsync(
        string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<LicenseAllowlistEntry>(
            """
            SELECT id as Id, org_id as OrgId, license_spdx as LicenseSpdx, created_at as CreatedAt
            FROM license_allowlist WHERE org_id = @orgId ORDER BY license_spdx
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<LicenseAllowlistEntry?> AddAllowlistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var id = Guid.NewGuid().ToString("N");
        try
        {
            await conn.ExecuteAsync(
                "INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES (@id, @orgId, @licenseSpdx)",
                new { id, orgId, licenseSpdx });
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            // UNIQUE constraint — already exists
            return null;
        }
        return new LicenseAllowlistEntry
        {
            Id = id, OrgId = orgId, LicenseSpdx = licenseSpdx, CreatedAt = DateTimeOffset.UtcNow
        };
    }

    public async Task<bool> RemoveAllowlistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var affected = await conn.ExecuteAsync(
            "DELETE FROM license_allowlist WHERE org_id = @orgId AND license_spdx = @licenseSpdx",
            new { orgId, licenseSpdx });
        return affected > 0;
    }

    // ── License blocklist ─────────────────────────────────────────────────────

    public async Task<IReadOnlyList<LicenseBlocklistEntry>> GetBlocklistAsync(
        string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<LicenseBlocklistEntry>(
            """
            SELECT id as Id, org_id as OrgId, license_spdx as LicenseSpdx, created_at as CreatedAt
            FROM license_blocklist WHERE org_id = @orgId ORDER BY license_spdx
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<LicenseBlocklistEntry?> AddBlocklistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var id = Guid.NewGuid().ToString("N");
        try
        {
            await conn.ExecuteAsync(
                "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES (@id, @orgId, @licenseSpdx)",
                new { id, orgId, licenseSpdx });
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return null;
        }
        return new LicenseBlocklistEntry
        {
            Id = id, OrgId = orgId, LicenseSpdx = licenseSpdx, CreatedAt = DateTimeOffset.UtcNow
        };
    }

    public async Task<bool> RemoveBlocklistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var affected = await conn.ExecuteAsync(
            "DELETE FROM license_blocklist WHERE org_id = @orgId AND license_spdx = @licenseSpdx",
            new { orgId, licenseSpdx });
        return affected > 0;
    }

    // ── Review queue ──────────────────────────────────────────────────────────

    /// <summary>
    /// Returns SPDX identifiers observed during ingestion for this tenant that are on
    /// neither the allow- nor block-list. Includes a per-row package count and first-seen
    /// timestamp so the admin UI can prioritise high-impact licenses.
    ///
    /// Compound expressions (PyPI PEP 639 emits "MIT OR Apache-2.0" verbatim) are surfaced
    /// with <c>IsCompound = true</c>. The UI disables Approve/Block on those rows because
    /// <see cref="CheckPolicyAsync"/> compares license strings literally — adding a compound
    /// to the allowlist would not match a future "MIT" lookup.
    ///
    /// Deprecated SPDX identifiers are excluded by default to keep the queue actionable;
    /// they reappear under <c>includeDeprecated = true</c> for backfill workflows.
    /// </summary>
    public async Task<IReadOnlyList<LicenseReviewEntry>> GetReviewQueueAsync(
        string orgId, bool includeDeprecated, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<LicenseReviewEntry>(
            """
            SELECT pvl.license_spdx                                         AS LicenseSpdx,
                   COUNT(DISTINCT pv.package_id)                            AS PackageCount,
                   MIN(pvl.created_at)                                      AS FirstSeen,
                   CASE
                     WHEN pvl.license_spdx LIKE '% OR %'
                       OR pvl.license_spdx LIKE '% AND %'
                       OR pvl.license_spdx LIKE '% WITH %'
                       OR pvl.license_spdx LIKE '(%'
                     THEN 1 ELSE 0
                   END                                                      AS IsCompound,
                   COALESCE(spdx.is_deprecated, 0)                          AS IsDeprecated
            FROM package_version_licenses pvl
            JOIN package_versions pv ON pv.id = pvl.package_version_id
            JOIN packages         p  ON p.id  = pv.package_id
            LEFT JOIN license_allowlist al
              ON al.org_id = p.org_id AND al.license_spdx = pvl.license_spdx
            LEFT JOIN license_blocklist bl
              ON bl.org_id = p.org_id AND bl.license_spdx = pvl.license_spdx
            LEFT JOIN spdx_license spdx
              ON spdx.identifier = pvl.license_spdx
            WHERE p.org_id = @orgId
              AND al.id IS NULL
              AND bl.id IS NULL
              AND (@includeDeprecated = 1 OR COALESCE(spdx.is_deprecated, 0) = 0)
            GROUP BY pvl.license_spdx, COALESCE(spdx.is_deprecated, 0)
            ORDER BY COUNT(DISTINCT pv.package_id) DESC,
                     MIN(pvl.created_at) ASC,
                     pvl.license_spdx ASC
            """,
            new { orgId, includeDeprecated = includeDeprecated ? 1 : 0 });

        return rows.ToList();
    }

    // ── Policy check ──────────────────────────────────────────────────────────

    /// <summary>
    /// Returns whether the given set of SPDX license identifiers passes the org's license policy.
    /// Returns (allowed: true, reason: null) when mode is 'off' or licenses are empty.
    /// Returns (allowed: false, blockedLicense) when a blocklisted license is found.
    /// Returns (allowed: false, unknownLicense) when mode is 'block' and no license is on the allowlist.
    /// </summary>
    public async Task<(bool Allowed, string? BlockedLicense)> CheckPolicyAsync(
        string orgId, string mode, IReadOnlyList<string> spdxIds, CancellationToken ct = default)
    {
        if (mode == "off" || spdxIds.Count == 0)
            return (true, null);

        var blocklist = await GetBlocklistAsync(orgId, ct);
        var blockSet = blocklist.Select(e => e.LicenseSpdx).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var blocked = spdxIds.FirstOrDefault(blockSet.Contains);
        if (blocked is not null)
            return (false, blocked);

        if (mode == "block")
        {
            var allowlist = await GetAllowlistAsync(orgId, ct);
            var allowSet = allowlist.Select(e => e.LicenseSpdx).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var spdx in spdxIds)
            {
                if (!allowSet.Contains(spdx))
                    return (false, spdx);
            }
        }

        return (true, null);
    }
}
