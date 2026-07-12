using Dapper;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// CRUD for package_version_licenses, license_allowlist, and license_blocklist tables.
/// </summary>
public sealed class LicenseRepository
{
    // SQLite SQLITE_CONSTRAINT error code (unique constraint violation on insert).
    private const int SqliteConstraintErrorCode = 19;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly LicenseNormalizer _normalizer;

    public LicenseRepository(IMetadataStore db, TimeProvider time, LicenseNormalizer normalizer)
    {
        _db = db;
        _time = time;
        _normalizer = normalizer;
    }

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
        foreach (string spdx in spdxIds)
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

    /// <summary>
    /// Attaches SPDX license identifiers to a global <c>cache_artifact</c> row using
    /// <c>owner_kind='cache_artifact'</c>. Idempotent — duplicate inserts are silently
    /// ignored via the <c>UNIQUE(cache_artifact_id, license_spdx)</c> constraint. Called
    /// from the dual-write path so global license facts are written in parallel with the
    /// per-tenant <c>package_version_licenses</c> rows.
    /// </summary>
    // xtenant: cache_artifact is a global table; the id comes from the caller's
    // CacheAccessRecorder result so no cross-tenant row is writable here.
    public async Task SetLicensesForCacheArtifactAsync(
        string cacheArtifactId,
        IEnumerable<string> spdxIds,
        string source,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        foreach (string spdx in spdxIds)
        {
            // xtenant: cache_artifact is a global table; cacheArtifactId comes from the
            // caller's CacheAccessRecorder result so no cross-tenant row is reachable here.
            await conn.ExecuteAsync(
                """
                INSERT INTO package_version_licenses
                    (id, cache_artifact_id, owner_kind, license_spdx, source)
                VALUES (@id, @caId, 'cache_artifact', @spdx, @source)
                ON CONFLICT(cache_artifact_id, license_spdx) DO NOTHING
                """,
                new { id = Guid.NewGuid().ToString("N"), caId = cacheArtifactId, spdx, source });
        }
    }

    public async Task<ILookup<string, string>> GetSpdxForVersionsAsync(
        IEnumerable<string> versionIds, CancellationToken ct = default)
    {
        var ids = versionIds.ToList();
        if (ids.Count == 0)
        {
            return Enumerable.Empty<VersionLicenseRow>().ToLookup(r => r.VersionId, r => r.Spdx);
        }

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

    /// <summary>
    /// Bulk-reads SPDX license identifiers attached to a set of <c>cache_artifact</c> rows
    /// (rows where <c>owner_kind='cache_artifact'</c>). Returns an <see cref="ILookup{TKey,TElement}"/>
    /// keyed by <c>cache_artifact_id</c> so callers can resolve licenses for a batch of global
    /// artifacts in one round-trip. Artifacts with no license rows are absent from the lookup.
    /// </summary>
    public async Task<ILookup<string, string>> GetSpdxForCacheArtifactsAsync(
        IEnumerable<string> cacheArtifactIds, CancellationToken ct = default)
    {
        var ids = cacheArtifactIds.ToList();
        if (ids.Count == 0)
        {
            return Enumerable.Empty<CacheArtifactLicenseRow>()
                .ToLookup(r => r.ArtifactId, r => r.Spdx);
        }

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: cache_artifact is a global table; rows are keyed by cache_artifact_id
        // (content-addressed, no org column). Callers supply IDs from their own tenant's
        // artifact access records so no arbitrary cross-tenant row is reachable.
        var rows = await conn.QueryAsync<CacheArtifactLicenseRow>(
            """
            SELECT cache_artifact_id as ArtifactId, license_spdx as Spdx
            FROM package_version_licenses
            WHERE cache_artifact_id IN @ids
              AND owner_kind = 'cache_artifact'
            ORDER BY license_spdx
            """,
            new { ids });
        return rows.ToLookup(r => r.ArtifactId, r => r.Spdx);
    }

    private sealed record VersionLicenseRow(string VersionId, string Spdx);
    private sealed record CacheArtifactLicenseRow(string ArtifactId, string Spdx);

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
        // Normalize the incoming id to its canonical SPDX form before storing, so the entry is
        // consistent with the case-sensitive Remove* / CheckPolicy comparisons and collapses
        // name variants ("Apache License 2.0" -> "Apache-2.0") onto one canonical row.
        string normalized = _normalizer.Normalize(licenseSpdx);
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        try
        {
            await conn.ExecuteAsync(
                "INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES (@id, @orgId, @licenseSpdx)",
                new { id, orgId, licenseSpdx = normalized });
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == SqliteConstraintErrorCode)
        {
            // UNIQUE constraint — already exists
            return null;
        }
        return new LicenseAllowlistEntry
        {
            Id = id,
            OrgId = orgId,
            LicenseSpdx = normalized,
            CreatedAt = _time.GetUtcNow()
        };
    }

    public async Task<bool> RemoveAllowlistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
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
        // Normalize the incoming id to its canonical SPDX form before storing (see AddAllowlist).
        string normalized = _normalizer.Normalize(licenseSpdx);
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        try
        {
            await conn.ExecuteAsync(
                "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES (@id, @orgId, @licenseSpdx)",
                new { id, orgId, licenseSpdx = normalized });
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == SqliteConstraintErrorCode)
        {
            return null;
        }
        return new LicenseBlocklistEntry
        {
            Id = id,
            OrgId = orgId,
            LicenseSpdx = normalized,
            CreatedAt = _time.GetUtcNow()
        };
    }

    public async Task<bool> RemoveBlocklistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            "DELETE FROM license_blocklist WHERE org_id = @orgId AND license_spdx = @licenseSpdx",
            new { orgId, licenseSpdx });
        return affected > 0;
    }

    // ── Review queue ──────────────────────────────────────────────────────────

    /// <summary>
    /// Returns single canonical SPDX license leaves observed during ingestion for this tenant
    /// that are on neither the allow- nor block-list. Includes a per-leaf package count and
    /// first-seen timestamp so the admin UI can prioritise high-impact licenses.
    ///
    /// Licenses are merged across both planes: hosted/published artifacts (per-tenant
    /// <c>package_versions</c>) and proxied artifacts (the global <c>cache_artifact</c> plane,
    /// org-scoped via <c>tenant_artifact_access</c>).
    ///
    /// Compound expressions (PyPI PEP 639 emits "MIT OR Apache-2.0" verbatim) are split into
    /// their individual leaves — each leaf is reviewed and approved independently — and name
    /// variants collapse onto their canonical SPDX id ("Apache License 2.0" and "Apache-2.0"
    /// become one <c>Apache-2.0</c> row). A package contributing the same leaf through two
    /// expressions is counted once (the count is set-based over package keys).
    ///
    /// Observed deprecated leaves are always surfaced: the normalizer does not remap a
    /// deprecated id, so a real <c>GPL-3.0</c> package must appear to be actionable. The
    /// <paramref name="includeDeprecated"/> parameter is retained for API compatibility but is
    /// now a no-op for this reason; the <c>IsDeprecated</c> flag still drives the UI badge.
    /// </summary>
    public async Task<IReadOnlyList<LicenseReviewEntry>> GetReviewQueueAsync(
        string orgId, bool includeDeprecated, CancellationToken ct = default)
    {
        _ = includeDeprecated;

        var allowlist = await GetAllowlistAsync(orgId, ct);
        var blocklist = await GetBlocklistAsync(orgId, ct);
        var allowSet = allowlist.Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var blockSet = blocklist.Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        await using var conn = await _db.OpenAsync(ct);
        // Both UNION arms filter on @orgId (hosted via packages.org_id, proxied via
        // tenant_artifact_access.org_id), so no cross-tenant row is reachable.
        var rawRows = await conn.QueryAsync<ReviewRawRow>(
            """
            SELECT pvl.license_spdx                     AS RawLicenseSpdx,
                   p.ecosystem || ':' || p.purl_name    AS PackageKey,
                   pvl.created_at                        AS CreatedAt
            FROM package_version_licenses pvl
            JOIN package_versions pv ON pv.id = pvl.package_version_id
            JOIN packages         p  ON p.id  = pv.package_id
            WHERE p.org_id = @orgId
            UNION ALL
            SELECT pvl.license_spdx                     AS RawLicenseSpdx,
                   ca.ecosystem || ':' || ca.name       AS PackageKey,
                   pvl.created_at                        AS CreatedAt
            FROM package_version_licenses pvl
            JOIN cache_artifact ca
              ON ca.id = pvl.cache_artifact_id
            JOIN tenant_artifact_access taa
              ON taa.cache_artifact_id = pvl.cache_artifact_id
             AND taa.org_id = @orgId
            WHERE pvl.owner_kind = 'cache_artifact'
            """,
            new { orgId });

        // Split each raw expression into leaves, normalize identity, and aggregate by leaf.
        var accum = new Dictionary<string, LeafAccumulator>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rawRows)
        {
            foreach (string leaf in SpdxLicenseExpression.Parse(row.RawLicenseSpdx).Leaves())
            {
                string norm = _normalizer.Normalize(leaf);
                if (string.IsNullOrEmpty(norm) || allowSet.Contains(norm) || blockSet.Contains(norm))
                {
                    continue;
                }
                if (!accum.TryGetValue(norm, out var leafAccum))
                {
                    leafAccum = new LeafAccumulator();
                    accum[norm] = leafAccum;
                }
                leafAccum.PackageKeys.Add(row.PackageKey);
                if (row.CreatedAt < leafAccum.MinFirstSeen)
                {
                    leafAccum.MinFirstSeen = row.CreatedAt;
                }
            }
        }

        if (accum.Count == 0)
        {
            return [];
        }

        // Hydrate name/copyleft/is_deprecated per distinct canonical leaf id in one round-trip.
        var ids = accum.Keys.ToList();
        // xtenant: spdx_license is a global reference table, no org scoping.
        var meta = (await conn.QueryAsync<SpdxMetaRow>(
            """
            SELECT identifier AS Identifier, name AS Name,
                   COALESCE(copyleft, 'unclassified') AS Copyleft,
                   is_deprecated AS IsDeprecated
            FROM spdx_license
            WHERE identifier IN @ids
            """,
            new { ids }))
            .ToDictionary(m => m.Identifier, StringComparer.OrdinalIgnoreCase);

        var entries = new List<LicenseReviewEntry>(accum.Count);
        foreach (var (norm, leafAccum) in accum)
        {
            meta.TryGetValue(norm, out var m);
            entries.Add(new LicenseReviewEntry
            {
                LicenseSpdx = norm,
                PackageCount = leafAccum.PackageKeys.Count,
                FirstSeen = leafAccum.MinFirstSeen,
                IsDeprecated = m?.IsDeprecated ?? false,
                Name = m?.Name,
                Copyleft = m?.Copyleft ?? "unclassified",
            });
        }

        return entries
            .OrderByDescending(e => e.PackageCount)
            .ThenBy(e => e.FirstSeen)
            .ThenBy(e => e.LicenseSpdx, StringComparer.Ordinal)
            .ToList();
    }

    private sealed class ReviewRawRow
    {
        public string RawLicenseSpdx { get; set; } = "";
        public string PackageKey { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
    }

    private sealed class SpdxMetaRow
    {
        public string Identifier { get; set; } = "";
        public string? Name { get; set; }
        public string Copyleft { get; set; } = "unclassified";
        public bool IsDeprecated { get; set; }
    }

    private sealed class LeafAccumulator
    {
        public HashSet<string> PackageKeys { get; } = new(StringComparer.Ordinal);
        public DateTimeOffset MinFirstSeen { get; set; } = DateTimeOffset.MaxValue;
    }

    // ── Policy check ──────────────────────────────────────────────────────────

    /// <summary>
    /// Returns whether the given SPDX license entries pass the org's license policy. Each entry
    /// may be a whole compound expression (e.g. "MIT OR Apache-2.0", "GPL-2.0-only WITH
    /// Classpath-exception-2.0") — it is parsed and evaluated, so an OR is satisfied when any
    /// one leaf is allowed (a blocked sibling does not sink it) and an AND requires every leaf.
    /// Both stored allow/block ids and each observed leaf are normalized to canonical SPDX form
    /// before comparison, so "Apache License 2.0" matches an "Apache-2.0" allowlist entry.
    ///
    /// Returns (allowed: true, null) when mode is 'off' or entries are empty. On the first
    /// unsatisfied entry returns (allowed: false, offendingLeaf) where the offending leaf is the
    /// first normalized leaf under that entry the policy rejects — naming a concrete license,
    /// not the whole expression.
    /// </summary>
    public async Task<(bool Allowed, string? BlockedLicense)> CheckPolicyAsync(
        string orgId, string mode, IReadOnlyList<string> spdxIds, CancellationToken ct = default)
    {
        if (mode == "off" || spdxIds.Count == 0)
        {
            return (true, null);
        }

        var allowlist = await GetAllowlistAsync(orgId, ct);
        var blocklist = await GetBlocklistAsync(orgId, ct);
        var allowSet = allowlist.Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var blockSet = blocklist.Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool LeafSatisfied(string leaf)
        {
            string norm = _normalizer.Normalize(leaf);
            return mode == "block"
                ? allowSet.Contains(norm) && !blockSet.Contains(norm)
                : !blockSet.Contains(norm);
        }

        foreach (string entry in spdxIds)
        {
            var expr = SpdxLicenseExpression.Parse(entry);
            if (!expr.Evaluate(LeafSatisfied))
            {
                string offending = expr.Leaves().FirstOrDefault(leaf => !LeafSatisfied(leaf)) ?? entry;
                return (false, _normalizer.Normalize(offending));
            }
        }

        return (true, null);
    }
}
