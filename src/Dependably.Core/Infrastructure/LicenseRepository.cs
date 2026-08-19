using System.Diagnostics.CodeAnalysis;
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

    // Extended constraint codes. The bare SQLITE_CONSTRAINT (19) covers every constraint kind,
    // including the foreign key on created_by — catching it wholesale would report a dangling
    // author id as "this licence is already listed", a 409 for a request that has no duplicate
    // in it. Only a genuine uniqueness collision means "already listed".
    private const int SqliteConstraintUnique = 2067;
    private const int SqliteConstraintPrimaryKey = 1555;

    private static bool IsUniquenessViolation(Microsoft.Data.Sqlite.SqliteException ex) =>
        ex.SqliteErrorCode == SqliteConstraintErrorCode
        && ex.SqliteExtendedErrorCode is SqliteConstraintUnique or SqliteConstraintPrimaryKey;

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
        const string sql = """
            SELECT package_version_id as VersionId, license_spdx as Spdx
            FROM package_version_licenses
            WHERE package_version_id IN @ids
            ORDER BY license_spdx
            """;
        // The @ids token is swapped for a literal (@id0, @id1, ...) list before the query ever
        // reaches Dapper — see DapperInClause for why Dapper's own IN @ids auto-expansion cannot
        // be trusted here (it silently binds the whole list as one Postgres array parameter
        // instead, which IN never accepts).
        var (idsClause, idsParams) = DapperInClause.Expand("id", ids);
        var rows = await conn.QueryAsync<VersionLicenseRow>(sql.Replace("@ids", idsClause), idsParams);
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
        const string sql = """
            SELECT cache_artifact_id as ArtifactId, license_spdx as Spdx
            FROM package_version_licenses
            WHERE cache_artifact_id IN @ids
              AND owner_kind = 'cache_artifact'
            ORDER BY license_spdx
            """;
        // See DapperInClause: Dapper's own IN @ids auto-expansion binds the whole list as one
        // Postgres array parameter instead of expanding the SQL text, which IN never accepts.
        var (idsClause, idsParams) = DapperInClause.Expand("id", ids);
        var rows = await conn.QueryAsync<CacheArtifactLicenseRow>(sql.Replace("@ids", idsClause), idsParams);
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
            SELECT id as Id, org_id as OrgId, license_spdx as LicenseSpdx,
                   disposition as Disposition, note as Note, created_by as CreatedBy,
                   created_at as CreatedAt
            FROM license_allowlist WHERE org_id = @orgId ORDER BY license_spdx
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<LicenseAllowlistEntry?> AddAllowlistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
        => await AddAllowlistAsync(orgId, licenseSpdx, LicenseDispositions.Allowed, null, null, ct);

    /// <summary>Adds an allow- or conditional-list entry. <paramref name="disposition"/> selects
    /// which of the two non-denied postures the licence takes; <paramref name="note"/> records the
    /// operator's rationale, which for a conditional entry is the condition itself. Returns null
    /// when the org already has an entry for this licence — one licence carries one disposition,
    /// enforced by UNIQUE (org_id, license_spdx).</summary>
    public async Task<LicenseAllowlistEntry?> AddAllowlistAsync(
        string orgId, string licenseSpdx, string disposition, string? note, string? createdBy,
        CancellationToken ct = default)
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
                """
                INSERT INTO license_allowlist (id, org_id, license_spdx, disposition, note, created_by)
                VALUES (@id, @orgId, @licenseSpdx, @disposition, @note, @createdBy)
                """,
                new { id, orgId, licenseSpdx = normalized, disposition, note, createdBy });
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (IsUniquenessViolation(ex))
        {
            // UNIQUE constraint — already exists
            return null;
        }
        return new LicenseAllowlistEntry
        {
            Id = id,
            OrgId = orgId,
            LicenseSpdx = normalized,
            Disposition = disposition,
            Note = note,
            CreatedBy = createdBy,
            CreatedAt = _time.GetUtcNow()
        };
    }

    /// <summary>Edits an existing allowlist entry in place. Both fields are leave-unchanged when
    /// the corresponding <c>Optional</c> is absent, so a caller that only means to retitle a note
    /// cannot silently reset the disposition — the same posture the proxy-settings endpoint takes.
    /// Returns the updated entry, or null when the org has no entry for this licence.</summary>
    public async Task<LicenseAllowlistEntry?> UpdateAllowlistAsync(
        string orgId, string licenseSpdx, string? disposition, bool noteSet, string? note,
        CancellationToken ct = default)
    {
        string normalized = _normalizer.Normalize(licenseSpdx);
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            """
            UPDATE license_allowlist
               SET disposition = COALESCE(@disposition, disposition),
                   note        = CASE WHEN @noteSet = 1 THEN @note ELSE note END
             WHERE org_id = @orgId AND license_spdx = @licenseSpdx
            """,
            new { orgId, licenseSpdx = normalized, disposition, noteSet = noteSet ? 1 : 0, note });
        return affected == 0
            ? null
            : await conn.QuerySingleOrDefaultAsync<LicenseAllowlistEntry>(
                """
                SELECT id as Id, org_id as OrgId, license_spdx as LicenseSpdx,
                       disposition as Disposition, note as Note, created_by as CreatedBy,
                       created_at as CreatedAt
                FROM license_allowlist WHERE org_id = @orgId AND license_spdx = @licenseSpdx
                """,
                new { orgId, licenseSpdx = normalized });
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
            SELECT id as Id, org_id as OrgId, license_spdx as LicenseSpdx,
                   note as Note, created_by as CreatedBy, created_at as CreatedAt
            FROM license_blocklist WHERE org_id = @orgId ORDER BY license_spdx
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<LicenseBlocklistEntry?> AddBlocklistAsync(
        string orgId, string licenseSpdx, CancellationToken ct = default)
        => await AddBlocklistAsync(orgId, licenseSpdx, null, null, ct);

    /// <summary>Adds a blocklist entry. <paramref name="note"/> records why the licence is
    /// refused — the most frequently asked question of any policy row.</summary>
    public async Task<LicenseBlocklistEntry?> AddBlocklistAsync(
        string orgId, string licenseSpdx, string? note, string? createdBy,
        CancellationToken ct = default)
    {
        // Normalize the incoming id to its canonical SPDX form before storing (see AddAllowlist).
        string normalized = _normalizer.Normalize(licenseSpdx);
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        try
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO license_blocklist (id, org_id, license_spdx, note, created_by)
                VALUES (@id, @orgId, @licenseSpdx, @note, @createdBy)
                """,
                new { id, orgId, licenseSpdx = normalized, note, createdBy });
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (IsUniquenessViolation(ex))
        {
            return null;
        }
        return new LicenseBlocklistEntry
        {
            Id = id,
            OrgId = orgId,
            LicenseSpdx = normalized,
            Note = note,
            CreatedBy = createdBy,
            CreatedAt = _time.GetUtcNow()
        };
    }

    /// <summary>Edits an existing blocklist entry's note in place. Leave-unchanged when
    /// <paramref name="noteSet"/> is false. Returns the updated entry, or null when absent.</summary>
    public async Task<LicenseBlocklistEntry?> UpdateBlocklistAsync(
        string orgId, string licenseSpdx, bool noteSet, string? note, CancellationToken ct = default)
    {
        string normalized = _normalizer.Normalize(licenseSpdx);
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            """
            UPDATE license_blocklist
               SET note = CASE WHEN @noteSet = 1 THEN @note ELSE note END
             WHERE org_id = @orgId AND license_spdx = @licenseSpdx
            """,
            new { orgId, licenseSpdx = normalized, noteSet = noteSet ? 1 : 0, note });
        return affected == 0
            ? null
            : await conn.QuerySingleOrDefaultAsync<LicenseBlocklistEntry>(
                """
                SELECT id as Id, org_id as OrgId, license_spdx as LicenseSpdx,
                       note as Note, created_by as CreatedBy, created_at as CreatedAt
                FROM license_blocklist WHERE org_id = @orgId AND license_spdx = @licenseSpdx
                """,
                new { orgId, licenseSpdx = normalized });
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
    /// Reads the canonical <c>artifact_license</c> / <c>artifact_inventory</c> read model (see
    /// <c>SchemaInitializer.Views.cs</c>) rather than hand-rolling the hosted/proxied union:
    /// <c>artifact_license</c> already spans both artifact planes — hosted/published artifacts
    /// (per-tenant <c>package_versions</c>) and proxied artifacts (the global <c>cache_artifact</c>
    /// plane, org-scoped via <c>tenant_artifact_access</c>) — and an OCI image's license is
    /// projected onto whichever plane catalogued it, so it needs no arm of its own.
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
        // artifact_license is already org-scoped (org_id spans both its hosted and proxied
        // arms), so filtering it alone keeps every row within the caller's tenant; the join to
        // artifact_inventory is keyed by the same (org_id, owner_kind, owner_id) pair and adds
        // no additional tenant it could leak across.
        var rawRows = await conn.QueryAsync<ReviewRawRow>(
            """
            SELECT al.license_spdx           AS RawLicenseSpdx,
                   ai.ecosystem || ':' || ai.name AS PackageKey,
                   al.created_at             AS CreatedAt
            FROM artifact_license al
            JOIN artifact_inventory ai
              ON ai.org_id = al.org_id AND ai.owner_kind = al.owner_kind AND ai.owner_id = al.owner_id
            WHERE al.org_id = @orgId
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
        const string metaSql = """
            SELECT identifier AS Identifier, name AS Name,
                   COALESCE(copyleft, 'unclassified') AS Copyleft,
                   is_deprecated AS IsDeprecated
            FROM spdx_license
            WHERE identifier IN @ids
            """;
        // See DapperInClause: Dapper's own IN @ids auto-expansion binds the whole list as one
        // Postgres array parameter instead of expanding the SQL text, which IN never accepts.
        var (idsClause, idsParams) = DapperInClause.Expand("id", ids);
        var meta = (await conn.QueryAsync<SpdxMetaRow>(metaSql.Replace("@ids", idsClause), idsParams))
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

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ReviewRawRow
    {
        public string RawLicenseSpdx { get; set; } = "";
        public string PackageKey { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
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
    /// Evaluates the given SPDX license entries against the org's license policy. Each entry
    /// may be a whole compound expression (e.g. "MIT OR Apache-2.0", "GPL-2.0-only WITH
    /// Classpath-exception-2.0") — it is parsed and evaluated, so an OR is satisfied when any
    /// one leaf is satisfied (a blocked sibling does not sink it) and an AND requires every leaf.
    /// Both stored policy ids and each observed leaf are normalized to canonical SPDX form
    /// before comparison, so "Apache License 2.0" matches an "Apache-2.0" allowlist entry.
    ///
    /// <para>A licence carries one of three postures. 'allowed' and 'conditional' both satisfy
    /// the block-mode leaf check — a conditional licence serves and publishes normally — while
    /// the blocklist refuses. The blocklist still wins over both: a licence somehow present on
    /// the allowlist and the blocklist at once is refused.</para>
    ///
    /// <para>The verdict names the conditional leaves it matched, because "allowed" alone cannot
    /// express "allowed, and somebody should look at this". Callers surface those for review
    /// rather than refusing them.</para>
    /// </summary>
    public async Task<LicensePolicyVerdict> CheckPolicyAsync(
        string orgId, string mode, IReadOnlyList<string> spdxIds, CancellationToken ct = default)
    {
        if (mode == "off" || spdxIds.Count == 0)
        {
            return LicensePolicyVerdict.Clean;
        }

        var allowlist = await GetAllowlistAsync(orgId, ct);
        var blocklist = await GetBlocklistAsync(orgId, ct);
        var allowSet = allowlist
            .Where(e => e.Disposition != LicenseDispositions.Conditional)
            .Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var conditionalSet = allowlist
            .Where(e => e.Disposition == LicenseDispositions.Conditional)
            .Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var blockSet = blocklist.Select(e => _normalizer.Normalize(e.LicenseSpdx))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool LeafSatisfied(string leaf)
        {
            string norm = _normalizer.Normalize(leaf);
            if (blockSet.Contains(norm))
            {
                // Blocklist wins over both non-denied postures, in either mode.
                return false;
            }
            return mode != "block" || allowSet.Contains(norm) || conditionalSet.Contains(norm);
        }

        // True when removing this leaf from the satisfied set would leave the expression
        // unsatisfied — i.e. the artifact genuinely relies on the conditional licence. Under an
        // AND every leaf is load-bearing; under an OR a conditional leaf only matters when no
        // unconditional sibling already satisfies the expression on its own.
        bool LeafIsLoadBearing(SpdxLicenseExpression expr, string normalizedLeaf) =>
            !expr.Evaluate(leaf =>
                !_normalizer.Normalize(leaf).Equals(normalizedLeaf, StringComparison.OrdinalIgnoreCase)
                && LeafSatisfied(leaf));

        var conditionalLeaves = new List<string>();
        foreach (string entry in spdxIds)
        {
            var expr = SpdxLicenseExpression.Parse(entry);
            if (!expr.Evaluate(LeafSatisfied))
            {
                string offending = expr.Leaves().FirstOrDefault(leaf => !LeafSatisfied(leaf)) ?? entry;
                return LicensePolicyVerdict.Blocked(_normalizer.Normalize(offending));
            }

            // Only leaves that actually carried the expression are reported. A satisfied OR whose
            // conditional branch was not the one that satisfied it (say "MIT OR LGPL-3.0" with MIT
            // plainly allowed) raises nothing — the artifact is usable under the unconditional
            // branch, so there is no condition for anyone to review.
            foreach (string leaf in expr.Leaves())
            {
                string norm = _normalizer.Normalize(leaf);
                if (conditionalSet.Contains(norm)
                    && !conditionalLeaves.Contains(norm, StringComparer.OrdinalIgnoreCase)
                    && LeafIsLoadBearing(expr, norm))
                {
                    conditionalLeaves.Add(norm);
                }
            }
        }

        return conditionalLeaves.Count == 0
            ? LicensePolicyVerdict.Clean
            : LicensePolicyVerdict.Conditional(conditionalLeaves);
    }

}

/// <summary>
/// Outcome of a licence-policy evaluation. Three states, not two: an artifact can be refused,
/// plainly usable, or usable under a licence the org marked conditional — the last of which is
/// allowed to serve but named so callers can surface it for review.
/// </summary>
/// <param name="Allowed">False only when the policy refuses the artifact.</param>
/// <param name="BlockedLicense">The first leaf the policy rejected; null when allowed.</param>
/// <param name="ConditionalLicenses">Conditional leaves the artifact actually relies on. Empty
/// when nothing needs review.</param>
public sealed record LicensePolicyVerdict(
    bool Allowed,
    string? BlockedLicense,
    IReadOnlyList<string> ConditionalLicenses)
{
    private static readonly string[] None = [];

    public static readonly LicensePolicyVerdict Clean = new(true, null, None);

    public static LicensePolicyVerdict Blocked(string? offendingLeaf) => new(false, offendingLeaf, None);

    public static LicensePolicyVerdict Conditional(IReadOnlyList<string> leaves) => new(true, null, leaves);

    /// <summary>True when the artifact serves but relies on a licence the org marked conditional.</summary>
    public bool IsConditional => Allowed && ConditionalLicenses.Count > 0;
}
