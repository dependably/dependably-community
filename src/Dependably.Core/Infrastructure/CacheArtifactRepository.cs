using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Persistence for the global shared proxy-cache index. One row per
/// <c>(ecosystem, name, version, filename)</c>; no tenant column. Per-tenant access lives in
/// <see cref="TenantArtifactAccessRepository"/>.
/// </summary>
public sealed class CacheArtifactRepository
{
    private readonly IMetadataStore _db;

    public CacheArtifactRepository(IMetadataStore db) { _db = db; }

    public async Task<CacheArtifact?> GetByCoordinateAsync(
        string ecosystem, string name, string version, string filename, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<CacheArtifact>("""
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, version AS Version,
                   filename AS Filename, blob_key AS BlobKey, content_hash AS ContentHash,
                   size_bytes AS SizeBytes, upstream_url AS UpstreamUrl,
                   upstream_etag AS UpstreamEtag, first_cached_at AS FirstCachedAt,
                   last_accessed_at AS LastAccessedAt
            FROM cache_artifact
            WHERE ecosystem = @ecosystem AND name = @name
              AND version = @version AND filename = @filename
            """, new { ecosystem, name, version, filename });
    }

    /// <summary>
    /// Inserts a new cache artifact row and returns the authoritative persisted record.
    /// Uses <c>ON CONFLICT (ecosystem, name, version, filename) DO NOTHING</c> so concurrent
    /// first-fetch races resolve to the single winner row without throwing. When the INSERT
    /// is a no-op (another tenant won the race), the winner's row is returned via a
    /// coordinate re-read so callers always receive the real persisted id.
    /// </summary>
    public async Task<CacheArtifact> InsertAsync(CacheArtifact artifact, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact (
                id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                upstream_url, upstream_etag, first_cached_at, last_accessed_at)
            VALUES (
                @Id, @Ecosystem, @Name, @Version, @Filename, @BlobKey, @ContentHash, @SizeBytes,
                @UpstreamUrl, @UpstreamEtag, @FirstCachedAt, @LastAccessedAt)
            ON CONFLICT (ecosystem, name, version, filename) DO NOTHING
            """, artifact);
        // Re-read by coordinate — the INSERT may have been a no-op when a concurrent
        // first-fetch won the race, so the returned row's id may differ from artifact.Id.
        return (await conn.QuerySingleOrDefaultAsync<CacheArtifact>("""
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, version AS Version,
                   filename AS Filename, blob_key AS BlobKey, content_hash AS ContentHash,
                   size_bytes AS SizeBytes, upstream_url AS UpstreamUrl,
                   upstream_etag AS UpstreamEtag, first_cached_at AS FirstCachedAt,
                   last_accessed_at AS LastAccessedAt
            FROM cache_artifact
            WHERE ecosystem = @Ecosystem AND name = @Name
              AND version = @Version AND filename = @Filename
            """, artifact))!;
    }

    public async Task TouchAccessAsync(string id, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET last_accessed_at = @at WHERE id = @id",
            new { id, at });
    }

    /// <summary>
    /// Returns artifacts eligible for LRU eviction in oldest-access-first order. The caller
    /// decides how many to evict per pass based on size/count caps.
    ///
    /// Excludes OCI, but no longer because OCI is un-evictable — the per-org retention arms
    /// (keep_versions, keep_days, purge_unlisted) now evict OCI images by releasing the digest
    /// claim, and OciBlobReclaimer's sweep reclaims what that orphans. The exclusion here is
    /// narrower: this path is global rather than per-org, and the caller's blob delete is guarded
    /// only against sibling cache_artifact rows, not against the oci_blobs rows that also point at
    /// a manifest. Evicting an OCI row here would still delete manifest bytes out from under them.
    /// Doing it correctly means releasing the claim for every org holding access before the row
    /// goes, inside a sweep that has no org context — a change with its own failure modes, so it
    /// is deliberately not folded in here.
    /// </summary>
    public async Task<IReadOnlyList<CacheArtifact>> ListLruCandidatesAsync(
        DateTimeOffset olderThan, int limit, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<CacheArtifact>("""
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, version AS Version,
                   filename AS Filename, blob_key AS BlobKey, content_hash AS ContentHash,
                   size_bytes AS SizeBytes, upstream_url AS UpstreamUrl,
                   upstream_etag AS UpstreamEtag, first_cached_at AS FirstCachedAt,
                   last_accessed_at AS LastAccessedAt
            FROM cache_artifact
            WHERE last_accessed_at < @olderThan
              AND ecosystem != 'oci'
            ORDER BY last_accessed_at ASC
            LIMIT @limit
            """, new { olderThan, limit });
        return rows.AsList();
    }

    /// <summary>
    /// Total bytes on the evictable cache plane, used by <c>CacheEvictionService</c>'s size cap.
    /// Excludes OCI to stay consistent with <see cref="ListLruCandidatesAsync"/>: the cap has to be
    /// measured against the bytes this path can actually reclaim, or counting rows it will never
    /// select makes the cap unreachable and the sweep spins.
    /// </summary>
    public async Task<long> GetTotalSizeBytesAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM cache_artifact WHERE ecosystem != 'oci'");
    }

    /// <summary>
    /// Total row count on the evictable cache plane, used by <c>CacheEvictionService</c>'s
    /// artifact-count cap. Excludes OCI for the same reason as
    /// <see cref="GetTotalSizeBytesAsync"/> — the cap must range over the rows this path can
    /// actually select.
    /// </summary>
    public async Task<long> GetTotalCountAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem != 'oci'");
    }

    public async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id });
    }

    /// <summary>
    /// True when at least one <c>cache_artifact</c> row other than <paramref name="excludingId"/>
    /// still references <paramref name="blobKey"/>. Content-addressed proxy blobs
    /// (<see cref="Storage.BlobKeys.Proxy"/>) are shared across every coordinate — any org, any
    /// ecosystem/name/version/filename — that happens to hash to the same upstream bytes, so
    /// evicting one coordinate must never physically delete a blob a sibling coordinate still
    /// needs. Used by <see cref="CacheOrphanBlobDeleter"/> as the shared-key refcount guard ahead
    /// of the physical delete on both cache-tier eviction paths.
    /// </summary>
    // xtenant: cache_artifact is a global, content-addressed table; whether a blob is still needed
    // anywhere is deliberately checked across every org's rows, not scoped to one tenant.
    public async Task<bool> BlobKeyReferencedElsewhereAsync(
        string blobKey, string excludingId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE blob_key = @blobKey AND id <> @excludingId",
            new { blobKey, excludingId });
        return count > 0;
    }

    /// <summary>
    /// Evicts <paramref name="orgId"/>'s access to every cached proxy version of
    /// <c>(ecosystem, name)</c> and returns how many versions were evicted plus the blob keys that
    /// were dereferenced (whose <c>cache_artifact</c> row had no other tenant retaining access and
    /// was deleted, so the caller can delete the blob).
    ///
    /// Removing the <c>tenant_artifact_access</c> row is what stops this org serving the cached
    /// copy — every proxy serve path joins on it — so this alone closes a stale-serve on the cache
    /// plane. The shared <c>cache_artifact</c> row and its blob are deleted only when no tenant
    /// retains access, so a version another tenant still proxies is never dereferenced. OCI is
    /// excluded from the shared-row delete: dropping an OCI <c>cache_artifact</c> destroys the
    /// manifest blob while its <c>oci_blobs</c> row and layer blobs survive — the same
    /// broken-serve / orphaned-layer hazard the retention and LRU paths guard against. The OCI
    /// tenant access row is still removed, so this org stops serving it either way.
    /// </summary>
    // xtenant: cache_artifact is global; this org's access is scoped through tenant_artifact_access,
    // and the shared-row reclamation is a single guarded DELETE across every tenant's access.
    public async Task<TenantProxyEviction> EvictTenantProxyVersionsForNameAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var accessed = (await conn.QueryAsync<(string Id, string BlobKey, string Ecosystem)>(
            new CommandDefinition(
                """
                SELECT ca.id AS Id, ca.blob_key AS BlobKey, ca.ecosystem AS Ecosystem
                FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId AND ca.ecosystem = @ecosystem AND ca.name = @name
                """,
                new { orgId, ecosystem, name }, cancellationToken: ct))).ToList();

        var dereferenced = new List<string>();
        foreach (var (id, blobKey, eco) in accessed)
        {
            if (ct.IsCancellationRequested) { break; }

            // Drop this org's access first — the serve path joins on it, so the cached copy stops
            // being served for this org even when the shared row survives for other tenants.
            await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                new { orgId, id }, cancellationToken: ct));

            if (string.Equals(eco, "oci", StringComparison.Ordinal))
            {
                // Never delete an OCI cache_artifact / manifest blob here — see the summary.
                continue;
            }

            // Reclaim the shared row only when no tenant retains access. The NOT EXISTS guard runs
            // inside the DELETE, so a concurrent fetch that (re)acquires access between a check and
            // the delete can't lose its row to a stale count — the row is dropped iff it is genuinely
            // unreferenced, and its blob is dereferenced only when that DELETE actually removed it.
            // xtenant: deliberately cross-tenant reclamation of the global cache_artifact row.
            int deleted = await conn.ExecuteAsync(new CommandDefinition(
                """
                DELETE FROM cache_artifact
                WHERE id = @id
                  AND NOT EXISTS (SELECT 1 FROM tenant_artifact_access WHERE cache_artifact_id = @id)
                """,
                new { id }, cancellationToken: ct));
            if (deleted == 1)
            {
                dereferenced.Add(blobKey);
            }
        }

        return new TenantProxyEviction(accessed.Count, dereferenced);
    }

    /// <summary>
    /// Returns distinct (ecosystem, name, org_id) groups in <c>cache_artifact</c> whose
    /// <c>deprecation_checked_at</c> is stale — never checked or checked more than
    /// <paramref name="ageHours"/> ago. Ordered oldest-first so a partial run still makes
    /// progress on the most stale packages. Excludes tenants in soft-delete state.
    /// npm/PyPI groups are refreshed for deprecation + upstream-latest; NuGet/Maven groups have no
    /// per-version deprecation signal and are refreshed for upstream-latest only (the same
    /// <c>deprecation_checked_at</c> column stamps "we did an upstream pass" for both).
    /// </summary>
    // xtenant: cross-tenant enumeration for the deprecation-refresh background pass; caller
    // processes each (ecosystem, name, orgId) group independently.
    public async Task<IReadOnlyList<(string Ecosystem, string Name, string OrgId)>>
        ListGroupsNeedingDeprecationRefreshAsync(int ageHours, int limit, TimeProvider time, CancellationToken ct = default)
    {
        string threshold = time.GetUtcNow().AddHours(-ageHours).ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Ecosystem, string Name, string OrgId)>(
            """
            SELECT ca.ecosystem AS Ecosystem, ca.name AS Name, taa.org_id AS OrgId
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
            JOIN orgs o ON o.id = taa.org_id
            LEFT JOIN org_settings os ON os.org_id = taa.org_id
            WHERE ca.ecosystem IN ('npm', 'pypi', 'nuget', 'maven')
              AND (ca.deprecation_checked_at IS NULL OR ca.deprecation_checked_at < @threshold)
              AND o.deleted_at IS NULL
              AND COALESCE(os.air_gapped, 0) = 0
            GROUP BY ca.ecosystem, ca.name, taa.org_id
            ORDER BY MIN(ca.deprecation_checked_at) ASC
            LIMIT @limit
            """,
            new { threshold, limit });
        return rows.ToList();
    }

    /// <summary>
    /// Returns proxy <c>cache_artifact</c> rows that have never had a license-extraction pass
    /// (<c>license_checked_at IS NULL</c>) for the ecosystems whose bytes carry an extractable
    /// license manifest (npm/PyPI/NuGet), LICENSE-file text (Go), or a POM (Maven). Keyset-paginated
    /// on <c>(first_cached_at, id)</c> — a total order, since <c>first_cached_at</c> alone is not
    /// unique — via <paramref name="afterFirstCachedAt"/> / <paramref name="afterId"/> (both null
    /// for the first page of a pass). LIMIT-batched so the backfill pass bounds its per-tick work.
    /// The caller advances the cursor from the last row of every batch regardless of per-row
    /// outcome, so a row that fails to process (and so is never stamped) cannot re-enter a later
    /// page of the SAME pass and starve newer rows behind it — it is simply retried on the next
    /// scheduled pass, when the cursor resets. Returns the coordinate plus the blob key the caller
    /// needs to open the artifact bytes. Maven cache rows mix jars, poms, and checksum sidecars
    /// under one ecosystem, and the extractable license signal lives only in the <c>.pom</c> —
    /// so Maven candidates are restricted to rows whose filename ends in <c>.pom</c>; jar and
    /// sidecar rows never become candidates and keep <c>license_checked_at</c> permanently NULL,
    /// which is harmless since this query excludes them regardless.
    /// </summary>
    // xtenant: cache_artifact is a global table (no org_id); the license-backfill pass enumerates
    // the whole shared cache plane oldest-first and processes each row independently.
    public async Task<IReadOnlyList<LicenseBackfillCandidate>> ListNeedingLicenseBackfillAsync(
        int limit,
        DateTimeOffset? afterFirstCachedAt = null,
        string? afterId = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<LicenseBackfillCandidate>(
            """
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, version AS Version,
                   filename AS Filename, blob_key AS BlobKey, first_cached_at AS FirstCachedAt
            FROM cache_artifact
            WHERE license_checked_at IS NULL
              AND (
                    ecosystem IN ('npm', 'pypi', 'nuget', 'golang', 'cargo')
                    OR (ecosystem = 'maven' AND LOWER(filename) LIKE '%.pom')
                  )
              AND (
                    @afterFirstCachedAt IS NULL
                    OR first_cached_at > @afterFirstCachedAt
                    OR (first_cached_at = @afterFirstCachedAt AND id > @afterId)
                  )
            ORDER BY first_cached_at ASC, id ASC
            LIMIT @limit
            """,
            new { limit, afterFirstCachedAt, afterId });
        return rows.ToList();
    }

    /// <summary>
    /// Stamps <c>license_checked_at</c> on a <c>cache_artifact</c> row. Called after every
    /// license-backfill attempt — whether a license was found, none was present, or the blob was
    /// missing — so the row leaves the <see cref="ListNeedingLicenseBackfillAsync"/> queue and is
    /// never rescanned. The timestamp is supplied by the caller's <see cref="TimeProvider"/>.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task MarkLicenseCheckedAsync(string id, DateTimeOffset checkedAt, CancellationToken ct = default)
    {
        string checkedAtIso = checkedAt.ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET license_checked_at = @checkedAtIso WHERE id = @id",
            new { id, checkedAtIso });
    }

    /// <summary>
    /// Returns all <c>cache_artifact</c> rows for a given (ecosystem, name) pair — the global
    /// view of all versions cached for that package. Used by the deprecation refresh pass to
    /// find which version rows need their <c>deprecated</c> / <c>deprecation_checked_at</c>
    /// columns updated.
    /// </summary>
    // xtenant: cache_artifact is global (no org_id); scoped by (ecosystem, name) coordinate.
    public async Task<IReadOnlyList<(string Id, string Version, string? Deprecated, string? DeprecationCheckedAt, string? RevokedAt, string? Purl)>>
        ListVersionsForNameAsync(string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string Version, string? Deprecated, string? DeprecationCheckedAt, string? RevokedAt, string? Purl)>(
            """
            SELECT id AS Id, version AS Version, deprecated AS Deprecated,
                   deprecation_checked_at AS DeprecationCheckedAt, revoked_at AS RevokedAt,
                   purl AS Purl
            FROM cache_artifact
            WHERE ecosystem = @ecosystem AND name = @name
            """,
            new { ecosystem, name });
        return rows.ToList();
    }

    /// <summary>
    /// Stamps both <c>deprecated</c> and <c>deprecation_checked_at</c> on a
    /// <c>cache_artifact</c> row. Passes NULL as <paramref name="deprecated"/> when the
    /// upstream confirms the version is not deprecated.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task UpdateDeprecationAsync(string id, string? deprecated, TimeProvider time, CancellationToken ct = default)
    {
        string now = time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET deprecated = @deprecated, deprecation_checked_at = @now WHERE id = @id",
            new { id, deprecated, now });
    }

    /// <summary>
    /// Stamps <c>deprecation_checked_at</c> without changing <c>deprecated</c>. Called when
    /// an upstream metadata fetch confirms no state change.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task TouchDeprecationCheckedAtAsync(string id, TimeProvider time, CancellationToken ct = default)
    {
        string now = time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET deprecation_checked_at = @now WHERE id = @id",
            new { id, now });
    }

    /// <summary>
    /// Writes the operational-risk versions-behind count on a <c>cache_artifact</c> row. Called
    /// every refresh pass (independent of whether <c>deprecated</c> changed) since upstream keeps
    /// publishing new versions even when this version's own deprecation state is unchanged.
    /// <paramref name="versionsBehind"/> is null when the count is unknown — never coerced to 0.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task UpdateVersionsBehindAsync(string id, int? versionsBehind, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET versions_behind = @versionsBehind WHERE id = @id",
            new { id, versionsBehind });
    }

    /// <summary>
    /// Stamps <c>revoked_at</c> on a <c>cache_artifact</c> row the first time the version is
    /// observed removed from upstream. Caller guards on the NULL→set transition so the
    /// timestamp records first-observation, not the latest refresh pass.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task SetRevokedAtAsync(string id, TimeProvider time, CancellationToken ct = default)
    {
        string now = time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET revoked_at = @now WHERE id = @id",
            new { id, now });
    }

    /// <summary>
    /// Clears <c>revoked_at</c> when a previously-revoked version reappears upstream.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task ClearRevokedAtAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET revoked_at = NULL WHERE id = @id",
            new { id });
    }

    /// <summary>
    /// Returns the serve facts for a proxy artifact at the given coordinate, joining
    /// <c>cache_artifact</c> (global) and <c>tenant_artifact_access</c> (org-scoped). Used by
    /// ecosystem download handlers as the cache-hit lookup on the proxy serve path. Returns null
    /// when no artifact is registered for the coordinate or when this tenant has never accessed it.
    /// </summary>
    // xtenant: cache_artifact is global (no org_id); org_id filter is on tenant_artifact_access.
    public async Task<CacheArtifactServeFacts?> GetServeFactsByCoordinateAsync(
        string orgId, string ecosystem, string name, string version, string filename,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<CacheArtifactServeFacts>("""
            SELECT
                ca.id               AS Id,
                ca.blob_key         AS BlobKey,
                ca.size_bytes       AS SizeBytes,
                ca.content_hash     AS ContentHash,
                ca.purl             AS Purl,
                ca.published_at     AS PublishedAt,
                ca.deprecated       AS Deprecated,
                ca.revoked_at       AS RevokedAt,
                ca.vuln_checked_at  AS VulnCheckedAt,
                ca.has_install_script      AS HasInstallScript,
                ca.install_script_kind     AS InstallScriptKind,
                ca.provenance_status       AS ProvenanceStatus,
                ca.provenance_signer       AS ProvenanceSigner,
                taa.manual_block_state     AS ManualBlockState,
                taa.yanked                 AS Yanked
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa
              ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = @ecosystem
              AND ca.name      = @name
              AND ca.version   = @version
              AND ca.filename  = @filename
            """,
            new { orgId, ecosystem, name, version, filename });
    }

    /// <summary>
    /// Same per-tenant serve-facts projection as <see cref="GetServeFactsByCoordinateAsync"/>, but
    /// keyed on the <c>cache_artifact</c> id. The proxy first-fetch path uses this to gate exactly
    /// the row it just recorded, rather than re-deriving the coordinate — the recorded name comes
    /// from upstream repository metadata and need not match the name parsed out of the requested
    /// filename, so a coordinate round-trip could miss the row that is about to be served.
    /// </summary>
    // xtenant: cache_artifact is global (no org_id); org_id filter is on tenant_artifact_access.
    public async Task<CacheArtifactServeFacts?> GetServeFactsByIdAsync(
        string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<CacheArtifactServeFacts>("""
            SELECT
                ca.id               AS Id,
                ca.blob_key         AS BlobKey,
                ca.size_bytes       AS SizeBytes,
                ca.content_hash     AS ContentHash,
                ca.purl             AS Purl,
                ca.published_at     AS PublishedAt,
                ca.deprecated       AS Deprecated,
                ca.revoked_at       AS RevokedAt,
                ca.vuln_checked_at  AS VulnCheckedAt,
                ca.has_install_script      AS HasInstallScript,
                ca.install_script_kind     AS InstallScriptKind,
                ca.provenance_status       AS ProvenanceStatus,
                ca.provenance_signer       AS ProvenanceSigner,
                taa.manual_block_state     AS ManualBlockState,
                taa.yanked                 AS Yanked
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa
              ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.id = @id
            """,
            new { orgId, id });
    }

    /// <summary>
    /// Returns all proxy artifacts accessible to <paramref name="orgId"/> for the given
    /// (ecosystem, name) pair — the per-tenant view of cached proxy versions for use by index
    /// and metadata renderers. Joins <c>cache_artifact</c> (global) with
    /// <c>tenant_artifact_access</c> (org-scoped) so only versions this tenant has previously
    /// accessed are returned. Used by the list/index/metadata renderer path as the source of
    /// proxy entries after the proxy first-fetch write path stopped inserting rows into
    /// <c>package_versions</c>.
    /// </summary>
    // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
    public async Task<IReadOnlyList<CacheArtifactIndexFacts>> ListServeFactsForNameAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<CacheArtifactIndexFacts>("""
            SELECT
                ca.id                   AS Id,
                ca.version              AS Version,
                ca.filename             AS Filename,
                ca.blob_key             AS BlobKey,
                ca.content_hash         AS ContentHash,
                ca.size_bytes           AS SizeBytes,
                ca.purl                 AS Purl,
                ca.published_at         AS PublishedAt,
                ca.first_cached_at      AS CreatedAt,
                ca.deprecated           AS Deprecated,
                ca.revoked_at           AS RevokedAt,
                ca.versions_behind      AS VersionsBehind,
                ca.vuln_checked_at      AS VulnCheckedAt,
                ca.checksum_sha1        AS ChecksumSha1,
                ca.has_install_script   AS HasInstallScript,
                ca.install_script_kind  AS InstallScriptKind,
                ca.provenance_status    AS ProvenanceStatus,
                ca.provenance_signer    AS ProvenanceSigner,
                ca.upstream_integrity_value     AS UpstreamIntegrityValue,
                ca.upstream_integrity_algorithm AS UpstreamIntegrityAlgorithm,
                ca.upstream_url         AS UpstreamUrl,
                ca.manifest_json        AS ManifestJson,
                taa.manual_block_state  AS ManualBlockState,
                taa.yanked              AS Yanked,
                taa.yank_reason         AS YankReason,
                taa.download_count      AS DownloadCount
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa
              ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = @ecosystem AND ca.name = @name
            ORDER BY ca.first_cached_at DESC
            """,
            new { orgId, ecosystem, name });
        return rows.AsList();
    }

    /// <summary>
    /// Idempotently writes supply-chain facts onto an existing <c>cache_artifact</c> row. Called
    /// after every proxy first-fetch once the artifact id is known, regardless of whether the row
    /// was just inserted or had already been created by a concurrent fetch. NULL parameters leave
    /// the corresponding columns unchanged (COALESCE keep-existing semantics).
    /// </summary>
    // xtenant: cache_artifact is a global table (no org_id); keyed by id from the caller's own
    // CacheAccessRecorder result so no cross-tenant data is accessible.
    // Wide parameter list is inherent to a multi-column supply-chain fact upsert; DI is not involved.
#pragma warning disable S107
    public async Task UpdateGlobalFactsAsync(
        string id,
        string? purl,
        string? checksumSha1,
        DateTimeOffset? publishedAt,
        string? deprecated,
        bool hasInstallScript,
        string? installScriptKind,
        string? provenanceStatus,
        string? provenanceSigner,
        string? upstreamIntegrityValue,
        string? upstreamIntegrityAlgorithm,
        // JSON install-manifest subset (dependencies/optionalDependencies/bin/engines) extracted
        // from the npm tarball's package.json at first-fetch. NULL for every non-npm ecosystem and
        // left unchanged (COALESCE keep-existing) when extraction fails, so a pre-migration row
        // backfills the next time this artifact is re-fetched rather than being overwritten back
        // to NULL.
        string? manifestJson = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            UPDATE cache_artifact SET
                purl                         = COALESCE(@purl, purl),
                checksum_sha1                = COALESCE(@checksumSha1, checksum_sha1),
                published_at                 = COALESCE(@publishedAt, published_at),
                deprecated                   = COALESCE(@deprecated, deprecated),
                has_install_script           = CASE WHEN @hasInstallScript = 1 THEN 1
                                                    ELSE has_install_script END,
                install_script_kind          = COALESCE(@installScriptKind, install_script_kind),
                provenance_status            = COALESCE(@provenanceStatus, provenance_status),
                provenance_signer            = COALESCE(@provenanceSigner, provenance_signer),
                upstream_integrity_value     = COALESCE(@upstreamIntegrityValue, upstream_integrity_value),
                upstream_integrity_algorithm = COALESCE(@upstreamIntegrityAlgorithm, upstream_integrity_algorithm),
                manifest_json                = COALESCE(@manifestJson, manifest_json)
            WHERE id = @id
            """,
            new
            {
                id,
                purl,
                checksumSha1,
                // Normalized to the canonical UTC string rather than bound as a DateTimeOffset:
                // the provider renders that type as `2026-07-25 14:00:00+02:00` — space-separated,
                // offset preserved — which neither matches the ISO-8601 `Z` form every other value
                // in this TEXT column uses nor collates with it. Microsecond precision because
                // this instant is declared by the upstream registry and re-served to clients
                // (PyPI's upload_time_iso_8601), so seconds would drop information we report.
                publishedAt = publishedAt.ToUtcIsoPreciseOrNull(),
                deprecated,
                hasInstallScript = hasInstallScript ? 1 : 0,
                installScriptKind,
                provenanceStatus,
                provenanceSigner,
                upstreamIntegrityValue,
                upstreamIntegrityAlgorithm,
                manifestJson,
            });
    }
#pragma warning restore S107
}

/// <summary>
/// Projection returned by <see cref="CacheArtifactRepository.ListNeedingLicenseBackfillAsync"/>:
/// the coordinate of a proxy artifact awaiting a license-extraction pass plus the
/// <c>blob_key</c> needed to open its bytes. <c>Filename</c> disambiguates the PyPI wheel/sdist
/// parse path; the extractor entry points key off it. <c>FirstCachedAt</c> (paired with
/// <c>Id</c>) is the keyset-pagination cursor the caller advances after every batch.
/// </summary>
public sealed record LicenseBackfillCandidate(
    string Id,
    string Ecosystem,
    string Name,
    string Version,
    string Filename,
    string BlobKey,
    DateTimeOffset FirstCachedAt);

/// <summary>
/// Result of <see cref="CacheArtifactRepository.EvictTenantProxyVersionsForNameAsync"/>:
/// <see cref="VersionsEvicted"/> is how many cached proxy versions this org lost access to;
/// <see cref="DereferencedBlobKeys"/> is the subset whose shared row had no remaining tenant and
/// was deleted, so the caller deletes those blobs. The two differ when a version stays proxied by
/// another tenant (evicted for this org, blob retained) or is OCI (access dropped, manifest kept).
/// </summary>
public sealed record TenantProxyEviction(int VersionsEvicted, IReadOnlyList<string> DereferencedBlobKeys);

public sealed class CacheArtifact
{
    public string Id { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string Filename { get; init; } = "";
    public string BlobKey { get; init; } = "";
    public string ContentHash { get; init; } = "";
    public long SizeBytes { get; init; }
    public string? UpstreamUrl { get; init; }
    public string? UpstreamEtag { get; init; }
    public DateTimeOffset FirstCachedAt { get; init; }
    public DateTimeOffset LastAccessedAt { get; init; }
}

/// <summary>
/// Projection returned by <see cref="CacheArtifactRepository.GetServeFactsByCoordinateAsync"/>.
/// Carries the blob-location fields from <c>cache_artifact</c> (global) and the per-tenant
/// policy state from <c>tenant_artifact_access</c>. Used by ecosystem download handlers to
/// serve proxy artifacts from the global plane and pass the correct signals to the block gate.
/// </summary>
public sealed class CacheArtifactServeFacts
{
    public string Id { get; init; } = "";
    public string BlobKey { get; init; } = "";
    public long SizeBytes { get; init; }
    public string ContentHash { get; init; } = "";
    public string? Purl { get; init; }
    public DateTimeOffset? PublishedAt { get; init; }
    public string? Deprecated { get; init; }
    /// <summary>ISO 8601 UTC; set when the version was observed removed from upstream. NULL = still published.</summary>
    public DateTimeOffset? RevokedAt { get; init; }
    public DateTimeOffset? VulnCheckedAt { get; init; }
    public bool HasInstallScript { get; init; }
    public string? InstallScriptKind { get; init; }
    public string? ProvenanceStatus { get; init; }
    public string? ProvenanceSigner { get; init; }
    /// <summary>Per-tenant manual policy override from <c>tenant_artifact_access.manual_block_state</c>.</summary>
    public string? ManualBlockState { get; init; }
    /// <summary>Per-tenant yank flag from <c>tenant_artifact_access.yanked</c>.</summary>
    public bool Yanked { get; init; }
}

/// <summary>
/// Per-tenant projection of a <c>cache_artifact</c> row joined with
/// <c>tenant_artifact_access</c>. Returned by
/// <see cref="CacheArtifactRepository.ListServeFactsForNameAsync"/> for use by the
/// list/index/metadata renderers so proxy versions appear even when no
/// <c>package_versions</c> row exists for them. Carries the subset of fields the
/// block-gate evaluator and index HTML/JSON builders need.
/// </summary>
public sealed class CacheArtifactIndexFacts
{
    public string Id { get; init; } = "";
    public string Version { get; init; } = "";
    public string Filename { get; init; } = "";
    public string BlobKey { get; init; } = "";
    public string ContentHash { get; init; } = "";
    /// <summary>Artifact size in bytes, sourced from <c>cache_artifact.size_bytes</c>.</summary>
    public long SizeBytes { get; init; }
    public string? Purl { get; init; }
    public DateTimeOffset? PublishedAt { get; init; }
    /// <summary>Timestamp of the global-plane first fetch, sourced from <c>cache_artifact.first_cached_at</c>.</summary>
    public DateTimeOffset CreatedAt { get; init; }
    public string? Deprecated { get; init; }
    /// <summary>ISO 8601 UTC; set when the version was observed removed from upstream. NULL = still published.</summary>
    public DateTimeOffset? RevokedAt { get; init; }
    /// <summary>
    /// Operational-risk versions-behind count from <c>cache_artifact.versions_behind</c>. NULL =
    /// unknown (never 0) — see <see cref="PackageVersion.VersionsBehind"/>.
    /// </summary>
    public int? VersionsBehind { get; init; }
    public DateTimeOffset? VulnCheckedAt { get; init; }
    /// <summary>Hex SHA-1, present for npm artifacts captured at first-fetch.</summary>
    public string? ChecksumSha1 { get; init; }
    public bool HasInstallScript { get; init; }
    public string? InstallScriptKind { get; init; }
    public string? ProvenanceStatus { get; init; }
    public string? ProvenanceSigner { get; init; }
    /// <summary>Per-tenant manual policy override from <c>tenant_artifact_access.manual_block_state</c>.</summary>
    public string? ManualBlockState { get; init; }
    /// <summary>Per-tenant yank flag from <c>tenant_artifact_access.yanked</c>.</summary>
    public bool Yanked { get; init; }
    /// <summary>Per-tenant yank reason from <c>tenant_artifact_access.yank_reason</c>.</summary>
    public string? YankReason { get; init; }
    /// <summary>Per-tenant cumulative download count from <c>tenant_artifact_access.download_count</c>.</summary>
    public long DownloadCount { get; init; }
    /// <summary>Upstream-declared SRI/digest from <c>cache_artifact.upstream_integrity_value</c>.</summary>
    public string? UpstreamIntegrityValue { get; init; }
    /// <summary>Algorithm tag ('sha256' | 'sha512-sri' | 'sha512-b64') for <see cref="UpstreamIntegrityValue"/>.</summary>
    public string? UpstreamIntegrityAlgorithm { get; init; }
    /// <summary>
    /// Full URL the artifact bytes were fetched from, sourced from <c>cache_artifact.upstream_url</c>.
    /// This is the resolved per-org upstream (a private registry when one is configured), recorded at
    /// first-fetch. NULL for rows created before the column existed.
    /// </summary>
    public string? UpstreamUrl { get; init; }
    /// <summary>
    /// JSON install-manifest subset (dependencies/optionalDependencies/bin/engines/…) from
    /// <c>cache_artifact.manifest_json</c>, in the same shape as
    /// <c>package_versions.manifest_json</c>. NULL for artifacts cached before ingest-time
    /// capture existed (backfilled lazily on next fetch) and for every non-npm ecosystem.
    /// </summary>
    public string? ManifestJson { get; init; }

    /// <summary>
    /// Projects this entry into a synthetic <see cref="PackageVersion"/> so the existing
    /// index renderers and block-gate helpers can process proxy cache-plane entries
    /// alongside uploaded versions without requiring separate code paths. The <c>Id</c>
    /// field is set to the <c>cache_artifact.id</c> so that
    /// <c>signals.GetValueOrDefault(v.Id)</c> resolves against the
    /// <paramref name="cacheSignals"/> dictionary (keyed by <c>cache_artifact_id</c>).
    /// <c>IsMalicious</c> is derived from the pre-loaded signals because the
    /// <c>package_version_vulns</c> join that normally populates it in SQL is keyed by
    /// <c>cache_artifact_id</c> for global-plane rows.
    /// </summary>
    public PackageVersion ToPackageVersionSynthetic(IReadOnlyDictionary<string, VulnGateSignals> cacheSignals)
    {
        var sig = cacheSignals.GetValueOrDefault(Id);
        return new PackageVersion
        {
            Id = Id,
            BlobKey = BlobKey,
            Filename = Filename,
            Version = Version,
            Purl = Purl ?? string.Empty,
            SizeBytes = SizeBytes,
            ChecksumSha256 = ContentHash,
            ChecksumSha1 = ChecksumSha1,
            Yanked = Yanked,
            YankReason = YankReason,
            ManualBlockState = ManualBlockState,
            Deprecated = Deprecated,
            RevokedAt = RevokedAt,
            VersionsBehind = VersionsBehind,
            PublishedAt = PublishedAt,
            CreatedAt = CreatedAt,
            VulnCheckedAt = VulnCheckedAt,
            HasInstallScript = HasInstallScript,
            InstallScriptKind = InstallScriptKind,
            ProvenanceStatus = ProvenanceStatus,
            ProvenanceSigner = ProvenanceSigner,
            UpstreamIntegrityValue = UpstreamIntegrityValue,
            UpstreamIntegrityAlgorithm = UpstreamIntegrityAlgorithm,
            UpstreamUrl = UpstreamUrl,
            ManifestJson = ManifestJson,
            DownloadCount = DownloadCount,
            Origin = "proxy",
            IsMalicious = sig?.HasMalicious ?? false,
            // The gate-signals dict carries a key only for artifacts with at least one linked
            // advisory, so presence mirrors the uploaded path's "EXISTS package_version_vulns"
            // HasAdvisory flag. Without this the status gate reads a vulnerable proxy version as
            // "clean" / No advisories.
            HasAdvisory = sig is not null,
        };
    }
}

