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
            ORDER BY last_accessed_at ASC
            LIMIT @limit
            """, new { olderThan, limit });
        return rows.AsList();
    }

    public async Task<long> GetTotalSizeBytesAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM cache_artifact");
    }

    public async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id });
    }

    /// <summary>
    /// Returns the block-gate-relevant facts from a <c>cache_artifact</c> row by id. Used by
    /// the proxy first-fetch path after scanning to build a <see cref="Protocol.BlockGateRequest"/>
    /// without a tenant context (global facts only; <c>ManualBlockState</c> is null for freshly
    /// created access rows). Returns null when the id is not found.
    /// </summary>
    // xtenant: cache_artifact is global; id comes from the caller's CacheAccessRecorder result
    // so no arbitrary cross-tenant row is reachable.
    public async Task<CacheArtifactGateFacts?> GetByIdForGateAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<CacheArtifactGateFacts>("""
            SELECT
                id              AS Id,
                deprecated      AS Deprecated,
                vuln_checked_at AS VulnCheckedAt,
                has_install_script   AS HasInstallScript,
                install_script_kind  AS InstallScriptKind,
                provenance_status    AS ProvenanceStatus,
                provenance_signer    AS ProvenanceSigner
            FROM cache_artifact
            WHERE id = @id
            """,
            new { id });
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
        string threshold = time.GetUtcNow().AddHours(-ageHours).ToString("yyyy-MM-ddTHH:mm:ssZ");
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
        string now = time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
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
        string now = time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET deprecation_checked_at = @now WHERE id = @id",
            new { id, now });
    }

    /// <summary>
    /// Stamps <c>revoked_at</c> on a <c>cache_artifact</c> row the first time the version is
    /// observed removed from upstream. Caller guards on the NULL→set transition so the
    /// timestamp records first-observation, not the latest refresh pass.
    /// </summary>
    // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
    public async Task SetRevokedAtAsync(string id, TimeProvider time, CancellationToken ct = default)
    {
        string now = time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
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
                ca.vuln_checked_at      AS VulnCheckedAt,
                ca.checksum_sha1        AS ChecksumSha1,
                ca.has_install_script   AS HasInstallScript,
                ca.install_script_kind  AS InstallScriptKind,
                ca.provenance_status    AS ProvenanceStatus,
                ca.provenance_signer    AS ProvenanceSigner,
                ca.upstream_integrity_value     AS UpstreamIntegrityValue,
                ca.upstream_integrity_algorithm AS UpstreamIntegrityAlgorithm,
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
                upstream_integrity_algorithm = COALESCE(@upstreamIntegrityAlgorithm, upstream_integrity_algorithm)
            WHERE id = @id
            """,
            new
            {
                id,
                purl,
                checksumSha1,
                publishedAt,
                deprecated,
                hasInstallScript = hasInstallScript ? 1 : 0,
                installScriptKind,
                provenanceStatus,
                provenanceSigner,
                upstreamIntegrityValue,
                upstreamIntegrityAlgorithm,
            });
    }
#pragma warning restore S107
}

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
            PublishedAt = PublishedAt,
            CreatedAt = CreatedAt,
            VulnCheckedAt = VulnCheckedAt,
            HasInstallScript = HasInstallScript,
            InstallScriptKind = InstallScriptKind,
            ProvenanceStatus = ProvenanceStatus,
            ProvenanceSigner = ProvenanceSigner,
            UpstreamIntegrityValue = UpstreamIntegrityValue,
            UpstreamIntegrityAlgorithm = UpstreamIntegrityAlgorithm,
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

/// <summary>
/// Minimal projection of <c>cache_artifact</c> needed to build a
/// <see cref="Protocol.BlockGateRequest"/> on the proxy first-fetch path. No tenant columns —
/// use <see cref="CacheArtifactServeFacts"/> when tenant context is available.
/// </summary>
public sealed class CacheArtifactGateFacts
{
    public string Id { get; init; } = "";
    public string? Deprecated { get; init; }
    public DateTimeOffset? VulnCheckedAt { get; init; }
    public bool HasInstallScript { get; init; }
    public string? InstallScriptKind { get; init; }
    public string? ProvenanceStatus { get; init; }
    public string? ProvenanceSigner { get; init; }
    /// <summary>
    /// Always null at the proxy first-fetch path (the tenant_artifact_access row was just
    /// created with no manual_block_state set). Present here so callers do not need to
    /// special-case the null check.
    /// </summary>
    public string? ManualBlockState => null;
}
