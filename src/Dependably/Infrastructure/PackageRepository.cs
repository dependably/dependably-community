using Dapper;

namespace Dependably.Infrastructure;

public sealed class PackageRepository
{
    private readonly IMetadataStore _db;
    private readonly DownloadCountWriter? _downloadCountWriter;
    private readonly TimeProvider _time;

    public PackageRepository(IMetadataStore db, DownloadCountWriter? downloadCountWriter = null, TimeProvider? time = null)
    {
        _db = db;
        _downloadCountWriter = downloadCountWriter;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Returns the trailing path segment of <paramref name="blobKey"/>. Surface-internal —
    /// callers building a <see cref="NewPackageVersion"/> only need to pass a blob key
    /// and the repository populates <c>filename</c> via this helper so the equality lookup
    /// in <see cref="FindVersionByBlobKeySuffixAsync"/> can use idx_package_versions_filename.
    /// </summary>
    internal static string DeriveFilename(string blobKey)
    {
        int lastSlash = blobKey.LastIndexOf('/');
        return lastSlash >= 0 ? blobKey[(lastSlash + 1)..] : blobKey;
    }

    public async Task<IReadOnlyList<Package>> ListAsync(string orgId, string ecosystem, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<Package>(
            """
            SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName,
                   is_proxy as IsProxy, created_at as CreatedAt
            FROM packages
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            ORDER BY purl_name
            """,
            new { orgId, ecosystem });
        return rows.ToList();
    }

    public async Task<Package?> GetByPurlNameAsync(string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<Package>(
            """
            SELECT p.id, p.org_id as OrgId, p.ecosystem, p.name, p.purl_name as PurlName,
                   p.is_proxy as IsProxy, p.created_at as CreatedAt,
                   p.upstream_latest_version as UpstreamLatestVersion,
                   CASE
                     WHEN p.upstream_latest_version IS NULL THEN 'unknown'
                     WHEN EXISTS (
                         SELECT 1 FROM package_versions pvl
                         WHERE pvl.package_id = p.id
                           AND pvl.version = p.upstream_latest_version
                           AND pvl.origin = 'uploaded'
                     ) OR EXISTS (
                         SELECT 1 FROM cache_artifact ca
                         JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                         WHERE taa.org_id = p.org_id
                           AND ca.ecosystem = p.ecosystem
                           AND ca.name = p.purl_name
                           AND ca.version = p.upstream_latest_version
                     ) THEN 'current'
                     ELSE 'stale'
                   END as LatestState
            FROM packages p
            WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem AND p.purl_name = @purlName
            """,
            new { orgId, ecosystem, purlName });
    }

    /// <summary>Gets or creates a package row; returns the resolved Package.</summary>
    public async Task<Package> GetOrCreateAsync(string orgId, string ecosystem, string name, string purlName, bool isProxy, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var existing = await conn.QuerySingleOrDefaultAsync<Package>(
            """
            SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName,
                   is_proxy as IsProxy, created_at as CreatedAt
            FROM packages WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
            """,
            new { orgId, ecosystem, purlName });

        if (existing is not null)
        {
            return existing;
        }

        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @orgId, @ecosystem, @name, @purlName, @isProxy)
            """,
            new { id, orgId, ecosystem, name, purlName, isProxy = isProxy ? 1 : 0 });

        return (await conn.QuerySingleOrDefaultAsync<Package>(
            "SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName, is_proxy as IsProxy, created_at as CreatedAt FROM packages WHERE id = @id",
            new { id }))!;
    }

    /// <summary>
    /// Finds a package version by its filename (the trailing path segment of blob_key), joined
    /// with its parent package. When <paramref name="uploadedOnly"/> is <c>true</c> (default),
    /// only <c>origin='uploaded'</c> rows are returned — proxy artifacts for ecosystems that
    /// have been flipped to the global plane are excluded. Pass <c>false</c> for ecosystems
    /// (e.g. RPM) that still record proxy origin rows in <c>package_versions</c>.
    /// Uses an equality lookup against <c>idx_package_versions_filename</c>.
    /// </summary>
    public async Task<(Package Package, PackageVersion Version)?> FindVersionByBlobKeySuffixAsync(
        string orgId, string ecosystem, string filename, CancellationToken ct = default,
        bool uploadedOnly = true)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (PkgId, PkgOrgId, PkgEcosystem, PkgName, PkgPurlName, PkgIsProxy, PkgCreatedAt,
            VerId, VerPackageId, VerVersion, VerPurl, VerBlobKey, VerSizeBytes, VerChecksumSha256,
            VerYanked, VerYankReason, VerFirstFetch, VerCreatedAt, VerVulnCheckedAt,
            VerManualBlockState, VerDeprecated, VerOrigin, VerPublishedAt, VerChecksumSha1,
            VerUpstreamIntegrityValue, VerUpstreamIntegrityAlgorithm) =
            await conn.QuerySingleOrDefaultAsync<(
            string PkgId, string PkgOrgId, string PkgEcosystem, string PkgName, string PkgPurlName, bool PkgIsProxy, string PkgCreatedAt,
            string VerId, string VerPackageId, string VerVersion, string VerPurl, string VerBlobKey,
            long VerSizeBytes, string? VerChecksumSha256, bool VerYanked, string? VerYankReason,
            bool VerFirstFetch, string VerCreatedAt, string? VerVulnCheckedAt, string? VerManualBlockState,
            string? VerDeprecated, string VerOrigin, string? VerPublishedAt, string? VerChecksumSha1,
            string? VerUpstreamIntegrityValue, string? VerUpstreamIntegrityAlgorithm)>(
            """
            SELECT p.id, p.org_id, p.ecosystem, p.name, p.purl_name, p.is_proxy, p.created_at,
                   pv.id, pv.package_id, pv.version, pv.purl, pv.blob_key,
                   pv.size_bytes, pv.checksum_sha256, pv.yanked, pv.yank_reason,
                   pv.first_fetch, pv.created_at, pv.vuln_checked_at, pv.manual_block_state,
                   pv.deprecated, pv.origin, pv.published_at, pv.checksum_sha1,
                   pv.upstream_integrity_value, pv.upstream_integrity_algorithm
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.filename = @filename AND p.org_id = @orgId AND p.ecosystem = @ecosystem
              AND (@uploadedOnly = 0 OR pv.origin = 'uploaded')
            LIMIT 1
            """,
            new { orgId, ecosystem, filename, uploadedOnly = uploadedOnly ? 1 : 0 });

        if (PkgId is null)
        {
            return null;
        }

        var pkg = new Package
        {
            Id = PkgId,
            OrgId = PkgOrgId,
            Ecosystem = PkgEcosystem,
            Name = PkgName,
            PurlName = PkgPurlName,
            IsProxy = PkgIsProxy,
            CreatedAt = DateTimeOffset.Parse(PkgCreatedAt)
        };
        var ver = new PackageVersion
        {
            Id = VerId,
            PackageId = VerPackageId,
            Version = VerVersion,
            Purl = VerPurl,
            BlobKey = VerBlobKey,
            SizeBytes = VerSizeBytes,
            ChecksumSha256 = VerChecksumSha256,
            Yanked = VerYanked,
            YankReason = VerYankReason,
            FirstFetch = VerFirstFetch,
            CreatedAt = DateTimeOffset.Parse(VerCreatedAt),
            VulnCheckedAt = VerVulnCheckedAt is not null ? DateTimeOffset.Parse(VerVulnCheckedAt) : null,
            ManualBlockState = VerManualBlockState,
            Deprecated = VerDeprecated,
            Origin = VerOrigin,
            PublishedAt = VerPublishedAt is not null ? DateTimeOffset.Parse(VerPublishedAt) : null,
            ChecksumSha1 = VerChecksumSha1,
            UpstreamIntegrityValue = VerUpstreamIntegrityValue,
            UpstreamIntegrityAlgorithm = VerUpstreamIntegrityAlgorithm
        };
        return (pkg, ver);
    }

    public async Task<IReadOnlyList<PackageVersion>> GetVersionsAsync(string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by package_id which the caller obtained via an org-scoped lookup.
        // package_versions FKs into packages(id), so org isolation rides on the parent.
        // is_malicious / has_advisory are derived from the version's advisory links: a MAL-
        // osv_id marks a known-malicious version; any link marks it as carrying advisories.
        var rows = await conn.QueryAsync<PackageVersion>(
            """
            SELECT pv.id, pv.package_id as PackageId, pv.version, pv.purl, pv.blob_key as BlobKey,
                   pv.size_bytes as SizeBytes, pv.checksum_sha256 as ChecksumSha256,
                   pv.yanked, pv.yank_reason as YankReason, pv.first_fetch as FirstFetch, pv.download_count as DownloadCount, pv.created_at as CreatedAt,
                   pv.vuln_checked_at as VulnCheckedAt, pv.manual_block_state as ManualBlockState,
                   pv.deprecated as Deprecated, pv.origin as Origin, pv.published_at as PublishedAt,
                   pv.checksum_sha1 as ChecksumSha1,
                   pv.upstream_integrity_value as UpstreamIntegrityValue,
                   pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   pv.has_install_script as HasInstallScript,
                   pv.install_script_kind as InstallScriptKind,
                   pv.provenance_status as ProvenanceStatus,
                   pv.provenance_signer as ProvenanceSigner,
                   EXISTS (SELECT 1 FROM package_version_vulns pvv
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE pvv.package_version_id = pv.id
                             AND v.osv_id LIKE 'MAL-%') as IsMalicious,
                   EXISTS (SELECT 1 FROM package_version_vulns pvv
                           WHERE pvv.package_version_id = pv.id) as HasAdvisory
            FROM package_versions pv
            WHERE pv.package_id = @packageId
            ORDER BY pv.created_at DESC
            """,
            new { packageId });
        return rows.ToList();
    }

    public async Task<PackageVersion?> GetVersionAsync(string packageId, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by package_id (caller-org-scoped); inherited via FK to packages(id).
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, download_count as DownloadCount, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin, published_at as PublishedAt,
                   checksum_sha1 as ChecksumSha1,
                   upstream_integrity_value as UpstreamIntegrityValue,
                   upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   has_install_script as HasInstallScript,
                   install_script_kind as InstallScriptKind,
                   provenance_status as ProvenanceStatus,
                   provenance_signer as ProvenanceSigner
            FROM package_versions
            WHERE package_id = @packageId AND version = @version
            """,
            new { packageId, version });
    }

    /// <summary>
    /// Lookup by blob_key, scoped to <paramref name="orgId"/> via the parent package's org_id.
    /// The org filter is defence-in-depth: blob_key is globally unique today, but joining
    /// through packages.org_id makes the tenancy invariant load-bearing in SQL rather than
    /// relying on every caller having org-scoped the lookup beforehand.
    /// </summary>
    public async Task<PackageVersion?> GetVersionByBlobKeyAsync(string orgId, string blobKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT pv.id, pv.package_id as PackageId, pv.version, pv.purl, pv.blob_key as BlobKey,
                   pv.size_bytes as SizeBytes, pv.checksum_sha256 as ChecksumSha256,
                   pv.yanked, pv.yank_reason as YankReason, pv.first_fetch as FirstFetch, pv.download_count as DownloadCount, pv.created_at as CreatedAt,
                   pv.vuln_checked_at as VulnCheckedAt, pv.manual_block_state as ManualBlockState,
                   pv.deprecated as Deprecated, pv.origin as Origin, pv.published_at as PublishedAt,
                   pv.checksum_sha1 as ChecksumSha1,
                   pv.upstream_integrity_value as UpstreamIntegrityValue,
                   pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   pv.has_install_script as HasInstallScript,
                   pv.install_script_kind as InstallScriptKind,
                   pv.provenance_status as ProvenanceStatus,
                   pv.provenance_signer as ProvenanceSigner
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.blob_key = @blobKey AND p.org_id = @orgId
            """,
            new { orgId, blobKey });
    }

    public async Task<PackageVersion> CreateVersionAsync(
        NewPackageVersion data, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        // Derive filename from blob_key's last path segment so download lookups can
        // hit idx_package_versions_filename instead of a leading-wildcard LIKE.
        string filename = DeriveFilename(data.BlobKey);
        // xtenant: INSERT pinned to a caller-supplied package_id (org-scoped via FK).
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes,
                 checksum_sha256, first_fetch, origin, published_at,
                 checksum_sha1, upstream_integrity_value, upstream_integrity_algorithm)
            VALUES
                (@id, @packageId, @version, @purl, @blobKey, @filename, @sizeBytes,
                 @checksumSha256, @firstFetch, @origin, @publishedAt,
                 @checksumSha1, @upstreamIntegrityValue, @upstreamIntegrityAlgorithm)
            """,
            new
            {
                id,
                packageId = data.PackageId,
                version = data.Version,
                purl = data.Purl,
                blobKey = data.BlobKey,
                filename,
                sizeBytes = data.SizeBytes,
                checksumSha256 = data.ChecksumSha256,
                firstFetch = data.FirstFetch ? 1 : 0,
                origin = data.Origin,
                publishedAt = data.PublishedAt?.ToUniversalTime().ToString("o"),
                checksumSha1 = data.ChecksumSha1,
                upstreamIntegrityValue = data.UpstreamIntegrityValue,
                upstreamIntegrityAlgorithm = data.UpstreamIntegrityAlgorithm,
            });

        // xtenant: keyed by version id (globally unique UUID, already org-scoped via FK)
        return (await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch,
                   download_count as DownloadCount, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin, published_at as PublishedAt,
                   checksum_sha1 as ChecksumSha1,
                   upstream_integrity_value as UpstreamIntegrityValue,
                   upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   has_install_script as HasInstallScript,
                   install_script_kind as InstallScriptKind,
                   provenance_status as ProvenanceStatus,
                   provenance_signer as ProvenanceSigner
            FROM package_versions WHERE id = @id
            """,
            new { id }))!;
    }

    public async Task TouchLastUsedAsync(string versionId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET last_used = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Records one served download against a version: bumps the durable all-time counter and
    /// stamps <c>last_used</c> in the same write (the download is the moment the retention/eviction
    /// freshness signal should advance). Called from every download-serve path — proxy first-fetch,
    /// protocol-client pulls, and UI downloads — so the counter matches the analytics download
    /// taxonomy ('download' + 'first_fetch').
    ///
    /// When a <see cref="DownloadCountWriter"/> is wired in, the increment is enqueued into the
    /// bounded channel and returns immediately without touching the DB. The companion
    /// <see cref="DownloadCountWriterHostedService"/> drains and aggregates the channel in batched
    /// UPDATEs off the request path. Falls back to a synchronous UPDATE when no writer is present
    /// (tests, embedded use-cases).
    /// </summary>
    public async Task IncrementDownloadCountAsync(string versionId, CancellationToken ct = default)
    {
        if (_downloadCountWriter is not null)
        {
            _downloadCountWriter.TryEnqueue(new DownloadCountRecord(VersionId: versionId, Purl: null));
            return;
        }

        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET download_count = download_count + 1, last_used = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Same as <see cref="IncrementDownloadCountAsync(string,CancellationToken)"/> but keyed by
    /// <c>purl</c> and scoped to <paramref name="orgId"/>. Used by download-serve paths (RPM proxy,
    /// Maven proxy) that hold the purl but not the version id. Increments
    /// <c>tenant_artifact_access.download_count</c> for the org's cache_artifact rows matching the
    /// purl. A no-op if no matching row exists yet.
    ///
    /// When a <see cref="DownloadCountWriter"/> is wired in, the increment is enqueued off the
    /// request path; otherwise falls back to a synchronous UPDATE.
    /// </summary>
    public async Task IncrementDownloadCountByPurlAsync(string orgId, string purl, CancellationToken ct = default)
    {
        if (_downloadCountWriter is not null)
        {
            _downloadCountWriter.TryEnqueue(new DownloadCountRecord(VersionId: null, Purl: purl, OrgId: orgId));
            return;
        }

        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_artifact_access
            SET download_count = download_count + 1,
                last_used = @now
            WHERE org_id = @orgId
              AND cache_artifact_id IN (
                  SELECT id FROM cache_artifact WHERE purl = @purl
              )
            """,
            new { now, orgId, purl });
    }

    public async Task UpdateDeprecatedAsync(string versionId, string? message, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @message WHERE id = @id",
            new { id = versionId, message });
    }

    /// <summary>
    /// Persists the install/lifecycle-script signal detected at ingest. <paramref name="kind"/>
    /// is NULL when no script was found. Called by the proxy first-fetch recorder and the
    /// hosted publish path after the version row exists.
    /// </summary>
    public async Task UpdateInstallScriptAsync(
        string versionId, bool hasScript, string? kind, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET has_install_script = @has, install_script_kind = @kind WHERE id = @id",
            new { id = versionId, has = hasScript ? 1 : 0, kind = hasScript ? kind : null });
    }

    /// <summary>
    /// Persists the provenance/signature-verification outcome captured at proxy first-fetch.
    /// <paramref name="status"/> is one of <c>'verified'</c>/<c>'failed'</c>/<c>'unsigned'</c> (or
    /// NULL when not applicable); <paramref name="signer"/> is the verifying trust-anchor keyid,
    /// non-null only for <c>'verified'</c>. Called by the proxy first-fetch recorder after the
    /// version row exists.
    /// </summary>
    public async Task UpdateProvenanceAsync(
        string versionId, string? status, string? signer, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET provenance_status = @status, provenance_signer = @signer WHERE id = @id",
            new { id = versionId, status, signer });
    }

    /// <summary>
    /// Replacement-policy update: rewrites blob_key/size/checksum/origin on an existing
    /// row when allow_version_overwrite is on. The package_version id is preserved so vuln
    /// scans, license rows, and existing FKs follow the new artefact without re-stitching.
    /// </summary>
    public async Task UpdateVersionForOverwriteAsync(
        string versionId, string blobKey, long sizeBytes, string sha256, string origin,
        string? sha1, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            """
            UPDATE package_versions
               SET blob_key = @blobKey,
                   size_bytes = @sizeBytes,
                   checksum_sha256 = @sha256,
                   checksum_sha1 = @sha1,
                   origin = @origin,
                   vuln_checked_at = NULL
             WHERE id = @id
            """,
            new { id = versionId, blobKey, sizeBytes, sha256, sha1, origin });
    }

    public async Task<(IReadOnlyList<Package> Items, int Total)> ListPaginatedAsync(
        PackageListQuery query, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? escapedSearch = query.Search?.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        string? searchPattern = escapedSearch is not null ? $"%{escapedSearch}%" : null;

        int total = await conn.ExecuteScalarAsync<int>(CountSql,
            new { orgId = query.OrgId, ecosystem = query.Ecosystem, searchPattern });

        var rows = await conn.QueryAsync<Package>(SelectSqlFor(query.SortBy, query.SortDir),
            new { orgId = query.OrgId, ecosystem = query.Ecosystem, searchPattern, limit = query.Limit, offset = query.Offset });
        return (rows.ToList(), total);
    }

    private const string CountSql =
        "SELECT COUNT(*) FROM packages p WHERE p.org_id = @orgId" +
        " AND (@ecosystem IS NULL OR p.ecosystem = @ecosystem)" +
        " AND (@searchPattern IS NULL OR p.name LIKE @searchPattern ESCAPE '\\')";

    private const string SelectSqlPrefix = """
        WITH pkg_data AS (
            SELECT p.id, p.org_id as OrgId, p.ecosystem, p.name, p.purl_name as PurlName,
                   p.is_proxy as IsProxy, p.created_at as CreatedAt,
                   (
                       SELECT COUNT(*) FROM package_versions WHERE package_id = p.id AND origin = 'uploaded'
                   ) + COALESCE((
                       SELECT COUNT(*) FROM cache_artifact ca
                       JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                       WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ), 0) as VersionCount,
                   -- Severity counts span both planes: uploaded versions carry
                   -- owner_kind='package_version' vuln rows (joined via package_version_id),
                   -- proxy versions carry owner_kind='cache_artifact' rows on the global plane
                   -- (joined via cache_artifact_id, org-scoped through tenant_artifact_access and
                   -- matched to this package by ecosystem + purl_name). UNION + COUNT(DISTINCT)
                   -- dedupes a CVE present on both planes for the same package.
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'CRITICAL'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'CRITICAL'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   )) as CriticalCount,
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'HIGH'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'HIGH'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   )) as HighCount,
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'MEDIUM'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'MEDIUM'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   )) as MediumCount,
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'LOW'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'LOW'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   )) as LowCount,
                   (
                       SELECT COALESCE(SUM(download_count), 0) FROM package_versions
                       WHERE package_id = p.id AND origin = 'uploaded'
                   ) + COALESCE((
                       SELECT SUM(taa.download_count) FROM cache_artifact ca
                       JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                       WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ), 0) as TotalDownloads,
                   p.upstream_latest_version as UpstreamLatestVersion,
                   (EXISTS (SELECT 1 FROM package_versions pvm
                           JOIN package_version_vulns pvv ON pvv.package_version_id = pvm.id
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE pvm.package_id = p.id
                             AND v.osv_id LIKE 'MAL-%')
                    OR EXISTS (SELECT 1 FROM cache_artifact ca
                           JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                           JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                             AND v.osv_id LIKE 'MAL-%')) as HasMaliciousVersion,
                   CASE
                     WHEN p.upstream_latest_version IS NULL THEN 'unknown'
                     WHEN EXISTS (
                         SELECT 1 FROM package_versions pvl
                         WHERE pvl.package_id = p.id
                           AND pvl.version = p.upstream_latest_version
                           AND pvl.origin = 'uploaded'
                     ) OR EXISTS (
                         SELECT 1 FROM cache_artifact ca
                         JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                         WHERE taa.org_id = p.org_id
                           AND ca.ecosystem = p.ecosystem
                           AND ca.name = p.purl_name
                           AND ca.version = p.upstream_latest_version
                     ) THEN 'current'
                     ELSE 'stale'
                   END as LatestState
            FROM packages p WHERE p.org_id = @orgId
              AND (@ecosystem IS NULL OR p.ecosystem = @ecosystem)
              AND (@searchPattern IS NULL OR p.name LIKE @searchPattern ESCAPE '\')
        )
        SELECT * FROM pkg_data ORDER BY
        """;

    private const string SelectSqlSuffix = " LIMIT @limit OFFSET @offset";

    // Static (sortBy, sortDir) → ORDER BY clauses. Bounded whitelist; never composes user input.
    private static string SelectSqlFor(string sortBy, string sortDir)
    {
        bool desc = sortDir == "desc";
        return sortBy switch
        {
            "name" => SelectSqlPrefix + (desc ? " name DESC" : " name ASC") + SelectSqlSuffix,
            "purl" => SelectSqlPrefix + (desc ? " PurlName DESC" : " PurlName ASC") + SelectSqlSuffix,
            "vulns" => SelectSqlPrefix + (desc
                ? " (CriticalCount * 1000 + HighCount * 100 + MediumCount * 10 + LowCount) DESC"
                : " (CriticalCount * 1000 + HighCount * 100 + MediumCount * 10 + LowCount) ASC") + SelectSqlSuffix,
            "ecosystem" => SelectSqlPrefix + (desc ? " ecosystem DESC" : " ecosystem ASC") + SelectSqlSuffix,
            "versions" => SelectSqlPrefix + (desc ? " VersionCount DESC" : " VersionCount ASC") + SelectSqlSuffix,
            "downloads" => SelectSqlPrefix + (desc ? " TotalDownloads DESC" : " TotalDownloads ASC") + SelectSqlSuffix,
            _ => SelectSqlPrefix + (desc ? " CreatedAt DESC" : " CreatedAt ASC") + SelectSqlSuffix,
        };
    }

    /// <summary>
    /// Lookup a version by its primary key, scoped to <paramref name="orgId"/> via the parent
    /// package. version id is a Guid so collisions are not the concern — the org filter is the
    /// defence-in-depth tenancy invariant. Returns null when the id exists in a different org.
    /// </summary>
    public async Task<PackageVersion?> GetVersionByIdAsync(string orgId, string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT pv.id, pv.package_id as PackageId, pv.version, pv.purl, pv.blob_key as BlobKey,
                   pv.size_bytes as SizeBytes, pv.checksum_sha256 as ChecksumSha256,
                   pv.yanked, pv.yank_reason as YankReason, pv.first_fetch as FirstFetch, pv.download_count as DownloadCount, pv.created_at as CreatedAt,
                   pv.vuln_checked_at as VulnCheckedAt, pv.manual_block_state as ManualBlockState,
                   pv.deprecated as Deprecated, pv.origin as Origin, pv.published_at as PublishedAt,
                   pv.checksum_sha1 as ChecksumSha1,
                   pv.upstream_integrity_value as UpstreamIntegrityValue,
                   pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   pv.has_install_script as HasInstallScript,
                   pv.install_script_kind as InstallScriptKind,
                   pv.provenance_status as ProvenanceStatus,
                   pv.provenance_signer as ProvenanceSigner
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.id = @versionId AND p.org_id = @orgId
            """,
            new { orgId, versionId });
    }

    /// <summary>
    /// Deletes the <c>packages</c> row IFF no <c>package_versions</c> rows reference it.
    /// Atomic via NOT EXISTS in the WHERE clause — safe against a concurrent publish that
    /// races the last-version delete. Returns true when the parent row was removed.
    ///
    /// Claims live in a separate table FK'd to <c>orgs(id)</c>, not <c>packages(id)</c>,
    /// so a claim on the same name survives package GC by design — claims are about
    /// reserving a name, not anchoring storage.
    /// </summary>
    public async Task<bool> DeletePackageIfEmptyAsync(string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: DELETE keyed by packages.id (a Guid issued by GetOrCreate under an
        // org-scoped lookup); the NOT EXISTS sub-select stays bound to that same id.
        int affected = await conn.ExecuteAsync(
            """
            DELETE FROM packages
            WHERE id = @id
              AND NOT EXISTS (SELECT 1 FROM package_versions WHERE package_id = @id)
            """,
            new { id = packageId });
        return affected > 0;
    }

    /// <summary>
    /// Deletes a <c>package_versions</c> row, decrements the tenant's
    /// <c>org_settings.storage_used_bytes</c> counter by the version's <c>size_bytes</c>,
    /// and recomputes <c>packages.is_proxy</c> so it is <c>true</c> exactly when no
    /// <c>origin='uploaded'</c> versions remain for the parent package.
    /// The decrement uses the same MAX(0, …) clamp as the release path so counter underflow
    /// (e.g. a row deleted before the counter column existed) cannot produce negative values.
    /// </summary>
    public async Task DeleteVersionAsync(string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Resolve org, size, and parent package before the delete so we can decrement the
        // counter and recompute is_proxy. If the join returns nothing (version already gone),
        // the DELETE below is also a no-op.
        // xtenant: keyed by version PK (pv.id), a globally unique surrogate; caller already
        // verified org ownership before invoking this method.
        var info = await conn.QuerySingleOrDefaultAsync<(string OrgId, long SizeBytes, string PackageId)>(
            """
            SELECT p.org_id AS OrgId, pv.size_bytes AS SizeBytes, pv.package_id AS PackageId
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.id = @id
            """,
            new { id = versionId });

        await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = versionId });

        if (info != default)
        {
            await conn.ExecuteAsync(
                """
                UPDATE org_settings
                SET storage_used_bytes = MAX(0, storage_used_bytes - @delta)
                WHERE org_id = @orgId
                """,
                new { orgId = info.OrgId, delta = info.SizeBytes });

            // xtenant: keyed by packages.id (the package PK resolved above from an
            // org-scoped version PK); the NOT EXISTS sub-select stays bound to that same id.
            await conn.ExecuteAsync(
                """
                UPDATE packages
                SET is_proxy = NOT EXISTS (
                    SELECT 1 FROM package_versions
                    WHERE package_id = @pkgId AND origin = 'uploaded'
                )
                WHERE id = @pkgId
                """,
                new { pkgId = info.PackageId });
        }
    }

    /// <summary>
    /// Deletes every <c>origin = 'proxy'</c> version row for (org, ecosystem, purl_name)
    /// and returns the blob keys that were just dereferenced. Caller is expected to delete the
    /// blobs after this completes — doing it here would couple the repo to <c>IBlobStore</c> and
    /// leave the path harder to test. Imported / private artefacts are never touched.
    /// </summary>
    public async Task<IReadOnlyList<string>> DeleteProxyVersionsForNameAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var blobKeys = (await conn.QueryAsync<string>("""
            SELECT pv.blob_key
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = @ecosystem
              AND p.purl_name = @purlName
              AND pv.origin = 'proxy'
            """, new { orgId, ecosystem, purlName })).ToList();

        if (blobKeys.Count > 0)
        {
            await conn.ExecuteAsync("""
                DELETE FROM package_versions
                WHERE id IN (
                    SELECT pv.id
                    FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.org_id = @orgId
                      AND p.ecosystem = @ecosystem
                      AND p.purl_name = @purlName
                      AND pv.origin = 'proxy'
                )
                """, new { orgId, ecosystem, purlName });
        }
        return blobKeys;
    }

    /// <summary>
    /// Streams every blob_key currently referenced from <c>package_versions</c>. Backs the
    /// orphan-blob reconciler — caller materializes the set, then walks the registry tier
    /// asking "is this key in the set?". Streaming (rather than returning a list) keeps memory
    /// bounded on stores with millions of versions.
    /// </summary>
    public async IAsyncEnumerable<string> StreamAllBlobKeysAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<string>(
            "SELECT blob_key FROM package_versions",
            commandTimeout: 0);
        foreach (string key in rows)
        {
            if (ct.IsCancellationRequested)
            {
                yield break;
            }

            yield return key;
        }
    }

    /// <summary>
    /// Sum of <c>size_bytes</c> across every <c>package_versions</c> row whose parent package
    /// belongs to the given org. The number underlying the per-tenant quota check in
    /// <see cref="Publish.PackagePublishService"/>. Origin-agnostic on purpose — proxy bytes
    /// also count against the tenant's storage budget on the data plane.
    /// </summary>
    public async Task<long> GetTotalSizeBytesAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long?>(
            """
            SELECT COALESCE(SUM(pv.size_bytes), 0)
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
            """,
            new { orgId }) ?? 0L;
    }

    public async Task SetManualBlockStateAsync(string versionId, string? state, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET manual_block_state = @state WHERE id = @id",
            new { id = versionId, state });
    }

    /// <summary>
    /// Flips the <c>yanked</c> flag on a version, clearing <c>yank_reason</c> when unyanking.
    /// Yank hides a version from dependency resolution (Cargo, npm) without deleting the
    /// artefact — a yanked crate is still downloadable by exact coordinate. The caller resolves
    /// the version id from an already org-scoped lookup, so no org filter is needed here.
    /// </summary>
    public async Task SetYankedAsync(string versionId, bool yanked, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET yanked = @yanked, yank_reason = NULL WHERE id = @id",
            new { id = versionId, yanked = yanked ? 1 : 0 });
    }

    /// <summary>
    /// Stamps <c>deprecation_checked_at</c> to now without changing the <c>deprecated</c> value.
    /// Called when an upstream metadata fetch confirms the deprecation status is unchanged.
    /// </summary>
    public async Task UpdateDeprecationCheckedAtAsync(string versionId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecation_checked_at = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Updates both <c>deprecated</c> and <c>deprecation_checked_at</c> in a single UPDATE.
    /// Called when upstream metadata shows a changed deprecation state.
    /// </summary>
    public async Task UpdateDeprecatedAndCheckedAsync(string versionId, string? deprecated, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @deprecated, deprecation_checked_at = @now WHERE id = @id",
            new { id = versionId, deprecated, now });
    }

    /// <summary>
    /// Records upstream's declared latest version for a package and stamps the refresh time.
    /// Called by DeprecationRefreshService on each upstream-metadata pass. A null
    /// <paramref name="latestVersion"/> clears the baseline (upstream had no latest claim).
    /// </summary>
    // xtenant: UPDATE keyed by the package id (already org-scoped via FK); caller resolves the
    // package within a single org's refresh pass.
    public async Task UpdateUpstreamLatestAsync(string packageId, string? latestVersion, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE packages SET upstream_latest_version = @latestVersion, upstream_latest_checked_at = @now WHERE id = @id",
            new { id = packageId, latestVersion, now });
    }

    // ── Go module proxy helpers ──────────────────────────────────────────────

    /// <summary>
    /// Returns a list of cached Go module versions for the given module path, ordered
    /// newest-first by creation time. Used by the <c>/@v/list</c> endpoint.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListVersionsForGoModuleAsync(
        string orgId, string module, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var pvVersions = await conn.QueryAsync<string>(
            """
            SELECT pv.version
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'golang'
              AND p.purl_name = @module
            ORDER BY pv.created_at DESC
            """,
            new { orgId, module });

        // Also include versions from the global plane for proxy .zips cached after the P3b flip.
        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var globalVersions = await conn.QueryAsync<string>(
            """
            SELECT ca.version
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = 'golang'
              AND ca.name = @module
            ORDER BY ca.first_cached_at DESC
            """,
            new { orgId, module });

        var pvList = pvVersions.ToList();
        var globalList = globalVersions.ToList();
        if (globalList.Count == 0)
        {
            return pvList;
        }
        if (pvList.Count == 0)
        {
            return globalList;
        }

        // Union: local (package_versions) wins on collision; deduplicate.
        var pvSet = new HashSet<string>(pvList, StringComparer.OrdinalIgnoreCase);
        var merged = new List<string>(pvList);
        foreach (string v in globalList)
        {
            if (!pvSet.Contains(v))
            {
                merged.Add(v);
            }
        }
        return merged;
    }

    /// <summary>
    /// Returns the most-recently-created cached version for the given Go module, or null
    /// when nothing is cached. Used by the <c>/@latest</c> endpoint. Checks both the
    /// legacy <c>package_versions</c> path and the global plane (<c>cache_artifact</c>)
    /// for proxy .zips cached after the P3b flip; returns the newest across both planes.
    /// </summary>
    public async Task<PackageVersion?> GetLatestGoVersionAsync(
        string orgId, string module, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var pvLatest = await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT pv.id AS Id, pv.package_id AS PackageId,
                   pv.version AS Version, pv.purl AS Purl,
                   pv.blob_key AS BlobKey, pv.size_bytes AS SizeBytes,
                   pv.checksum_sha256 AS ChecksumSha256,
                   pv.created_at AS CreatedAt
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'golang'
              AND p.purl_name = @module
            ORDER BY pv.created_at DESC
            LIMIT 1
            """,
            new { orgId, module });

        // Also check global-plane proxy .zips for versions cached after the P3b flip.
        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var caLatest = await conn.QuerySingleOrDefaultAsync<(string Version, string FirstCachedAt)>(
            """
            SELECT ca.version AS Version, ca.first_cached_at AS FirstCachedAt
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = 'golang'
              AND ca.name = @module
            ORDER BY ca.first_cached_at DESC
            LIMIT 1
            """,
            new { orgId, module });

        if (caLatest.Version is null)
        {
            return pvLatest;
        }

        if (pvLatest is null)
        {
            // Build a synthetic PackageVersion from the global-plane row so @latest can serve it.
            return new PackageVersion
            {
                Id = string.Empty,
                PackageId = string.Empty,
                Version = caLatest.Version,
                Purl = string.Empty,
                BlobKey = string.Empty,
                CreatedAt = DateTimeOffset.Parse(
                    caLatest.FirstCachedAt,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal),
            };
        }

        // Return whichever is more recent between the PV row and the global-plane row.
        var caTime = DateTimeOffset.Parse(
            caLatest.FirstCachedAt,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
        return caTime > pvLatest.CreatedAt
            ? new PackageVersion
            {
                Id = string.Empty,
                PackageId = string.Empty,
                Version = caLatest.Version,
                Purl = string.Empty,
                BlobKey = string.Empty,
                CreatedAt = caTime,
            }
            : pvLatest;
    }

    /// <summary>
    /// Gets or creates a <c>packages</c> row for the Go module, then inserts a
    /// <c>package_versions</c> row for the given version. Idempotent via ON CONFLICT DO NOTHING
    /// so concurrent first-fetches of the same version are safe.
    /// </summary>
    public async Task GetOrCreateGoVersionAsync(
        string orgId, string module, string version, string purl, string blobKey,
        string? userId, CancellationToken ct = default)
    {
        var pkg = await GetOrCreateAsync(
            orgId, "golang", module, module, isProxy: true, ct);

        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        string filename = DeriveFilename(blobKey);
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: INSERT pinned to package_id resolved by GetOrCreateAsync under the caller's org.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, first_fetch, origin, created_at)
            VALUES
                (@id, @packageId, @version, @purl, @blobKey, @filename, 0, 1, 'proxy', @now)
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                packageId = pkg.Id,
                version,
                purl,
                blobKey,
                filename,
                now,
            });
    }
}

public sealed record PackageListQuery(
    string OrgId,
    int Limit,
    int Offset,
    string? Ecosystem,
    string? Search = null,
    string SortBy = "created",
    string SortDir = "asc");

public sealed record NewPackageVersion(
    string PackageId,
    string Version,
    string Purl,
    string BlobKey,
    long SizeBytes,
    string? ChecksumSha256,
    bool FirstFetch = false,
    string Origin = "proxy",  // 'proxy' (upstream cache) | 'uploaded' (user-pushed file)
    DateTimeOffset? PublishedAt = null,  // upstream first-publish timestamp; null on capture failure or for uploaded versions
    string? ChecksumSha1 = null,         // hex SHA-1 (npm only — for packument dist.shasum); null elsewhere
    string? UpstreamIntegrityValue = null,      // upstream's published hash, verbatim in its native encoding
    string? UpstreamIntegrityAlgorithm = null); // 'sha256' | 'sha512-sri' | 'sha512-b64'
