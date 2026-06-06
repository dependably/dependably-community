using Dapper;

namespace Dependably.Infrastructure;

public sealed class PackageRepository
{
    private readonly IMetadataStore _db;

    public PackageRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Returns the trailing path segment of <paramref name="blobKey"/>. Surface-internal —
    /// callers building a <see cref="NewPackageVersion"/> only need to pass a blob key
    /// and the repository populates <c>filename</c> via this helper so the equality lookup
    /// in <see cref="FindVersionByBlobKeySuffixAsync"/> can use idx_package_versions_filename.
    /// </summary>
    internal static string DeriveFilename(string blobKey)
    {
        var lastSlash = blobKey.LastIndexOf('/');
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
            SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName,
                   is_proxy as IsProxy, created_at as CreatedAt
            FROM packages
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
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
            return existing;

        var id = Guid.NewGuid().ToString("N");
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
    /// Finds a package version by its filename (the trailing path segment of blob_key),
    /// joined with its parent package. Used by PyPI/npm/NuGet downloads — equality lookup
    /// against <c>idx_package_versions_filename</c> instead of the legacy leading-wildcard
    /// LIKE on blob_key (which couldn't use any index).
    /// </summary>
    public async Task<(Package Package, PackageVersion Version)?> FindVersionByBlobKeySuffixAsync(
        string orgId, string ecosystem, string filename, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(
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
            LIMIT 1
            """,
            new { orgId, ecosystem, filename });

        if (row.PkgId is null) return null;

        var pkg = new Package
        {
            Id = row.PkgId, OrgId = row.PkgOrgId, Ecosystem = row.PkgEcosystem,
            Name = row.PkgName, PurlName = row.PkgPurlName, IsProxy = row.PkgIsProxy,
            CreatedAt = DateTimeOffset.Parse(row.PkgCreatedAt)
        };
        var ver = new PackageVersion
        {
            Id = row.VerId, PackageId = row.VerPackageId, Version = row.VerVersion,
            Purl = row.VerPurl, BlobKey = row.VerBlobKey, SizeBytes = row.VerSizeBytes,
            ChecksumSha256 = row.VerChecksumSha256, Yanked = row.VerYanked, YankReason = row.VerYankReason,
            FirstFetch = row.VerFirstFetch, CreatedAt = DateTimeOffset.Parse(row.VerCreatedAt),
            VulnCheckedAt = row.VerVulnCheckedAt is not null ? DateTimeOffset.Parse(row.VerVulnCheckedAt) : null,
            ManualBlockState = row.VerManualBlockState,
            Deprecated = row.VerDeprecated,
            Origin = row.VerOrigin,
            PublishedAt = row.VerPublishedAt is not null ? DateTimeOffset.Parse(row.VerPublishedAt) : null,
            ChecksumSha1 = row.VerChecksumSha1,
            UpstreamIntegrityValue = row.VerUpstreamIntegrityValue,
            UpstreamIntegrityAlgorithm = row.VerUpstreamIntegrityAlgorithm
        };
        return (pkg, ver);
    }

    public async Task<IReadOnlyList<PackageVersion>> GetVersionsAsync(string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by package_id which the caller obtained via an org-scoped lookup.
        // package_versions FKs into packages(id), so org isolation rides on the parent.
        var rows = await conn.QueryAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, download_count as DownloadCount, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin, published_at as PublishedAt, checksum_sha1 as ChecksumSha1, upstream_integrity_value as UpstreamIntegrityValue, upstream_integrity_algorithm as UpstreamIntegrityAlgorithm
            FROM package_versions
            WHERE package_id = @packageId
            ORDER BY created_at DESC
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
                   deprecated as Deprecated, origin as Origin, published_at as PublishedAt, checksum_sha1 as ChecksumSha1, upstream_integrity_value as UpstreamIntegrityValue, upstream_integrity_algorithm as UpstreamIntegrityAlgorithm
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
                   pv.deprecated as Deprecated, pv.origin as Origin, pv.published_at as PublishedAt, pv.checksum_sha1 as ChecksumSha1, pv.upstream_integrity_value as UpstreamIntegrityValue, pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm
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
        var id = Guid.NewGuid().ToString("N");
        // Derive filename from blob_key's last path segment so download lookups can
        // hit idx_package_versions_filename instead of a leading-wildcard LIKE.
        var filename = DeriveFilename(data.BlobKey);
        // xtenant: INSERT pinned to a caller-supplied package_id (org-scoped via FK).
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, first_fetch, origin, published_at, checksum_sha1, upstream_integrity_value, upstream_integrity_algorithm)
            VALUES (@id, @packageId, @version, @purl, @blobKey, @filename, @sizeBytes, @checksumSha256, @firstFetch, @origin, @publishedAt, @checksumSha1, @upstreamIntegrityValue, @upstreamIntegrityAlgorithm)
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

        return (await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            "SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey, size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256, yanked, yank_reason as YankReason, first_fetch as FirstFetch, download_count as DownloadCount, created_at as CreatedAt, vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState, deprecated as Deprecated, origin as Origin, published_at as PublishedAt, checksum_sha1 as ChecksumSha1, upstream_integrity_value as UpstreamIntegrityValue, upstream_integrity_algorithm as UpstreamIntegrityAlgorithm FROM package_versions WHERE id = @id",
            new { id }))!;
    }

    public async Task TouchLastUsedAsync(string versionId, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
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
    /// </summary>
    public async Task IncrementDownloadCountAsync(string versionId, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET download_count = download_count + 1, last_used = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Same as <see cref="IncrementDownloadCountAsync(string,CancellationToken)"/> but keyed by the
    /// globally-unique <c>purl</c>, for download-serve paths (RPM proxy, OCI) that hold the purl but
    /// not the version id. A no-op if the purl has no row yet.
    /// </summary>
    public async Task IncrementDownloadCountByPurlAsync(string purl, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET download_count = download_count + 1, last_used = @now WHERE purl = @purl",
            new { now, purl });
    }

    public async Task UpdateDeprecatedAsync(string versionId, string? message, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @message WHERE id = @id",
            new { id = versionId, message });
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
        var escapedSearch = query.Search?.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        var searchPattern = escapedSearch is not null ? $"%{escapedSearch}%" : null;

        var total = await conn.ExecuteScalarAsync<int>(CountSql,
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
                   (SELECT COUNT(*) FROM package_versions WHERE package_id = p.id) as VersionCount,
                   (SELECT COUNT(DISTINCT pvv.vuln_id) FROM package_versions pv2
                    JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                    JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'CRITICAL'
                    WHERE pv2.package_id = p.id) as CriticalCount,
                   (SELECT COUNT(DISTINCT pvv.vuln_id) FROM package_versions pv2
                    JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                    JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'HIGH'
                    WHERE pv2.package_id = p.id) as HighCount,
                   (SELECT COUNT(DISTINCT pvv.vuln_id) FROM package_versions pv2
                    JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                    JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'MEDIUM'
                    WHERE pv2.package_id = p.id) as MediumCount,
                   (SELECT COUNT(DISTINCT pvv.vuln_id) FROM package_versions pv2
                    JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                    JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'LOW'
                    WHERE pv2.package_id = p.id) as LowCount
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
        var desc = sortDir == "desc";
        return sortBy switch
        {
            "name"      => SelectSqlPrefix + (desc ? " name DESC"          : " name ASC")          + SelectSqlSuffix,
            "purl"      => SelectSqlPrefix + (desc ? " PurlName DESC"      : " PurlName ASC")      + SelectSqlSuffix,
            "vulns"     => SelectSqlPrefix + (desc
                ? " (CriticalCount * 1000 + HighCount * 100 + MediumCount * 10 + LowCount) DESC"
                : " (CriticalCount * 1000 + HighCount * 100 + MediumCount * 10 + LowCount) ASC") + SelectSqlSuffix,
            "ecosystem" => SelectSqlPrefix + (desc ? " ecosystem DESC"     : " ecosystem ASC")     + SelectSqlSuffix,
            "versions"  => SelectSqlPrefix + (desc ? " VersionCount DESC"  : " VersionCount ASC")  + SelectSqlSuffix,
            _           => SelectSqlPrefix + (desc ? " CreatedAt DESC"     : " CreatedAt ASC")     + SelectSqlSuffix,
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
                   pv.deprecated as Deprecated, pv.origin as Origin, pv.published_at as PublishedAt, pv.checksum_sha1 as ChecksumSha1, pv.upstream_integrity_value as UpstreamIntegrityValue, pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm
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
        var affected = await conn.ExecuteAsync(
            """
            DELETE FROM packages
            WHERE id = @id
              AND NOT EXISTS (SELECT 1 FROM package_versions WHERE package_id = @id)
            """,
            new { id = packageId });
        return affected > 0;
    }

    public async Task DeleteVersionAsync(string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = versionId });
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
        foreach (var key in rows)
        {
            if (ct.IsCancellationRequested) yield break;
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
    /// Stamps <c>deprecation_checked_at</c> to now without changing the <c>deprecated</c> value.
    /// Called when an upstream metadata fetch confirms the deprecation status is unchanged.
    /// </summary>
    public async Task UpdateDeprecationCheckedAtAsync(string versionId, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
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
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @deprecated, deprecation_checked_at = @now WHERE id = @id",
            new { id = versionId, deprecated, now });
    }

    /// <summary>
    /// Returns distinct packages that have at least one proxy version whose deprecation metadata
    /// is stale (never checked, or checked more than <paramref name="ageHours"/> ago). Ordered
    /// oldest-first so a partial run still makes progress on the most stale packages. Soft-deleted
    /// tenants are excluded.
    /// </summary>
    // xtenant: cross-tenant query scoped to proxy origin and age threshold; caller (DeprecationRefreshService)
    // processes each package independently and gates writes on the version id.
    public async Task<IReadOnlyList<(string PackageId, string Ecosystem, string PurlName, string OrgId)>>
        ListPackagesNeedingDeprecationRefreshAsync(int ageHours, int limit, CancellationToken ct = default)
    {
        var threshold = DateTimeOffset.UtcNow.AddHours(-ageHours).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string PackageId, string Ecosystem, string PurlName, string OrgId)>(
            """
            SELECT p.id AS PackageId, p.ecosystem AS Ecosystem, p.purl_name AS PurlName, p.org_id AS OrgId
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            JOIN orgs o ON o.id = p.org_id
            LEFT JOIN org_settings os ON os.org_id = p.org_id
            WHERE pv.origin = 'proxy'
              AND (pv.deprecation_checked_at IS NULL OR pv.deprecation_checked_at < @threshold)
              AND o.deleted_at IS NULL
              AND COALESCE(os.air_gapped, 0) = 0
            GROUP BY p.id, p.ecosystem, p.purl_name, p.org_id
            ORDER BY MIN(pv.deprecation_checked_at) ASC
            LIMIT @limit
            """,
            new { threshold, limit });
        return rows.ToList();
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
