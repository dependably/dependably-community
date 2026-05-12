using Dapper;

namespace Dependably.Infrastructure;

public sealed class PackageRepository
{
    private readonly IMetadataStore _db;

    public PackageRepository(IMetadataStore db) => _db = db;

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
    /// Finds a package version whose blob_key ends with /{filename}, joined with its parent package.
    /// Used by PyPI download to avoid N+1 queries when looking up a file by name.
    /// </summary>
    public async Task<(Package Package, PackageVersion Version)?> FindVersionByBlobKeySuffixAsync(
        string orgId, string ecosystem, string filename, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var suffix = "%/" + filename;
        var row = await conn.QuerySingleOrDefaultAsync<(
            string PkgId, string PkgOrgId, string PkgEcosystem, string PkgName, string PkgPurlName, bool PkgIsProxy, string PkgCreatedAt,
            string VerId, string VerPackageId, string VerVersion, string VerPurl, string VerBlobKey,
            long VerSizeBytes, string? VerChecksumSha256, bool VerYanked, string? VerYankReason,
            bool VerFirstFetch, string VerCreatedAt, string? VerVulnCheckedAt, string? VerManualBlockState,
            string? VerDeprecated)>(
            """
            SELECT p.id, p.org_id, p.ecosystem, p.name, p.purl_name, p.is_proxy, p.created_at,
                   pv.id, pv.package_id, pv.version, pv.purl, pv.blob_key,
                   pv.size_bytes, pv.checksum_sha256, pv.yanked, pv.yank_reason,
                   pv.first_fetch, pv.created_at, pv.vuln_checked_at, pv.manual_block_state,
                   pv.deprecated
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem
              AND pv.blob_key LIKE @suffix ESCAPE '\'
            LIMIT 1
            """,
            new { orgId, ecosystem, suffix });

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
            Deprecated = row.VerDeprecated
        };
        return (pkg, ver);
    }

    public async Task<IReadOnlyList<PackageVersion>> GetVersionsAsync(string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin
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
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin
            FROM package_versions
            WHERE package_id = @packageId AND version = @version
            """,
            new { packageId, version });
    }

    public async Task<PackageVersion?> GetVersionByBlobKeyAsync(string blobKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin
            FROM package_versions WHERE blob_key = @blobKey
            """,
            new { blobKey });
    }

    public async Task<PackageVersion> CreateVersionAsync(
        NewPackageVersion data, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, first_fetch, origin)
            VALUES (@id, @packageId, @version, @purl, @blobKey, @sizeBytes, @checksumSha256, @firstFetch, @origin)
            """,
            new
            {
                id,
                packageId = data.PackageId,
                version = data.Version,
                purl = data.Purl,
                blobKey = data.BlobKey,
                sizeBytes = data.SizeBytes,
                checksumSha256 = data.ChecksumSha256,
                firstFetch = data.FirstFetch ? 1 : 0,
                origin = data.Origin,
            });

        return (await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            "SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey, size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256, yanked, yank_reason as YankReason, first_fetch as FirstFetch, created_at as CreatedAt, vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState, deprecated as Deprecated, origin as Origin FROM package_versions WHERE id = @id",
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

    public async Task UpdateDeprecatedAsync(string versionId, string? message, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @message WHERE id = @id",
            new { id = versionId, message });
    }

    /// <summary>
    /// #45 replacement-policy update: rewrites blob_key/size/checksum/origin on an existing
    /// row when allow_version_overwrite is on. The package_version id is preserved so vuln
    /// scans, license rows, and existing FKs follow the new artefact without re-stitching.
    /// </summary>
    public async Task UpdateVersionForOverwriteAsync(
        string versionId, string blobKey, long sizeBytes, string sha256, string origin,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE package_versions
               SET blob_key = @blobKey,
                   size_bytes = @sizeBytes,
                   checksum_sha256 = @sha256,
                   origin = @origin,
                   vuln_checked_at = NULL
             WHERE id = @id
            """,
            new { id = versionId, blobKey, sizeBytes, sha256, origin });
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

    public async Task<PackageVersion?> GetVersionByIdAsync(string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, origin as Origin
            FROM package_versions WHERE id = @versionId
            """,
            new { versionId });
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
    /// #47: deletes every <c>origin = 'proxy'</c> version row for (org, ecosystem, purl_name)
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

    public async Task SetManualBlockStateAsync(string versionId, string? state, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET manual_block_state = @state WHERE id = @id",
            new { id = versionId, state });
    }

    public async Task<OrgStats> GetOrgStatsAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var packagesByEco = (await conn.QueryAsync<EcoCount>(
            """
            SELECT ecosystem as Ecosystem, COUNT(*) as Count
            FROM packages WHERE org_id = @orgId
            GROUP BY ecosystem
            """,
            new { orgId })).ToList();

        var downloadsByHour = (await conn.QueryAsync<HourCount>(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as Hour, COUNT(*) as Count
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('pull', 'first_fetch')
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-24 hours'))
            GROUP BY strftime('%Y-%m-%dT%H', created_at)
            ORDER BY Hour ASC
            """,
            new { orgId })).ToList();

        var vulnsByEcoSeverity = (await conn.QueryAsync<EcoSeverityCount>(
            """
            SELECT p.ecosystem as Ecosystem, COALESCE(v.severity, 'UNKNOWN') as Severity,
                   COUNT(DISTINCT pvv.vuln_id) as Count
            FROM package_version_vulns pvv
            JOIN vulnerabilities v ON v.id = pvv.vuln_id
            JOIN package_versions pv ON pv.id = pvv.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
            GROUP BY p.ecosystem, v.severity
            """,
            new { orgId })).ToList();

        var diskByEco = (await conn.QueryAsync<EcoDiskBytes>(
            """
            SELECT p.ecosystem as Ecosystem, COALESCE(SUM(pv.size_bytes), 0) as TotalBytes
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
            GROUP BY p.ecosystem
            """,
            new { orgId })).ToList();

        var vulnPeriods = await conn.QuerySingleOrDefaultAsync<VulnPeriodCounts>(
            """
            SELECT
              COUNT(DISTINCT CASE WHEN pvv.checked_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-1 days'))  THEN pvv.vuln_id END) as Day,
              COUNT(DISTINCT CASE WHEN pvv.checked_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-7 days'))  THEN pvv.vuln_id END) as Week,
              COUNT(DISTINCT CASE WHEN pvv.checked_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days')) THEN pvv.vuln_id END) as Month
            FROM package_version_vulns pvv
            JOIN package_versions pv ON pv.id = pvv.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
            """,
            new { orgId }) ?? new VulnPeriodCounts();

        var activeUsers = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(DISTINCT actor_id)
            FROM activity
            WHERE org_id = @orgId
              AND actor_id IS NOT NULL
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-7 days'))
            """,
            new { orgId });

        var blockedPulls = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('blocked', 'blocked_vuln_score', 'blocked_manual')
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days'))
            """,
            new { orgId });

        return new OrgStats(
            PackagesByEcosystem: packagesByEco,
            DownloadsByHour: downloadsByHour,
            VulnsByEcosystemAndSeverity: vulnsByEcoSeverity,
            DiskByEcosystem: diskByEco,
            TotalDiskBytes: diskByEco.Sum(d => d.TotalBytes),
            NewVulns: vulnPeriods,
            ActiveUsers7d: activeUsers,
            BlockedPulls30d: blockedPulls);
    }
}

// Use classes with public setters (not positional records) so Dapper can coerce
// SQLite's Int64/TEXT to C# int/long via its property-setter path.
public class EcoCount       { public string Ecosystem { get; set; } = ""; public int Count { get; set; } }
public class HourCount      { public string Hour { get; set; } = ""; public int Count { get; set; } }
public class EcoSeverityCount { public string Ecosystem { get; set; } = ""; public string Severity { get; set; } = ""; public int Count { get; set; } }
public class EcoDiskBytes   { public string Ecosystem { get; set; } = ""; public long TotalBytes { get; set; } }
public class VulnPeriodCounts { public int Day { get; set; } public int Week { get; set; } public int Month { get; set; } }
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
    string Origin = "proxy");  // 'proxy' (upstream cache) | 'uploaded' (user-pushed file)

public sealed record OrgStats(
    IReadOnlyList<EcoCount> PackagesByEcosystem,
    IReadOnlyList<HourCount> DownloadsByHour,
    IReadOnlyList<EcoSeverityCount> VulnsByEcosystemAndSeverity,
    IReadOnlyList<EcoDiskBytes> DiskByEcosystem,
    long TotalDiskBytes,
    VulnPeriodCounts NewVulns,
    int ActiveUsers7d,
    int BlockedPulls30d);
