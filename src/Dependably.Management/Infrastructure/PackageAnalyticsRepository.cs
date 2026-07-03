using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Dashboard aggregation queries. Split out of <see cref="PackageRepository"/> so the
/// publish/proxy hot path doesn't carry the org-stats SQL surface, and so callers can
/// depend on <see cref="PackageRepository"/> alone for CRUD without dragging analytics.
/// </summary>
public sealed class PackageAnalyticsRepository
{
    private readonly IMetadataStore _db;
    private readonly SamlConfigRepository? _samlConfig;
    private readonly TimeProvider _time;

    public PackageAnalyticsRepository(IMetadataStore db, SamlConfigRepository? samlConfig = null, TimeProvider? time = null)
    {
        _db = db;
        _samlConfig = samlConfig;
        _time = time ?? TimeProvider.System;
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

        // Every served download, counted once. Cache hits and hosted/published serves log
        // 'download'; PyPI/npm/NuGet/Maven proxy cache-misses log 'first_fetch' instead (and
        // never a paired 'download'), while RPM/OCI log 'download' for both hit and miss and
        // never emit 'first_fetch'. So spanning both event types covers all downloads with no
        // double-counting — do not narrow this to 'download' alone or cache-miss downloads on
        // PyPI/npm/NuGet/Maven vanish from the chart. Blocked attempts ('blocked*') are not
        // downloads and are excluded.
        var downloadsByHour = (await conn.QueryAsync<HourCount>(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as Hour, COUNT(*) as Count
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('download', 'first_fetch')
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-24 hours'))
            GROUP BY strftime('%Y-%m-%dT%H', created_at)
            ORDER BY Hour ASC
            """,
            new { orgId })).ToList();

        // The dashboard pending count must agree with the review queue, which purges aged-out
        // release_age holds on load (QuarantineRepository.PurgeAgedReleaseHoldsAsync). Pass the
        // org's hold threshold and the current clock down so the count excludes the same stale
        // holds — otherwise the card shows a number the (empty) queue can't account for.
        int? minReleaseAgeHours = await conn.ExecuteScalarAsync<int?>(
            "SELECT min_release_age_hours FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        var (vulnsByEcoSeverity, diskByEco, vulnPeriods, activeUsers, blockedByGate, blockedPulls, quarantinePending) =
            await QueryVulnAndActivityStatsAsync(conn, orgId, minReleaseAgeHours, _time.GetUtcNow());

        var (hostedPackages, proxiedPackages, storageQuotaBytes, totalDownloads30d) =
            await QueryPackageCountsAndQuotaAsync(conn, orgId);

        var samlCertExpiry = await BuildSamlCertExpiryAsync(orgId, ct);

        return new OrgStats(
            PackagesByEcosystem: packagesByEco,
            DownloadsByHour: downloadsByHour,
            VulnsByEcosystemAndSeverity: vulnsByEcoSeverity,
            DiskByEcosystem: diskByEco,
            TotalDiskBytes: diskByEco.Sum(d => d.TotalBytes),
            NewVulns: vulnPeriods,
            ActiveUsers7d: activeUsers,
            BlockedPulls30d: blockedPulls,
            TotalDownloads30d: totalDownloads30d,
            SamlCertExpiry: samlCertExpiry,
            BlockedByGate30d: blockedByGate,
            QuarantinePending: quarantinePending,
            HostedPackages: hostedPackages,
            ProxiedPackages: proxiedPackages,
            StorageQuotaBytes: storageQuotaBytes);
    }

    // Queries vuln/severity counts, disk-by-ecosystem, vuln-period buckets, active users,
    // blocked-by-gate summary, and quarantine pending count. All org-scoped via WHERE org_id=@orgId.
    private static async Task<(
        List<EcoSeverityCount> VulnsByEcoSeverity,
        List<EcoDiskBytes> DiskByEco,
        VulnPeriodCounts VulnPeriods,
        int ActiveUsers,
        List<GateCount> BlockedByGate,
        int BlockedPulls,
        int QuarantinePending)>
        QueryVulnAndActivityStatsAsync(
            System.Data.Common.DbConnection conn, string orgId,
            int? minReleaseAgeHours, DateTimeOffset now)
    {
        var (vulnsByEcoSeverity, diskByEco, vulnPeriods) = await QueryVulnDataAsync(conn, orgId);
        var (activeUsers, blockedByGate, blockedPulls, quarantinePending) =
            await QueryActivityDataAsync(conn, orgId, minReleaseAgeHours, now);
        return (vulnsByEcoSeverity, diskByEco, vulnPeriods, activeUsers, blockedByGate, blockedPulls, quarantinePending);
    }

    // Queries vuln-by-severity, disk-by-ecosystem, and vuln-period buckets. Uses a two-plane
    // union (package_versions + cache_artifact) so both uploaded and proxy artifacts are covered.
    private static async Task<(
        List<EcoSeverityCount> VulnsByEcoSeverity,
        List<EcoDiskBytes> DiskByEco,
        VulnPeriodCounts VulnPeriods)>
        QueryVulnDataAsync(System.Data.Common.DbConnection conn, string orgId)
    {
        // Vulns live on two planes since proxy artifacts moved to the global cache_artifact table:
        // uploaded artifacts keep package_version_vulns rows with owner_kind='package_version'
        // (org-scoped via packages.org_id), while proxy artifacts carry owner_kind='cache_artifact'
        // rows on the global plane, org-scoped via tenant_artifact_access.org_id and labelled by
        // cache_artifact.ecosystem. Both arms are unioned; COUNT(DISTINCT vuln_id) dedupes a CVE
        // affecting the same ecosystem on both planes so it is counted once.
        var vulnsByEcoSeverity = (await conn.QueryAsync<EcoSeverityCount>(
            """
            SELECT Ecosystem, Severity, COUNT(DISTINCT VulnId) as Count
            FROM (
                SELECT p.ecosystem as Ecosystem, COALESCE(v.severity, 'UNKNOWN') as Severity, pvv.vuln_id as VulnId
                FROM package_version_vulns pvv
                JOIN vulnerabilities v ON v.id = pvv.vuln_id
                JOIN package_versions pv ON pv.id = pvv.package_version_id
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND pvv.owner_kind = 'package_version'
                UNION ALL
                SELECT ca.ecosystem as Ecosystem, COALESCE(v.severity, 'UNKNOWN') as Severity, pvv.vuln_id as VulnId
                FROM package_version_vulns pvv
                JOIN vulnerabilities v ON v.id = pvv.vuln_id
                JOIN cache_artifact ca ON ca.id = pvv.cache_artifact_id
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId AND pvv.owner_kind = 'cache_artifact'
            )
            GROUP BY Ecosystem, Severity
            """,
            new { orgId })).ToList();

        // Disk usage spans three sources, each org-scoped. (1) Uploaded artifacts: package_versions
        // sized rows (origin='uploaded'; proxy rows now live on the cache plane). (2) Proxy artifacts:
        // the global cache_artifact table, attributed per-org via tenant_artifact_access — the same
        // per-tenant footprint the package_versions sum showed before proxy rows moved planes.
        // (3) OCI: blob bytes live in oci_blobs (content-addressed, deduped within an org), not in
        // either sized table, so 'oci' is excluded from the first two arms and summed from oci_blobs.
        // Outer GROUP BY collapses the uploaded and proxy arms into one row per ecosystem (npm can
        // appear in both) so the dashboard's per-ecosystem lookup stays single-valued.
        var diskByEco = (await conn.QueryAsync<EcoDiskBytes>(
            """
            SELECT Ecosystem, SUM(TotalBytes) as TotalBytes
            FROM (
                SELECT p.ecosystem as Ecosystem, COALESCE(SUM(pv.size_bytes), 0) as TotalBytes
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem != 'oci'
                  AND pv.origin = 'uploaded'
                GROUP BY p.ecosystem
                UNION ALL
                SELECT ca.ecosystem as Ecosystem, COALESCE(SUM(ca.size_bytes), 0) as TotalBytes
                FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId AND ca.ecosystem != 'oci'
                GROUP BY ca.ecosystem
                UNION ALL
                SELECT 'oci' as Ecosystem, COALESCE(SUM(size_bytes), 0) as TotalBytes
                FROM oci_blobs
                WHERE org_id = @orgId
            )
            GROUP BY Ecosystem
            """,
            new { orgId })).ToList();

        // Same two-plane union as the severity breakdown: uploaded vulns are org-scoped via
        // packages.org_id, proxy vulns via tenant_artifact_access.org_id. COUNT(DISTINCT vuln_id)
        // per window dedupes a CVE seen on both planes.
        var vulnPeriods = await conn.QuerySingleOrDefaultAsync<VulnPeriodCounts>(
            """
            SELECT
              COUNT(DISTINCT CASE WHEN CheckedAt >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-1 days'))  THEN VulnId END) as Day,
              COUNT(DISTINCT CASE WHEN CheckedAt >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-7 days'))  THEN VulnId END) as Week,
              COUNT(DISTINCT CASE WHEN CheckedAt >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days')) THEN VulnId END) as Month
            FROM (
                SELECT pvv.checked_at as CheckedAt, pvv.vuln_id as VulnId
                FROM package_version_vulns pvv
                JOIN package_versions pv ON pv.id = pvv.package_version_id
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND pvv.owner_kind = 'package_version'
                UNION ALL
                SELECT pvv.checked_at as CheckedAt, pvv.vuln_id as VulnId
                FROM package_version_vulns pvv
                JOIN cache_artifact ca ON ca.id = pvv.cache_artifact_id
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId AND pvv.owner_kind = 'cache_artifact'
            )
            """,
            new { orgId }) ?? new VulnPeriodCounts();

        return (vulnsByEcoSeverity, diskByEco, vulnPeriods);
    }

    // Queries active-user count (7d), blocked-pull summary by gate (30d), and quarantine
    // pending count. All org-scoped via WHERE org_id=@orgId.
    private static async Task<(int ActiveUsers, List<GateCount> BlockedByGate, int BlockedPulls, int QuarantinePending)>
        QueryActivityDataAsync(
            System.Data.Common.DbConnection conn, string orgId,
            int? minReleaseAgeHours, DateTimeOffset now)
    {
        int activeUsers = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(DISTINCT actor_id)
            FROM activity
            WHERE org_id = @orgId
              AND actor_id IS NOT NULL
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-7 days'))
            """,
            new { orgId });

        // Every block gate, counted per gate over 30 days. Matching the 'blocked%' prefix (rather
        // than enumerating event types) keeps this in step with BlockGateService as gates are added
        // — an enumerated list silently drops new gates from the dashboard. Strip the 'blocked_'
        // prefix to the bare gate name; the legacy bare 'blocked' event collapses to 'manual'.
        var blockedRows = (await conn.QueryAsync<(string EventType, int Count)>(
            """
            SELECT event_type AS EventType, COUNT(*) AS Count
            FROM activity
            WHERE org_id = @orgId
              AND event_type LIKE 'blocked%'
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days'))
            GROUP BY event_type
            """,
            new { orgId })).ToList();

        var blockedByGate = blockedRows
            .GroupBy(r => r.EventType == "blocked" ? "manual" : r.EventType["blocked_".Length..])
            .Select(g => new GateCount { Gate = g.Key, Count = g.Sum(r => r.Count) })
            .OrderByDescending(g => g.Count)
            .ToList();
        int blockedPulls = blockedByGate.Sum(g => g.Count);

        // Pending review rows that the queue would actually show. Non-release_age holds always
        // count; a release_age hold counts only while its version is still inside the hold window —
        // once it ages out it is a phantom the queue purges on load (see
        // QuarantineRepository.PurgeAgedReleaseHoldsAsync), so it must not inflate the card. The
        // staleness test is shared with the purge (QuarantineRepository.IsReleaseHoldStale) so the
        // count and the queue can never disagree.
        int nonReleaseAgePending = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM quarantine
            WHERE org_id = @orgId AND state = 'pending' AND gate <> 'release_age'
            """,
            new { orgId });

        // xtenant: package_versions joined by FK id already bound to the org-scoped quarantine row
        var releaseHoldPublishDates = await conn.QueryAsync<DateTimeOffset?>(
            """
            SELECT pv.published_at
            FROM quarantine q
            LEFT JOIN package_versions pv ON pv.id = q.package_version_id
            WHERE q.org_id = @orgId AND q.state = 'pending' AND q.gate = 'release_age'
            """,
            new { orgId });

        int activeReleaseHolds = releaseHoldPublishDates
            .Count(p => !QuarantineRepository.IsReleaseHoldStale(p, minReleaseAgeHours, now));

        int quarantinePending = nonReleaseAgePending + activeReleaseHolds;

        return (activeUsers, blockedByGate, blockedPulls, quarantinePending);
    }

    // Queries package hosted/proxy counts, the org storage quota, and 30-day download total.
    // Extracted to keep GetOrgStatsAsync under 80 lines while sharing the same open connection.
    private static async Task<(int Hosted, int Proxied, long? QuotaBytes, int Downloads30d)>
        QueryPackageCountsAndQuotaAsync(System.Data.Common.DbConnection conn, string orgId)
    {
        var proxyCounts = (await conn.QueryAsync<(long IsProxy, int Count)>(
            """
            SELECT is_proxy AS IsProxy, COUNT(*) AS Count
            FROM packages WHERE org_id = @orgId
            GROUP BY is_proxy
            """,
            new { orgId })).ToList();
        int hostedPackages = proxyCounts.Where(r => r.IsProxy == 0).Sum(r => r.Count);
        int proxiedPackages = proxyCounts.Where(r => r.IsProxy != 0).Sum(r => r.Count);

        // Per-tenant storage quota (null = unlimited). Read alongside the per-ecosystem disk sums
        // so the dashboard can render "used of quota" without a second round trip.
        long? storageQuotaBytes = await conn.ExecuteScalarAsync<long?>(
            "SELECT storage_quota_bytes FROM orgs WHERE id = @orgId",
            new { orgId });

        // Total served downloads over the same 30-day window as the blocked count — the same
        // 'download' + 'first_fetch' definition the hourly chart uses (see GetOrgStatsAsync above).
        // Blocked attempts are not downloads and are counted separately by blockedPulls.
        int totalDownloads30d = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('download', 'first_fetch')
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days'))
            """,
            new { orgId });

        return (hostedPackages, proxiedPackages, storageQuotaBytes, totalDownloads30d);
    }

    // Computes the SAML cert expiry snapshot for the org's effective IdP signing cert.
    // Returns null when no cert is configured or the cert cannot be parsed.
    private async Task<SamlCertExpiryStats?> BuildSamlCertExpiryAsync(string orgId, CancellationToken ct)
    {
        if (_samlConfig is null)
        {
            return null;
        }

        TenantSamlConfig? cfg;
        try { cfg = await _samlConfig.GetAsync(orgId, ct); }
        catch { return null; }

        if (cfg is null)
        {
            return null;
        }

        string? effectiveCert = !string.IsNullOrWhiteSpace(cfg.IdpSigningCertOverride)
            ? cfg.IdpSigningCertOverride
            : cfg.IdpSigningCert;

        if (string.IsNullOrWhiteSpace(effectiveCert))
        {
            return null;
        }

        try
        {
            byte[] bytes = Convert.FromBase64String(
                effectiveCert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
            var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            double daysRemaining = (notAfter - _time.GetUtcNow()).TotalDays;
            string status = daysRemaining < 0 ? "expired"
                : daysRemaining <= 7 ? "expiring"
                : "ok";
            return new SamlCertExpiryStats
            {
                Status = status,
                DaysRemaining = (int)Math.Floor(daysRemaining),
                NotAfter = notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            };
        }
        catch { return null; }
    }
}
