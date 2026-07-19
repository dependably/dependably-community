using Dapper;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Infrastructure;

/// <summary>
/// Dashboard aggregation queries. Split out of <see cref="PackageRepository"/> so the
/// publish/proxy hot path doesn't carry the org-stats SQL surface, and so callers can
/// depend on <see cref="PackageRepository"/> alone for CRUD without dragging analytics.
/// </summary>
public sealed class PackageAnalyticsRepository
{
    // Operational-risk dashboard tile threshold: a package counts toward the tile once any of
    // its versions is at least this many stable releases behind upstream. Deliberately simple
    // (matches the ticket's own "N packages ≥ X versions behind" example) — not configurable yet.
    internal const int VersionsBehindDashboardThreshold = 5;

    private readonly IMetadataStore _db;
    private readonly SamlConfigRepository? _samlConfig;
    private readonly TimeProvider _time;
    private readonly ILogger<PackageAnalyticsRepository> _logger;

    public PackageAnalyticsRepository(
        IMetadataStore db,
        SamlConfigRepository? samlConfig = null,
        TimeProvider? time = null,
        ILogger<PackageAnalyticsRepository>? logger = null)
    {
        _db = db;
        _samlConfig = samlConfig;
        _time = time ?? TimeProvider.System;
        _logger = logger ?? NullLogger<PackageAnalyticsRepository>.Instance;
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
        //
        // The hour bucket is a substr() of the ISO-8601 TEXT timestamp, not strftime/to_char: both
        // engines support substr() identically, and the cutoff is computed in C# from the injected
        // clock so the statement stays dialect-neutral.
        var now = _time.GetUtcNow();
        string hourCutoff = now.AddHours(-24).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var downloadsByHour = (await conn.QueryAsync<HourCount>(
            """
            SELECT substr(created_at, 1, 13) || ':00:00Z' as Hour, COUNT(*) as Count
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('download', 'first_fetch')
              AND created_at >= @hourCutoff
            GROUP BY substr(created_at, 1, 13)
            ORDER BY Hour ASC
            """,
            new { orgId, hourCutoff })).ToList();

        // The dashboard pending count must agree with the review queue, which purges aged-out
        // release_age holds on load (QuarantineRepository.PurgeAgedReleaseHoldsAsync). Pass the
        // org's hold threshold and the current clock down so the count excludes the same stale
        // holds — otherwise the card shows a number the (empty) queue can't account for.
        int? minReleaseAgeHours = await conn.ExecuteScalarAsync<int?>(
            "SELECT min_release_age_hours FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        var (vulnsByEcoSeverity, diskByEco, vulnPeriods, activeUsers, blockedByGate, blockedPulls, quarantinePending) =
            await QueryVulnAndActivityStatsAsync(conn, orgId, minReleaseAgeHours, now);

        var (hostedPackages, proxiedPackages, storageQuotaBytes, totalDownloads30d) =
            await QueryPackageCountsAndQuotaAsync(conn, orgId, now);

        var (operationalRiskPackages, licenseRiskVersions) = await QueryRiskPillarStatsAsync(conn, orgId);

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
            StorageQuotaBytes: storageQuotaBytes,
            OperationalRiskPackageCount: operationalRiskPackages,
            VersionsBehindThreshold: VersionsBehindDashboardThreshold,
            LicenseRiskVersionCount: licenseRiskVersions);
    }

    // The two risk pillars (operational + license) each union the uploaded (package_versions) and
    // proxy (cache_artifact) planes the same way the vuln/disk aggregates above do. Each union body
    // is declared once and shared by the dashboard tile's COUNT and the drill-down list, so the
    // list a user lands on can never disagree with the number they clicked.
    //
    // The proxy arm LEFT JOINs packages purely for the display name: a cache_artifact is reachable
    // for an org through tenant_artifact_access alone, and an org can hold one with no packages row
    // of its own. An INNER JOIN here would silently drop those rows from the list while the tile
    // still counted them. packages is UNIQUE (org_id, ecosystem, purl_name), so the join cannot
    // multiply rows.
    //
    // Both bodies take @orgId, @ecosystem (NULL = every ecosystem); the operational body also takes
    // @threshold. A NULL versions_behind (unknown) never satisfies >= @threshold — the operational
    // signal only fires on a known, high count.
    private const string OperationalRiskBody =
        """
        SELECT p.ecosystem               AS Ecosystem,
               p.purl_name               AS Name,
               p.name                    AS DisplayName,
               pv.purl                   AS Purl,
               pv.version                AS Version,
               pv.versions_behind        AS VersionsBehind,
               pv.origin                 AS Origin,
               p.upstream_latest_version AS UpstreamLatestVersion,
               pv.published_at           AS PublishedAt,
               pv.deprecated             AS Deprecated,
               pv.revoked_at             AS RevokedAt
        FROM package_versions pv
        JOIN packages p ON p.id = pv.package_id
        WHERE p.org_id = @orgId
          AND pv.versions_behind >= @threshold
          AND (@ecosystem IS NULL OR p.ecosystem = @ecosystem)
        UNION ALL
        SELECT ca.ecosystem              AS Ecosystem,
               ca.name                   AS Name,
               COALESCE(p.name, ca.name) AS DisplayName,
               ca.purl                   AS Purl,
               ca.version                AS Version,
               ca.versions_behind        AS VersionsBehind,
               'proxy'                   AS Origin,
               p.upstream_latest_version AS UpstreamLatestVersion,
               ca.published_at           AS PublishedAt,
               ca.deprecated             AS Deprecated,
               ca.revoked_at             AS RevokedAt
        FROM cache_artifact ca
        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
        LEFT JOIN packages p
               ON p.org_id = taa.org_id AND p.ecosystem = ca.ecosystem AND p.purl_name = ca.name
        WHERE taa.org_id = @orgId
          AND ca.versions_behind >= @threshold
          AND (@ecosystem IS NULL OR ca.ecosystem = @ecosystem)
        """;

    // A blocklisted SPDX identifier and a total absence of license data are both signals the
    // operator should look at, so they share the one tile — and the list labels which is which
    // through the Reason column. Reads the canonical artifact_inventory / artifact_license model
    // (SchemaInitializer.Views.cs) rather than hand-unioning package_versions and cache_artifact:
    // one ecosystem column across both catalogues and one (owner_kind, owner_id) key into the
    // licence rows, so a proxied artefact can't be missed the way a hand-written arm forgets a
    // plane. artifact_inventory is already one row per artefact, so a Maven (name, version) with
    // several proxied files still surfaces as several rows (one cache_artifact each) — the
    // per-filename count the tile relies on is preserved without this body deduping.
    private const string LicenseRiskBody =
        """
        SELECT ai.owner_kind   AS OwnerKind,
               ai.owner_id     AS OwnerId,
               ai.ecosystem    AS Ecosystem,
               ai.name         AS Name,
               ai.display_name AS DisplayName,
               ai.purl         AS Purl,
               ai.version      AS Version,
               ai.filename     AS Filename,
               ai.origin       AS Origin,
               ai.published_at AS PublishedAt,
               CASE WHEN NOT EXISTS (SELECT 1 FROM artifact_license al
                                     WHERE al.org_id = ai.org_id AND al.owner_kind = ai.owner_kind
                                       AND al.owner_id = ai.owner_id)
                    THEN 'unknown' ELSE 'blocklisted' END AS Reason
        FROM artifact_inventory ai
        WHERE ai.org_id = @orgId
          AND (@ecosystem IS NULL OR ai.ecosystem = @ecosystem)
          AND (
            NOT EXISTS (SELECT 1 FROM artifact_license al
                        WHERE al.org_id = ai.org_id AND al.owner_kind = ai.owner_kind
                          AND al.owner_id = ai.owner_id)
            OR EXISTS (SELECT 1 FROM artifact_license al
                       JOIN license_blocklist bl
                         ON bl.license_spdx = al.license_spdx AND bl.org_id = @orgId
                       WHERE al.org_id = ai.org_id AND al.owner_kind = ai.owner_kind
                         AND al.owner_id = ai.owner_id)
          )
        """;

    // Const concatenation, not interpolation: these are compile-time constants, so the SQL stays
    // literal and no parameter can be smuggled in through the body.
    private const string OperationalRiskPackageCountSql =
        "SELECT COUNT(*) FROM (SELECT DISTINCT Ecosystem, Name FROM (" + OperationalRiskBody + ") u) d";

    private const string OperationalRiskListSql =
        "SELECT * FROM (" + OperationalRiskBody + ") u " +
        "ORDER BY u.VersionsBehind DESC, u.Ecosystem ASC, u.Name ASC, u.Version ASC " +
        "LIMIT @limit OFFSET @offset";

    private const string LicenseRiskCountSql =
        "SELECT COUNT(*) FROM (" + LicenseRiskBody + ") u WHERE (@reason IS NULL OR u.Reason = @reason)";

    private const string LicenseRiskListSql =
        "SELECT * FROM (" + LicenseRiskBody + ") u WHERE (@reason IS NULL OR u.Reason = @reason) " +
        "ORDER BY u.Reason ASC, u.Ecosystem ASC, u.Name ASC, u.Version ASC " +
        "LIMIT @limit OFFSET @offset";

    // Queries the two remaining risk-pillar dashboard tiles (operational + license), each
    // unioning the uploaded (package_versions) and proxy (cache_artifact) planes the same way
    // the vuln/disk aggregates above do.
    private static async Task<(int OperationalRiskPackages, int LicenseRiskVersions)> QueryRiskPillarStatsAsync(
        System.Data.Common.DbConnection conn, string orgId)
    {
        // Distinct on (ecosystem, name), not name alone: the same package name in two ecosystems is
        // two packages, and the drill-down lists them as two rows.
        int operationalRiskPackages = await conn.ExecuteScalarAsync<int>(
            OperationalRiskPackageCountSql,
            new { orgId, threshold = VersionsBehindDashboardThreshold, ecosystem = (string?)null });

        int licenseRiskVersions = await conn.ExecuteScalarAsync<int>(
            LicenseRiskCountSql,
            new { orgId, ecosystem = (string?)null, reason = (string?)null });

        return (operationalRiskPackages, licenseRiskVersions);
    }

    /// <summary>
    /// Lists the versions behind the operational-risk drill-down tile: one row per version at or
    /// over the <see cref="VersionsBehindDashboardThreshold"/>, across both storage planes.
    /// <c>PackageCount</c> is the tile's own number (distinct packages, not versions) computed from
    /// the same union, so the page can render a summary that reads exactly like the tile.
    /// </summary>
    public async Task<(IReadOnlyList<OperationalRiskRow> Items, int Total, int PackageCount)> ListOperationalRiskAsync(
        string orgId, string? ecosystem, int limit, int offset, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var args = new { orgId, threshold = VersionsBehindDashboardThreshold, ecosystem, limit, offset };

        int total = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM (" + OperationalRiskBody + ") u", args);
        int packageCount = await conn.ExecuteScalarAsync<int>(OperationalRiskPackageCountSql, args);
        var rows = await conn.QueryAsync<OperationalRiskRow>(OperationalRiskListSql, args);

        return (rows.ToList(), total, packageCount);
    }

    /// <summary>
    /// Lists the versions behind the license-risk drill-down tile, across both storage planes.
    /// With no <paramref name="reason"/> or <paramref name="ecosystem"/> filter the total is the
    /// tile's own count. SPDX identifiers are stitched onto the page's rows by the caller — see
    /// <see cref="LicenseRepository.GetSpdxForVersionsAsync"/>.
    /// </summary>
    public async Task<(IReadOnlyList<LicenseRiskRow> Items, int Total)> ListLicenseRiskAsync(
        string orgId, string? ecosystem, string? reason, int limit, int offset, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var args = new { orgId, ecosystem, reason, limit, offset };

        int total = await conn.ExecuteScalarAsync<int>(LicenseRiskCountSql, args);
        var rows = await conn.QueryAsync<LicenseRiskRow>(LicenseRiskListSql, args);

        return (rows.ToList(), total);
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
        var (vulnsByEcoSeverity, diskByEco, vulnPeriods) = await QueryVulnDataAsync(conn, orgId, now);
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
        QueryVulnDataAsync(System.Data.Common.DbConnection conn, string orgId, DateTimeOffset now)
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
            ) u
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
            ) u
            GROUP BY Ecosystem
            """,
            new { orgId })).ToList();

        // Same two-plane union as the severity breakdown: uploaded vulns are org-scoped via
        // packages.org_id, proxy vulns via tenant_artifact_access.org_id. COUNT(DISTINCT vuln_id)
        // per window dedupes a CVE seen on both planes. The three window cutoffs are computed in
        // C# from the injected clock, not strftime/datetime('now'), so the statement stays
        // dialect-neutral.
        string dayCutoff = now.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");
        string weekCutoff = now.AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ");
        string monthCutoff = now.AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var vulnPeriods = await conn.QuerySingleOrDefaultAsync<VulnPeriodCounts>(
            """
            SELECT
              COUNT(DISTINCT CASE WHEN CheckedAt >= @dayCutoff   THEN VulnId END) as Day,
              COUNT(DISTINCT CASE WHEN CheckedAt >= @weekCutoff  THEN VulnId END) as Week,
              COUNT(DISTINCT CASE WHEN CheckedAt >= @monthCutoff THEN VulnId END) as Month
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
            ) u
            """,
            new { orgId, dayCutoff, weekCutoff, monthCutoff }) ?? new VulnPeriodCounts();

        return (vulnsByEcoSeverity, diskByEco, vulnPeriods);
    }

    // Queries active-user count (7d), blocked-pull summary by gate (30d), and quarantine
    // pending count. All org-scoped via WHERE org_id=@orgId.
    private static async Task<(int ActiveUsers, List<GateCount> BlockedByGate, int BlockedPulls, int QuarantinePending)>
        QueryActivityDataAsync(
            System.Data.Common.DbConnection conn, string orgId,
            int? minReleaseAgeHours, DateTimeOffset now)
    {
        // Cutoffs computed in C# from the injected clock, not strftime/datetime('now'), so the
        // statements stay dialect-neutral.
        string sevenDaysCutoff = now.AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ");
        string thirtyDaysCutoff = now.AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");

        int activeUsers = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(DISTINCT actor_id)
            FROM activity
            WHERE org_id = @orgId
              AND actor_id IS NOT NULL
              AND created_at >= @sevenDaysCutoff
            """,
            new { orgId, sevenDaysCutoff });

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
              AND created_at >= @thirtyDaysCutoff
            GROUP BY event_type
            """,
            new { orgId, thirtyDaysCutoff })).ToList();

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

        // The same relation the review queue purges from, so this count cannot describe a queue that
        // shows something else. The gate raises release-age holds on both planes, and a proxied hold
        // carries no package_versions row — see QuarantineRepository.PendingReleaseHoldsSql.
        var releaseHolds = await conn.QueryAsync<QuarantineRepository.ReleaseHoldRow>(
            QuarantineRepository.PendingReleaseHoldsSql, new { orgId });

        int activeReleaseHolds = releaseHolds
            .Count(h => !QuarantineRepository.IsReleaseHoldStale(h.PublishedAt, minReleaseAgeHours, now));

        int quarantinePending = nonReleaseAgePending + activeReleaseHolds;

        return (activeUsers, blockedByGate, blockedPulls, quarantinePending);
    }

    // Queries package hosted/proxy counts, the org storage quota, and 30-day download total.
    // Extracted to keep GetOrgStatsAsync under 80 lines while sharing the same open connection.
    private static async Task<(int Hosted, int Proxied, long? QuotaBytes, int Downloads30d)>
        QueryPackageCountsAndQuotaAsync(System.Data.Common.DbConnection conn, string orgId, DateTimeOffset now)
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
        // Blocked attempts are not downloads and are counted separately by blockedPulls. The cutoff
        // is computed in C# from the injected clock, not strftime/datetime('now'), so the statement
        // stays dialect-neutral.
        string thirtyDaysCutoff = now.AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");
        int totalDownloads30d = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('download', 'first_fetch')
              AND created_at >= @thirtyDaysCutoff
            """,
            new { orgId, thirtyDaysCutoff });

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
        try
        {
            cfg = await _samlConfig.GetAsync(orgId, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A DB failure here must stay observable — the dashboard silently losing the
            // cert-expiry warning is how an operator finds out about an expired IdP cert from a
            // login outage instead of from the tile.
            _logger.LogWarning(ex,
                "{ExceptionType} reading SAML config for org {OrgId}; omitting cert-expiry stats. TraceId={TraceId}",
                ex.GetType().Name, orgId, System.Diagnostics.Activity.Current?.TraceId.ToString());
            return null;
        }

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
