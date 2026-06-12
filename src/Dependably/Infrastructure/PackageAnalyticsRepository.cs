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

    public PackageAnalyticsRepository(IMetadataStore db, SamlConfigRepository? samlConfig = null)
    {
        _db = db;
        _samlConfig = samlConfig;
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

        // OCI disk usage lives in oci_blobs (manifest + layer blobs, content-addressed and
        // deduped within an org), not in package_versions — an OCI version row carries only the
        // tiny manifest size. So exclude 'oci' from the package_versions sum and add its real
        // cached footprint from oci_blobs. Both branches are org-scoped (WHERE org_id = @orgId).
        var diskByEco = (await conn.QueryAsync<EcoDiskBytes>(
            """
            SELECT p.ecosystem as Ecosystem, COALESCE(SUM(pv.size_bytes), 0) as TotalBytes
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem != 'oci'
            GROUP BY p.ecosystem
            UNION ALL
            SELECT 'oci' as Ecosystem, COALESCE(SUM(size_bytes), 0) as TotalBytes
            FROM oci_blobs
            WHERE org_id = @orgId
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

        int activeUsers = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(DISTINCT actor_id)
            FROM activity
            WHERE org_id = @orgId
              AND actor_id IS NOT NULL
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-7 days'))
            """,
            new { orgId });

        int blockedPulls = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM activity
            WHERE org_id = @orgId
              AND event_type IN ('blocked', 'blocked_vuln_score', 'blocked_manual')
              AND created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-30 days'))
            """,
            new { orgId });

        // Total served downloads over the same 30-day window as the blocked count — the same
        // 'download' + 'first_fetch' definition the hourly chart uses (see DownloadsByHour above).
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
            SamlCertExpiry: samlCertExpiry);
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
            double daysRemaining = (notAfter - DateTimeOffset.UtcNow).TotalDays;
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
