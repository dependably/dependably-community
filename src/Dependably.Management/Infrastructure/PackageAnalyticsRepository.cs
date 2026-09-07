using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Protocol;
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
    private readonly Dependably.Infrastructure.VulnTracker.InstanceVulnTrackerConfig? _trackerConfig;

    public PackageAnalyticsRepository(
        IMetadataStore db,
        SamlConfigRepository? samlConfig = null,
        TimeProvider? time = null,
        ILogger<PackageAnalyticsRepository>? logger = null,
        Dependably.Infrastructure.VulnTracker.InstanceVulnTrackerConfig? trackerConfig = null)
    {
        _db = db;
        _samlConfig = samlConfig;
        _time = time ?? TimeProvider.System;
        _logger = logger ?? NullLogger<PackageAnalyticsRepository>.Instance;
        _trackerConfig = trackerConfig;
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
        // clock so the statement stays dialect-neutral. activity.created_at is millisecond-precision
        // text (AuditRepository.LogActivityAsync is its only writer), so the cutoff is formatted at
        // the same precision — a second-precision bound sorts wrong against it on the boundary
        // second, since '.' (0x2E) collates before 'Z' (0x5A).
        var now = _time.GetUtcNow();
        string hourCutoff = now.AddHours(-24).ToUtcIsoMillis();
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

        var (vulnsByEcoSeverity, diskByEco, vulnPeriods, activeUsers, blockedByGate, blockedPulls, quarantinePending,
            activeOverrideCount, oldestActiveOverrideDays) =
            await QueryVulnAndActivityStatsAsync(conn, orgId, minReleaseAgeHours, now);

        var (hostedPackages, proxiedPackages, storageQuotaBytes, totalDownloads30d) =
            await QueryPackageCountsAndQuotaAsync(conn, orgId, now);

        var (operationalRiskPackages, licenseRiskVersions) = await QueryRiskPillarStatsAsync(conn, orgId);

        var (scannedVersions, unscannedVersions, noFeedVersions) = await QueryCoverageStatsAsync(conn, orgId);

        var (trackerConfigured, enrichedAdvisories, totalAdvisories) =
            await QueryEnrichmentCoverageAsync(conn, orgId, ct);

        var samlCertExpiry = await BuildSamlCertExpiryAsync(orgId, ct);

        // Projects dashboard tile. project_versions.policy_status is materialized precisely so
        // this needs no fan-out per finding: one COUNT-GROUP-BY over each project's is_latest
        // row gives the whole "N pass / N warn / N violation" picture. A NULL status (never
        // evaluated) is its own bucket, not folded into 'pass'.
        //
        // Deliberately is_latest and NOT ProjectLifecycle.InServiceFilter, unlike the blast
        // radius: this tile counts PROJECTS, one verdict each, and its sub-line has to add up to
        // the headline total beside it. Admitting every active version would count a project once
        // per concurrently-deployed release and produce a breakdown larger than the number of
        // projects it claims to describe — a tile whose parts do not add up.
        var projectPolicyStatus = (await conn.QueryAsync<ProjectPolicyStatusCount>(
            """
            SELECT COALESCE(pv.policy_status, 'unevaluated') AS Status, COUNT(*) AS Count
            FROM project_versions pv
            WHERE pv.org_id = @orgId AND pv.is_latest = 1
            GROUP BY pv.policy_status
            """,
            new { orgId })).ToList();
        // Scoped to kind='project' — a collection (folder) holds no versions and so never
        // appears in the policy-status breakdown above. Counting every projects row here,
        // collections included, would make the headline larger than the sum of its own
        // pass/warn/violation/unevaluated sub-line, a tile whose parts do not add up.
        int totalProjects = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM projects WHERE org_id = @orgId AND kind = @projectKind",
            new { orgId, projectKind = ProjectKinds.Project });

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
            LicenseRiskVersionCount: licenseRiskVersions,
            ProjectVersionPolicyStatus: projectPolicyStatus,
            TotalProjects: totalProjects,
            ScannedVersionCount: scannedVersions,
            UnscannedVersionCount: unscannedVersions,
            NoFeedVersionCount: noFeedVersions,
            ActiveOverrideCount: activeOverrideCount,
            OldestActiveOverrideDays: oldestActiveOverrideDays,
            TrackerConfigured: trackerConfigured,
            EnrichedAdvisoryCount: enrichedAdvisories,
            TotalAdvisoryCount: totalAdvisories);
    }

    // Scan-coverage tile: unions the same two planes as the risk pillars above (uploaded
    // package_versions and proxy cache_artifact, org-scoped via tenant_artifact_access), but only
    // over the rows VulnerabilityScanService itself would consider scanning — see that
    // service's own scan-pass query, whose structural predicates this mirrors: origin='uploaded' on the uploaded plane
    // (a legacy non-uploaded-origin row is a structural non-participant, not a coverage gap) and a
    // non-null purl on the proxy plane (an artifact whose purl hasn't resolved yet has nothing to
    // look up against OSV). Rows failing that structural filter are excluded from every bucket —
    // scanned, unscanned, and no-feed alike — because the scanner will never touch them for either
    // reason.
    //
    // Within that domain, a row's ecosystem decides the bucket: OsvFeedCoverage.NoFeedEcosystems
    // (OCI, Terraform — OSV publishes no feed to check them against at all) is its own third
    // bucket, never "unscanned". Folding it into "unscanned" is the bug this exists to prevent: an
    // org that only ever pushes OCI images would read "0% scanned" forever with vuln_checked_at
    // permanently NULL and no operator action able to change it — indistinguishable from a backlog
    // the scanner just hasn't reached yet. The remaining rows split scanned/unscanned by whether
    // vuln_checked_at is stamped; a deferred scan (left NULL when the OSV source was unreachable)
    // reads identically to a version never scanned at all — both belong in "unscanned". The
    // scanner's remaining predicates are deliberately not mirrored: org status is a per-pass
    // concern (a suspended org cannot reach this surface at all), and the per-org air-gap
    // setting, which leaves every row unscanned while it is on, stays in "unscanned" because —
    // unlike no-feed — it is operator-reversible and "0% scanned" is a true statement there.
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated fragment is DapperInClause.Expand's own parenthesized, " +
                        "individually-parameterized (@noFeed0, @noFeed1, …) list, not user text — " +
                        "see DapperInClause's own doc comment for why Dapper's own IN @list " +
                        "auto-expansion cannot be used here (it binds a Postgres connection's " +
                        "enumerable as a single native array parameter, valid only after " +
                        "= ANY(...), never after IN, which is a syntax error at bind time).")]
    private static async Task<(int Scanned, int Unscanned, int NoFeed)> QueryCoverageStatsAsync(
        System.Data.Common.DbConnection conn, string orgId)
    {
        // See DapperInClause: Dapper's own IN @noFeedEcosystems auto-expansion binds the whole
        // list as one Postgres array parameter instead of expanding the SQL text, which IN never
        // accepts — confirmed by PostgresQuerySmokeTests against a live Postgres, not just reasoned
        // about (a bare `IN @noFeedEcosystems` here previously passed the SQLite-only repository
        // tests and only failed on that smoke test's real Postgres connection).
        var (noFeedClause, parameters) = DapperInClause.Expand("noFeed", OsvFeedCoverage.NoFeedEcosystems);
        parameters.Add("orgId", orgId);

        // DapperInClause's contract makes the empty list the caller's problem: "IN ()" is invalid
        // SQL on both engines. An empty no-feed set (every ecosystem gained a feed) degrades the
        // classifier to a constant 0 — nothing is no-feed — instead of reaching the SQL.
        string uploadedIsNoFeed = OsvFeedCoverage.NoFeedEcosystems.Count == 0
            ? "0" : $"CASE WHEN p.ecosystem IN {noFeedClause} THEN 1 ELSE 0 END";
        string proxyIsNoFeed = OsvFeedCoverage.NoFeedEcosystems.Count == 0
            ? "0" : $"CASE WHEN ca.ecosystem IN {noFeedClause} THEN 1 ELSE 0 END";

        // rawsql: noFeedClause is a DapperInClause-built parameterized (@noFeed0, @noFeed1, …) list, not user text.
        var row = await conn.QuerySingleOrDefaultAsync<(int Scanned, int Unscanned, int NoFeed)>(
            $"""
            SELECT
                COALESCE(SUM(CASE WHEN IsNoFeed = 0 AND VulnCheckedAt IS NOT NULL THEN 1 ELSE 0 END), 0) AS Scanned,
                COALESCE(SUM(CASE WHEN IsNoFeed = 0 AND VulnCheckedAt IS NULL THEN 1 ELSE 0 END), 0) AS Unscanned,
                COALESCE(SUM(CASE WHEN IsNoFeed = 1 THEN 1 ELSE 0 END), 0) AS NoFeed
            FROM (
                SELECT pv.vuln_checked_at AS VulnCheckedAt,
                       {uploadedIsNoFeed} AS IsNoFeed
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId
                  AND pv.origin = 'uploaded'
                UNION ALL
                SELECT ca.vuln_checked_at AS VulnCheckedAt,
                       {proxyIsNoFeed} AS IsNoFeed
                FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId
                  AND ca.purl IS NOT NULL
            ) u
            """,
            parameters);
        return row;
    }

    /// <summary>
    /// Vulnerability-tracker enrichment coverage for one org: of the distinct advisories affecting
    /// its packages across both storage planes, how many carry an NVD band or SSVC decision.
    ///
    /// <para>
    /// <b>Deduplicated by advisory, not counted per version.</b> The same CVE commonly affects
    /// several of an org's package versions; counting rows would inflate both the numerator and
    /// denominator by however many versions happen to share it, and — because <c>vulnerabilities</c>
    /// is the shared, deployment-wide advisory store — the enrichment fact belongs to the advisory
    /// once, not once per linking row.
    /// </para>
    ///
    /// <para>
    /// <b>The tracker connection is instance-level, so "configured" is a fact about the deployment,
    /// not the org.</b> With no <see cref="InstanceVulnTrackerConfig"/> resolver supplied — the
    /// constructor's null default, matching every other optional dependency here — this returns
    /// <c>Configured: false</c> without querying the advisory corpus at all, because there is
    /// nothing an unconfigured connection could have enriched.
    /// </para>
    /// </summary>
    private async Task<(bool Configured, int Enriched, int Total)> QueryEnrichmentCoverageAsync(
        System.Data.Common.DbConnection conn, string orgId, CancellationToken ct)
    {
        if (_trackerConfig is null)
        {
            return (false, 0, 0);
        }

        var resolved = await _trackerConfig.ResolveAsync(ct);
        if (!resolved.Configured)
        {
            return (false, 0, 0);
        }

        // xtenant: package_version_vulns.cache_artifact_id is a global-plane row; org membership
        // for that arm is resolved through tenant_artifact_access, not a column on the row itself.
        var row = await conn.QuerySingleAsync<EnrichmentCoverageCounts>(new CommandDefinition(
            """
            SELECT COUNT(DISTINCT v.id) AS Total,
                   COUNT(DISTINCT CASE
                       WHEN v.nvd_checked_at IS NOT NULL OR v.ssvc_checked_at IS NOT NULL
                       THEN v.id END) AS Enriched
            FROM (
                SELECT pvv.vuln_id
                FROM package_version_vulns pvv
                JOIN package_versions pv ON pv.id = pvv.package_version_id
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND pvv.owner_kind = 'package_version'
                UNION ALL
                SELECT pvv.vuln_id
                FROM package_version_vulns pvv
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = pvv.cache_artifact_id
                WHERE taa.org_id = @orgId AND pvv.owner_kind = 'cache_artifact'
            ) u
            JOIN vulnerabilities v ON v.id = u.vuln_id
            """,
            new { orgId }, cancellationToken: ct));

        return (true, (int)row.Enriched, (int)row.Total);
    }

    /// <summary>
    /// Materialization shape for <see cref="QueryEnrichmentCoverageAsync"/> and
    /// <see cref="GetInstanceEnrichmentCoverageAsync"/>. A settable-property class, not a tuple:
    /// <c>COUNT(DISTINCT …)</c> over an all-filtered-out group still returns 0 on both providers
    /// (unlike <c>SUM</c>), but Dapper's tuple materializer requires an exact constructor match
    /// and both columns are projected as 64-bit integers by SQLite.
    /// </summary>
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed",
        Justification = "Dapper sets these projection properties by reflection at the SELECT mapping site.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "Dapper sets these projection properties by reflection at the SELECT mapping site.")]
    private sealed class EnrichmentCoverageCounts
    {
        public long Total { get; set; }
        public long Enriched { get; set; }
    }

    /// <summary>
    /// Vulnerability-tracker enrichment coverage across the whole deployment: the same
    /// advisory-level completeness fact as <see cref="QueryEnrichmentCoverageAsync"/>, without
    /// scoping to one org's packages. <c>Configured</c> is a single instance-wide fact regardless
    /// of which org would ask, so the apex/operator dashboard and the per-tenant "Enrichment %"
    /// column both read it from here rather than summing N per-org queries.
    /// </summary>
    public async Task<(bool Configured, int Enriched, int Total)> GetInstanceEnrichmentCoverageAsync(
        CancellationToken ct = default)
    {
        if (_trackerConfig is null)
        {
            return (false, 0, 0);
        }

        var resolved = await _trackerConfig.ResolveAsync(ct);
        if (!resolved.Configured)
        {
            return (false, 0, 0);
        }

        await using var conn = await _db.OpenAsync(ct);

        // xtenant: apex/operator dashboard rollup, counting enrichment across every org's
        // advisories by design — the same instance-wide-rollup posture as
        // OrgRepository.CountByStatusAsync. TrackerConfigured is already deployment-wide above.
        var row = await conn.QuerySingleAsync<EnrichmentCoverageCounts>(new CommandDefinition(
            """
            SELECT COUNT(DISTINCT v.id) AS Total,
                   COUNT(DISTINCT CASE
                       WHEN v.nvd_checked_at IS NOT NULL OR v.ssvc_checked_at IS NOT NULL
                       THEN v.id END) AS Enriched
            FROM package_version_vulns pvv
            JOIN vulnerabilities v ON v.id = pvv.vuln_id
            """,
            cancellationToken: ct));

        return (true, (int)row.Enriched, (int)row.Total);
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
    // Three reasons, ranked most-severe first by the CASE: an artifact with no recorded licence
    // at all ('unknown'), one carrying a blocklisted licence ('blocklisted'), and one carrying a
    // licence the org marked conditional ('conditional'). The third is not a risk in the same
    // sense as the other two — it serves normally — but it is the review surface the conditional
    // disposition exists to feed, and it belongs on the same drill-down rather than a page of its
    // own. An artifact matching more than one reason reports the most severe.
    //
    // The comparison joins on the raw license_spdx text rather than parsing expressions, matching
    // the blocklist arm that preceded it: a compound expression recorded verbatim will not match a
    // single-leaf policy row here even though CheckPolicyAsync would decompose it. That is a known
    // limitation of this read model, not of enforcement.
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
                    THEN 'unknown'
                    WHEN EXISTS (SELECT 1 FROM artifact_license al
                                 JOIN license_blocklist bl
                                   ON bl.license_spdx = al.license_spdx AND bl.org_id = @orgId
                                 WHERE al.org_id = ai.org_id AND al.owner_kind = ai.owner_kind
                                   AND al.owner_id = ai.owner_id)
                    THEN 'blocklisted'
                    ELSE 'conditional' END AS Reason
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
            OR EXISTS (SELECT 1 FROM artifact_license al
                       JOIN license_allowlist cl
                         ON cl.license_spdx = al.license_spdx AND cl.org_id = @orgId
                        AND cl.disposition = 'conditional'
                       WHERE al.org_id = ai.org_id AND al.owner_kind = ai.owner_kind
                         AND al.owner_id = ai.owner_id)
          )
        """;

    // Const concatenation, not interpolation: these are compile-time constants, so the SQL stays
    // literal and no parameter can be smuggled in through the body.
    // rawsql: const concatenation of compile-time-constant fragments; no runtime value interpolated.
    private const string OperationalRiskPackageCountSql =
        "SELECT COUNT(*) FROM (SELECT DISTINCT Ecosystem, Name FROM (" + OperationalRiskBody + ") u) d";

    // rawsql: const concatenation of compile-time-constant fragments; no runtime value interpolated.
    private const string LicenseRiskCountSql =
        "SELECT COUNT(*) FROM (" + LicenseRiskBody + ") u WHERE (@reason IS NULL OR u.Reason = @reason)";

    // Dashboard-tile count: the two reasons that are genuinely risk, never 'conditional'.
    // rawsql: const concatenation of compile-time-constant fragments; no runtime value interpolated.
    private const string LicenseRiskRiskOnlyCountSql =
        "SELECT COUNT(*) FROM (" + LicenseRiskBody + ") u " +
        "WHERE u.Reason <> 'conditional' AND (@reason IS NULL OR u.Reason = @reason)";

    // The `sort=` values the Risk page's operational table accepts, mapped to the SQL expression
    // that orders by them plus that column's own natural default direction — a closed allowlist,
    // never interpolated caller text. Deliberately the same set as the sortable headers
    // Risk.svelte draws (AnalysisSortKeyParityTests-style parity is pinned in
    // RiskSortKeyParityTests), so the accepted surface stays reviewable from either side.
    //
    // Each column carries its own default direction rather than one instance-wide default (the
    // ProjectRepository.ListSortColumns shape) because "worst first" means opposite directions
    // for different columns here: a versions-behind count wants its biggest offenders first
    // (desc), while a package name wants A-before-Z (asc). Un-versioned string columns are
    // lower-cased for the same cross-engine reason VulnReportSortColumns lower-cases its own
    // (LOWER() needs no collation lookup; SQLite's COLLATE NOCASE has no Postgres equivalent).
    private static readonly Dictionary<string, (string Expr, string DefaultDir)> OperationalRiskSortColumns =
        new(StringComparer.Ordinal)
        {
            ["package"] = ("LOWER(u.DisplayName)", "asc"),
            ["version"] = ("LOWER(u.Version)", "asc"),
            ["behind"] = ("u.VersionsBehind", "desc"),
            // Nullable — an ecosystem whose upstream feed carries no "latest" fact (or a version
            // this org has never checked) sinks to the end of an ascending sort via the sentinel,
            // rather than floating to the top under SQLite's NULLS-FIRST-on-ASC default while
            // Postgres would put it last for the same query.
            ["latest"] = ("LOWER(COALESCE(u.UpstreamLatestVersion, '~'))", "asc"),
            ["origin"] = ("LOWER(u.Origin)", "asc"),
            // Nullable for the same reason as VulnReportSortColumns["published"]; newest first by
            // default, an unknown publish date sinking to the very end of an ascending sort.
            ["published"] = ("COALESCE(u.PublishedAt, '9999-12-31T23:59:59Z')", "desc"),
        };

    /// <summary>The sort applied to the operational-risk list when the caller names none, or names one that is not allowed.</summary>
    public const string DefaultOperationalRiskSort = "behind";

    /// <summary>The <c>sort=</c> keys <see cref="ListOperationalRiskAsync"/> honours.</summary>
    public static IReadOnlyCollection<string> OperationalRiskSortKeys => OperationalRiskSortColumns.Keys;

    // The `sort=` values the Risk page's license table accepts. `licenses` is deliberately absent:
    // the SPDX identifiers are stitched onto the page's rows by RiskController AFTER paging (one
    // lookup per owner id, see ListLicenseRiskAsync's own doc comment), the same reason
    // ProjectRepository.ListSortColumns excludes the projects list's per-page-computed columns —
    // sorting on a value that does not exist until after the page is selected would order one
    // page against itself and disagree with the pager's own total.
    private static readonly Dictionary<string, (string Expr, string DefaultDir)> LicenseRiskSortColumns =
        new(StringComparer.Ordinal)
        {
            ["package"] = ("LOWER(u.DisplayName)", "asc"),
            ["version"] = ("LOWER(u.Version)", "asc"),
            // Reason is already one of the three fixed lower-case literals the LicenseRiskBody
            // CASE emits ('blocklisted' < 'conditional' < 'unknown'), so no LOWER() is needed.
            ["reason"] = ("u.Reason", "asc"),
            ["origin"] = ("LOWER(u.Origin)", "asc"),
            ["published"] = ("COALESCE(u.PublishedAt, '9999-12-31T23:59:59Z')", "desc"),
        };

    /// <summary>The sort applied to the license-risk list when the caller names none, or names one that is not allowed.</summary>
    public const string DefaultLicenseRiskSort = "reason";

    /// <summary>The <c>sort=</c> keys <see cref="ListLicenseRiskAsync"/> honours.</summary>
    public static IReadOnlyCollection<string> LicenseRiskSortKeys => LicenseRiskSortColumns.Keys;

    private static string NormalizeSortDirection(string? requested, string defaultDir)
    {
        return string.Equals(requested, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC"
            : string.Equals(requested, "desc", StringComparison.OrdinalIgnoreCase) ? "DESC"
            : string.Equals(defaultDir, "desc", StringComparison.OrdinalIgnoreCase) ? "DESC" : "ASC";
    }

    // Both fragments come from the closed *SortColumns allowlist above plus a two-value direction
    // check, never from caller text. Ecosystem/Name/Version are the fixed tiebreaker on every
    // sort, matching the pre-sortable default order, so a page boundary never splits or repeats a
    // row when two rows share the sorted value.
    private static string BuildOperationalRiskOrderBy(string? sort, string? dir)
    {
        if (!OperationalRiskSortColumns.TryGetValue(sort ?? "", out var col))
        {
            col = OperationalRiskSortColumns[DefaultOperationalRiskSort];
        }

        return $"{col.Expr} {NormalizeSortDirection(dir, col.DefaultDir)}, u.Ecosystem ASC, u.Name ASC, u.Version ASC";
    }

    private static string BuildLicenseRiskOrderBy(string? sort, string? dir)
    {
        if (!LicenseRiskSortColumns.TryGetValue(sort ?? "", out var col))
        {
            col = LicenseRiskSortColumns[DefaultLicenseRiskSort];
        }

        return $"{col.Expr} {NormalizeSortDirection(dir, col.DefaultDir)}, u.Ecosystem ASC, u.Name ASC, u.Version ASC";
    }

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

        // The tile counts artifacts at licence *risk* — unknown or blocklisted. Conditional rows
        // now share the drill-down but are deliberately excluded here: they serve normally, and
        // folding them in would make a tile that has always meant "these are problems" start
        // counting artifacts the org already decided were acceptable. The drill-down's own
        // reason filter is where conditional is surfaced.
        int licenseRiskVersions = await conn.ExecuteScalarAsync<int>(
            LicenseRiskRiskOnlyCountSql,
            new { orgId, ecosystem = (string?)null, reason = (string?)null });

        return (operationalRiskPackages, licenseRiskVersions);
    }

    /// <summary>
    /// Lists the versions behind the operational-risk drill-down tile: one row per version at or
    /// over the <see cref="VersionsBehindDashboardThreshold"/>, across both storage planes.
    /// <c>PackageCount</c> is the tile's own number (distinct packages, not versions) computed from
    /// the same union, so the page can render a summary that reads exactly like the tile.
    /// <paramref name="sort"/>/<paramref name="dir"/> are resolved through
    /// <see cref="OperationalRiskSortColumns"/>; an unrecognised value falls back to
    /// <see cref="DefaultOperationalRiskSort"/> rather than erroring, so a stale bookmark still
    /// renders.
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated ORDER BY fragment is composed exclusively from compile-time-constant SQL " +
                        "expressions in OperationalRiskSortColumns plus the literal strings \"ASC\"/\"DESC\". " +
                        "Caller-supplied sort/dir values only select which constant to use (TryGetValue + " +
                        "case-insensitive equality against literals); they never reach the SQL string.")]
    public async Task<(IReadOnlyList<OperationalRiskRow> Items, int Total, int PackageCount)> ListOperationalRiskAsync(
        string orgId, string? ecosystem, int limit, int offset,
        string? sort = null, string? dir = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var args = new { orgId, threshold = VersionsBehindDashboardThreshold, ecosystem, limit, offset };

        // rawsql: OperationalRiskBody is a compile-time-constant SQL fragment; no runtime value interpolated.
        int total = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM (" + OperationalRiskBody + ") u", args);
        int packageCount = await conn.ExecuteScalarAsync<int>(OperationalRiskPackageCountSql, args);

        string orderBy = BuildOperationalRiskOrderBy(sort, dir);
        // rawsql: orderBy is built above from the closed OperationalRiskSortColumns allowlist plus
        // a two-value direction check — never from caller text (see the S2077 justification above).
        var rows = await conn.QueryAsync<OperationalRiskRow>(
            "SELECT * FROM (" + OperationalRiskBody + $") u ORDER BY {orderBy} LIMIT @limit OFFSET @offset",
            args);

        return (rows.ToList(), total, packageCount);
    }

    /// <summary>
    /// Lists the versions behind the license-risk drill-down tile, across both storage planes.
    /// With no <paramref name="reason"/> or <paramref name="ecosystem"/> filter the total is the
    /// tile's own count. SPDX identifiers are stitched onto the page's rows by the caller — see
    /// <see cref="LicenseRepository.GetSpdxForVersionsAsync"/>. <paramref name="sort"/>/
    /// <paramref name="dir"/> are resolved through <see cref="LicenseRiskSortColumns"/>; an
    /// unrecognised value falls back to <see cref="DefaultLicenseRiskSort"/> rather than erroring.
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated ORDER BY fragment is composed exclusively from compile-time-constant SQL " +
                        "expressions in LicenseRiskSortColumns plus the literal strings \"ASC\"/\"DESC\". " +
                        "Caller-supplied sort/dir values only select which constant to use (TryGetValue + " +
                        "case-insensitive equality against literals); they never reach the SQL string.")]
    [SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "A paged query signature: tenant, two optional filters, limit/offset and the sort pair the endpoint binds straight from its query string.")]
    public async Task<(IReadOnlyList<LicenseRiskRow> Items, int Total)> ListLicenseRiskAsync(
        string orgId, string? ecosystem, string? reason, int limit, int offset,
        string? sort = null, string? dir = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var args = new { orgId, ecosystem, reason, limit, offset };

        int total = await conn.ExecuteScalarAsync<int>(LicenseRiskCountSql, args);

        string orderBy = BuildLicenseRiskOrderBy(sort, dir);
        // rawsql: orderBy is built above from the closed LicenseRiskSortColumns allowlist plus a
        // two-value direction check — never from caller text (see the S2077 justification above).
        var rows = await conn.QueryAsync<LicenseRiskRow>(
            "SELECT * FROM (" + LicenseRiskBody + $") u WHERE (@reason IS NULL OR u.Reason = @reason) " +
            $"ORDER BY {orderBy} LIMIT @limit OFFSET @offset",
            args);

        return (rows.ToList(), total);
    }

    // Queries vuln/severity counts, disk-by-ecosystem, vuln-period buckets, active users,
    // blocked-by-gate summary, quarantine pending count, and active-override stats. All
    // org-scoped via WHERE org_id=@orgId.
    private static async Task<(
        List<EcoSeverityCount> VulnsByEcoSeverity,
        List<EcoDiskBytes> DiskByEco,
        VulnPeriodCounts VulnPeriods,
        int ActiveUsers,
        List<GateCount> BlockedByGate,
        int BlockedPulls,
        int QuarantinePending,
        int ActiveOverrideCount,
        int? OldestActiveOverrideDays)>
        QueryVulnAndActivityStatsAsync(
            System.Data.Common.DbConnection conn, string orgId,
            int? minReleaseAgeHours, DateTimeOffset now)
    {
        var (vulnsByEcoSeverity, diskByEco, vulnPeriods) = await QueryVulnDataAsync(conn, orgId, now);
        var (activeUsers, blockedByGate, blockedPulls, quarantinePending, activeOverrideCount, oldestActiveOverrideDays) =
            await QueryActivityDataAsync(conn, orgId, minReleaseAgeHours, now);
        return (vulnsByEcoSeverity, diskByEco, vulnPeriods, activeUsers, blockedByGate, blockedPulls, quarantinePending,
            activeOverrideCount, oldestActiveOverrideDays);
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
                SELECT ca.ecosystem as Ecosystem,
                       COALESCE(SUM(COALESCE(taa.size_bytes, ca.size_bytes)), 0) as TotalBytes
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
        string dayCutoff = now.AddDays(-1).ToUtcIso();
        string weekCutoff = now.AddDays(-7).ToUtcIso();
        string monthCutoff = now.AddDays(-30).ToUtcIso();
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

    // Queries active-user count (7d), blocked-pull summary by gate (30d), quarantine pending
    // count, and active-override stats (approved quarantine rows). All org-scoped via
    // WHERE org_id=@orgId.
    private static async Task<(
        int ActiveUsers,
        List<GateCount> BlockedByGate,
        int BlockedPulls,
        int QuarantinePending,
        int ActiveOverrideCount,
        int? OldestActiveOverrideDays)>
        QueryActivityDataAsync(
            System.Data.Common.DbConnection conn, string orgId,
            int? minReleaseAgeHours, DateTimeOffset now)
    {
        // Cutoffs computed in C# from the injected clock, not strftime/datetime('now'), so the
        // statements stay dialect-neutral. Both bounds compare against activity.created_at, which
        // is millisecond-precision text (AuditRepository.LogActivityAsync is its only writer), so
        // they are formatted at the same precision — a second-precision bound sorts wrong against
        // it on the boundary second, since '.' (0x2E) collates before 'Z' (0x5A).
        string sevenDaysCutoff = now.AddDays(-7).ToUtcIsoMillis();
        string thirtyDaysCutoff = now.AddDays(-30).ToUtcIsoMillis();

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

        // Active overrides: approved quarantine rows (a human decision that outranks every policy
        // gate). The oldest one's age is what tells an operator how long a bypass has stood, in
        // whole days from the injected clock — null when there are no approved rows.
        var (activeOverrideCount, oldestDecidedAt) = await conn.QuerySingleOrDefaultAsync<(int Count, DateTimeOffset? OldestDecidedAt)>(
            """
            SELECT COUNT(*) AS Count, MIN(decided_at) AS OldestDecidedAt
            FROM quarantine
            WHERE org_id = @orgId AND state = 'approved'
            """,
            new { orgId });
        int? oldestActiveOverrideDays = oldestDecidedAt is { } oldest
            ? (int)Math.Floor((now - oldest).TotalDays)
            : null;

        return (activeUsers, blockedByGate, blockedPulls, quarantinePending, activeOverrideCount, oldestActiveOverrideDays);
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
        // stays dialect-neutral. activity.created_at is millisecond-precision text (see the cutoffs
        // above), so the bound matches that precision rather than the second-precision default.
        string thirtyDaysCutoff = now.AddDays(-30).ToUtcIsoMillis();
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
                NotAfter = notAfter.ToUtcIso(),
            };
        }
        catch { return null; }
    }
}
