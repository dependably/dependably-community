using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Fleet-wide usage reporting for the apex system-admin plane: one row per tenant over a date
/// range, fleet totals, and the per-ecosystem breakdown. Every query here deliberately spans
/// every tenant — this is the operator's own view of the whole fleet, not a tenant-scoped read —
/// so each one carries a <c>// xtenant:</c> justification rather than an <c>org_id</c> filter.
///
/// The usage tables carry no FK to <c>orgs</c> (rows survive an org's hard delete), so a fleet row
/// can exist for an org id that no longer has an <c>orgs</c> row. <see cref="ListFleetUsageAsync"/>
/// surfaces that org with a null <c>Slug</c>/<c>Status</c> rather than silently dropping its usage.
/// </summary>
public sealed class UsageReportRepository
{
    // xtenant: system-admin fleet usage listing — one row per tenant, deliberately spanning every
    // tenant. The per-org usage-in-range and latest-snapshot shapes appear twice below (once per
    // UNION ALL arm) because each arm joins them to a different population — every orgs row, and
    // the second arm's orphaned org ids with no surviving orgs row (usage_daily/storage_snapshot
    // carry no FK to orgs, so their rows outlive a hard-deleted tenant); the second arm surfaces
    // those with a null slug/status instead of silently dropping their usage. Written out as one
    // literal rather than composed from shared fragments so this stays a single non-interpolated
    // SQL string throughout.
    private const string FleetRowsBody = """
        SELECT o.id AS OrgId, o.slug AS Slug, o.status AS Status, o.deleted_at AS DeletedAt,
               COALESCE(u.EgressBytes, 0) AS EgressBytes,
               COALESCE(u.EgressRedirectBytes, 0) AS EgressRedirectBytes,
               COALESCE(u.EgressMetadataBytes, 0) AS EgressMetadataBytes,
               COALESCE(u.RequestCount, 0) AS RequestCount,
               COALESCE(u.MetadataRequestCount, 0) AS MetadataRequestCount,
               COALESCE(u.StorageMarkSum, 0) AS StorageMarkSum,
               COALESCE(u.StorageMarkCount, 0) AS StorageMarkCount,
               COALESCE(u.CacheMarkSum, 0) AS CacheMarkSum,
               COALESCE(u.CacheMarkCount, 0) AS CacheMarkCount,
               u.LastComputedAt AS LastComputedAt,
               s.hosted_bytes AS SnapshotHostedBytes,
               s.oci_uploaded_bytes AS SnapshotOciUploadedBytes,
               s.cache_attributed_bytes AS SnapshotCacheAttributedBytes,
               s.billable_bytes AS SnapshotBillableBytes,
               s.hosted_version_count AS SnapshotHostedVersionCount,
               s.oci_manifest_count AS SnapshotOciManifestCount,
               s.oci_blob_count AS SnapshotOciBlobCount,
               s.cache_entry_count AS SnapshotCacheEntryCount,
               s.db_row_count AS SnapshotDbRowCount,
               s.captured_at AS SnapshotCapturedAt,
               s.day_utc AS SnapshotDayUtc
        FROM orgs o
        LEFT JOIN (
            SELECT org_id,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN quantity ELSE 0 END) AS EgressBytes,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN redirect_quantity ELSE 0 END) AS EgressRedirectBytes,
                   SUM(CASE WHEN meter = 'egress_metadata_bytes' THEN quantity ELSE 0 END) AS EgressMetadataBytes,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN request_count ELSE 0 END) AS RequestCount,
                   SUM(CASE WHEN meter = 'egress_metadata_bytes' THEN request_count ELSE 0 END) AS MetadataRequestCount,
                   SUM(CASE WHEN meter = 'storage_bytes' THEN quantity ELSE 0 END) AS StorageMarkSum,
                   SUM(CASE WHEN meter = 'storage_bytes' THEN 1 ELSE 0 END) AS StorageMarkCount,
                   SUM(CASE WHEN meter = 'cache_storage_bytes' THEN quantity ELSE 0 END) AS CacheMarkSum,
                   SUM(CASE WHEN meter = 'cache_storage_bytes' THEN 1 ELSE 0 END) AS CacheMarkCount,
                   MAX(computed_at) AS LastComputedAt
            FROM usage_daily
            WHERE bucket >= @fromDay AND bucket < @toDayExclusive
            GROUP BY org_id
        ) u ON u.org_id = o.id
        LEFT JOIN (
            SELECT ss.org_id, ss.hosted_bytes, ss.oci_uploaded_bytes, ss.cache_attributed_bytes,
                   ss.billable_bytes, ss.hosted_version_count, ss.oci_manifest_count, ss.oci_blob_count,
                   ss.cache_entry_count, ss.db_row_count, ss.captured_at, ss.day_utc
            FROM storage_snapshot ss
            INNER JOIN (SELECT org_id, MAX(day_utc) AS max_day FROM storage_snapshot GROUP BY org_id) latest
                ON latest.org_id = ss.org_id AND latest.max_day = ss.day_utc
        ) s ON s.org_id = o.id
        UNION ALL
        SELECT ids.org_id AS OrgId, NULL AS Slug, NULL AS Status, NULL AS DeletedAt,
               COALESCE(u.EgressBytes, 0), COALESCE(u.EgressRedirectBytes, 0), COALESCE(u.EgressMetadataBytes, 0),
               COALESCE(u.RequestCount, 0), COALESCE(u.MetadataRequestCount, 0),
               COALESCE(u.StorageMarkSum, 0), COALESCE(u.StorageMarkCount, 0),
               COALESCE(u.CacheMarkSum, 0), COALESCE(u.CacheMarkCount, 0), u.LastComputedAt,
               s.hosted_bytes, s.oci_uploaded_bytes, s.cache_attributed_bytes, s.billable_bytes,
               s.hosted_version_count, s.oci_manifest_count, s.oci_blob_count, s.cache_entry_count, s.db_row_count,
               s.captured_at, s.day_utc
        FROM (
            SELECT org_id FROM usage_daily WHERE bucket >= @fromDay AND bucket < @toDayExclusive
            UNION
            SELECT org_id FROM storage_snapshot
        ) ids
        LEFT JOIN (
            SELECT org_id,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN quantity ELSE 0 END) AS EgressBytes,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN redirect_quantity ELSE 0 END) AS EgressRedirectBytes,
                   SUM(CASE WHEN meter = 'egress_metadata_bytes' THEN quantity ELSE 0 END) AS EgressMetadataBytes,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN request_count ELSE 0 END) AS RequestCount,
                   SUM(CASE WHEN meter = 'egress_metadata_bytes' THEN request_count ELSE 0 END) AS MetadataRequestCount,
                   SUM(CASE WHEN meter = 'storage_bytes' THEN quantity ELSE 0 END) AS StorageMarkSum,
                   SUM(CASE WHEN meter = 'storage_bytes' THEN 1 ELSE 0 END) AS StorageMarkCount,
                   SUM(CASE WHEN meter = 'cache_storage_bytes' THEN quantity ELSE 0 END) AS CacheMarkSum,
                   SUM(CASE WHEN meter = 'cache_storage_bytes' THEN 1 ELSE 0 END) AS CacheMarkCount,
                   MAX(computed_at) AS LastComputedAt
            FROM usage_daily
            WHERE bucket >= @fromDay AND bucket < @toDayExclusive
            GROUP BY org_id
        ) u ON u.org_id = ids.org_id
        LEFT JOIN (
            SELECT ss.org_id, ss.hosted_bytes, ss.oci_uploaded_bytes, ss.cache_attributed_bytes,
                   ss.billable_bytes, ss.hosted_version_count, ss.oci_manifest_count, ss.oci_blob_count,
                   ss.cache_entry_count, ss.db_row_count, ss.captured_at, ss.day_utc
            FROM storage_snapshot ss
            INNER JOIN (SELECT org_id, MAX(day_utc) AS max_day FROM storage_snapshot GROUP BY org_id) latest
                ON latest.org_id = ss.org_id AND latest.max_day = ss.day_utc
        ) s ON s.org_id = ids.org_id
        WHERE NOT EXISTS (SELECT 1 FROM orgs o2 WHERE o2.id = ids.org_id)
        """;

    // Server-side sort whitelist — the only values ORDER BY may ever be built from. x.* refers to
    // the outer SELECT * FROM (FleetRowsBody) x wrapper in ListFleetUsageAsync.
    private static readonly Dictionary<string, (string Expr, string DefaultDir)> FleetSortColumns =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["slug"] = ("x.Slug", "ASC"),
            ["egressBytes"] = ("x.EgressBytes", "DESC"),
            ["egressMetadataBytes"] = ("x.EgressMetadataBytes", "DESC"),
            ["redirectBytes"] = ("x.EgressRedirectBytes", "DESC"),
            ["billableStorageBytes"] =
                ("(CASE WHEN x.StorageMarkCount = 0 THEN 0.0 ELSE x.StorageMarkSum * 1.0 / x.StorageMarkCount END)", "DESC"),
            ["cacheStorageBytes"] =
                ("(CASE WHEN x.CacheMarkCount = 0 THEN 0.0 ELSE x.CacheMarkSum * 1.0 / x.CacheMarkCount END)", "DESC"),
            ["requestCount"] = ("x.RequestCount", "DESC"),
            ["metadataRequestCount"] = ("x.MetadataRequestCount", "DESC"),
            // StorageSnapshotRow.CountArtifacts, in SQL.
            ["artifactCount"] =
                ("(COALESCE(x.SnapshotHostedVersionCount, 0) + COALESCE(x.SnapshotOciManifestCount, 0))", "DESC"),
            ["dbRowCount"] = ("COALESCE(x.SnapshotDbRowCount, 0)", "DESC"),
        };

    private const string DefaultFleetSort = "egressBytes";

    private readonly IMetadataStore _db;

    public UsageReportRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// One row per tenant for [<paramref name="fromDay"/>, <paramref name="toDayExclusive"/>),
    /// sorted through the <see cref="FleetSortColumns"/> allowlist and paginated server-side. An
    /// unrecognised <paramref name="sort"/> falls back to <see cref="DefaultFleetSort"/> rather
    /// than erroring, so a stale bookmark still renders.
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated ORDER BY fragment is composed exclusively from compile-time-constant SQL " +
                        "expressions in FleetSortColumns plus the literal strings \"ASC\"/\"DESC\". Caller-supplied " +
                        "sort/dir values only select which constant to use (TryGetValue + case-insensitive equality " +
                        "against literals); they never reach the SQL string.")]
    public async Task<(IReadOnlyList<FleetUsageRow> Items, int Total)> ListFleetUsageAsync(
        DateOnly fromDay, DateOnly toDayExclusive, string? sort, string? dir, int limit, int offset,
        CancellationToken ct = default)
    {
        string fromBucket = UsageRollupRepository.DayLabel(fromDay);
        string toBucket = UsageRollupRepository.DayLabel(toDayExclusive);
        var args = new { fromDay = fromBucket, toDayExclusive = toBucket, limit, offset };

        // xtenant: the system-admin fleet listing spans every tenant.
        await using var conn = await _db.OpenCrossTenantAsync("fleet usage listing", ct);
        // rawsql: FleetRowsBody is a compile-time-constant SQL fragment; no runtime value interpolated.
        int total = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM (" + FleetRowsBody + ") x", args);

        string orderBy = BuildFleetOrderBy(sort, dir);
        // rawsql: orderBy is built above from the closed FleetSortColumns allowlist plus a
        // two-value direction check — never from caller text (see the S2077 justification above).
        var rows = await conn.QueryAsync<FleetUsageRow>(
            "SELECT * FROM (" + FleetRowsBody + $") x ORDER BY {orderBy} LIMIT @limit OFFSET @offset",
            args);
        return (rows.ToList(), total);
    }

    /// <summary>
    /// Fleet-wide totals for the same range <see cref="ListFleetUsageAsync"/> lists — independent
    /// of pagination, so the totals row always reflects every tenant, not just the current page.
    /// The billable-storage figure is the sum of each tenant's own monthly average of daily
    /// <c>storage_bytes</c> marks in the range (the same figure <see cref="FleetUsageRow"/> reports
    /// per tenant), summed across the fleet.
    /// </summary>
    public async Task<FleetUsageTotals> GetFleetTotalsAsync(
        DateOnly fromDay, DateOnly toDayExclusive, CancellationToken ct = default)
    {
        string fromBucket = UsageRollupRepository.DayLabel(fromDay);
        string toBucket = UsageRollupRepository.DayLabel(toDayExclusive);
        var args = new { fromDay = fromBucket, toDayExclusive = toBucket };

        // xtenant: fleet-wide totals span every tenant.
        await using var conn = await _db.OpenCrossTenantAsync("fleet usage totals", ct);
        // xtenant: fleet-wide egress/metadata totals for the requested range, across every tenant.
        var egress = await conn.QuerySingleAsync<FleetEgressTotalsRow>(
            """
            SELECT SUM(CASE WHEN meter = 'egress_bytes' THEN quantity ELSE 0 END) AS EgressBytes,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN redirect_quantity ELSE 0 END) AS EgressRedirectBytes,
                   SUM(CASE WHEN meter = 'egress_metadata_bytes' THEN quantity ELSE 0 END) AS EgressMetadataBytes,
                   SUM(CASE WHEN meter = 'egress_bytes' THEN request_count ELSE 0 END) AS RequestCount,
                   SUM(CASE WHEN meter = 'egress_metadata_bytes' THEN request_count ELSE 0 END) AS MetadataRequestCount
            FROM usage_daily
            WHERE bucket >= @fromDay AND bucket < @toDayExclusive
            """,
            args);

        // xtenant: fleet-wide billable-storage total — sum of each tenant's own monthly average of
        // daily storage_bytes marks in the range, across every tenant.
        double storageAvgTotal = await conn.ExecuteScalarAsync<double?>(
            """
            SELECT COALESCE(SUM(avg_bytes), 0)
            FROM (
                SELECT org_id, SUM(quantity) * 1.0 / COUNT(*) AS avg_bytes
                FROM usage_daily
                WHERE meter = 'storage_bytes' AND bucket >= @fromDay AND bucket < @toDayExclusive
                GROUP BY org_id
            ) t
            """,
            args) ?? 0;

        // xtenant: fleet-wide billable proxy-cache-storage total — sum of each tenant's own
        // monthly average of daily cache_storage_bytes marks in the range, across every tenant.
        double cacheAvgTotal = await conn.ExecuteScalarAsync<double?>(
            """
            SELECT COALESCE(SUM(avg_bytes), 0)
            FROM (
                SELECT org_id, SUM(quantity) * 1.0 / COUNT(*) AS avg_bytes
                FROM usage_daily
                WHERE meter = 'cache_storage_bytes' AND bucket >= @fromDay AND bucket < @toDayExclusive
                GROUP BY org_id
            ) t
            """,
            args) ?? 0;

        return new FleetUsageTotals
        {
            EgressBytes = egress.EgressBytes ?? 0,
            EgressRedirectBytes = egress.EgressRedirectBytes ?? 0,
            EgressMetadataBytes = egress.EgressMetadataBytes ?? 0,
            RequestCount = egress.RequestCount ?? 0,
            MetadataRequestCount = egress.MetadataRequestCount ?? 0,
            BillableStorageBytes = (long)Math.Round(storageAvgTotal, MidpointRounding.AwayFromZero),
            CacheStorageBytes = (long)Math.Round(cacheAvgTotal, MidpointRounding.AwayFromZero),
        };
    }

    /// <summary>
    /// Per-ecosystem egress breakdown for [<paramref name="fromDay"/>, <paramref name="toDayExclusive"/>),
    /// across every tenant. Reads <c>usage_events</c> (the only table carrying the ecosystem, as
    /// <c>source</c>) rather than the daily/hourly rollups, bounded to the range so it stays a
    /// bounded scan of the <c>occurred_at</c>-indexed table rather than a full-table one.
    /// </summary>
    public async Task<IReadOnlyList<EcosystemUsageRow>> GetEcosystemBreakdownAsync(
        DateOnly fromDay, DateOnly toDayExclusive, CancellationToken ct = default)
    {
        string fromIso = UsageRollupRepository.DayLabel(fromDay) + "T00:00:00Z";
        string toIso = UsageRollupRepository.DayLabel(toDayExclusive) + "T00:00:00Z";

        // xtenant: the fleet-wide ecosystem breakdown spans every tenant.
        await using var conn = await _db.OpenCrossTenantAsync("fleet ecosystem breakdown", ct);
        // xtenant: fleet-wide per-ecosystem egress breakdown for the requested range, across every
        // tenant — bounded to [fromIso, toIso) over the occurred_at-indexed usage_events table.
        var rows = await conn.QueryAsync<EcosystemUsageRow>(
            """
            SELECT source AS Ecosystem,
                   meter  AS Meter,
                   SUM(quantity) AS Bytes,
                   SUM(CASE WHEN delivery = 'redirect' THEN quantity ELSE 0 END) AS RedirectBytes
            FROM usage_events
            WHERE occurred_at >= @fromIso AND occurred_at < @toIso
            GROUP BY source, meter
            ORDER BY source, meter
            """,
            new { fromIso, toIso });
        return rows.ToList();
    }

    private static string BuildFleetOrderBy(string? sort, string? dir)
    {
        if (!FleetSortColumns.TryGetValue(sort ?? "", out var col))
        {
            col = FleetSortColumns[DefaultFleetSort];
        }

        return $"{col.Expr} {NormalizeSortDirection(dir, col.DefaultDir)}, x.OrgId ASC";
    }

    private static string NormalizeSortDirection(string? dir, string fallback) =>
        string.Equals(dir, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC"
        : string.Equals(dir, "desc", StringComparison.OrdinalIgnoreCase) ? "DESC"
        : fallback;

    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class FleetEgressTotalsRow
    {
        public long? EgressBytes { get; init; }
        public long? EgressRedirectBytes { get; init; }
        public long? EgressMetadataBytes { get; init; }
        public long? RequestCount { get; init; }
        public long? MetadataRequestCount { get; init; }
    }
}

/// <summary>One tenant's row in the fleet usage listing.</summary>
public sealed class FleetUsageRow
{
    public string OrgId { get; init; } = "";
    public string? Slug { get; init; }
    public string? Status { get; init; }
    public DateTimeOffset? DeletedAt { get; init; }
    public long EgressBytes { get; init; }
    public long EgressRedirectBytes { get; init; }
    public long EgressMetadataBytes { get; init; }

    /// <summary>Metered artefact requests in range: an operator signal, not a billed meter.</summary>
    public long RequestCount { get; init; }

    /// <summary>Metered metadata requests in range: an operator signal, not a billed meter.</summary>
    public long MetadataRequestCount { get; init; }

    public long StorageMarkSum { get; init; }
    public int StorageMarkCount { get; init; }
    public long CacheMarkSum { get; init; }
    public int CacheMarkCount { get; init; }
    public string? LastComputedAt { get; init; }
    public long? SnapshotHostedBytes { get; init; }
    public long? SnapshotOciUploadedBytes { get; init; }
    public long? SnapshotCacheAttributedBytes { get; init; }
    public long? SnapshotBillableBytes { get; init; }
    public long? SnapshotHostedVersionCount { get; init; }
    public long? SnapshotOciManifestCount { get; init; }
    public long? SnapshotOciBlobCount { get; init; }
    public long? SnapshotCacheEntryCount { get; init; }
    public long? SnapshotDbRowCount { get; init; }
    public string? SnapshotCapturedAt { get; init; }
    public string? SnapshotDayUtc { get; init; }

    /// <summary>
    /// The latest snapshot's artefact count (<see cref="StorageSnapshotRow.ArtifactCount"/>), or
    /// null when the org has no snapshot.
    /// </summary>
    public long? SnapshotArtifactCount =>
        SnapshotCapturedAt is null
            ? null
            : StorageSnapshotRow.CountArtifacts(SnapshotHostedVersionCount ?? 0, SnapshotOciManifestCount ?? 0);

    /// <summary>The average of the day's <c>storage_bytes</c> marks over days in range that have
    /// one — 0 when the org captured none in the range.</summary>
    public long BillableStorageBytes =>
        StorageMarkCount == 0 ? 0 : (long)Math.Round(StorageMarkSum / (double)StorageMarkCount, MidpointRounding.AwayFromZero);

    /// <summary>The average of the day's <c>cache_storage_bytes</c> marks over days in range that
    /// have one — 0 when the org captured none in the range.</summary>
    public long CacheStorageBytes =>
        CacheMarkCount == 0 ? 0 : (long)Math.Round(CacheMarkSum / (double)CacheMarkCount, MidpointRounding.AwayFromZero);
}

/// <summary>Fleet-wide totals over the same range a <see cref="FleetUsageRow"/> listing covers.</summary>
public sealed class FleetUsageTotals
{
    public long EgressBytes { get; init; }
    public long EgressRedirectBytes { get; init; }
    public long EgressMetadataBytes { get; init; }
    public long RequestCount { get; init; }
    public long MetadataRequestCount { get; init; }
    public long BillableStorageBytes { get; init; }
    public long CacheStorageBytes { get; init; }
}

/// <summary>One (ecosystem, meter) bucket of the fleet-wide egress breakdown.</summary>
public sealed class EcosystemUsageRow
{
    public string Ecosystem { get; init; } = "";
    public string Meter { get; init; } = "";
    public long Bytes { get; init; }
    public long RedirectBytes { get; init; }
}
