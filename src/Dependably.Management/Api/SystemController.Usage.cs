using System.Globalization;
using Dependably.Infrastructure.Usage;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only fleet usage reporting (multi-tenant deployments). Operator view of the whole
/// fleet's metering data — the same plane and authorization as the rest of
/// <see cref="SystemController"/>: every route requires <c>scope=system</c> + apex context,
/// enforced globally by <see cref="Dependably.Security.RouteScopeFilter"/>. system_admin sees
/// every tenant's usage here; a tenant admin never reaches these routes (a tenant-scoped JWT
/// carries <c>scope=tenant</c>, which the filter refuses on any <c>/api/v1/system/</c> path with
/// a 404, and an unauthenticated or tenant-host request is refused the same way as every other
/// system route).
///
/// Every figure returned is a raw byte count or a raw count read straight from <c>usage_daily</c>/
/// <c>usage_hourly</c>/<c>usage_events</c>/<c>storage_snapshot</c> — no unit conversion, no rate,
/// no plan. Human-readable formatting belongs to the operator SPA, not this API. The request
/// counts, artefact counts, OCI blob and cache-entry counts and database row count are operator
/// capacity and abuse signals, not billed meters.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>Maximum span of a fleet or per-tenant day-granularity usage query.</summary>
    private const int MaxUsageRangeDays = 400;

    /// <summary>Maximum span of a per-tenant hour-granularity usage query.</summary>
    private const int MaxUsageHourRangeDays = 14;

    /// <summary>Maximum page size for the fleet usage listing.</summary>
    private const int MaxUsagePageSize = 200;

    /// <summary>Row cap for the CSV export — bounds memory the same way the audit export does.</summary>
    private const int UsageCsvExportRowCap = 50_000;

    /// <summary>
    /// GET /api/v1/system/usage — one row per tenant over a date range: artifact egress bytes
    /// (with the redirect-delivered subset broken out), metadata egress bytes, metered request
    /// counts, average billable storage over the range, the tenant's latest captured storage
    /// snapshot (bytes, artefact and entry counts, database row count), plus fleet totals
    /// and a fleet-wide per-ecosystem breakdown. Defaults to the current UTC month to date.
    /// Sortable/paginated server-side; <c>sort</c> is resolved through a closed column allowlist
    /// in <see cref="UsageReportRepository"/>, so an unrecognised value falls back to the default
    /// rather than erroring.
    /// </summary>
    [HttpGet("usage")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each parameter is an independently bound query value or [FromServices] repository; a bundling model would " +
            "change the documented OpenAPI parameter list for no gain in cohesion.")]
    public async Task<IActionResult> GetFleetUsage(
        [FromServices] UsageReportRepository reports,
        [FromQuery] string? from,
        [FromQuery] string? to,
        [FromQuery] string? sort,
        [FromQuery] string? dir,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var range = ResolveUsageRange(from, to, MaxUsageRangeDays, out var rangeError);
        if (rangeError is not null)
        {
            return rangeError;
        }

        pageSize = Math.Clamp(pageSize, 1, MaxUsagePageSize);
        int offset = PaginationHelper.ComputeOffset(page, pageSize);

        var (fromDay, toDayExclusive) = range!.Value;
        var (items, total) = await reports.ListFleetUsageAsync(fromDay, toDayExclusive, sort, dir, pageSize, offset, ct);
        var totals = await reports.GetFleetTotalsAsync(fromDay, toDayExclusive, ct);
        var ecosystems = await reports.GetEcosystemBreakdownAsync(fromDay, toDayExclusive, ct);

        return Ok(new
        {
            items = items.Select(ProjectFleetUsageRow),
            total,
            page,
            pageSize,
            from = UsageRollupRepository.DayLabel(fromDay),
            to = UsageRollupRepository.DayLabel(toDayExclusive.AddDays(-1)),
            totals = ProjectFleetTotals(totals),
            ecosystems = ecosystems.Select(e => new
            {
                ecosystem = e.Ecosystem,
                meter = e.Meter,
                bytes = e.Bytes,
                redirectBytes = e.RedirectBytes,
            }),
        });
    }

    /// <summary>
    /// GET /api/v1/system/usage.csv — every row <see cref="GetFleetUsage"/> would page through
    /// (up to <see cref="UsageCsvExportRowCap"/>), as a CSV attachment. Same range/sort query
    /// parameters as the JSON listing; stable column names so a saved import mapping survives
    /// across exports, with columns added only at the end.
    /// </summary>
    [HttpGet("usage.csv")]
    public async Task<IActionResult> GetFleetUsageCsv(
        [FromServices] UsageReportRepository reports,
        [FromQuery] string? from,
        [FromQuery] string? to,
        [FromQuery] string? sort,
        [FromQuery] string? dir,
        CancellationToken ct = default)
    {
        var range = ResolveUsageRange(from, to, MaxUsageRangeDays, out var rangeError);
        if (rangeError is not null)
        {
            return rangeError;
        }

        var (fromDay, toDayExclusive) = range!.Value;
        var (items, _) = await reports.ListFleetUsageAsync(
            fromDay, toDayExclusive, sort, dir, UsageCsvExportRowCap, 0, ct);

        var sb = new System.Text.StringBuilder();
        CsvWriter.WriteRow(sb,
            "org_id", "slug", "status", "egress_bytes", "egress_redirect_bytes", "egress_metadata_bytes",
            "billable_storage_bytes", "storage_mark_days", "snapshot_billable_bytes", "snapshot_hosted_bytes",
            "snapshot_oci_uploaded_bytes", "snapshot_cache_attributed_bytes", "snapshot_captured_at", "last_computed_at",
            "request_count", "metadata_request_count", "snapshot_artifact_count", "snapshot_hosted_version_count",
            "snapshot_oci_manifest_count", "snapshot_oci_blob_count", "snapshot_cache_entry_count",
            "snapshot_db_row_count");
        foreach (var row in items)
        {
            CsvWriter.WriteRow(sb,
                row.OrgId, row.Slug, row.Status,
                row.EgressBytes.ToString(CultureInfo.InvariantCulture),
                row.EgressRedirectBytes.ToString(CultureInfo.InvariantCulture),
                row.EgressMetadataBytes.ToString(CultureInfo.InvariantCulture),
                row.BillableStorageBytes.ToString(CultureInfo.InvariantCulture),
                row.StorageMarkCount.ToString(CultureInfo.InvariantCulture),
                row.SnapshotBillableBytes?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotHostedBytes?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotOciUploadedBytes?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotCacheAttributedBytes?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotCapturedAt, row.LastComputedAt,
                row.RequestCount.ToString(CultureInfo.InvariantCulture),
                row.MetadataRequestCount.ToString(CultureInfo.InvariantCulture),
                row.SnapshotArtifactCount?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotHostedVersionCount?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotOciManifestCount?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotOciBlobCount?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotCacheEntryCount?.ToString(CultureInfo.InvariantCulture),
                row.SnapshotDbRowCount?.ToString(CultureInfo.InvariantCulture));
        }

        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
        string filename = $"usage-{_time.GetUtcNow():yyyyMMddTHHmmssZ}.csv";
        return File(bytes, "text/csv", filename);
    }

    /// <summary>
    /// GET /api/v1/system/tenants/{slug}/usage — one tenant's usage series: daily (default) or
    /// hourly buckets per meter over a date range, its latest storage snapshot, and a
    /// current-UTC-month-to-date summary independent of the requested range. Hour granularity
    /// caps the requested span at <see cref="MaxUsageHourRangeDays"/> days — <c>usage_hourly</c>
    /// is pruned on a fixed retention horizon, so an older range would read back sparse anyway.
    /// 404 when <paramref name="slug"/> does not resolve to a tenant (soft-deleted tenants still
    /// resolve, so an operator can review a suspended-for-deletion tenant's usage history).
    /// </summary>
    [HttpGet("tenants/{slug}/usage")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each parameter is an independently bound query value or [FromServices] repository; a bundling model would " +
            "change the documented OpenAPI parameter list for no gain in cohesion.")]
    public async Task<IActionResult> GetTenantUsage(
        string slug,
        [FromServices] UsageReportRepository reports,
        [FromServices] UsageRollupRepository rollups,
        [FromServices] StorageSnapshotRepository snapshots,
        [FromQuery] string? from,
        [FromQuery] string? to,
        [FromQuery] string? granularity,
        CancellationToken ct = default)
    {
        if (granularity is not (null or "day" or "hour"))
        {
            return _problems.ValidationErrorActionKey("granularity", "error.system.usageGranularityInvalid");
        }

        bool hourly = granularity == "hour";
        var range = ResolveUsageRange(from, to, hourly ? MaxUsageHourRangeDays : MaxUsageRangeDays, out var rangeError);
        if (rangeError is not null)
        {
            return rangeError;
        }

        var org = await _orgs.GetBySlugAsync(slug, includeDeleted: true, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        var (fromDay, toDayExclusive) = range!.Value;

        object series;
        if (hourly)
        {
            var hourlyRows = await rollups.GetHourlyAsync(org.Id, fromDay, toDayExclusive, ct);
            series = ProjectHourlySeries(hourlyRows);
        }
        else
        {
            var dailyRows = await rollups.GetDailyAsync(org.Id, fromDay, toDayExclusive, ct);
            series = ProjectDailySeries(dailyRows);
        }

        var latestSnapshot = await snapshots.GetLatestAsync(org.Id, ct);

        var now = _time.GetUtcNow();
        var monthStart = new DateOnly(now.Year, now.Month, 1);
        var monthEnd = DateOnly.FromDateTime(now.UtcDateTime).AddDays(1);
        var monthRows = await rollups.GetDailyAsync(org.Id, monthStart, monthEnd, ct);
        var mtd = SummarizeDaily(monthRows);

        return Ok(new
        {
            slug = org.Slug,
            status = org.Status,
            deletedAt = org.DeletedAt,
            granularity = hourly ? "hour" : "day",
            from = UsageRollupRepository.DayLabel(fromDay),
            to = UsageRollupRepository.DayLabel(toDayExclusive.AddDays(-1)),
            series,
            latestSnapshot = latestSnapshot is null
                ? null
                : new
                {
                    dayUtc = latestSnapshot.DayUtc,
                    hostedBytes = latestSnapshot.HostedBytes,
                    ociUploadedBytes = latestSnapshot.OciUploadedBytes,
                    cacheAttributedBytes = latestSnapshot.CacheAttributedBytes,
                    billableBytes = latestSnapshot.BillableBytes,
                    artifactCount = latestSnapshot.ArtifactCount,
                    hostedVersionCount = latestSnapshot.HostedVersionCount,
                    ociManifestCount = latestSnapshot.OciManifestCount,
                    ociBlobCount = latestSnapshot.OciBlobCount,
                    cacheEntryCount = latestSnapshot.CacheEntryCount,
                    dbRowCount = latestSnapshot.DbRowCount,
                    capturedAt = latestSnapshot.CapturedAt,
                },
            monthToDate = new
            {
                from = UsageRollupRepository.DayLabel(monthStart),
                to = UsageRollupRepository.DayLabel(monthEnd.AddDays(-1)),
                egressBytes = mtd.EgressBytes,
                egressRedirectBytes = mtd.EgressRedirectBytes,
                egressMetadataBytes = mtd.EgressMetadataBytes,
                billableStorageBytes = mtd.BillableStorageBytes,
                requestCount = mtd.RequestCount,
                metadataRequestCount = mtd.MetadataRequestCount,
            },
        });
    }

    private static object ProjectFleetUsageRow(FleetUsageRow row) => new
    {
        orgId = row.OrgId,
        slug = row.Slug,
        status = row.Status,
        deletedAt = row.DeletedAt,
        egressBytes = row.EgressBytes,
        egressRedirectBytes = row.EgressRedirectBytes,
        egressMetadataBytes = row.EgressMetadataBytes,
        requestCount = row.RequestCount,
        metadataRequestCount = row.MetadataRequestCount,
        billableStorageBytes = row.BillableStorageBytes,
        storageMarkDays = row.StorageMarkCount,
        lastComputedAt = row.LastComputedAt,
        snapshot = row.SnapshotCapturedAt is null
            ? null
            : new
            {
                dayUtc = row.SnapshotDayUtc,
                hostedBytes = row.SnapshotHostedBytes,
                ociUploadedBytes = row.SnapshotOciUploadedBytes,
                cacheAttributedBytes = row.SnapshotCacheAttributedBytes,
                billableBytes = row.SnapshotBillableBytes,
                artifactCount = row.SnapshotArtifactCount,
                hostedVersionCount = row.SnapshotHostedVersionCount,
                ociManifestCount = row.SnapshotOciManifestCount,
                ociBlobCount = row.SnapshotOciBlobCount,
                cacheEntryCount = row.SnapshotCacheEntryCount,
                dbRowCount = row.SnapshotDbRowCount,
                capturedAt = row.SnapshotCapturedAt,
            },
    };

    private static object ProjectFleetTotals(FleetUsageTotals totals) => new
    {
        egressBytes = totals.EgressBytes,
        egressRedirectBytes = totals.EgressRedirectBytes,
        egressMetadataBytes = totals.EgressMetadataBytes,
        requestCount = totals.RequestCount,
        metadataRequestCount = totals.MetadataRequestCount,
        billableStorageBytes = totals.BillableStorageBytes,
    };

    /// <summary>One pivoted bucket's accumulated meters. A record struct (not a plain value
    /// tuple) so the per-meter folds below can use <c>with</c>-expressions.</summary>
    private readonly record struct DailyBucketAccumulator(
        long EgressBytes, long EgressRedirectBytes, long EgressMetadataBytes, long RequestCount,
        long MetadataRequestCount, long? StorageBytes, string? ComputedAt);

    private readonly record struct HourlyBucketAccumulator(
        long EgressBytes, long EgressRedirectBytes, long EgressMetadataBytes, long RequestCount,
        long MetadataRequestCount, string? ComputedAt);

    /// <summary>Pivots flat <c>usage_daily</c> rows (one row per org/meter/bucket) into one
    /// object per bucket with each meter as a field.</summary>
    private static IReadOnlyList<object> ProjectDailySeries(IReadOnlyList<UsageDailyRow> rows)
    {
        var byBucket = new SortedDictionary<string, DailyBucketAccumulator>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            byBucket.TryGetValue(row.Bucket, out var acc);
            acc = row.Meter switch
            {
                UsageMeters.EgressBytes => acc with { EgressBytes = row.Quantity, EgressRedirectBytes = row.RedirectQuantity, RequestCount = row.RequestCount, ComputedAt = row.ComputedAt },
                UsageMeters.EgressMetadataBytes => acc with { EgressMetadataBytes = row.Quantity, MetadataRequestCount = row.RequestCount, ComputedAt = row.ComputedAt },
                UsageMeters.StorageBytes => acc with { StorageBytes = row.Quantity, ComputedAt = row.ComputedAt },
                _ => acc,
            };
            byBucket[row.Bucket] = acc;
        }

        return byBucket.Select(kv => (object)new
        {
            bucket = kv.Key,
            egressBytes = kv.Value.EgressBytes,
            egressRedirectBytes = kv.Value.EgressRedirectBytes,
            egressMetadataBytes = kv.Value.EgressMetadataBytes,
            requestCount = kv.Value.RequestCount,
            metadataRequestCount = kv.Value.MetadataRequestCount,
            storageBytes = kv.Value.StorageBytes,
            computedAt = kv.Value.ComputedAt,
        }).ToList();
    }

    /// <summary>Pivots flat <c>usage_hourly</c> rows into one object per bucket. Egress meters
    /// only — <c>usage_hourly</c> carries no <c>storage_bytes</c> meter.</summary>
    private static IReadOnlyList<object> ProjectHourlySeries(IReadOnlyList<UsageHourlyRow> rows)
    {
        var byBucket = new SortedDictionary<string, HourlyBucketAccumulator>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            byBucket.TryGetValue(row.Bucket, out var acc);
            acc = row.Meter switch
            {
                UsageMeters.EgressBytes => acc with { EgressBytes = row.Quantity, EgressRedirectBytes = row.RedirectQuantity, RequestCount = row.RequestCount, ComputedAt = row.ComputedAt },
                UsageMeters.EgressMetadataBytes => acc with { EgressMetadataBytes = row.Quantity, MetadataRequestCount = row.RequestCount, ComputedAt = row.ComputedAt },
                _ => acc,
            };
            byBucket[row.Bucket] = acc;
        }

        return byBucket.Select(kv => (object)new
        {
            bucket = kv.Key,
            egressBytes = kv.Value.EgressBytes,
            egressRedirectBytes = kv.Value.EgressRedirectBytes,
            egressMetadataBytes = kv.Value.EgressMetadataBytes,
            requestCount = kv.Value.RequestCount,
            metadataRequestCount = kv.Value.MetadataRequestCount,
            computedAt = kv.Value.ComputedAt,
        }).ToList();
    }

    private readonly record struct UsageSummary(
        long EgressBytes, long EgressRedirectBytes, long EgressMetadataBytes, long BillableStorageBytes,
        long RequestCount, long MetadataRequestCount);

    private static UsageSummary SummarizeDaily(IReadOnlyList<UsageDailyRow> rows)
    {
        long egress = 0, egressRedirect = 0, egressMeta = 0, storageSum = 0, requests = 0, metaRequests = 0;
        int storageMarks = 0;
        foreach (var row in rows)
        {
            switch (row.Meter)
            {
                case UsageMeters.EgressBytes:
                    egress += row.Quantity;
                    egressRedirect += row.RedirectQuantity;
                    requests += row.RequestCount;
                    break;
                case UsageMeters.EgressMetadataBytes:
                    egressMeta += row.Quantity;
                    metaRequests += row.RequestCount;
                    break;
                case UsageMeters.StorageBytes:
                    storageSum += row.Quantity;
                    storageMarks++;
                    break;
            }
        }

        long billableStorage = storageMarks == 0
            ? 0
            : (long)Math.Round(storageSum / (double)storageMarks, MidpointRounding.AwayFromZero);
        return new UsageSummary(egress, egressRedirect, egressMeta, billableStorage, requests, metaRequests);
    }

    /// <summary>
    /// Parses/defaults <paramref name="from"/>/<paramref name="to"/> (inclusive, <c>YYYY-MM-DD</c>)
    /// into <c>[fromDay, toDayExclusive)</c>, bounded to <paramref name="maxDays"/>. Missing
    /// values default to the current UTC month to date. Sets <paramref name="error"/> and returns
    /// null on a validation failure; callers return the error action result unchanged.
    /// </summary>
    private (DateOnly From, DateOnly ToExclusive)? ResolveUsageRange(
        string? from, string? to, int maxDays, out IActionResult? error)
    {
        error = null;
        var now = _time.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);

        DateOnly fromDay;
        if (string.IsNullOrWhiteSpace(from))
        {
            fromDay = new DateOnly(today.Year, today.Month, 1);
        }
        else if (!DateOnly.TryParseExact(from, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out fromDay))
        {
            error = _problems.ValidationErrorActionKey("from", "error.system.usageRangeInvalid");
            return null;
        }

        DateOnly toDay;
        if (string.IsNullOrWhiteSpace(to))
        {
            toDay = today;
        }
        else if (!DateOnly.TryParseExact(to, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out toDay))
        {
            error = _problems.ValidationErrorActionKey("to", "error.system.usageRangeInvalid");
            return null;
        }

        if (toDay < fromDay)
        {
            error = _problems.ValidationErrorActionKey("to", "error.system.usageRangeOrder");
            return null;
        }

        var toExclusive = toDay.AddDays(1);
        int spanDays = toExclusive.DayNumber - fromDay.DayNumber;
        if (spanDays > maxDays)
        {
            error = _problems.ValidationErrorActionKey("to", "error.system.usageRangeTooLarge", maxDays);
            return null;
        }

        return (fromDay, toExclusive);
    }
}
