using Dapper;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Derives <c>usage_hourly</c> from <c>usage_events</c> and <c>usage_daily</c>'s egress meters
/// from <c>usage_hourly</c>, and reads the daily totals back.
///
/// Every derivation is a recompute, not an increment: it aggregates the source rows in a window
/// and overwrites the target buckets with the result. Running one twice, or re-running it after a
/// crash part-way through, therefore leaves the same rows as running it once, and any bucket can
/// be regenerated from the raw events for as long as they are retained.
///
/// Bucket labels are cut from the stored ISO-8601 text with <c>substr</c>, which both providers
/// implement identically, so no statement here branches on the database dialect. Range bounds
/// over <c>occurred_at</c> are written at millisecond precision, the precision events are stored
/// at: a second-precision bound sorts after every millisecond value in its own second, because
/// '.' collates before 'Z'.
/// </summary>
public sealed class UsageRollupRepository
{
    private readonly IMetadataStore _db;

    public UsageRollupRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Recomputes every hourly bucket that overlaps [<paramref name="from"/>, <paramref name="to"/>),
    /// widened outward to whole hours, across every org. Each bucket carries the summed quantity,
    /// its redirect-delivered share, and the number of events it holds. Returns the number of
    /// buckets written.
    /// </summary>
    public async Task<int> RecomputeHourlyAsync(
        DateTimeOffset from, DateTimeOffset to, DateTimeOffset computedAt, CancellationToken ct = default)
    {
        string fromIso = FloorToHour(from).ToUtcIsoMillis();
        string toIso = CeilToHour(to).ToUtcIsoMillis();
        string computedAtIso = computedAt.ToUtcIso();

        // xtenant: the rollup recomputes every org's buckets in one pass.
        await using var conn = await _db.OpenCrossTenantAsync("hourly usage rollup", ct);
        // xtenant: the rollup recomputes every org's buckets in one pass; org_id is carried
        // through the GROUP BY into the INSERT column list, so no row crosses a tenant.
        return await conn.ExecuteAsync(
            """
            INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            SELECT org_id,
                   meter,
                   substr(occurred_at, 1, 13) || ':00:00Z',
                   CAST(SUM(quantity) AS BIGINT),
                   CAST(SUM(CASE WHEN delivery = 'redirect' THEN quantity ELSE 0 END) AS BIGINT),
                   CAST(COUNT(*) AS BIGINT),
                   @computedAtIso
            FROM usage_events
            WHERE occurred_at >= @fromIso AND occurred_at < @toIso
            GROUP BY org_id, meter, substr(occurred_at, 1, 13)
            ON CONFLICT (org_id, meter, bucket) DO UPDATE SET
                quantity = excluded.quantity,
                redirect_quantity = excluded.redirect_quantity,
                request_count = excluded.request_count,
                computed_at = excluded.computed_at
            """,
            new { fromIso, toIso, computedAtIso });
    }

    /// <summary>
    /// Recomputes the egress meters of every daily bucket in [<paramref name="fromDay"/>,
    /// <paramref name="toDayExclusive"/>) from <c>usage_hourly</c>, across every org. Days are
    /// UTC calendar dates. Returns the number of buckets written.
    /// </summary>
    public async Task<int> RecomputeDailyEgressAsync(
        DateOnly fromDay, DateOnly toDayExclusive, DateTimeOffset computedAt, CancellationToken ct = default)
    {
        string fromBucket = DayLabel(fromDay) + "T00:00:00Z";
        string toBucket = DayLabel(toDayExclusive) + "T00:00:00Z";
        string computedAtIso = computedAt.ToUtcIso();

        // xtenant: the rollup recomputes every org's buckets in one pass.
        await using var conn = await _db.OpenCrossTenantAsync("daily usage rollup", ct);
        // xtenant: the rollup recomputes every org's buckets in one pass; org_id is carried
        // through the GROUP BY into the INSERT column list, so no row crosses a tenant.
        return await conn.ExecuteAsync(
            """
            INSERT INTO usage_daily (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            SELECT org_id,
                   meter,
                   substr(bucket, 1, 10),
                   CAST(SUM(quantity) AS BIGINT),
                   CAST(SUM(redirect_quantity) AS BIGINT),
                   CAST(SUM(request_count) AS BIGINT),
                   @computedAtIso
            FROM usage_hourly
            WHERE bucket >= @fromBucket AND bucket < @toBucket
            GROUP BY org_id, meter, substr(bucket, 1, 10)
            ON CONFLICT (org_id, meter, bucket) DO UPDATE SET
                quantity = excluded.quantity,
                redirect_quantity = excluded.redirect_quantity,
                request_count = excluded.request_count,
                computed_at = excluded.computed_at
            """,
            new { fromBucket, toBucket, computedAtIso });
    }

    /// <summary>
    /// One org's daily rows for [<paramref name="fromDay"/>, <paramref name="toDayExclusive"/>),
    /// every meter, oldest first.
    /// </summary>
    public async Task<IReadOnlyList<UsageDailyRow>> GetDailyAsync(
        string orgId, DateOnly fromDay, DateOnly toDayExclusive, CancellationToken ct = default)
    {
        string fromBucket = DayLabel(fromDay);
        string toBucket = DayLabel(toDayExclusive);

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<UsageDailyRow>(
            """
            SELECT org_id            AS OrgId,
                   meter             AS Meter,
                   bucket            AS Bucket,
                   quantity          AS Quantity,
                   redirect_quantity AS RedirectQuantity,
                   request_count     AS RequestCount,
                   computed_at       AS ComputedAt
            FROM usage_daily
            WHERE org_id = @orgId AND bucket >= @fromBucket AND bucket < @toBucket
            ORDER BY bucket, meter
            """,
            new { orgId, fromBucket, toBucket });
        return rows.ToList();
    }

    /// <summary>
    /// One org's hourly rows for [<paramref name="fromDay"/>, <paramref name="toDayExclusive"/>),
    /// egress meters only (<c>usage_hourly</c> carries no <c>storage_bytes</c> meter), oldest first.
    /// Callers are responsible for keeping the span short — hourly buckets are pruned on a fixed
    /// retention horizon (<see cref="PruneHourlyOlderThanAsync"/>) so an old enough range reads back
    /// empty rather than erroring.
    /// </summary>
    public async Task<IReadOnlyList<UsageHourlyRow>> GetHourlyAsync(
        string orgId, DateOnly fromDay, DateOnly toDayExclusive, CancellationToken ct = default)
    {
        string fromBucket = DayLabel(fromDay) + "T00:00:00Z";
        string toBucket = DayLabel(toDayExclusive) + "T00:00:00Z";

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<UsageHourlyRow>(
            """
            SELECT org_id            AS OrgId,
                   meter             AS Meter,
                   bucket            AS Bucket,
                   quantity          AS Quantity,
                   redirect_quantity AS RedirectQuantity,
                   request_count     AS RequestCount,
                   computed_at       AS ComputedAt
            FROM usage_hourly
            WHERE org_id = @orgId AND bucket >= @fromBucket AND bucket < @toBucket
            ORDER BY bucket, meter
            """,
            new { orgId, fromBucket, toBucket });
        return rows.ToList();
    }

    /// <summary>
    /// Deletes every hourly bucket that starts before <paramref name="cutoff"/>, across every org.
    /// </summary>
    public async Task<int> PruneHourlyOlderThanAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        string cutoffBucket = FloorToHour(cutoff).ToUtcIso();
        // xtenant: an instance-wide retention sweep at a fixed horizon.
        await using var conn = await _db.OpenCrossTenantAsync("hourly usage retention", ct);
        // xtenant: instance-wide retention sweep at a fixed horizon that no tenant controls.
        return await conn.ExecuteAsync(
            "DELETE FROM usage_hourly WHERE bucket < @cutoffBucket",
            new { cutoffBucket });
    }

    /// <summary>
    /// Every org's stored <c>usage_daily</c> egress-meter rows in [<paramref name="fromDay"/>,
    /// <paramref name="toDayExclusive"/>) — the weekly reconciliation's "what we billed" side.
    /// <c>storage_bytes</c> and <c>cache_storage_bytes</c> are excluded: both are snapshot
    /// high-water marks, not an events sum, so neither has an events-derived counterpart to
    /// reconcile against.
    /// </summary>
    public async Task<IReadOnlyList<UsageDailyRow>> ListDailyEgressAsync(
        DateOnly fromDay, DateOnly toDayExclusive, CancellationToken ct = default)
    {
        string fromBucket = DayLabel(fromDay);
        string toBucket = DayLabel(toDayExclusive);

        // xtenant: reconciliation reads every org's stored daily egress.
        await using var conn = await _db.OpenCrossTenantAsync("usage reconciliation read", ct);
        // xtenant: the weekly reconciliation compares every org's stored rows against a fresh
        // recompute from usage_events in one pass; org_id flows through unfiltered because the
        // comparison itself is what scopes each row — it is judged only against its own org's
        // events, never against another org's.
        var rows = await conn.QueryAsync<UsageDailyRow>(
            """
            SELECT org_id AS OrgId, meter AS Meter, bucket AS Bucket,
                   quantity AS Quantity, redirect_quantity AS RedirectQuantity,
                   request_count AS RequestCount, computed_at AS ComputedAt
            FROM usage_daily
            WHERE bucket >= @fromBucket AND bucket < @toBucket
              AND meter IN ('egress_bytes', 'egress_metadata_bytes')
            ORDER BY org_id, meter, bucket
            """,
            new { fromBucket, toBucket });
        return rows.ToList();
    }

    /// <summary>
    /// Every org's daily egress totals and event counts recomputed directly from <c>usage_events</c> — bypassing
    /// <c>usage_hourly</c> entirely — for [<paramref name="fromDay"/>, <paramref name="toDayExclusive"/>).
    /// The weekly reconciliation's "what actually happened" side: comparing against a recompute
    /// that shares no code path with the hourly rollup catches a corruption in
    /// <c>usage_hourly</c> itself, not just a stale <c>usage_daily</c>.
    /// </summary>
    public async Task<IReadOnlyList<UsageDailyRow>> ComputeDailyEgressFromEventsAsync(
        DateOnly fromDay, DateOnly toDayExclusive, CancellationToken ct = default)
    {
        string fromIso = UtcMidnight(fromDay).ToUtcIsoMillis();
        string toIso = UtcMidnight(toDayExclusive).ToUtcIsoMillis();

        // xtenant: reconciliation recomputes every org's daily egress from the events.
        await using var conn = await _db.OpenCrossTenantAsync("usage reconciliation recompute", ct);
        // xtenant: recomputes every org's daily egress directly from usage_events in one pass;
        // org_id flows unfiltered through the GROUP BY into the projection, so no row crosses a
        // tenant — same posture as RecomputeHourlyAsync/RecomputeDailyEgressAsync above.
        var rows = await conn.QueryAsync<UsageDailyRow>(
            """
            SELECT org_id AS OrgId,
                   meter AS Meter,
                   substr(occurred_at, 1, 10) AS Bucket,
                   CAST(SUM(quantity) AS BIGINT) AS Quantity,
                   CAST(SUM(CASE WHEN delivery = 'redirect' THEN quantity ELSE 0 END) AS BIGINT) AS RedirectQuantity,
                   CAST(COUNT(*) AS BIGINT) AS RequestCount,
                   '' AS ComputedAt
            FROM usage_events
            WHERE occurred_at >= @fromIso AND occurred_at < @toIso
            GROUP BY org_id, meter, substr(occurred_at, 1, 10)
            """,
            new { fromIso, toIso });
        return rows.ToList();
    }

    internal static string DayLabel(DateOnly day) => day.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>UTC midnight for <paramref name="day"/>, as the instant every day-bucket boundary is measured from.</summary>
    internal static DateTimeOffset UtcMidnight(DateOnly day) =>
        new(day.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);

    private static DateTimeOffset FloorToHour(DateTimeOffset instant)
    {
        var utc = instant.ToUniversalTime();
        return new DateTimeOffset(utc.Year, utc.Month, utc.Day, utc.Hour, 0, 0, TimeSpan.Zero);
    }

    private static DateTimeOffset CeilToHour(DateTimeOffset instant)
    {
        var floor = FloorToHour(instant);
        return floor == instant.ToUniversalTime() ? floor : floor.AddHours(1);
    }
}
