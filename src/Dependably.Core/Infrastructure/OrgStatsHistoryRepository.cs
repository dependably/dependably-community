using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Reads and writes the append-only daily trend history in <c>org_stats_history</c> (one row per
/// org per calendar day). <see cref="StatsRefreshService"/> upserts the current day's row on every
/// pass — last write of the day wins — and folds the most recent rows into the trend series it
/// embeds on the <c>org_stats_snapshot</c> it writes. <c>trend_json</c> holds a serialized
/// <see cref="OrgStatsHistoryPoint"/>, a small subset of <see cref="OrgStats"/> rather than the
/// full payload, so a year of daily rows per org stays bounded.
///
/// Observational only: nothing reads this table for gating, retention, or policy decisions. Its
/// only consumers are the trend series on the <c>/api/v1/stats</c> response and the Dashboard's
/// sparklines/deltas.
/// </summary>
public sealed class OrgStatsHistoryRepository
{
    private readonly IMetadataStore _db;

    public OrgStatsHistoryRepository(IMetadataStore db) => _db = db;

    /// <summary>Upserts today's trend row for an org. Last write of the day wins.</summary>
    public async Task UpsertAsync(
        string orgId, string day, string trendJson, string computedAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_stats_history (org_id, day, trend_json, computed_at)
            VALUES (@orgId, @day, @trendJson, @computedAt)
            ON CONFLICT (org_id, day) DO UPDATE SET
                trend_json = excluded.trend_json,
                computed_at = excluded.computed_at
            """,
            new { orgId, day, trendJson, computedAt });
    }

    /// <summary>
    /// Returns up to <paramref name="days"/> most recent rows for an org, oldest first — the
    /// shape a trend series/sparkline renders in.
    /// </summary>
    public async Task<IReadOnlyList<OrgStatsHistoryRow>> GetRecentAsync(
        string orgId, int days, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = (await conn.QueryAsync<OrgStatsHistoryRow>(
            """
            SELECT day AS Day, trend_json AS TrendJson
            FROM org_stats_history
            WHERE org_id = @orgId
            ORDER BY day DESC
            LIMIT @days
            """,
            new { orgId, days })).ToList();
        rows.Reverse();
        return rows;
    }

    /// <summary>
    /// Deletes every row older than <paramref name="cutoffDay"/> (exclusive lower bound: rows on
    /// or after it survive), across every org. Called from <see cref="RetentionService"/>'s
    /// instance-wide sweep, bounded by <c>STATS_HISTORY_RETENTION_DAYS</c>.
    /// </summary>
    public async Task<int> PruneOlderThanAsync(string cutoffDay, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: instance-wide retention sweep by day cutoff, the same posture as
        // RetentionService.PruneEmailOutboxAsync — every org's aged trend rows are deleted
        // together rather than per-org, and the table carries no gating/policy meaning to leak
        // cross-tenant.
        return await conn.ExecuteAsync(
            "DELETE FROM org_stats_history WHERE day < @cutoffDay",
            new { cutoffDay });
    }
}

public sealed class OrgStatsHistoryRow
{
    public string Day { get; init; } = "";
    public string TrendJson { get; init; } = "";
}

/// <summary>
/// The small subset of <see cref="OrgStats"/> persisted per day in <c>org_stats_history.trend_json</c>.
/// Deliberately narrow rather than the full <see cref="OrgStats"/> payload: these three figures
/// are what the Dashboard trends today (deltas + sparklines), and keeping the stored shape small
/// means a year of daily rows per org stays bounded and immune to <see cref="OrgStats"/>'s own
/// field growth. <see cref="TotalVulnerabilities"/> is the sum of
/// <see cref="OrgStats.VulnsByEcosystemAndSeverity"/>'s counts (distinct known vulnerabilities
/// across every ecosystem/severity bucket) rather than a distinct-vulnerable-version count, which
/// <see cref="OrgStats"/> does not compute anywhere.
/// </summary>
public sealed class OrgStatsHistoryPoint
{
    public int TotalVulnerabilities { get; set; }
    public int BlockedPulls30d { get; set; }
    public int TotalDownloads30d { get; set; }
}

/// <summary>
/// One day's point on the dashboard trend series returned as part of <see cref="OrgStats"/>.
/// <see cref="Day"/> is the row's own key (ISO date, <c>yyyy-MM-dd</c>); the remaining fields
/// mirror <see cref="OrgStatsHistoryPoint"/>.
/// </summary>
public sealed class StatsTrendPoint
{
    public string Day { get; set; } = "";
    public int TotalVulnerabilities { get; set; }
    public int BlockedPulls30d { get; set; }
    public int TotalDownloads30d { get; set; }
}
