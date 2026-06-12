using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Reads and writes the pre-computed dashboard snapshot in <c>org_stats_snapshot</c>
/// (one row per org). The /api/v1/stats endpoint reads the snapshot instead of running
/// <see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>'s eight live aggregate
/// queries on every page load; <see cref="StatsRefreshService"/> recomputes the row per
/// org on a fixed interval. <c>stats_json</c> holds a serialized <see cref="OrgStats"/>.
/// </summary>
public sealed class StatsSnapshotRepository
{
    private readonly IMetadataStore _db;

    public StatsSnapshotRepository(IMetadataStore db) => _db = db;

    public async Task<StatsSnapshotRow?> GetSnapshotAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<StatsSnapshotRow>(
            """
            SELECT stats_json AS StatsJson, computed_at AS ComputedAt
            FROM org_stats_snapshot
            WHERE org_id = @orgId
            """,
            new { orgId });
    }

    public async Task UpsertSnapshotAsync(
        string orgId, string statsJson, string computedAt, long durationMs, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_stats_snapshot (org_id, stats_json, computed_at, duration_ms)
            VALUES (@orgId, @statsJson, @computedAt, @durationMs)
            ON CONFLICT (org_id) DO UPDATE SET
                stats_json = excluded.stats_json,
                computed_at = excluded.computed_at,
                duration_ms = excluded.duration_ms
            """,
            new { orgId, statsJson, computedAt, durationMs });
    }

    public async Task<IReadOnlyList<string>> ListActiveOrgIdsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: system-wide background sweep; each org's stats are computed in isolation
        // by GetOrgStatsAsync (org-scoped) and written to that org's own snapshot row.
        var ids = await conn.QueryAsync<string>("SELECT id FROM orgs WHERE deleted_at IS NULL");
        return ids.ToList();
    }
}

public sealed class StatsSnapshotRow
{
    public string StatsJson { get; init; } = "";
    public string ComputedAt { get; init; } = "";
}
