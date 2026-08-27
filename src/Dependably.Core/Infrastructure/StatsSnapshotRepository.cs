using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Reads and writes the pre-computed dashboard snapshot in <c>org_stats_snapshot</c>
/// (one row per org). The /api/v1/stats endpoint reads the snapshot instead of running
/// <see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>'s live aggregate
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
        // A suspended/archived/deleting org (see TenantLifecycle) is excluded the same way a
        // soft-deleted one already is: this pass runs eight aggregate queries per org on every
        // tick (default 60s), forever, for no reason once the tenant is locked out of
        // /api/v1/stats — operator DB time spent on a non-active org's behalf indefinitely. This
        // IS operator-visible: SystemController.DeriveHealthAndStats reads org_stats_snapshot
        // cross-tenant (including non-active orgs) for the Tenants page and surfaces the frozen
        // snapshot as its own "stats_frozen_non_active" reason, deliberately distinct from
        // "stats_stale", so the exclusion here reads as an explained consequence of suspension
        // rather than a health-pipeline problem.
        var ids = await conn.QueryAsync<string>(
            "SELECT id FROM orgs o WHERE o.deleted_at IS NULL AND o.status = 'active'");
        return ids.ToList();
    }
}

public sealed class StatsSnapshotRow
{
    public string StatsJson { get; init; } = "";
    public string ComputedAt { get; init; } = "";
}
