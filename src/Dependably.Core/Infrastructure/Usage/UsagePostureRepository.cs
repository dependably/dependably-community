using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Stores per-meter usage caps (<c>org_usage_caps</c>) and keeps <c>orgs.usage_posture</c> in step
/// with them. The posture is what the hot path reads: every tenant resolver selects it into
/// <see cref="TenantContext.UsagePosture"/>, so enforcement costs no aggregate per request.
///
/// <para>
/// Usage is measured the same way on every path. The egress meters are the sum of
/// <c>usage_hourly</c> since the start of the current UTC month. <c>storage_bytes</c> is the
/// latest <c>storage_snapshot.billable_bytes</c>, and <c>artifact_count</c> is the same
/// snapshot's <see cref="StorageSnapshotRow.ArtifactCount"/>; an org with no snapshot yet
/// measures 0 on both. <see cref="UsagePostureEvaluator"/> turns caps and usage into a posture.
/// </para>
///
/// <para>
/// Both recompute paths write only a posture that changed, so a pass over a fleet whose postures
/// all hold writes nothing.
/// </para>
/// </summary>
public sealed class UsagePostureRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public UsagePostureRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>The org's caps, keyed by meter. Empty when the org has none.</summary>
    public async Task<IReadOnlyDictionary<string, long>> GetCapsAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<CapRow>(
            "SELECT org_id AS OrgId, meter AS Meter, cap_quantity AS CapQuantity FROM org_usage_caps WHERE org_id = @orgId",
            new { orgId });
        return rows.ToDictionary(r => r.Meter, r => r.CapQuantity, StringComparer.Ordinal);
    }

    /// <summary>The org's stored posture, or <see cref="UsagePostures.Normal"/> when the org does not exist.</summary>
    public async Task<string> GetPostureAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT usage_posture FROM orgs WHERE id = @orgId", new { orgId }) ?? UsagePostures.Normal;
    }

    /// <summary>
    /// Applies <paramref name="changes"/> to the org's caps in one transaction: a quantity sets
    /// that meter's cap, null removes it, and a meter not named is left as it is. Callers
    /// validate the meters and quantities first; an unknown meter or a quantity of zero or less
    /// is rejected here too, by the table's CHECK constraints.
    /// </summary>
    public Task SetCapsAsync(
        string orgId, IReadOnlyDictionary<string, long?> changes, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(changes);
        return SetCapsCoreAsync(orgId, changes, ct);
    }

    private async Task SetCapsCoreAsync(
        string orgId, IReadOnlyDictionary<string, long?> changes, CancellationToken ct)
    {
        string updatedAt = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        foreach (var (meter, cap) in changes)
        {
            if (cap is long quantity)
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO org_usage_caps (org_id, meter, cap_quantity, updated_at)
                    VALUES (@orgId, @meter, @quantity, @updatedAt)
                    ON CONFLICT (org_id, meter) DO UPDATE SET
                        cap_quantity = excluded.cap_quantity,
                        updated_at = excluded.updated_at
                    """,
                    new { orgId, meter, quantity, updatedAt },
                    transaction: tx);
            }
            else
            {
                await conn.ExecuteAsync(
                    "DELETE FROM org_usage_caps WHERE org_id = @orgId AND meter = @meter",
                    new { orgId, meter },
                    transaction: tx);
            }
        }

        await tx.CommitAsync(ct);
    }

    /// <summary>
    /// Recomputes one org's posture from its caps and current usage, stores it when it changed,
    /// and returns it. Called when an operator changes the org's caps, so a lifted cap takes
    /// effect without waiting for the next hourly pass.
    /// </summary>
    public async Task<string> RecomputeForOrgAsync(string orgId, CancellationToken ct = default)
    {
        string monthStart = MonthStartBucket(_time.GetUtcNow());

        await using var conn = await _db.OpenAsync(ct);
        var caps = (await conn.QueryAsync<CapRow>(
                "SELECT org_id AS OrgId, meter AS Meter, cap_quantity AS CapQuantity FROM org_usage_caps WHERE org_id = @orgId",
                new { orgId }))
            .ToDictionary(r => r.Meter, r => r.CapQuantity, StringComparer.Ordinal);

        var usage = UsageMeasurements.None;
        if (caps.Count > 0)
        {
            var egress = await conn.QueryAsync<EgressRow>(
                """
                SELECT org_id AS OrgId, meter AS Meter, CAST(SUM(quantity) AS BIGINT) AS Quantity
                FROM usage_hourly
                WHERE org_id = @orgId AND bucket >= @monthStart
                GROUP BY org_id, meter
                """,
                new { orgId, monthStart });
            var snapshot = await conn.QuerySingleOrDefaultAsync<SnapshotRow>(
                """
                SELECT org_id AS OrgId, billable_bytes AS BillableBytes,
                       hosted_version_count AS HostedVersionCount, oci_manifest_count AS OciManifestCount
                FROM storage_snapshot
                WHERE org_id = @orgId
                ORDER BY day_utc DESC
                LIMIT 1
                """,
                new { orgId });
            usage = Measure(egress, snapshot);
        }

        string posture = UsagePostureEvaluator.Evaluate(caps, usage);
        await WritePostureIfChangedAsync(conn, orgId, posture);
        return posture;
    }

    /// <summary>
    /// Recomputes the posture of every org that has a cap or is not currently
    /// <see cref="UsagePostures.Normal"/>, the latter so an org whose caps were all cleared
    /// returns to normal. Returns the number of orgs whose posture changed. The final step of
    /// the hourly usage rollup.
    /// </summary>
    public async Task<int> RecomputeAsync(CancellationToken ct = default)
    {
        // xtenant: the posture sweep evaluates every org with caps in one pass.
        await using var conn = await _db.OpenCrossTenantAsync("usage posture sweep", ct);
        var changes = await EvaluateFleetAsync(conn);
        return await ApplyFleetAsync(conn, changes);
    }

    /// <summary>
    /// A posture the sweep computed for an org, beside the posture it read for that org at the
    /// start of the pass.
    /// </summary>
    internal sealed record PostureChange(string OrgId, string ReadPosture, string NewPosture);

    /// <summary>
    /// The sweep's read phase: every candidate org whose computed posture differs from the one
    /// read. Writes nothing.
    /// </summary>
    internal async Task<IReadOnlyList<PostureChange>> EvaluateFleetAsync(DbConnection conn)
    {
        string monthStart = MonthStartBucket(_time.GetUtcNow());

        // xtenant: selects the orgs to evaluate; the caps subquery is correlated on orgs.id, so
        // each org is judged only by its own rows.
        var candidates = (await conn.QueryAsync<PostureRow>(
                """
                SELECT o.id AS OrgId, o.usage_posture AS Posture
                FROM orgs o
                WHERE o.usage_posture <> 'normal'
                   OR EXISTS (SELECT 1 FROM org_usage_caps c WHERE c.org_id = o.id)
                """))
            .ToList();
        if (candidates.Count == 0)
        {
            return [];
        }

        // xtenant: every org's caps in one read; org_id is carried into the per-org grouping below.
        var capsByOrg = (await conn.QueryAsync<CapRow>(
                "SELECT org_id AS OrgId, meter AS Meter, cap_quantity AS CapQuantity FROM org_usage_caps"))
            .GroupBy(r => r.OrgId, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyDictionary<string, long>)g.ToDictionary(r => r.Meter, r => r.CapQuantity, StringComparer.Ordinal),
                StringComparer.Ordinal);

        // xtenant: month-to-date egress for every capped org, grouped by org_id so no org's total
        // includes another's buckets.
        var egressByOrg = (await conn.QueryAsync<EgressRow>(
                """
                SELECT org_id AS OrgId, meter AS Meter, CAST(SUM(quantity) AS BIGINT) AS Quantity
                FROM usage_hourly
                WHERE bucket >= @monthStart
                  AND org_id IN (SELECT org_id FROM org_usage_caps)
                GROUP BY org_id, meter
                """,
                new { monthStart }))
            .ToLookup(r => r.OrgId, StringComparer.Ordinal);

        // xtenant: the latest snapshot of every capped org, joined on org_id to that org's own
        // latest day.
        var snapshotByOrg = (await conn.QueryAsync<SnapshotRow>(
                """
                SELECT s.org_id AS OrgId, s.billable_bytes AS BillableBytes,
                       s.hosted_version_count AS HostedVersionCount, s.oci_manifest_count AS OciManifestCount
                FROM storage_snapshot s
                JOIN (
                    SELECT org_id, MAX(day_utc) AS day_utc
                    FROM storage_snapshot
                    WHERE org_id IN (SELECT org_id FROM org_usage_caps)
                    GROUP BY org_id
                ) latest ON latest.org_id = s.org_id AND latest.day_utc = s.day_utc
                """))
            .ToDictionary(r => r.OrgId, StringComparer.Ordinal);

        var changes = new List<PostureChange>();
        foreach (var candidate in candidates)
        {
            var caps = capsByOrg.TryGetValue(candidate.OrgId, out var c)
                ? c
                : new Dictionary<string, long>(StringComparer.Ordinal);
            var usage = caps.Count == 0
                ? UsageMeasurements.None
                : Measure(egressByOrg[candidate.OrgId], snapshotByOrg.GetValueOrDefault(candidate.OrgId));

            string posture = UsagePostureEvaluator.Evaluate(caps, usage);
            if (!string.Equals(posture, candidate.Posture, StringComparison.Ordinal))
            {
                changes.Add(new PostureChange(candidate.OrgId, candidate.Posture, posture));
            }
        }

        return changes;
    }

    /// <summary>
    /// The sweep's write phase. Each write is a compare-and-set on the posture the read phase saw:
    /// an org whose posture moved in between — an operator's usage-limits PATCH recomputed it from
    /// newer caps — is left as the PATCH set it, rather than overwritten with a posture computed
    /// from caps that no longer exist. The next pass evaluates it afresh. Returns the number of
    /// orgs written.
    /// </summary>
    internal static async Task<int> ApplyFleetAsync(DbConnection conn, IReadOnlyList<PostureChange> changes)
    {
        int written = 0;
        foreach (var change in changes)
        {
            written += await conn.ExecuteAsync(
                "UPDATE orgs SET usage_posture = @newPosture WHERE id = @orgId AND usage_posture = @readPosture",
                new { orgId = change.OrgId, newPosture = change.NewPosture, readPosture = change.ReadPosture });
        }

        return written;
    }

    private static async Task<bool> WritePostureIfChangedAsync(DbConnection conn, string orgId, string posture) =>
        await conn.ExecuteAsync(
            "UPDATE orgs SET usage_posture = @posture WHERE id = @orgId AND usage_posture <> @posture",
            new { orgId, posture }) > 0;

    private static UsageMeasurements Measure(IEnumerable<EgressRow> egress, SnapshotRow? snapshot)
    {
        long egressBytes = 0;
        long egressMetadataBytes = 0;
        foreach (var row in egress)
        {
            switch (row.Meter)
            {
                case UsageMeters.EgressBytes:
                    egressBytes = row.Quantity;
                    break;
                case UsageMeters.EgressMetadataBytes:
                    egressMetadataBytes = row.Quantity;
                    break;
            }
        }

        return new UsageMeasurements(
            egressBytes,
            egressMetadataBytes,
            snapshot?.BillableBytes ?? 0,
            snapshot is null ? 0 : StorageSnapshotRow.CountArtifacts(snapshot.HostedVersionCount, snapshot.OciManifestCount));
    }

    /// <summary>The <c>usage_hourly</c> bucket label of the first hour of <paramref name="now"/>'s UTC month.</summary>
    internal static string MonthStartBucket(DateTimeOffset now)
    {
        var utc = now.ToUniversalTime();
        return new DateTimeOffset(utc.Year, utc.Month, 1, 0, 0, 0, TimeSpan.Zero).ToUtcIso();
    }

    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class CapRow
    {
        public string OrgId { get; init; } = "";
        public string Meter { get; init; } = "";
        public long CapQuantity { get; init; }
    }

    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class EgressRow
    {
        public string OrgId { get; init; } = "";
        public string Meter { get; init; } = "";
        public long Quantity { get; init; }
    }

    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class SnapshotRow
    {
        public string OrgId { get; init; } = "";
        public long BillableBytes { get; init; }
        public long HostedVersionCount { get; init; }
        public long OciManifestCount { get; init; }
    }

    private sealed class PostureRow
    {
        public string OrgId { get; init; } = "";
        public string Posture { get; init; } = "";
    }
}
