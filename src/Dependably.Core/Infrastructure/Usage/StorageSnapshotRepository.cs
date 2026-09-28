using Dapper;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Captures each org's storage into <c>storage_snapshot</c> and carries the billable figure into
/// <c>usage_daily</c> as the day's <c>storage_bytes</c> high-water mark. The same capture records the
/// org's operator signals: its artefact, OCI blob and proxy-cache entry counts and its database
/// footprint. None of them is billed, and none is recomputed on a page load.
///
/// The snapshot row is last-capture-wins for its day; the <c>usage_daily</c> row only ever rises.
/// Capturing twice in one day therefore records the latest composition while keeping the highest
/// billable figure seen, and a recompute can never lower a mark already written.
/// </summary>
public sealed class StorageSnapshotRepository
{
    /// <summary>
    /// The org-scoped growth tables whose rows make up <c>db_row_count</c>. A fixed list rather
    /// than a catalogue walk, because a walk needs interpolated table names. Every table here
    /// declares <c>org_id</c>, which a unit test checks against <c>Schema.sql</c>, and the same
    /// test checks that <see cref="CaptureSql"/> counts exactly these tables. Tables with no
    /// <c>org_id</c> are excluded because none of their rows can be attributed to one org:
    /// instance-wide tables (<c>background_job_runs</c>, <c>spdx_license</c>, the vulnerability
    /// feeds), the shared proxy catalogue (<c>cache_artifact</c>, which each org reaches through
    /// its own <c>tenant_artifact_access</c> rows), and the version-scoped child tables
    /// (<c>package_versions</c> among them, which <c>hosted_version_count</c> and
    /// <c>cache_entry_count</c> already cover).
    /// </summary>
    internal static readonly IReadOnlyList<string> DbFootprintTables =
    [
        "activity",
        "audit_log",
        "audit_event",
        "packages",
        "package_version_files",
        "npm_dist_tags",
        "nuget_symbol_index",
        "tenant_artifact_access",
        "oci_blobs",
        "oci_manifest_blobs",
        "oci_tags",
        "projects",
        "project_versions",
        "project_documents",
        "sbom_components",
        "sbom_policy_findings",
        "project_vuln_analysis",
        "usage_events",
    ];

    // The manifest media types below are OciManifestParser.AcceptedMediaTypes, the types a push
    // accepts as a manifest; a unit test pins the two together.
    // xtenant: the capture sweeps every org in one statement. org_id comes from orgs.id and is
    // joined to each per-org view and count on org_id, so a row carries only its own org's figures.
    internal const string CaptureSql =
        """
        INSERT INTO storage_snapshot
            (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes,
             hosted_version_count, oci_manifest_count, oci_blob_count, cache_entry_count, db_row_count,
             captured_at)
        SELECT o.id,
               @day,
               COALESCE(b.hosted_bytes, 0),
               COALESCE(b.oci_uploaded_bytes, 0),
               CASE WHEN COALESCE(t.total_bytes, 0) > COALESCE(b.billable_bytes, 0)
                    THEN COALESCE(t.total_bytes, 0) - COALESCE(b.billable_bytes, 0)
                    ELSE 0 END,
               COALESCE(b.billable_bytes, 0),
               COALESCE(hv.n, 0),
               COALESCE(oc.manifests, 0),
               COALESCE(oc.blobs, 0),
               COALESCE(ce.n, 0),
               COALESCE(dr.n, 0),
               @capturedAt
        FROM orgs o
        LEFT JOIN org_billable_storage_bytes b ON b.org_id = o.id
        LEFT JOIN org_storage_bytes t ON t.org_id = o.id
        LEFT JOIN (
            SELECT p.org_id AS org_id, CAST(COUNT(*) AS BIGINT) AS n
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem != 'oci' AND pv.origin = 'uploaded'
            GROUP BY p.org_id
        ) hv ON hv.org_id = o.id
        LEFT JOIN (
            SELECT org_id,
                   CAST(SUM(CASE WHEN media_type IN (
                            'application/vnd.oci.image.manifest.v1+json',
                            'application/vnd.oci.image.index.v1+json',
                            'application/vnd.docker.distribution.manifest.v2+json',
                            'application/vnd.docker.distribution.manifest.list.v2+json')
                        THEN 1 ELSE 0 END) AS BIGINT) AS manifests,
                   CAST(SUM(CASE WHEN media_type IN (
                            'application/vnd.oci.image.manifest.v1+json',
                            'application/vnd.oci.image.index.v1+json',
                            'application/vnd.docker.distribution.manifest.v2+json',
                            'application/vnd.docker.distribution.manifest.list.v2+json')
                        THEN 0 ELSE 1 END) AS BIGINT) AS blobs
            FROM oci_blobs
            WHERE origin = 'uploaded'
            GROUP BY org_id
        ) oc ON oc.org_id = o.id
        LEFT JOIN (
            SELECT org_id, CAST(COUNT(*) AS BIGINT) AS n
            FROM tenant_artifact_access
            GROUP BY org_id
        ) ce ON ce.org_id = o.id
        LEFT JOIN (
            SELECT r.org_id AS org_id, CAST(SUM(r.n) AS BIGINT) AS n
            FROM (
                SELECT org_id, COUNT(*) AS n FROM activity GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM audit_log GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM audit_event GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM packages GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM package_version_files GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM npm_dist_tags GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM nuget_symbol_index GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM tenant_artifact_access GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM oci_blobs GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM oci_manifest_blobs GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM oci_tags GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM projects GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM project_versions GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM project_documents GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM sbom_components GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM sbom_policy_findings GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM project_vuln_analysis GROUP BY org_id
                UNION ALL
                SELECT org_id, COUNT(*) AS n FROM usage_events GROUP BY org_id
            ) r
            GROUP BY r.org_id
        ) dr ON dr.org_id = o.id
        WHERE 1 = 1
        ON CONFLICT (org_id, day_utc) DO UPDATE SET
            hosted_bytes = excluded.hosted_bytes,
            oci_uploaded_bytes = excluded.oci_uploaded_bytes,
            cache_attributed_bytes = excluded.cache_attributed_bytes,
            billable_bytes = excluded.billable_bytes,
            hosted_version_count = excluded.hosted_version_count,
            oci_manifest_count = excluded.oci_manifest_count,
            oci_blob_count = excluded.oci_blob_count,
            cache_entry_count = excluded.cache_entry_count,
            db_row_count = excluded.db_row_count,
            captured_at = excluded.captured_at
        """;

    // xtenant: carries every org's snapshot for one day into usage_daily; org_id flows from the
    // snapshot row into the INSERT column list unchanged.
    private const string HighWaterSqlite =
        """
        INSERT INTO usage_daily (org_id, meter, bucket, quantity, redirect_quantity, computed_at)
        SELECT org_id, 'storage_bytes', day_utc, billable_bytes, 0, @capturedAt
        FROM storage_snapshot
        WHERE day_utc = @day
        ON CONFLICT (org_id, meter, bucket) DO UPDATE SET
            quantity = MAX(usage_daily.quantity, excluded.quantity),
            computed_at = excluded.computed_at
        """;

    // xtenant: carries every org's snapshot for one day into usage_daily; org_id flows from the
    // snapshot row into the INSERT column list unchanged.
    private const string HighWaterPostgres =
        """
        INSERT INTO usage_daily (org_id, meter, bucket, quantity, redirect_quantity, computed_at)
        SELECT org_id, 'storage_bytes', day_utc, billable_bytes, 0, @capturedAt
        FROM storage_snapshot
        WHERE day_utc = @day
        ON CONFLICT (org_id, meter, bucket) DO UPDATE SET
            quantity = GREATEST(usage_daily.quantity, excluded.quantity),
            computed_at = excluded.computed_at
        """;

    private readonly IMetadataStore _db;

    public StorageSnapshotRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Captures every org's storage for <paramref name="day"/> and raises that day's
    /// <c>storage_bytes</c> mark in <c>usage_daily</c> where the capture exceeds it. Both writes
    /// commit together. Returns the number of orgs captured.
    /// </summary>
    public async Task<int> CaptureAsync(DateOnly day, DateTimeOffset capturedAt, CancellationToken ct = default)
    {
        string dayLabel = UsageRollupRepository.DayLabel(day);
        string capturedAtIso = capturedAt.ToUtcIso();

        // xtenant: the capture records every org's billable storage in one statement.
        await using var conn = await _db.OpenCrossTenantAsync("storage snapshot capture", ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        int captured = await conn.ExecuteAsync(
            CaptureSql, new { day = dayLabel, capturedAt = capturedAtIso }, transaction: tx);
        await conn.ExecuteAsync(
            _db.Provider == DbProvider.Postgres ? HighWaterPostgres : HighWaterSqlite,
            new { day = dayLabel, capturedAt = capturedAtIso },
            transaction: tx);

        await tx.CommitAsync(ct);
        return captured;
    }

    /// <summary>
    /// Whether any org has a captured snapshot for <paramref name="day"/> — used only to decide
    /// whether a catch-up capture is needed after downtime, never to read a specific org's figures.
    /// </summary>
    public async Task<bool> HasAnySnapshotForDayAsync(DateOnly day, CancellationToken ct = default)
    {
        string dayLabel = UsageRollupRepository.DayLabel(day);
        // xtenant: an instance-wide existence check over every org's snapshot for the day.
        await using var conn = await _db.OpenCrossTenantAsync("storage snapshot existence check", ct);
        // xtenant: instance-wide existence check across every org's snapshot for one day, feeding
        // only a boolean catch-up decision — no org's own figures are read or returned.
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM (SELECT 1 FROM storage_snapshot WHERE day_utc = @dayLabel LIMIT 1)",
            new { dayLabel });
        return count > 0;
    }

    /// <summary>One org's snapshot for <paramref name="day"/>, or null when none was captured.</summary>
    public async Task<StorageSnapshotRow?> GetAsync(string orgId, DateOnly day, CancellationToken ct = default)
    {
        string dayLabel = UsageRollupRepository.DayLabel(day);
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<StorageSnapshotRow>(
            """
            SELECT org_id                 AS OrgId,
                   day_utc                AS DayUtc,
                   hosted_bytes           AS HostedBytes,
                   oci_uploaded_bytes     AS OciUploadedBytes,
                   cache_attributed_bytes AS CacheAttributedBytes,
                   billable_bytes         AS BillableBytes,
                   hosted_version_count   AS HostedVersionCount,
                   oci_manifest_count     AS OciManifestCount,
                   oci_blob_count         AS OciBlobCount,
                   cache_entry_count      AS CacheEntryCount,
                   db_row_count           AS DbRowCount,
                   captured_at            AS CapturedAt
            FROM storage_snapshot
            WHERE org_id = @orgId AND day_utc = @dayLabel
            """,
            new { orgId, dayLabel });
    }

    /// <summary>The org's most recently captured snapshot, or null when it has never been captured.</summary>
    public async Task<StorageSnapshotRow?> GetLatestAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<StorageSnapshotRow>(
            """
            SELECT org_id                 AS OrgId,
                   day_utc                AS DayUtc,
                   hosted_bytes           AS HostedBytes,
                   oci_uploaded_bytes     AS OciUploadedBytes,
                   cache_attributed_bytes AS CacheAttributedBytes,
                   billable_bytes         AS BillableBytes,
                   hosted_version_count   AS HostedVersionCount,
                   oci_manifest_count     AS OciManifestCount,
                   oci_blob_count         AS OciBlobCount,
                   cache_entry_count      AS CacheEntryCount,
                   db_row_count           AS DbRowCount,
                   captured_at            AS CapturedAt
            FROM storage_snapshot
            WHERE org_id = @orgId
            ORDER BY day_utc DESC
            LIMIT 1
            """,
            new { orgId });
    }
}
