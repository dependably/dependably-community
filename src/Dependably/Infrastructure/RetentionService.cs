using Dapper;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Background GC worker that runs on a cron schedule (GC_SCHEDULE env var, default daily at 3am).
/// Enforces per-org retention policies:
///   - keep_versions: delete oldest versions beyond the limit per package
///   - keep_days: evict proxy blobs unused beyond this many days
///   - activity_retention_days: delete old activity rows
/// Respects the shutdown CancellationToken — stops at the next checkpoint.
/// </summary>
public sealed class RetentionService : ScheduledBackgroundService
{
    /// <summary>
    /// Injected dependencies for <see cref="RetentionService"/>. Bundles all DI services into
    /// one record so the constructor stays within the parameter-count gate (S107).
    /// </summary>
    public sealed record Dependencies(
        IMetadataStore Db,
        IBlobStore Blobs,
        JwtRevocationRepository JwtRevocations,
        InviteRepository Invites,
        SamlConfigRepository SamlConfig,
        IConfiguration Config,
        ILogger<RetentionService> Logger,
        TimeProvider Time);

    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly JwtRevocationRepository _jwtRevocations;
    private readonly InviteRepository _invites;
    private readonly SamlConfigRepository _samlConfig;
    private readonly IConfiguration _config;
    private readonly ILogger<RetentionService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "GC_SCHEDULE";
    protected override string DefaultCron => "0 3 * * *";
    protected override string ScopeJobName => "retention";
    protected override string ScopeMetricName => "retention.gc";

    public RetentionService(Dependencies deps)
        : base(deps.Config, deps.Logger, deps.Time)
    {
        _db = deps.Db;
        _blobs = deps.Blobs;
        _jwtRevocations = deps.JwtRevocations;
        _invites = deps.Invites;
        _samlConfig = deps.SamlConfig;
        _config = deps.Config;
        _logger = deps.Logger;
        _time = deps.Time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunGcPassAsync(ct);

    private async Task RunGcPassAsync(CancellationToken ct)
    {
        _logger.LogInformation("Retention GC pass starting.");

        await using var conn = await _db.OpenAsync(ct);

        // Fetch active orgs with retention settings (skip soft-deleted — TenantHardDeleteService
        // owns those, and retention work on a tenant pending hard-delete is wasted I/O).
        var orgs = await conn.QueryAsync<(string OrgId, int? KeepVersions, int? KeepDays, int? ActivityRetentionDays)>(
            """
            SELECT o.id, s.keep_versions, s.keep_days, s.activity_retention_days
            FROM orgs o
            JOIN org_settings s ON s.org_id = o.id
            WHERE o.deleted_at IS NULL
              AND (s.keep_versions IS NOT NULL OR s.keep_days IS NOT NULL OR s.activity_retention_days IS NOT NULL)
            """);

        foreach (var (OrgId, KeepVersions, KeepDays, ActivityRetentionDays) in orgs)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            if (KeepVersions.HasValue)
            {
                await EnforceVersionLimitAsync(conn, OrgId, KeepVersions.Value, ct);
            }

            if (KeepDays.HasValue)
            {
                await EvictStaleBlobsAsync(conn, OrgId, KeepDays.Value, ct);
            }

            if (ActivityRetentionDays.HasValue)
            {
                await PruneActivityAsync(conn, OrgId, ActivityRetentionDays.Value, _time.GetUtcNow(), ct);
            }
        }

        // Prune expired JWT revocations (global — not org-scoped)
        await _jwtRevocations.PruneExpiredAsync(ct);

        // Prune expired, unconsumed invite rows (global sweep — see PruneExpiredAsync xtenant comment).
        int prunedInvites = await _invites.PruneExpiredAsync(ct);
        if (prunedInvites > 0)
        {
            _logger.LogInformation("Retention GC: pruned {Count} expired invite rows.", prunedInvites);
        }

        // Prune typed audit_event rows past the retention window. Default window is 365
        // days, set in cross-cutting-decisions.md section 4 (audit_event is append-only and
        // archived after one year). Hard delete for now; once archive support lands, the
        // reaper will write to cold storage first.
        await PruneAuditEventsAsync(conn, ct);

        // Reclaim expired SAML one-shot rows (pending requests, consumed assertions, test runs).
        // These prune on write too; this sweep bounds them when a tenant goes idle.
        await _samlConfig.PurgeExpiredSamlAsync(ct);

        _logger.LogInformation("Retention GC pass complete.");
    }

    internal async Task PruneAuditEventsAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        int retentionDays = int.TryParse(_config["AUDIT_EVENT_RETENTION_DAYS"], out int d) && d > 0
            ? d : 365;
        string cutoff = _time.GetUtcNow().AddDays(-retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Hard-delete is the right shape today: there's no archive destination yet (decision
        // deferred per cross-cutting-decisions.md). When archive lands, this becomes a copy
        // followed by a delete behind a single transaction.
        int deleted = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM audit_event WHERE occurred_at < @cutoff",
            new { cutoff },
            cancellationToken: ct));

        if (deleted > 0)
        {
            _logger.LogInformation("Audit reaper: pruned {Count} audit_event rows older than {Days} days.",
                deleted, retentionDays);
        }
    }

    private async Task EnforceVersionLimitAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepVersions, CancellationToken ct)
    {
        // Uploaded versions: keep the most recent N per package; delete older ones from package_versions.
        var uploadedToDelete = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND pv.id NOT IN (
                  SELECT id FROM package_versions pv2
                  WHERE pv2.package_id = pv.package_id
                    AND pv2.origin = 'uploaded'
                  ORDER BY pv2.created_at DESC
                  LIMIT @keepVersions
              )
            """,
            new { orgId, keepVersions });

        foreach (var (VersionId, BlobKey) in uploadedToDelete)
        {
            if (ct.IsCancellationRequested) { break; }
            await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
            _logger.LogDebug("GC: deleted uploaded version {Id} (blob {Key})", VersionId, BlobKey);
        }

        // Proxy versions: evict this org's least-recently-accessed cache_artifact rows per name,
        // beyond the keep limit. Removes the tenant_artifact_access row; cascade-deletes the
        // cache_artifact and its blob when no other tenant retains access.
        // xtenant: cache_artifact is global; org_id filter is in tenant_artifact_access.
        var proxyToEvict = await conn.QueryAsync<(string CacheArtifactId, string Name, string BlobKey)>(
            """
            SELECT ca.id AS CacheArtifactId, ca.name AS Name, ca.blob_key AS BlobKey
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND taa.cache_artifact_id NOT IN (
                  SELECT taa2.cache_artifact_id
                  FROM tenant_artifact_access taa2
                  JOIN cache_artifact ca2 ON ca2.id = taa2.cache_artifact_id
                  WHERE taa2.org_id = @orgId AND ca2.name = ca.name AND ca2.ecosystem = ca.ecosystem
                  ORDER BY taa2.last_accessed_at DESC
                  LIMIT @keepVersions
              )
            """,
            new { orgId, keepVersions });

        foreach (var (CacheArtifactId, Name, BlobKey) in proxyToEvict)
        {
            if (ct.IsCancellationRequested) { break; }

            await conn.ExecuteAsync(
                "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                new { orgId, id = CacheArtifactId });

            // Delete the global cache_artifact and its blob when no tenant retains access.
            long remaining = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
                new { id = CacheArtifactId });
            if (remaining == 0)
            {
                await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
                await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id = CacheArtifactId });
            }
            _logger.LogDebug("GC: evicted proxy version {Id} name={Name} (blob {Key})", CacheArtifactId, Name, BlobKey);
        }
    }

    private async Task EvictStaleBlobsAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepDays, CancellationToken ct)
    {
        string cutoff = _time.GetUtcNow().AddDays(-keepDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Uploaded versions: evict by last_used timestamp on package_versions.
        var uploadedStale = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND pv.last_used IS NOT NULL AND pv.last_used < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (VersionId, BlobKey) in uploadedStale)
        {
            if (ct.IsCancellationRequested) { break; }
            await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
        }

        // Proxy versions: evict this org's tenant_artifact_access rows where the tenant's
        // last_used is older than the cutoff. Removes the per-tenant row; cascade-deletes the
        // global cache_artifact and its blob when no other tenant retains access.
        // xtenant: cache_artifact is global; org_id filter is in tenant_artifact_access.
        var proxyStale = await conn.QueryAsync<(string CacheArtifactId, string BlobKey)>(
            """
            SELECT ca.id AS CacheArtifactId, ca.blob_key AS BlobKey
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND taa.last_used IS NOT NULL AND taa.last_used < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (CacheArtifactId, BlobKey) in proxyStale)
        {
            if (ct.IsCancellationRequested) { break; }

            await conn.ExecuteAsync(
                "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                new { orgId, id = CacheArtifactId });

            long remaining = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
                new { id = CacheArtifactId });
            if (remaining == 0)
            {
                await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), ct);
                await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id = CacheArtifactId });
            }
        }
    }

    private static async Task PruneActivityAsync(
        System.Data.Common.DbConnection conn, string orgId, int retentionDays, DateTimeOffset now, CancellationToken ct)
    {
        string cutoff = now.AddDays(-retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM activity WHERE org_id = @orgId AND created_at < @cutoff",
            new { orgId, cutoff },
            cancellationToken: ct));
    }
}
