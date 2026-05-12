using Cronos;
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
public sealed class RetentionService : BackgroundService
{
    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly JwtRevocationRepository _jwtRevocations;
    private readonly IConfiguration _config;
    private readonly ILogger<RetentionService> _logger;

    public RetentionService(IMetadataStore db, IBlobStore blobs, JwtRevocationRepository jwtRevocations, IConfiguration config, ILogger<RetentionService> logger)
    {
        _db = db;
        _blobs = blobs;
        _jwtRevocations = jwtRevocations;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var schedule = CronExpression.Parse(
            _config["GC_SCHEDULE"] ?? "0 3 * * *",
            CronFormat.Standard);

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
            if (next is null) break;

            var delay = next.Value - DateTimeOffset.UtcNow;
            if (delay > TimeSpan.Zero)
            {
                try { await Task.Delay(delay, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }

            if (stoppingToken.IsCancellationRequested) break;

            await RunGcPassAsync(stoppingToken);
        }
    }

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

        foreach (var org in orgs)
        {
            if (ct.IsCancellationRequested) break;

            if (org.KeepVersions.HasValue)
                await EnforceVersionLimitAsync(conn, org.OrgId, org.KeepVersions.Value, ct);

            if (org.KeepDays.HasValue)
                await EvictStaleBlobsAsync(conn, org.OrgId, org.KeepDays.Value, ct);

            if (org.ActivityRetentionDays.HasValue)
                await PruneActivityAsync(conn, org.OrgId, org.ActivityRetentionDays.Value, ct);
        }

        // Prune expired JWT revocations (global — not org-scoped)
        await _jwtRevocations.PruneExpiredAsync(ct);

        // Prune typed audit_event rows past the retention window. Default window is 365
        // days, set in cross-cutting-decisions.md section 4 (audit_event is append-only and
        // archived after one year). Hard delete for now; once archive support lands, the
        // reaper will write to cold storage first.
        await PruneAuditEventsAsync(conn, ct);

        _logger.LogInformation("Retention GC pass complete.");
    }

    internal async Task PruneAuditEventsAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        var retentionDays = int.TryParse(_config["AUDIT_EVENT_RETENTION_DAYS"], out var d) && d > 0
            ? d : 365;
        var cutoff = DateTimeOffset.UtcNow.AddDays(-retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Hard-delete is the right shape today: there's no archive destination yet (decision
        // deferred per cross-cutting-decisions.md). When archive lands, this becomes a copy
        // followed by a delete behind a single transaction.
        var deleted = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM audit_event WHERE occurred_at < @cutoff",
            new { cutoff },
            cancellationToken: ct));

        if (deleted > 0)
            _logger.LogInformation("Audit reaper: pruned {Count} audit_event rows older than {Days} days.",
                deleted, retentionDays);
    }

    private async Task EnforceVersionLimitAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepVersions, CancellationToken ct)
    {
        // Find versions beyond the keep limit, oldest first, for proxy packages
        var toDelete = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.is_proxy = 1
              AND pv.id NOT IN (
                  SELECT id FROM package_versions pv2
                  WHERE pv2.package_id = pv.package_id
                  ORDER BY pv2.created_at DESC
                  LIMIT @keepVersions
              )
            """,
            new { orgId, keepVersions });

        foreach (var v in toDelete)
        {
            if (ct.IsCancellationRequested) break;
            await _blobs.DeleteAsync(BlobKeys.StoreKey(v.BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = v.VersionId });
            _logger.LogDebug("GC: deleted version {Id} (blob {Key})", v.VersionId, v.BlobKey);
        }
    }

    private async Task EvictStaleBlobsAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepDays, CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-keepDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        var stale = await conn.QueryAsync<(string VersionId, string BlobKey)>(
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.is_proxy = 1
              AND pv.last_used IS NOT NULL AND pv.last_used < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var v in stale)
        {
            if (ct.IsCancellationRequested) break;
            await _blobs.DeleteAsync(BlobKeys.StoreKey(v.BlobKey), ct);
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = v.VersionId });
        }
    }

    private static async Task PruneActivityAsync(
        System.Data.Common.DbConnection conn, string orgId, int retentionDays, CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM activity WHERE org_id = @orgId AND created_at < @cutoff",
            new { orgId, cutoff },
            cancellationToken: ct));
    }
}
