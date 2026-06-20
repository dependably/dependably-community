using Dapper;

namespace Dependably.Infrastructure;

// Staging file paths swept by the janitor are read back from the DB (staging_path column) or
// enumerated from the operator-configured PROXY_STAGING_PATH root — never from user input.
// The path-traversal warning is a false positive here; disable it file-wide.
#pragma warning disable SCS0018

/// <summary>
/// Periodic janitor that reclaims abandoned OCI upload sessions and orphaned proxy staging
/// temp files. Runs on a cron schedule (<c>OCI_STAGING_TTL_SCHEDULE</c>, default every 15
/// minutes). Two sweep passes per tick:
/// <list type="bullet">
///   <item><b>Session sweep</b> — queries <c>oci_uploads</c> for rows whose
///     <c>created_at</c> is older than <c>OCI_UPLOAD_TTL_MINUTES</c> (default 60).
///     For each stale row, deletes the staging file first (file-then-row ordering: an
///     orphaned row on crash is recoverable; an orphaned file is a leak). A file-delete
///     failure is logged and the row is left for the next pass.</item>
///   <item><b>Orphan sweep</b> — enumerates <c>PROXY_STAGING_PATH</c> for
///     <c>dependably-stage-*.tmp</c> files (UpstreamClient proxy-miss staging) and
///     <c>oci-upload-*</c> files with no live DB row whose last-write time is older than
///     the TTL. Protects in-flight files younger than the TTL.</item>
/// </list>
/// The session sweep is cross-tenant by design (fleet-wide reclaim). The per-org cap in
/// <see cref="OrgRepository.GetActiveOciUploadCountAsync"/> is org-scoped; this sweep is
/// the complementary fleet-wide reclaim that prevents the staging volume from filling up.
/// </summary>
public sealed class OciStagingJanitorService : ScheduledBackgroundService
{
    // Default TTL for OCI upload sessions when OCI_UPLOAD_TTL_MINUTES is not configured.
    private const int DefaultUploadTtlMinutes = 60;

    private readonly IMetadataStore _db;
    private readonly IConfiguration _config;
    private readonly ILogger<OciStagingJanitorService> _logger;
    private readonly TimeProvider _time;
    private readonly string _stagingPath;

    protected override string CronEnvKey => "OCI_STAGING_TTL_SCHEDULE";
    protected override string DefaultCron => "*/15 * * * *";
    protected override string ScopeJobName => "oci-staging-janitor";
    protected override string ScopeMetricName => "oci.staging.janitor";

    public OciStagingJanitorService(
        IMetadataStore db,
        IConfiguration config,
        ILogger<OciStagingJanitorService> logger,
        TimeProvider time)
        : base(config, logger, time)
    {
        _db = db;
        _config = config;
        _logger = logger;
        _time = time;

        string? configured = config["PROXY_STAGING_PATH"];
        _stagingPath = string.IsNullOrWhiteSpace(configured) ? Path.GetTempPath() : configured;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunOnceAsync(ct);

    /// <summary>
    /// Runs a single janitor pass. Public so tests can call it directly without waiting on
    /// the cron schedule or needing to start the hosted service.
    /// </summary>
    public async Task<JanitorSummary> RunOnceAsync(CancellationToken ct = default)
    {
        int ttlMinutes = ParseTtlMinutes();
        var cutoff = _time.GetUtcNow().AddMinutes(-ttlMinutes);
        string cutoffStr = cutoff.ToString("yyyy-MM-ddTHH:mm:ssZ");

        _logger.LogInformation(
            "OCI staging janitor starting (ttlMinutes={TtlMinutes}, cutoff={Cutoff}).",
            ttlMinutes, cutoffStr);

        int sessionsSwept = await SweepStaleSessionsAsync(cutoffStr, ct);
        int orphansSwept = await SweepOrphanFilesAsync(cutoff, ct);

        _logger.LogInformation(
            "OCI staging janitor done (sessionsSwept={SessionsSwept}, orphansSwept={OrphansSwept}).",
            sessionsSwept, orphansSwept);

        return new JanitorSummary(sessionsSwept, orphansSwept);
    }

    /// <summary>
    /// Deletes stale <c>oci_uploads</c> rows (created_at older than the cutoff) and their
    /// staging files. File-first ordering ensures a crash leaves a recoverable row, not an
    /// orphaned file. A file-delete failure logs and leaves the row for the next pass.
    /// </summary>
    private async Task<int> SweepStaleSessionsAsync(string cutoffStr, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: fleet-wide TTL sweep of abandoned upload sessions; all tenants share the
        // PROXY_STAGING_PATH staging volume, so reclaim must be cross-tenant.
        var stale = (await conn.QueryAsync<(string UploadId, string OrgId, string StagingPath)>(
            """
            SELECT upload_id, org_id, staging_path
            FROM oci_uploads
            WHERE created_at < @cutoff
            """,
            new { cutoff = cutoffStr })).AsList();

        int swept = 0;
        foreach (var (uploadId, orgId, stagingPath) in stale)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            // Delete file first: an orphaned row is recoverable on next pass; an orphaned
            // file is a staging-volume leak that the janitor is here to prevent.
            // deepcode ignore PT: staging_path is the server-generated "oci-upload-{GUID}" path written by OciUploadService; not user-controlled.
            if (!TryDeleteFile(stagingPath))
            {
                // File delete failed — skip deleting the row so the row remains as a
                // reference pointing at the (still-present) staging file. The next pass
                // retries. This mirrors CacheEvictionService.EvictAsync's "blob delete
                // failed → row left in place" pattern.
                continue;
            }

            // xtenant: fleet-wide TTL sweep of abandoned upload sessions.
            await conn.ExecuteAsync(
                "DELETE FROM oci_uploads WHERE upload_id = @uploadId AND org_id = @orgId",
                new { uploadId, orgId });
            swept++;
        }
        return swept;
    }

    /// <summary>
    /// Sweeps orphaned proxy staging temp files (<c>dependably-stage-*.tmp</c>) and stale
    /// OCI staging files (<c>oci-upload-*</c> with no live DB row) whose last-write time is
    /// older than the TTL. In-flight files younger than the TTL are left untouched.
    /// </summary>
    private async Task<int> SweepOrphanFilesAsync(DateTimeOffset cutoff, CancellationToken ct)
    {
        if (!Directory.Exists(_stagingPath))
        {
            return 0;
        }

        int swept = 0;

        // Proxy-miss temp files: UpstreamClient creates dependably-stage-{guid}.tmp and
        // deletes them in a finally block. On SIGKILL the finally never runs, leaving orphans.
        // deepcode ignore PT: stagingPath is operator-configured PROXY_STAGING_PATH root — no user input reaches the enumeration path.
        var proxyTemps = Directory.EnumerateFiles(_stagingPath, "dependably-stage-*.tmp");
        foreach (string file in proxyTemps)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }
            swept += TrySweepOrphan(file, cutoff);
        }

        // OCI staging files with no live DB row: OciUploadService creates oci-upload-{guid}
        // files. Any such file whose age exceeds the TTL and has no matching DB row is an
        // orphan (the row was deleted but the file was not, e.g. on a prior failed cleanup).
        var ociFiles = Directory.EnumerateFiles(_stagingPath, "oci-upload-*");
        await using var conn = await _db.OpenAsync(ct);
        foreach (string file in ociFiles)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            string fileName = Path.GetFileName(file);
            // Extract the GUID from "oci-upload-{guid}". If it doesn't match the pattern,
            // skip it — don't touch files that might be from other tools.
            if (!fileName.StartsWith("oci-upload-", StringComparison.Ordinal))
            {
                continue;
            }
            string uploadId = fileName["oci-upload-".Length..];

            // xtenant: fleet-wide orphan check — checks all orgs for a matching row to
            // confirm the file is truly orphaned before deleting it.
            long liveRows = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(1) FROM oci_uploads WHERE upload_id = @uploadId",
                new { uploadId });

            if (liveRows > 0)
            {
                // File has a live DB row — the session is still active; skip it.
                continue;
            }

            swept += TrySweepOrphan(file, cutoff);
        }

        return swept;
    }

    private int TrySweepOrphan(string file, DateTimeOffset cutoff)
    {
        try
        {
            // deepcode ignore PT: file paths come from Directory.EnumerateFiles over the operator-configured staging root — no user input.
            var info = new FileInfo(file);
            if (!info.Exists)
            {
                return 0;
            }

            // Compare the file's last-write time against the caller-supplied cutoff, which
            // was derived from the injected TimeProvider. The filesystem timestamp itself
            // is a physical measurement of when the file was last written — not a wall-clock
            // substitution for time logic.
            // now-ok: LastWriteTimeUtc is a filesystem property of the file being evaluated; the cutoff comes from injected TimeProvider.
            var fileLastWrite = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
            if (fileLastWrite >= cutoff)
            {
                return 0;
            }

            // deepcode ignore PT: file path from enumeration over operator-configured staging root.
            File.Delete(file);
            _logger.LogInformation("OCI janitor swept orphaned staging file {File}.", file);
            return 1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(
                "OCI janitor could not delete orphaned file {File}: {ExceptionType}",
                file, ex.GetType().Name);
            return 0;
        }
    }

    /// <summary>
    /// Attempts to delete the staging file. Returns true on success or when the file does
    /// not exist (already cleaned up). Returns false and logs a warning on I/O failure,
    /// leaving the corresponding DB row intact for retry on the next pass.
    /// </summary>
    private bool TryDeleteFile(string path)
    {
        try
        {
            // deepcode ignore PT: path is the server-generated staging path from the DB; not user-controlled.
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(
                "OCI janitor could not delete staging file {StagingPath}: {ExceptionType}; row kept for next pass.",
                path, ex.GetType().Name);
            return false;
        }
    }

    private int ParseTtlMinutes()
    {
        return int.TryParse(_config["OCI_UPLOAD_TTL_MINUTES"], out int v) && v > 0 ? v : DefaultUploadTtlMinutes;
    }
}

/// <summary>Summary of a single OCI staging janitor pass.</summary>
public readonly record struct JanitorSummary(int SessionsSwept, int OrphansSwept);
