using Dapper;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Background GC worker that runs on a cron schedule (GC_SCHEDULE env var, default daily at 3am).
/// Enforces per-org retention policies:
///   - keep_versions: delete oldest versions beyond the limit per package (opt-in; NULL = off)
///   - keep_project_versions: delete oldest project versions beyond the limit per project, never
///     the is_latest row (opt-in; NULL = off)
///   - keep_days: evict proxy blobs unused beyond this many days (opt-in; NULL = off)
///   - purge_unlisted_after_days: hard-delete long-unlisted versions (opt-in; NULL = off)
///   - activity_retention_days: delete old activity rows; NULL resolves to the
///     ACTIVITY_RETENTION_DAYS instance default (90) so per-download IP/actor rows are bounded
///     by default rather than retained forever.
/// Plus instance-wide personal-data sweeps that run once per pass, not per org:
///   - audit_log: pseudonymize source_ip/detail past AUDIT_LOG_PII_DAYS (90), then delete past
///     AUDIT_LOG_RETENTION_DAYS (365) — a storage-limit for the highest-fidelity PII table.
///   - audit_event: same two-horizon shape as audit_log — pseudonymize source_ip/user_agent past
///     AUDIT_EVENT_PII_DAYS (90), then delete past AUDIT_EVENT_RETENTION_DAYS (365).
///   - login_attempts: delete idle, unlocked rows past LOGIN_ATTEMPTS_RETENTION_DAYS (30).
///   - account_send_throttle: delete rolled-over windows past ACCOUNT_SEND_THROTTLE_RETENTION_DAYS (7).
///   - mfa_trusted_devices: delete expired remembered-device rows.
///   - email_outbox: delete terminal rows past EMAIL_OUTBOX_TERMINAL_RETENTION_DAYS (30) — the only
///     delete path on the outbox, and the storage limit on the recipient addresses it holds.
///   - org_stats_history: delete rows older than STATS_HISTORY_RETENTION_DAYS (365) — the storage
///     limit on the dashboard's daily trend history. Observational only, same posture as the
///     table itself: nothing downstream of this sweep gates or reports on the rows it deletes.
///   - JWT revocations / invites / SAML one-shots: expiry prunes.
/// Respects the shutdown CancellationToken — stops at the next checkpoint.
/// </summary>
public sealed class RetentionService : ScheduledBackgroundService
{

    // Chunk size for the batched background_job_runs delete. Same reasoning as
    // AuditEventPruneBatchSize: bounded enough that each statement releases the writer lock
    // quickly, large enough that a months-deep backlog drains in a bounded number of round-trips.
    // Internal so tests seed a multi-chunk backlog scaled to this value rather than a copy of it.
    internal const int JobRunPruneBatchSize = 5000;

    /// <summary>
    /// Bounds <c>background_job_runs</c>, which nothing else deletes from. Successes age out at
    /// JOB_RUN_RETENTION_DAYS (14), everything else at JOB_RUN_FAILURE_RETENTION_DAYS (90) — a
    /// failed or cancelled run is the record an operator goes looking for, and there are few of
    /// them, so the cheap window is the one that removes almost all the volume.
    /// </summary>
    /// <remarks>
    /// The two rows per job that <c>HealthService</c> reads survive regardless of age; see
    /// <see cref="BackgroundJobRunRepository.PruneAsync"/> for which and why. Deletion is batched
    /// there, and looped here until a batch comes back short, so the first pass after an upgrade
    /// drains a months-deep backlog without holding one long write transaction.
    /// </remarks>
    internal async Task PruneBackgroundJobRunsAsync(CancellationToken ct)
    {
        int successDays = int.TryParse(_config["JOB_RUN_RETENTION_DAYS"], out int s) && s > 0 ? s : 14;
        int failureDays = int.TryParse(_config["JOB_RUN_FAILURE_RETENTION_DAYS"], out int f) && f > 0
            ? f : 90;
        var now = _time.GetUtcNow();
        // BackgroundJobRunRepository.RecordAsync is the only writer and stamps started_at at
        // second precision, so both cutoffs are formatted the same way — a finer-grained cutoff
        // would sort wrong against a stored value on the boundary second.
        string successCutoff = now.AddDays(-successDays).UtcDateTime.ToUtcIso();
        string failureCutoff = now.AddDays(-failureDays).UtcDateTime.ToUtcIso();

        int totalDeleted = 0;
        int deletedInChunk;
        do
        {
            deletedInChunk = await _jobRuns.PruneAsync(
                successCutoff, failureCutoff, JobRunPruneBatchSize, ct);
            totalDeleted += deletedInChunk;
        }
        while (deletedInChunk >= JobRunPruneBatchSize && !ct.IsCancellationRequested);

        if (totalDeleted > 0)
        {
            _logger.LogInformation(
                "Retention GC: deleted {Deleted} background_job_runs rows (successes older than {SuccessDays} days, other outcomes older than {FailureDays} days).",
                totalDeleted, successDays, failureDays);
        }
    }

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
        TrustedDeviceService TrustedDevices,
        IConfiguration Config,
        IAirGapMode AirGap,
        ILogger<RetentionService> Logger,
        TimeProvider Time,
        IDistributedLock Locks,
        Dependably.Protocol.OciOrphanBlobDeleter OciOrphanBlobs,
        Mail.EmailOutboxRepository EmailOutbox,
        Mail.EmailOutboxPolicy EmailOutboxPolicy,
        OrgStatsHistoryRepository StatsHistory,
        BackgroundJobRunRepository JobRuns);

    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly JwtRevocationRepository _jwtRevocations;
    private readonly InviteRepository _invites;
    private readonly SamlConfigRepository _samlConfig;
    private readonly TrustedDeviceService _trustedDevices;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<RetentionService> _logger;
    private readonly TimeProvider _time;
    private readonly PackageRepository _packages;
    private readonly Dependably.Protocol.OciOrphanBlobDeleter _ociOrphanBlobs;
    private readonly Mail.EmailOutboxRepository _emailOutbox;
    private readonly Mail.EmailOutboxPolicy _emailOutboxPolicy;
    private readonly OrgStatsHistoryRepository _statsHistory;
    private readonly BackgroundJobRunRepository _jobRuns;

    protected override string CronEnvKey => "GC_SCHEDULE";
    protected override string DefaultCron => "0 3 * * *";
    protected override string ScopeJobName => "retention";
    protected override string ScopeMetricName => "retention.gc";

    // Deletes shared version rows, blobs, and expired security/invite state — one replica per tick.
    protected override bool RequiresLeaderLock => true;

    public RetentionService(Dependencies deps)
        : base(deps.Config, deps.Logger, deps.Time, deps.Locks)
    {
        _db = deps.Db;
        _blobs = deps.Blobs;
        _jwtRevocations = deps.JwtRevocations;
        _invites = deps.Invites;
        _samlConfig = deps.SamlConfig;
        _trustedDevices = deps.TrustedDevices;
        _config = deps.Config;
        _airGap = deps.AirGap;
        _logger = deps.Logger;
        _time = deps.Time;
        // Stateless Dapper wrapper over the same IMetadataStore; built here rather than injected so
        // this singleton does not capture a scoped repository.
        _packages = new PackageRepository(deps.Db, time: deps.Time);
        _ociOrphanBlobs = deps.OciOrphanBlobs;
        _emailOutbox = deps.EmailOutbox;
        _emailOutboxPolicy = deps.EmailOutboxPolicy;
        _statsHistory = deps.StatsHistory;
        _jobRuns = deps.JobRuns;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunGcPassAsync(ct);

    // internal (not private) so RetentionPersonalDataSweepTests can drive a full pass — the
    // activity NULL-resolves-to-default logic and the instance-wide personal-data sweeps live
    // here, not in a per-table helper.
    internal async Task RunGcPassAsync(CancellationToken ct)
    {
        // A headless edge node holds no durable registry tier and no per-tenant retention
        // policy, so GC is inert there — edge mode force-disables retention (not in the allowlist).
        if (_airGap.IsJobDisabled("retention"))
        {
            _logger.LogInformation(
                "Retention GC skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return;
        }

        _logger.LogInformation("Retention GC pass starting.");

        await using var conn = await _db.OpenAsync(ct);

        // Fetch every active org (skip soft-deleted — TenantHardDeleteService owns those, and
        // retention work on a tenant pending hard-delete is wasted I/O). Unlike the version/blob
        // policies, which stay opt-in, activity pruning applies to every org: a NULL
        // activity_retention_days resolves to the instance default below, so the per-download
        // IP/actor rows are bounded for orgs that never set an explicit window. Iterating an org
        // whose opt-in policies are all NULL costs one indexed activity DELETE.
        //
        // A suspended/archived/deleting org is excluded the same way a soft-deleted one already
        // is — see TenantLifecycle for why this pass stops for a non-active org and the accepted
        // consequence (a suspended tenant's data stops aging out for as long as it stays
        // suspended, rather than continuing to be pruned on schedule).
        int activityDefaultDays = ResolveActivityRetentionDefaultDays();
        var orgs = await conn.QueryAsync<(string OrgId, int? KeepVersions, int? KeepDays, int? ActivityRetentionDays, int? PurgeUnlistedAfterDays, int? KeepProjectVersions)>(
            """
            SELECT o.id, s.keep_versions, s.keep_days, s.activity_retention_days,
                   s.purge_unlisted_after_days, s.keep_project_versions
            FROM orgs o
            JOIN org_settings s ON s.org_id = o.id
            WHERE o.deleted_at IS NULL
              AND o.status = 'active'
            """);

        foreach (var (OrgId, KeepVersions, KeepDays, ActivityRetentionDays, PurgeUnlistedAfterDays, KeepProjectVersions) in orgs)
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

            // NULL means "not configured", not "retain forever": fall back to the instance default.
            await PruneActivityAsync(conn, OrgId, ActivityRetentionDays ?? activityDefaultDays, _time.GetUtcNow(), ct);

            if (PurgeUnlistedAfterDays.HasValue)
            {
                await PurgeUnlistedAsync(conn, OrgId, PurgeUnlistedAfterDays.Value, ct);
            }

            if (KeepProjectVersions.HasValue)
            {
                await EnforceProjectVersionLimitAsync(conn, OrgId, KeepProjectVersions.Value, ct);
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

        // Pseudonymize then delete personal data in typed audit_event rows by age — the same
        // two-horizon shape as PruneAuditLogAsync below. Default delete window is 365 days, set in
        // cross-cutting-decisions.md section 4 (audit_event is append-only and archived after one
        // year). Hard delete for now; once archive support lands, the reaper will write to cold
        // storage first.
        await PruneAuditEventsAsync(conn, ct);

        // Reclaim expired SAML one-shot rows (pending requests, consumed assertions, test runs).
        // These prune on write too; this sweep bounds them when a tenant goes idle.
        await _samlConfig.PurgeExpiredSamlAsync(ct);

        // Pseudonymize then delete personal data in audit_log by age. audit_log has no FK to orgs
        // (forensic-retention design), so it neither cascades on tenant delete nor ages out on its
        // own — before this sweep it was the one high-fidelity PII table with no storage limit.
        await PruneAuditLogAsync(conn, ct);

        // Delete idle, unlocked login_attempts rows so the email-hash membership set does not grow
        // unbounded (one permanent, confirmable row per address ever attempted, incl. non-users).
        await PruneLoginAttemptsAsync(conn, ct);

        // Delete send-throttle rows whose window has long since rolled. Same membership-oracle
        // argument as login_attempts: a row is created for every address a reset was requested for,
        // including addresses that resolve to no account.
        await PruneAccountSendThrottleAsync(conn, ct);

        // Delete expired remembered-device rows. The service exposes this prune; nothing else calls
        // it, so an unbounded user_agent/last_seen_at device history accrued before this wiring.
        await _trustedDevices.PruneExpiredAsync(ct);

        // Delete long-terminal email_outbox rows. The outbox stores recipient addresses and rendered
        // bodies, and nothing in the delivery path ever deletes a row — terminal states are kept for
        // inspection on purpose. This is the only delete path, and the storage-limitation bound on
        // that data.
        await PruneEmailOutboxAsync(ct);

        // Delete org_stats_history rows past STATS_HISTORY_RETENTION_DAYS. Purely a storage
        // limit on the dashboard's own trend history — nothing else reads a deleted row.
        await PruneStatsHistoryAsync(ct);

        // Delete aged background_job_runs rows. Nothing else deletes from that table, and its
        // highest-volume writer is a 60-second timer, so without this sweep it grows without bound
        // and its own readers slow down as it does.
        await PruneBackgroundJobRunsAsync(ct);

        _logger.LogInformation("Retention GC pass complete.");
    }

    // Resolved by RetentionDefaults so the GC that enforces this window and the settings API that
    // reports it to the operator read one value. 90 days matches the schema column default and the
    // aggregate-survives-pruning design (tenant_artifact_access carries the monotonic
    // download_count, so analytics value does not depend on the per-event IP rows).
    private int ResolveActivityRetentionDefaultDays() =>
        RetentionDefaults.ResolveActivityRetentionDays(_config);

    // Two-horizon personal-data policy for audit_log, reconciling forensic value against Art.
    // 5(1)(e) storage limitation / Art. 17 erasure:
    //   * pseudonymize (drop source_ip + email/NameID-bearing detail) past AUDIT_LOG_PII_DAYS (90) —
    //     the forensic skeleton (actor_id, action, scope, timestamp) survives, the identifiers do not;
    //   * delete the row entirely past AUDIT_LOG_RETENTION_DAYS (365), matching the audit_event reaper.
    // Both horizons span every scope; per-tenant erasure on hard-delete is a separate org-scoped
    // path in TenantHardDeleteService. Chunked delete mirrors PruneAuditEventsAsync so a large
    // backlog never holds the writer lock for one long statement.
    internal async Task PruneAuditLogAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        int piiDays = int.TryParse(_config["AUDIT_LOG_PII_DAYS"], out int p) && p > 0 ? p : 90;
        int retentionDays = int.TryParse(_config["AUDIT_LOG_RETENTION_DAYS"], out int r) && r > 0 ? r : 365;
        var now = _time.GetUtcNow();
        // audit_log.created_at is millisecond-precision text (AuditRepository.WriteAsync is its only
        // writer), so both cutoffs are formatted at the same precision — a second-precision cutoff
        // sorts wrong against it on the boundary second, since '.' (0x2E) collates before 'Z' (0x5A),
        // which would delete/scrub rows one second newer than intended.
        string piiCutoff = now.AddDays(-piiDays).ToUtcIsoMillis();
        string deleteCutoff = now.AddDays(-retentionDays).ToUtcIsoMillis();

        // xtenant: instance-wide pseudonymization by age, same posture as PruneAuditEventsAsync —
        // every org's aged rows lose their identifiers together. actor_id is an opaque id, retained
        // as the forensic "who"; source_ip and detail are the personal fields dropped.
        int scrubbed = await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE audit_log SET source_ip = NULL, detail = NULL
            WHERE created_at < @piiCutoff AND (source_ip IS NOT NULL OR detail IS NOT NULL)
            """,
            new { piiCutoff },
            cancellationToken: ct));

        int totalDeleted = 0;
        int deletedInChunk;
        do
        {
            // xtenant: instance-wide retention sweep by age; same shape as the audit_event reaper.
            deletedInChunk = await conn.ExecuteAsync(new CommandDefinition(
                """
                DELETE FROM audit_log
                WHERE id IN (
                    SELECT id FROM audit_log WHERE created_at < @deleteCutoff LIMIT @batchSize
                )
                """,
                new { deleteCutoff, batchSize = AuditEventPruneBatchSize },
                cancellationToken: ct));
            totalDeleted += deletedInChunk;
        }
        while (deletedInChunk >= AuditEventPruneBatchSize && !ct.IsCancellationRequested);

        if (scrubbed > 0 || totalDeleted > 0)
        {
            _logger.LogInformation(
                "Audit reaper: pseudonymized {Scrubbed} audit_log rows older than {PiiDays} days, deleted {Deleted} older than {RetentionDays} days.",
                scrubbed, piiDays, totalDeleted, retentionDays);
        }
    }

    // Prune login_attempts rows that are idle past LOGIN_ATTEMPTS_RETENTION_DAYS (30) and not
    // currently locked. The window is far beyond any lockout duration, so an active throttle is
    // never dropped; the membership oracle over arbitrary attempted addresses is what ages out.
    internal async Task PruneLoginAttemptsAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        int retentionDays = int.TryParse(_config["LOGIN_ATTEMPTS_RETENTION_DAYS"], out int d) && d > 0 ? d : 30;
        var now = _time.GetUtcNow();
        string cutoff = now.AddDays(-retentionDays).ToUtcIso();
        string nowStr = now.ToUtcIso();

        // login_attempts has no org/tenant column of its own — the tenant is folded into the key
        // (LoginService.HashLockoutKey over realm/tenantId/email), not dropped from it. This sweep
        // is instance-wide because it is a single time-based retention pass over one physical
        // table, not because the throttle itself spans tenants.
        int deleted = await conn.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM login_attempts
            WHERE last_attempt < @cutoff AND (locked_until IS NULL OR locked_until < @now)
            """,
            new { cutoff, now = nowStr },
            cancellationToken: ct));

        if (deleted > 0)
        {
            _logger.LogInformation(
                "Retention GC: pruned {Count} idle login_attempts rows older than {Days} days.", deleted, retentionDays);
        }
    }

    // Prune account_send_throttle rows whose window started more than
    // ACCOUNT_SEND_THROTTLE_RETENTION_DAYS (7) ago. A row that old is inert — the next request for
    // that account restarts the window from 1 regardless — so deleting it changes no decision; it
    // only stops the pseudonym set growing without bound.
    internal async Task PruneAccountSendThrottleAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        int retentionDays = int.TryParse(_config["ACCOUNT_SEND_THROTTLE_RETENTION_DAYS"], out int d) && d > 0 ? d : 7;
        string cutoff = _time.GetUtcNow().AddDays(-retentionDays).ToUtcIso();

        // account_send_throttle has no org/tenant column — the tenant is folded into the key by
        // LoginService.HashLockoutKey, exactly as it is for login_attempts.
        // xtenant: instance-wide age sweep over a table keyed by a tenant-encoding pseudonym.
        int deleted = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM account_send_throttle WHERE window_start < @cutoff",
            new { cutoff },
            cancellationToken: ct));

        if (deleted > 0)
        {
            _logger.LogInformation(
                "Retention GC: pruned {Count} account_send_throttle rows older than {Days} days.", deleted, retentionDays);
        }
    }

    // Delete email_outbox rows that reached a terminal state (delivered, dead-lettered, or expired)
    // more than EMAIL_OUTBOX_TERMINAL_RETENTION_DAYS (30) ago. Terminal rows are deliberately not
    // removed by the delivery worker — a dead letter an operator cannot inspect is no better than a
    // dropped message — so this sweep is what keeps the recipient addresses and rendered bodies in
    // them from being retained indefinitely, and it logs what it removed so the removal is never
    // silent. Non-terminal rows are not touched here: they retire through the outbox's own retention
    // ceiling, which moves them to 'expired' rather than deleting them outright.
    internal async Task PruneEmailOutboxAsync(CancellationToken ct)
    {
        int retentionDays = _emailOutboxPolicy.TerminalRetentionDays;
        var cutoff = _time.GetUtcNow().AddDays(-retentionDays);

        int deleted = await _emailOutbox.PruneTerminalAsync(cutoff, ct);
        if (deleted > 0)
        {
            _logger.LogInformation(
                "Retention GC: pruned {Count} terminal email_outbox row(s) older than {Days} days.",
                deleted, retentionDays);
        }
    }

    // Deletes org_stats_history rows older than STATS_HISTORY_RETENTION_DAYS (default 365) —
    // the storage bound on the dashboard's daily trend history. day is a plain ISO date
    // (yyyy-MM-dd), so the cutoff is formatted the same way rather than through ToUtcIso, which
    // would emit a full instant that never matches the column's shape.
    internal async Task PruneStatsHistoryAsync(CancellationToken ct)
    {
        int retentionDays = int.TryParse(_config["STATS_HISTORY_RETENTION_DAYS"], out int d) && d > 0
            ? d : 365;
        string cutoffDay = _time.GetUtcNow().UtcDateTime.AddDays(-retentionDays)
            .ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

        int deleted = await _statsHistory.PruneOlderThanAsync(cutoffDay, ct);
        if (deleted > 0)
        {
            _logger.LogInformation(
                "Retention GC: pruned {Count} org_stats_history row(s) older than {Days} days.",
                deleted, retentionDays);
        }
    }

    // Chunk size for the batched audit_event delete below. Small enough that each chunk's
    // DELETE releases the writer lock quickly, large enough that a year-scale backlog drains
    // in a bounded number of round-trips. Internal (not private) so tests can seed a multi-chunk
    // backlog scaled to this exact size rather than hardcoding a copy of the production value.
    internal const int AuditEventPruneBatchSize = 5000;

    // Two-horizon personal-data policy for audit_event, mirroring PruneAuditLogAsync above:
    //   * pseudonymize (drop source_ip + user_agent) past AUDIT_EVENT_PII_DAYS (90) — the forensic
    //     skeleton (actor_id, event_type, payload, timestamp) survives, the identifiers do not;
    //   * delete the row entirely past AUDIT_EVENT_RETENTION_DAYS (365), unchanged from before.
    // Both horizons span every org; per-tenant erasure on tenant hard-delete is a separate
    // org-scoped path in TenantHardDeleteService (which pseudonymizes rather than deletes, since
    // audit_event.org_id's ON DELETE SET NULL means the schema already intends these rows to
    // outlive their org). payload is never scrubbed: unlike audit_log's freeform detail, every
    // typed event's payload is built from hashed/structural fields (AuditEmitter's callers hash
    // emails and NameIDs before they ever reach a payload), so it carries no raw identifier to drop.
    internal async Task PruneAuditEventsAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        int piiDays = int.TryParse(_config["AUDIT_EVENT_PII_DAYS"], out int p) && p > 0 ? p : 90;
        int retentionDays = int.TryParse(_config["AUDIT_EVENT_RETENTION_DAYS"], out int d) && d > 0
            ? d : 365;
        var now = _time.GetUtcNow();
        // audit_event.occurred_at is millisecond-precision text (AuditEventRepository.InsertAsync
        // is its only writer), so both cutoffs are formatted at the same precision — see
        // PruneAuditLogAsync's comment for why a second-precision cutoff sorts wrong against it on
        // the boundary second.
        string piiCutoff = now.AddDays(-piiDays).ToUtcIsoMillis();
        string deleteCutoff = now.AddDays(-retentionDays).ToUtcIsoMillis();

        // xtenant: instance-wide pseudonymization by age, same posture as PruneAuditLogAsync —
        // every org's aged rows lose their identifiers together.
        int scrubbed = await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE audit_event SET source_ip = NULL, user_agent = NULL
            WHERE occurred_at < @piiCutoff AND (source_ip IS NOT NULL OR user_agent IS NOT NULL)
            """,
            new { piiCutoff },
            cancellationToken: ct));

        // Hard-delete is the right shape today: there's no archive destination yet (decision
        // deferred per cross-cutting-decisions.md). When archive lands, this becomes a copy
        // followed by a delete behind a single transaction.
        //
        // Deletes in bounded chunks keyed by the event_id primary key (portable across SQLite
        // and Postgres — both support LIMIT inside the subselect) so a year-scale backlog
        // never holds the writer lock for one long-running statement; the lock is released
        // between chunks for other writers to make progress.
        int totalDeleted = 0;
        int deletedInChunk;
        do
        {
            // xtenant: instance-wide retention sweep by age, same as JwtRevocationRepository /
            // InviteRepository's expiry-only prunes — every org's stale rows age out together.
            deletedInChunk = await conn.ExecuteAsync(new CommandDefinition(
                """
                DELETE FROM audit_event
                WHERE event_id IN (
                    SELECT event_id FROM audit_event WHERE occurred_at < @deleteCutoff LIMIT @batchSize
                )
                """,
                new { deleteCutoff, batchSize = AuditEventPruneBatchSize },
                cancellationToken: ct));
            totalDeleted += deletedInChunk;
        }
        while (deletedInChunk >= AuditEventPruneBatchSize && !ct.IsCancellationRequested);

        if (scrubbed > 0 || totalDeleted > 0)
        {
            _logger.LogInformation(
                "Audit reaper: pseudonymized {Scrubbed} audit_event rows older than {PiiDays} days, deleted {Deleted} older than {RetentionDays} days.",
                scrubbed, piiDays, totalDeleted, retentionDays);
        }
    }

    /// <summary>
    /// Releases the bytes behind a version whose catalogue row this pass has just deleted.
    ///
    /// For every ecosystem but OCI the catalogue row owns its blob one-to-one, so the blob is
    /// deleted here directly. OCI is the exception, and the reason the eviction drivers excluded it
    /// outright until now: an OCI catalogue row's <c>blob_key</c> is the *manifest*, which
    /// <c>oci_blobs</c> also points at and which the image's layers hang off. Deleting it here would
    /// destroy the manifest while its <c>oci_blobs</c> row, its tags, and every layer survived — a
    /// broken serve path plus orphaned bytes nothing would ever reclaim.
    ///
    /// So an OCI version is *released*, not deleted. <see cref="PackageRepository.ReleaseOciDigestClaimAsync"/>
    /// drops the repository's tags for the digest and removes this org's <c>oci_blobs</c> row only
    /// when no claim survives anywhere in the org — a tag under another repository, or a hosted
    /// <c>package_versions</c> row carrying the digest — returning the blob key just when the row
    /// actually came off and the bytes were uploaded. Physical deletion then goes through
    /// <see cref="OciOrphanBlobDeleter"/>, which holds the per-key lock and counts across every org,
    /// because OCI blob keys carry no org segment. The image's layers are left to
    /// <see cref="OciBlobReclaimer"/>'s sweep, which reclaims them once nothing references them.
    ///
    /// Dropping the tags matters as much as dropping the row: a surviving <c>oci_tags</c> row is one
    /// of the four claims the sweep honours, so an eviction that left the tag behind would pin the
    /// manifest and its whole layer closure forever — the eviction would appear to work and reclaim
    /// nothing.
    /// </summary>
    private async Task RetireVersionAsync(
        string orgId, string ecosystem, string name, string version, string blobKey, CancellationToken ct)
    {
        if (!string.Equals(ecosystem, "oci", StringComparison.Ordinal))
        {
            await _blobs.DeleteAsync(BlobKeys.StoreKey(blobKey), ct);
            return;
        }

        string? orphaned = await _packages.ReleaseOciDigestClaimAsync(orgId, name, version, ct);
        if (orphaned is not null)
        {
            await _ociOrphanBlobs.DeleteIfUnreferencedAsync(orphaned, ct);
        }
    }

    // internal (not private) so RetentionServiceCacheExclusionTests can drive it directly without
    // the full cron/config scheduling machinery — mirrors PurgeUnlistedAsync below.
    internal async Task EnforceVersionLimitAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepVersions, CancellationToken ct)
    {
        // Uploaded versions: keep the most recent N per package; delete older ones from package_versions.
        // OCI participates, but never through the direct blob delete below — see RetireVersionAsync.
        var uploadedToDelete = await conn.QueryAsync<(string VersionId, string BlobKey, string Ecosystem, string Name, string Version)>(
            // plane-ok: uploaded-plane version-limit driver; the proxy plane is evicted by the sibling cache_artifact/tenant_artifact_access query below in this method.
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey, p.ecosystem AS Ecosystem,
                   p.purl_name AS Name, pv.version AS Version
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

        foreach (var (VersionId, BlobKey, Ecosystem, Name, Version) in uploadedToDelete)
        {
            if (ct.IsCancellationRequested) { break; }
            // xtenant: keyed by a version PK from the p.org_id = @orgId SELECT above.
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
            await RetireVersionAsync(orgId, Ecosystem, Name, Version, BlobKey, ct);
            _logger.LogDebug("GC: deleted uploaded version {Id} (blob {Key})", VersionId, BlobKey);
        }

        // Proxy versions: keep this org's @keepVersions least-recently-accessed VERSIONS per name
        // and evict every row of every version below that cut. Removes the tenant_artifact_access
        // row; cascade-deletes the cache_artifact and its blob when no other tenant retains access.
        //
        // The keep-set ranks versions, not rows, because cache_artifact is keyed
        // UNIQUE (ecosystem, name, version, filename): one version owns one row per file, so a
        // Maven version spans jar+pom+sources+javadoc. Ranking rows would make keep_versions=5
        // retain about one real Maven version, and — because the cut could fall between two files
        // of the same version — could evict a version's .pom while keeping its .jar, leaving a
        // partial version that resolves broken. A version's recency is its most recently accessed
        // file (MAX), and the NOT IN predicate matches on ca.version, so a version is always
        // wholly kept or wholly evicted. Versions are ordered by recency then by version as a
        // tiebreak, so two versions cached within the same second cut deterministically rather
        // than by plan order.
        // OCI participates; its rows are retired through RetireProxyVersionAsync rather than the
        // direct blob delete, for the reason spelled out on RetireVersionAsync.
        // xtenant: cache_artifact is global; org_id filter is in tenant_artifact_access.
        var proxyToEvict = await conn.QueryAsync<(string CacheArtifactId, string Ecosystem, string Name, string Version, string BlobKey, string? TenantBlobKey)>(
            """
            SELECT ca.id AS CacheArtifactId, ca.ecosystem AS Ecosystem, ca.name AS Name,
                   ca.version AS Version, ca.blob_key AS BlobKey, taa.blob_key AS TenantBlobKey
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND ca.version NOT IN (
                  SELECT ca2.version
                  FROM tenant_artifact_access taa2
                  JOIN cache_artifact ca2 ON ca2.id = taa2.cache_artifact_id
                  WHERE taa2.org_id = @orgId AND ca2.name = ca.name AND ca2.ecosystem = ca.ecosystem
                  GROUP BY ca2.version
                  ORDER BY MAX(taa2.last_accessed_at) DESC, ca2.version DESC
                  LIMIT @keepVersions
              )
            """,
            new { orgId, keepVersions });

        // Grouped by full version identity — (ecosystem, name, version), since two names or two
        // ecosystems can share a version string — so the cancellation checkpoint falls on a version
        // boundary. Checking it per row would let a shutdown land mid-version and leave exactly the
        // partial version the keep-set is shaped to prevent; a version whose eviction has started
        // runs to completion.
        foreach (var versionGroup in proxyToEvict.GroupBy(r => (r.Ecosystem, r.Name, r.Version)))
        {
            if (ct.IsCancellationRequested) { break; }

            foreach (var (CacheArtifactId, Ecosystem, Name, Version, BlobKey, TenantBlobKey) in versionGroup)
            {
                await conn.ExecuteAsync(
                    "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                    new { orgId, id = CacheArtifactId });

                bool isOci = string.Equals(Ecosystem, "oci", StringComparison.Ordinal);

                if (!isOci)
                {
                    await ReclaimTenantBoundBlobAsync(conn, TenantBlobKey, BlobKey);
                }

                // Delete the global cache_artifact and its blob when no tenant retains access.
                // xtenant: deliberately cross-tenant — this counts whether ANY OTHER tenant still
                // retains access to the shared cache_artifact before its blob is deleted. Filtering
                // by org_id here would always return 0 and delete a blob other tenants still use.
                long remaining = await conn.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
                    new { id = CacheArtifactId });
                if (remaining == 0)
                {
                    if (!isOci)
                    {
                        // CancellationToken.None, unlike every other blob delete in this service: the
                        // version boundary above is the checkpoint, and honouring ct here would let a
                        // shutdown abort between two files of one version — dropping a version's .jar
                        // while its .pom survives. The extra work a cancelled pass takes on is bounded
                        // by one version's file count.
                        await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), CancellationToken.None);
                    }

                    // The catalogue row goes either way — for OCI it is metadata over a manifest
                    // oci_blobs owns, so dropping it is both safe and necessary: a surviving
                    // cache_artifact row is one of the claims that would pin the manifest.
                    await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id = CacheArtifactId });
                }

                // Released per org rather than inside the remaining == 0 guard: oci_blobs is keyed
                // (digest, org_id), so this org's row comes off when this org stops holding the
                // image, whatever other tenants still cache it. The cross-org question is settled
                // by OciOrphanBlobDeleter before any byte is removed.
                if (isOci)
                {
                    await RetireVersionAsync(orgId, Ecosystem, Name, Version, BlobKey, CancellationToken.None);
                }
                _logger.LogDebug("GC: evicted proxy artifact {Id} name={Name} version={Version} (blob {Key})",
                    CacheArtifactId, Name, Version, BlobKey);
            }
        }
    }

    /// <summary>
    /// Opt-in projects-plane cap: keeps the most recently created <paramref name="keepProjectVersions"/>
    /// versions of each project and deletes the rest, releasing their SBOM/VEX/SARIF document blobs.
    ///
    /// <para>The uploaded and proxy catalogues both carry a bound; the projects plane carries none
    /// without this, so the one-SBOM-per-build CI pattern the plane exists to serve accretes a
    /// version row plus its whole component set on every build, permanently, with an interactive
    /// delete as the only reclaim.</para>
    ///
    /// <para>The <c>is_latest</c> row is never deleted, whatever its rank or age. A project with no
    /// latest version is a broken state rather than a small one — every <c>latest</c> route answers
    /// 404 and the list rollup degrades to "Not scanned" — and a retention cap must not be able to
    /// manufacture it. That row still participates in the ranking, so a project whose latest version
    /// is also its newest sees the cap honoured exactly; a project whose operator promoted an older
    /// version keeps one extra row, which is the safe direction to be wrong in.</para>
    ///
    /// <para>Blob keys are enumerated BEFORE the delete, the same ordering the interactive delete
    /// path uses: <c>project_documents.blob_key</c> is the blob's only reference, so once the FK
    /// cascade has removed the metadata row there is nothing left to read the key from and the bytes
    /// are stranded on the registry tier. The orphan reconciler is a backstop for lost races, not a
    /// substitute for naming the keys a deliberate delete releases.</para>
    /// </summary>
    // internal (not private) so the retention tests can drive it without the cron machinery —
    // mirrors EnforceVersionLimitAsync above and PurgeUnlistedAsync below.
    internal async Task EnforceProjectVersionLimitAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepProjectVersions, CancellationToken ct)
    {
        // Oldest-first, so a pass the shutdown token cuts short has made the progress an operator
        // would expect it to make — the rows furthest past the cap go first — rather than a
        // plan-order-dependent arbitrary subset.
        var toDelete = (await conn.QueryAsync<(string VersionId, string ProjectId, string Version)>(
            """
            SELECT pv.id AS VersionId, pv.project_id AS ProjectId, pv.version AS Version
            FROM project_versions pv
            WHERE pv.org_id = @orgId
              AND pv.is_latest = 0
              AND pv.id NOT IN (
                  SELECT pv2.id FROM project_versions pv2
                  WHERE pv2.org_id = @orgId AND pv2.project_id = pv.project_id
                  ORDER BY pv2.created_at DESC, pv2.id DESC
                  LIMIT @keepProjectVersions
              )
            ORDER BY pv.created_at, pv.id
            """,
            new { orgId, keepProjectVersions })).AsList();

        foreach (var (VersionId, ProjectId, Version) in toDelete)
        {
            if (ct.IsCancellationRequested) { break; }

            var blobKeys = (await conn.QueryAsync<string>(
                """
                SELECT d.blob_key FROM project_documents d
                WHERE d.org_id = @orgId AND d.project_version_id = @versionId
                """,
                new { orgId, versionId = VersionId })).AsList();

            // The DELETE re-asserts is_latest = 0 rather than trusting the id the SELECT chose.
            // The two run on one connection with no transaction between them, and a promotion —
            // interactive, or the auto-latest a new upload takes — can land in that window and
            // make this row the project's latest. Deleting it then manufactures exactly the
            // zero-latest state this cap exists not to manufacture. Re-asserting the predicate
            // costs nothing and makes the race a no-op instead of a broken project.
            int affected = await conn.ExecuteAsync(
                "DELETE FROM project_versions WHERE org_id = @orgId AND id = @versionId AND is_latest = 0",
                new { orgId, versionId = VersionId });

            if (affected == 0)
            {
                // The row was promoted out from under the sweep. Its documents are still
                // referenced by a live version, so releasing the bytes enumerated above would
                // strand the surviving metadata rows pointing at deleted blobs.
                _logger.LogDebug(
                    "GC: skipped project version {VersionId} (project {ProjectId}, version {Version}); it was promoted to latest after the sweep selected it.",
                    VersionId, ProjectId, Version);
                continue;
            }

            foreach (string key in blobKeys)
            {
                await _blobs.DeleteAsync(BlobKeys.StoreKey(key), ct);
            }

            _logger.LogDebug(
                "GC: deleted project version {VersionId} (project {ProjectId}, version {Version}, {Documents} document(s))",
                VersionId, ProjectId, Version, blobKeys.Count);
        }
    }

    /// <summary>
    /// Reclaims the bytes an org fetched for a coordinate when its own upstream served content
    /// other than the shared <c>cache_artifact</c> row's. Called once the org's
    /// <c>tenant_artifact_access</c> row is gone, on the proxy arms only.
    ///
    /// A divergent binding is the only record that its blob exists — no <c>cache_artifact.blob_key</c>
    /// anywhere names it — so a purge that reclaims only the shared key strands those bytes on the
    /// cache tier for good. The refcount before the delete is what keeps a second tenant that
    /// resolved the same divergent bytes serving: content-addressed proxy keys are shared by
    /// construction, so "this org no longer needs it" is not "nobody needs it".
    /// </summary>
    private async Task ReclaimTenantBoundBlobAsync(
        System.Data.Common.DbConnection conn, string? tenantBlobKey, string sharedBlobKey)
    {
        if (tenantBlobKey is null || string.Equals(tenantBlobKey, sharedBlobKey, StringComparison.Ordinal))
        {
            return;
        }

        // xtenant: a physical blob is shared across tenants, so whether it is still referenced is
        // deliberately asked of every org's rows and bindings — scoping to one tenant would strand
        // another tenant's bytes.
        long referenced = await conn.ExecuteScalarAsync<long>(
            """
            SELECT (SELECT COUNT(*) FROM cache_artifact WHERE blob_key = @tenantBlobKey)
                 + (SELECT COUNT(*) FROM tenant_artifact_access WHERE blob_key = @tenantBlobKey)
            """,
            new { tenantBlobKey });
        if (referenced > 0)
        {
            return;
        }

        // CancellationToken.None for the same reason the shared-key delete below uses it: the
        // version boundary is the checkpoint, and aborting mid-version leaves a partial version.
        await _blobs.DeleteAsync(BlobKeys.StoreKey(tenantBlobKey), CancellationToken.None);
    }

    // internal (not private) so RetentionServiceCacheExclusionTests can drive it directly — see
    // EnforceVersionLimitAsync above.
    internal async Task EvictStaleBlobsAsync(
        System.Data.Common.DbConnection conn, string orgId, int keepDays, CancellationToken ct)
    {
        string cutoff = _time.GetUtcNow().AddDays(-keepDays).ToUtcIso();

        // Uploaded versions: evict by last_used timestamp on package_versions. OCI participates,
        // retired through RetireVersionAsync rather than the direct blob delete.
        var uploadedStale = await conn.QueryAsync<(string VersionId, string BlobKey, string Ecosystem, string Name, string Version)>(
            // plane-ok: uploaded-plane stale-blob driver; the proxy plane is evicted by the sibling cache_artifact/tenant_artifact_access query below in this method.
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey, p.ecosystem AS Ecosystem,
                   p.purl_name AS Name, pv.version AS Version
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND pv.last_used IS NOT NULL AND pv.last_used < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (VersionId, BlobKey, Ecosystem, Name, Version) in uploadedStale)
        {
            if (ct.IsCancellationRequested) { break; }
            // xtenant: keyed by a version PK from the p.org_id = @orgId SELECT above.
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
            await RetireVersionAsync(orgId, Ecosystem, Name, Version, BlobKey, ct);
        }

        // Proxy versions: evict every row of this org's versions whose whole file set has aged
        // past the cutoff. Removes the per-tenant rows; cascade-deletes the global cache_artifact
        // and its blob when no other tenant retains access.
        //
        // The staleness decision is per VERSION, not per row, because cache_artifact is keyed
        // UNIQUE (ecosystem, name, version, filename): one version owns one row per file, and
        // those rows carry independent last_used values — a Maven version's .jar is re-read on
        // every build while its .pom may not be. Judging rows would evict the .pom and keep the
        // .jar, leaving a partial version that resolves broken. Same failure the keep_versions
        // arm above ranks versions to avoid, reached by the age filter instead.
        //
        // A version is stale only when NO file of it is either fresh or never-used: the NOT EXISTS
        // treats a NULL last_used as not-evictable, exactly as the previous per-row
        // `last_used IS NOT NULL` predicate did, so a version holding one never-read file survives
        // whole rather than being half-evicted. That is the conservative reading — it can retain a
        // version the newest-file rule would drop, never the reverse.
        // OCI participates — retired through RetireVersionAsync, see EnforceVersionLimitAsync.
        // xtenant: cache_artifact is global; org_id filter is in tenant_artifact_access.
        var proxyStale = await conn.QueryAsync<(string CacheArtifactId, string Ecosystem, string Name, string Version, string BlobKey, string? TenantBlobKey)>(
            """
            SELECT ca.id AS CacheArtifactId, ca.ecosystem AS Ecosystem, ca.name AS Name,
                   ca.version AS Version, ca.blob_key AS BlobKey, taa.blob_key AS TenantBlobKey
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND NOT EXISTS (
                  SELECT 1
                  FROM tenant_artifact_access taa2
                  JOIN cache_artifact ca2 ON ca2.id = taa2.cache_artifact_id
                  WHERE taa2.org_id = @orgId
                    AND ca2.ecosystem = ca.ecosystem
                    AND ca2.name = ca.name
                    AND ca2.version = ca.version
                    AND (taa2.last_used IS NULL OR taa2.last_used >= @cutoff)
              )
            """,
            new { orgId, cutoff });

        // Grouped by full version identity — (ecosystem, name, version), since two names or two
        // ecosystems can share a version string — so the cancellation checkpoint falls on a version
        // boundary. Checking it per row would let a shutdown land mid-version and leave exactly the
        // partial version the query above is shaped to prevent.
        foreach (var versionGroup in proxyStale.GroupBy(r => (r.Ecosystem, r.Name, r.Version)))
        {
            if (ct.IsCancellationRequested) { break; }

            foreach (var (CacheArtifactId, Ecosystem, Name, VersionId, BlobKey, TenantBlobKey) in versionGroup)
            {
                await conn.ExecuteAsync(
                    "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
                    new { orgId, id = CacheArtifactId });

                if (!string.Equals(Ecosystem, "oci", StringComparison.Ordinal))
                {
                    await ReclaimTenantBoundBlobAsync(conn, TenantBlobKey, BlobKey);
                }

                // xtenant: deliberately cross-tenant — this counts whether ANY OTHER tenant still
                // retains access to the shared cache_artifact before its blob is deleted. Filtering
                // by org_id here would always return 0 and delete a blob other tenants still use.
                long remaining = await conn.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
                    new { id = CacheArtifactId });
                bool isOci = string.Equals(Ecosystem, "oci", StringComparison.Ordinal);
                if (remaining == 0)
                {
                    if (!isOci)
                    {
                        // CancellationToken.None, unlike the uploaded arm above: the version boundary
                        // is the checkpoint, and honouring ct here would let a shutdown abort between
                        // two files of one version. Bounded by one version's file count.
                        await _blobs.DeleteAsync(BlobKeys.StoreKey(BlobKey), CancellationToken.None);
                    }

                    await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id = CacheArtifactId });
                }

                if (isOci)
                {
                    await RetireVersionAsync(orgId, Ecosystem, Name, VersionId, BlobKey, CancellationToken.None);
                }
            }
        }
    }

    /// <summary>
    /// Hard-deletes hosted (origin='uploaded') versions that have stayed unlisted longer than
    /// the org's purge_unlisted_after_days policy, reclaiming the row and its registry-tier blob.
    /// The age is measured from yanked_at — rows whose unlist pre-dates that column (NULL
    /// yanked_at) are never age-purgeable, so an operator can re-unlist to restart the clock.
    /// Proxy rows are excluded by the origin discriminator; cache-tier eviction is owned by
    /// CacheEvictionService.
    /// </summary>
    internal async Task PurgeUnlistedAsync(
        System.Data.Common.DbConnection conn, string orgId, int afterDays, CancellationToken ct)
    {
        string cutoff = _time.GetUtcNow().AddDays(-afterDays).ToUtcIso();

        // OCI participates, retired through RetireVersionAsync rather than the direct blob delete.
        var toPurge = await conn.QueryAsync<(string VersionId, string BlobKey, string Ecosystem, string Name, string Version)>(
            // plane-ok: uploaded-plane unlisted purge; proxy rows are excluded by the origin discriminator and cache-tier eviction is owned by CacheEvictionService.
            """
            SELECT pv.id as VersionId, pv.blob_key as BlobKey, p.ecosystem AS Ecosystem,
                   p.purl_name AS Name, pv.version AS Version
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND pv.origin = 'uploaded'
              AND pv.yanked = 1
              AND pv.yanked_at IS NOT NULL AND pv.yanked_at < @cutoff
            """,
            new { orgId, cutoff });

        foreach (var (VersionId, BlobKey, Ecosystem, Name, Version) in toPurge)
        {
            if (ct.IsCancellationRequested) { break; }
            // xtenant: keyed by a version PK from the p.org_id = @orgId SELECT above.
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = VersionId });
            await RetireVersionAsync(orgId, Ecosystem, Name, Version, BlobKey, ct);
            _logger.LogDebug("GC: purged unlisted version {Id} (blob {Key})", VersionId, BlobKey);
        }
    }

    // Chunk size for the batched activity delete below, mirroring AuditEventPruneBatchSize.
    // Internal (not private) so tests can seed a multi-chunk backlog scaled to this exact size
    // rather than hardcoding a copy of the production value.
    internal const int ActivityPruneBatchSize = 5000;

    private static async Task PruneActivityAsync(
        System.Data.Common.DbConnection conn, string orgId, int retentionDays, DateTimeOffset now, CancellationToken ct)
    {
        // activity.created_at is millisecond-precision text (AuditRepository.LogActivityAsync is its
        // only writer), so the cutoff is formatted at the same precision — a second-precision cutoff
        // sorts wrong against it on the boundary second, since '.' (0x2E) collates before 'Z' (0x5A),
        // which would delete rows one second newer than the retention window intends.
        string cutoff = now.AddDays(-retentionDays).ToUtcIsoMillis();

        // Deletes in bounded chunks keyed by the id primary key, the same shape
        // PruneAuditEventsAsync uses and for the same reason: activity is the highest-volume table
        // in the schema (one row per download), so one unbounded statement is the worst case here,
        // not the mildest. A backlog — retention re-enabled after a spell with jobs disabled, or a
        // window shortened by an operator — would otherwise delete millions of rows in a single
        // transaction, holding locks and bloating the table against a live serving cluster for the
        // whole run. The lock is released between chunks so other writers make progress.
        int deletedInChunk;
        do
        {
            deletedInChunk = await conn.ExecuteAsync(new CommandDefinition(
                """
                DELETE FROM activity
                WHERE id IN (
                    SELECT id FROM activity
                    WHERE org_id = @orgId AND created_at < @cutoff
                    LIMIT @batchSize
                )
                """,
                new { orgId, cutoff, batchSize = ActivityPruneBatchSize },
                cancellationToken: ct));
        }
        while (deletedInChunk >= ActivityPruneBatchSize && !ct.IsCancellationRequested);
    }
}
