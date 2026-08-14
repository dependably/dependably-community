using System.Linq;
using Cronos;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;

namespace Dependably.Background;

/// <summary>
/// Background job that hard-deletes tenants whose <c>orgs.deleted_at</c> is older than
/// <c>TENANT_HARD_DELETE_GRACE_DAYS</c> (default 30). Hard delete is a single guarded
/// <c>DELETE FROM orgs WHERE id = @id AND deleted_at IS NOT NULL AND deleted_at &lt; @cutoff</c>
/// that re-asserts the soft-deleted-past-grace predicate, so a concurrent restore between the
/// expired-list snapshot and the delete is honored (0 rows deleted → tenant left intact); FK
/// cascade removes the per-tenant data that carries an FK to <c>orgs</c> (org_settings, packages,
/// package_versions, tokens, invites, activity, etc.). Each successful hard-delete writes an
/// <c>audit_log</c> entry with <c>scope='system'</c>, <c>action='tenant.hard_deleted'</c>. A
/// transient DB failure on one tenant is logged and skipped so it cannot escape and, under
/// BackgroundService's default StopHost behavior, take the whole replica down.
///
/// One tenant's whole erasure — the guarded DELETE, the three non-cascading relations below, the
/// <c>audit_event</c> pseudonymization, and the <c>tenant.hard_deleted</c> audit row — runs in a
/// single transaction, so that skip is genuinely a retry rather than a partial erasure left behind
/// forever: the next pass's worklist is a <c>SELECT</c> over <c>orgs</c>, so an org row committed
/// away ahead of its dependent rows could never be listed again, and whatever was left behind
/// would be unreachable. Rolling the org row back with everything else is what keeps the tenant in
/// the worklist for the next pass.
///
/// Three relations carry no FK to <c>orgs</c>, so they do not cascade and are erased explicitly for
/// the org: <c>banners</c>; the tenant-scoped (<c>scope='tenant'</c>) <c>audit_log</c> rows — to
/// discharge Art. 17 erasure, since the forensic-retention design deliberately omits that FK
/// (operator <c>scope='system'</c> lifecycle rows are retained); and each surviving member's
/// <c>login_attempts</c>/<c>account_send_throttle</c> row — keyed by
/// <see cref="Dependably.Infrastructure.LoginService.HashLockoutKey"/> over (realm, tenantId,
/// email) rather than a user id, so the member emails are snapshotted before the guarded DELETE
/// cascades the <c>users</c> rows away, or there is nothing left to derive the keys from.
///
/// <c>audit_event.org_id</c> is the opposite shape: it carries an FK, but one that says
/// <c>ON DELETE SET NULL</c> rather than restrict/cascade, so the org's typed audit rows survive
/// deletion by design. Rather than erase them, the personal identifiers (<c>source_ip</c>,
/// <c>user_agent</c>) are pseudonymized — the same treatment as <c>audit_log</c>'s age-based
/// horizon, applied at the org's grain. The affected ids are snapshotted before the DELETE for the
/// same reason the member emails are: once the cascade fires, <c>org_id</c> is NULL on every one
/// of them, indistinguishable from any other org's already-orphaned rows.
///
/// Schedule: <c>TENANT_HARD_DELETE_SCHEDULE</c> cron (default <c>0 4 * * *</c> — once daily,
/// staggered 1h after the standard retention sweep).
/// </summary>
public sealed class TenantHardDeleteService : BackgroundService
{
    // In a multi-replica (HA) deployment every replica runs this cron; without coordination each
    // would list the same expired orgs, race the DELETE, and write its own tenant.hard_deleted
    // audit row. Only the sweep-lock winner runs the pass. Standalone always wins the in-process
    // lock. The sweep holds the lock through a LeaderLease that heartbeats the TTL, so the TTL
    // bounds how long the lock survives a crashed leader, not how long a sweep may take.
    private static readonly TimeSpan SweepLockTtl = TimeSpan.FromMinutes(5);
    private const string SweepLockName = "tenant-hard-delete:sweep";

    // Chunk size for the audit_event pseudonymization UPDATE below. Keeps one tenant's IN clause
    // well under SQLite's bound-parameter ceiling regardless of how large that tenant's audit
    // history is.
    private const int AuditEventPseudonymizeChunkSize = 500;

    private readonly OrgRepository _orgs;
    private readonly AuditRepository _audit;
    private readonly IMetadataStore _db;
    private readonly BannerRepository _banners;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly IDistributedLock _locks;
    private readonly ILogger<TenantHardDeleteService> _logger;
    private readonly TimeProvider _time;
    private readonly Dependably.Infrastructure.SystemEvents.ISystemEventNotifier? _systemEvents;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Dependency-injection constructor: the parameter list is the declared dependency set.")]
    public TenantHardDeleteService(
        OrgRepository orgs,
        AuditRepository audit,
        IMetadataStore db,
        BannerRepository banners,
        IConfiguration config,
        IAirGapMode airGap,
        IDistributedLock locks,
        ILogger<TenantHardDeleteService> logger,
        TimeProvider time,
        Dependably.Infrastructure.SystemEvents.ISystemEventNotifier? systemEvents = null)
    {
        _orgs = orgs;
        _audit = audit;
        _db = db;
        _banners = banners;
        _config = config;
        _airGap = airGap;
        _locks = locks;
        _logger = logger;
        _time = time;
        _systemEvents = systemEvents;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var schedule = CronExpression.Parse(
            _config["TENANT_HARD_DELETE_SCHEDULE"] ?? "0 4 * * *",
            CronFormat.Standard);

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(_time.GetUtcNow(), TimeZoneInfo.Utc);
            if (next is null)
            {
                break;
            }

            var delay = next.Value - _time.GetUtcNow();
            if (delay > TimeSpan.Zero)
            {
                try { await Task.Delay(delay, _time, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }

            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            await RunPassAsync(stoppingToken);
        }
    }

    public async Task RunPassAsync(CancellationToken ct)
    {
        // A headless edge node has one implicit org and never soft-deletes tenants, so this sweep
        // is inert there — edge mode force-disables tenant-hard-delete (not in the allowlist).
        if (_airGap.IsJobDisabled("tenant-hard-delete"))
        {
            return;
        }

        // Coordinate across replicas: only the lock winner performs the destructive sweep and
        // writes the tenant.hard_deleted audit rows. In standalone mode the in-process lock always
        // grants on first acquire, so the single node sweeps normally.
        ILockHandle? sweepLock;
        try
        {
            sweepLock = await _locks.TryAcquireAsync(SweepLockName, SweepLockTtl, ct);
        }
        catch (Exception ex)
        {
            // ExecuteAsync's cron loop has no catch around RunPassAsync, so an uncaught exception
            // here escapes and — under BackgroundService's default StopHost behavior — takes the
            // whole replica down on a routine distributed-lock backend blip (e.g. Redis
            // failover). Treat it exactly like "another instance holds the lock": skip this pass.
            _logger.LogError(ex, "TenantHardDelete sweep skipped — sweep lock acquire failed.");
            return;
        }

        if (sweepLock is null)
        {
            _logger.LogDebug("TenantHardDelete sweep skipped — another instance holds the sweep lock.");
            return;
        }

        // A sweep over a large tenant set can outrun the lock TTL, at which point a second
        // replica would acquire the same lock and start a concurrent hard-delete pass. Renew the
        // lease for as long as the sweep runs, and abort the sweep if renewal fails: an instance
        // that has lost its lease must stop deleting rather than finish unleased.
        var lease = LeaderLease.Start(sweepLock, SweepLockTtl, _time, _logger, ct);
        var leaseCt = lease.Token;
        try
        {
            int graceDays = int.TryParse(_config["TENANT_HARD_DELETE_GRACE_DAYS"], out int g) ? g : 30;
            // Same cutoff form the expired-list query computes, so the per-row DELETE below can
            // re-assert the "still soft-deleted past grace" predicate under its own connection.
            string cutoff = _time.GetUtcNow().AddDays(-graceDays).ToUtcIso();
            var expired = await _orgs.ListExpiredSoftDeletedOrgIdsAsync(graceDays, leaseCt);
            if (expired.Count == 0)
            {
                return;
            }

            _logger.LogInformation(
                "TenantHardDelete: {Count} tenant(s) past {Days}-day grace.",
                expired.Count, graceDays);

            await using var conn = await _db.OpenAsync(leaseCt);
            foreach (string orgId in expired)
            {
                // Re-check between tenants: the per-tenant guard below swallows failures, so this
                // is the point at which a lost lease (or a host shutdown) actually stops the batch.
                if (leaseCt.IsCancellationRequested)
                {
                    break;
                }

                await HardDeleteOneTenantAsync(conn, orgId, cutoff, leaseCt);
            }
        }
        catch (OperationCanceledException) when (lease.LeaseLost)
        {
            _logger.LogWarning(
                "TenantHardDelete sweep aborted — the {LockName} sweep lease was lost mid-pass.",
                SweepLockName);
        }
        catch (Exception ex)
        {
            // Listing the expired tenants or opening the sweep connection failed. As with the
            // per-tenant guard above, this must not escape RunPassAsync and fault the host — skip
            // the pass and let the next scheduled tick retry.
            _logger.LogError(ex, "TenantHardDelete sweep skipped — listing expired tenants or opening the connection failed.");
        }
        finally
        {
            // The lease owns the handle: stopping the heartbeat and releasing the lock are one step.
            await lease.DisposeAsync();
        }
    }

    // Hard-deletes one tenant past its grace window as a single transaction, re-asserting the
    // soft-deleted-past-grace predicate in the DELETE itself to close the race against a concurrent
    // system_admin restore. A transient failure on this one tenant is logged and swallowed rather
    // than escaping RunPassAsync — see the catch below for why the whole sweep must not abort on it.
    //
    // The transaction is what makes that swallow safe. The erasure spans six relations, and only
    // the org row is what the next pass's worklist query (ListExpiredSoftDeletedOrgIdsAsync, a
    // SELECT over orgs) can see: an un-transacted sequence that deleted the org row first and then
    // failed would strand the banners, login_attempts/account_send_throttle, audit_log and
    // audit_event rows permanently, because the id can never be selected again. Committing all of
    // it or none of it is what makes "the next pass retries this tenant" true rather than
    // aspirational. Every statement is also idempotent on its own (deletes by key, UPDATE … SET
    // NULL), so a retry after a rollback re-runs cleanly.
    private async Task HardDeleteOneTenantAsync(
        System.Data.Common.DbConnection conn, string orgId, string cutoff, CancellationToken ct)
    {
        try
        {
            // Read the slug before the row is gone — it's the only identity the operator
            // Slack notification below can carry. Outside the transaction: it opens its own
            // connection, which under a single-writer provider would contend with a write
            // transaction already held on conn.
            string? slug = (await _orgs.GetByIdAsync(orgId, ct))?.Slug;

            await using var tx = await conn.BeginTransactionAsync(ct);

            // Snapshot member emails before the guarded DELETE cascades the users table away.
            // login_attempts/account_send_throttle are keyed by LoginService.HashLockoutKey over
            // (realm, tenantId, email), not by user id, so once the user rows are gone there is no
            // way to recover which pseudonyms belonged to this tenant.
            var memberEmails = (await conn.QueryAsync<string>(new CommandDefinition(
                "SELECT email FROM users WHERE tenant_id = @orgId",
                new { orgId }, transaction: tx, cancellationToken: ct))).ToList();

            // Snapshot this org's audit_event ids before the guarded DELETE fires the table's own
            // ON DELETE SET NULL cascade (org_id REFERENCES orgs(id) ON DELETE SET NULL — the
            // schema deliberately retains the row past org deletion for forensic purposes). Once
            // that cascade runs, org_id is NULL on every one of them, indistinguishable from any
            // other org's already-orphaned rows, so there would be no way to find just this org's
            // rows again afterward. A plain SELECT, so it carries none of the DELETE's race risk
            // against a concurrent restore below — it is only ever acted on once that DELETE has
            // actually won.
            var auditEventIds = (await conn.QueryAsync<string>(new CommandDefinition(
                "SELECT event_id FROM audit_event WHERE org_id = @orgId",
                new { orgId }, transaction: tx, cancellationToken: ct))).ToList();

            // Re-assert soft-deleted-past-grace in the DELETE itself: a system_admin restore
            // (RestoreOrgAsync clears deleted_at) can land between the expired-list snapshot
            // and this iteration. The guarded statement then matches no row, and the just-
            // restored tenant is left untouched instead of irrecoverably hard-deleted.
            int deleted = await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM orgs WHERE id = @id AND deleted_at IS NOT NULL AND deleted_at < @cutoff",
                new { id = orgId, cutoff }, transaction: tx, cancellationToken: ct));
            if (deleted == 0)
            {
                await tx.RollbackAsync(ct);
                _logger.LogInformation(
                    "TenantHardDelete: tenant {OrgId} skipped — restored within its grace window since the pass began.",
                    orgId);
                return;
            }

            // The org row is gone; FK cascade removed its per-tenant data. Banners carry no
            // FK to orgs, so delete them explicitly. Only reached when the DELETE won the race.
            await _banners.DeleteForOrgAsync(conn, tx, orgId, ct);

            // login_attempts/account_send_throttle carry no FK to orgs either — the tenant is
            // folded into the pseudonym key, not held as a column — so the cascade above never
            // reached them. Erasing a whole tenant is the same Art. 17 obligation as erasing one
            // member (RemoveOrgMemberAsync), just at a larger blast radius: every surviving
            // member's lockout/send-throttle pseudonym must go with the tenant. xtenant: the key
            // already folds tenantId into the hash, so the bare equality predicate is tenant-safe.
            foreach (string email in memberEmails)
            {
                string lockoutKey = LoginService.HashLockoutKey("tenant", orgId, email);
                await conn.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM login_attempts WHERE email_hash = @lockoutKey",
                    new { lockoutKey }, transaction: tx, cancellationToken: ct));
                await conn.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM account_send_throttle WHERE email_hash = @lockoutKey",
                    new { lockoutKey }, transaction: tx, cancellationToken: ct));
            }

            // audit_log.org_id carries no FK to orgs (forensic-retention design), so tenant-scoped
            // rows — which hold the tenant users' source IPs and email/NameID-bearing detail — do
            // not cascade. On permanent erasure past grace, delete them to actually discharge Art.
            // 17. scope='system' operator lifecycle rows (incl. the tenant.hard_deleted row written
            // just below) are retained: this filters on scope='tenant'.
            await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM audit_log WHERE org_id = @orgId AND scope = 'tenant'",
                new { orgId }, transaction: tx, cancellationToken: ct));

            // audit_event takes the pseudonymization treatment, not deletion — unlike audit_log's
            // tenant-scoped rows, the schema's ON DELETE SET NULL on org_id says these rows are
            // meant to survive their org. Drop the personal identifiers (source_ip, user_agent)
            // while keeping actor_id/payload as the forensic skeleton, consistent with the
            // instance-wide two-horizon policy RetentionService.PruneAuditEventsAsync enforces by
            // age. Chunked so a tenant with a large audit_event history never builds one IN clause
            // past SQLite's bound-parameter ceiling. A chunk loop that fails partway rolls back
            // with the rest of the transaction, so the retry restarts from a re-snapshotted id
            // list rather than from a half-pseudonymized set no query could find again.
            foreach (string[] chunk in auditEventIds.Chunk(AuditEventPseudonymizeChunkSize))
            {
                // xtenant: keyed by event_id PKs captured from the org_id = @orgId snapshot taken
                // above, before the ON DELETE SET NULL cascade fired.
                await conn.ExecuteAsync(new CommandDefinition(
                    "UPDATE audit_event SET source_ip = NULL, user_agent = NULL WHERE event_id IN @ids",
                    new { ids = chunk }, transaction: tx, cancellationToken: ct));
            }

            // In the same transaction as the erasure it records: a row claiming a deletion that
            // then rolled back would be worse than no row at all, and a row lost while the erasure
            // committed leaves the operator audit list silent about a permanent deletion.
            // No actor: this is a background sweep, not an operator action.
            await _audit.LogSystemAsync(
                conn, tx,
                action: "tenant.hard_deleted",
                orgId: orgId,
                ct: ct);

            await tx.CommitAsync(ct);

            // After the commit: the notification describes a deletion that has actually landed,
            // and a notifier failure can no longer roll one back.
            _systemEvents?.Notify(new Dependably.Infrastructure.SystemEvents.SystemEventRecord(
                "tenant.hard_deleted", slug, null, null));
        }
        catch (OperationCanceledException)
        {
            // Cancellation is not a per-tenant failure to swallow: it means the sweep lease was
            // lost or the host is shutting down, and the batch must stop rather than move on to
            // the next tenant. RunPassAsync classifies and logs it.
            throw;
        }
        catch (Exception ex)
        {
            // A transient DB failure (e.g. SQLITE_BUSY under write contention while a large
            // import holds the single writer) on one tenant must not abort the batch or
            // escape RunPassAsync — an unhandled throw here faults the hosted
            // BackgroundService and, under the default StopHost behavior, takes the whole
            // replica down. The transaction above is what makes that swallow survivable: it is
            // rolled back on the way out, so the org row is still present and still soft-deleted
            // past grace, and the next scheduled pass lists this tenant again and retries the
            // whole erasure. The one step outside the transaction is the post-commit operator
            // notification, whose failure leaves a completed, audited deletion unannounced.
            _logger.LogError(ex,
                "TenantHardDelete: hard-delete of tenant {OrgId} failed — skipping; the next pass retries.",
                orgId);
        }
    }
}
