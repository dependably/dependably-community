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
/// cascade removes per-tenant data (org_settings, packages, package_versions, tokens, invites,
/// audit_log rows scoped to that org, etc.). Each successful hard-delete writes an <c>audit_log</c>
/// entry with <c>scope='system'</c>, <c>action='tenant.hard_deleted'</c>. A transient DB failure on
/// one tenant is logged and skipped so it cannot escape and, under BackgroundService's default
/// StopHost behavior, take the whole replica down.
///
/// Also explicitly deletes tenant-scoped banners for the org because <c>banners.org_id</c>
/// carries no FK to <c>orgs</c> (mirrors <c>audit_log.org_id</c>) and won't cascade on its own.
///
/// Schedule: <c>TENANT_HARD_DELETE_SCHEDULE</c> cron (default <c>0 4 * * *</c> — once daily,
/// staggered 1h after the standard retention sweep).
/// </summary>
public sealed class TenantHardDeleteService : BackgroundService
{
    // In a multi-replica (HA) deployment every replica runs this cron; without coordination each
    // would list the same expired orgs, race the DELETE, and write its own tenant.hard_deleted
    // audit row. Only the sweep-lock winner runs the pass. Standalone always wins the in-process lock.
    private static readonly TimeSpan SweepLockTtl = TimeSpan.FromMinutes(5);
    private const string SweepLockName = "tenant-hard-delete:sweep";

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
                try { await Task.Delay(delay, stoppingToken); }
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

        try
        {
            int graceDays = int.TryParse(_config["TENANT_HARD_DELETE_GRACE_DAYS"], out int g) ? g : 30;
            // Same cutoff form the expired-list query computes, so the per-row DELETE below can
            // re-assert the "still soft-deleted past grace" predicate under its own connection.
            string cutoff = _time.GetUtcNow().AddDays(-graceDays).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var expired = await _orgs.ListExpiredSoftDeletedOrgIdsAsync(graceDays, ct);
            if (expired.Count == 0)
            {
                return;
            }

            _logger.LogInformation(
                "TenantHardDelete: {Count} tenant(s) past {Days}-day grace.",
                expired.Count, graceDays);

            await using var conn = await _db.OpenAsync(ct);
            foreach (string orgId in expired)
            {
                await HardDeleteOneTenantAsync(conn, orgId, cutoff, ct);
            }
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
            await sweepLock.DisposeAsync();
        }
    }

    // Hard-deletes one tenant past its grace window, re-asserting the soft-deleted-past-grace
    // predicate in the DELETE itself to close the race against a concurrent system_admin restore.
    // A transient failure on this one tenant is logged and swallowed rather than escaping
    // RunPassAsync — see the catch below for why the whole sweep must not abort on it.
    private async Task HardDeleteOneTenantAsync(
        System.Data.Common.DbConnection conn, string orgId, string cutoff, CancellationToken ct)
    {
        try
        {
            // Read the slug before the row is gone — it's the only identity the operator
            // Slack notification below can carry.
            string? slug = (await _orgs.GetByIdAsync(orgId, ct))?.Slug;

            // Re-assert soft-deleted-past-grace in the DELETE itself: a system_admin restore
            // (RestoreOrgAsync clears deleted_at) can land between the expired-list snapshot
            // and this iteration. The guarded statement then matches no row, and the just-
            // restored tenant is left untouched instead of irrecoverably hard-deleted.
            int deleted = await conn.ExecuteAsync(
                "DELETE FROM orgs WHERE id = @id AND deleted_at IS NOT NULL AND deleted_at < @cutoff",
                new { id = orgId, cutoff });
            if (deleted == 0)
            {
                _logger.LogInformation(
                    "TenantHardDelete: tenant {OrgId} skipped — restored within its grace window since the pass began.",
                    orgId);
                return;
            }

            // The org row is gone; FK cascade removed its per-tenant data. Banners carry no
            // FK to orgs, so delete them explicitly. Only reached when the DELETE won the race.
            await _banners.DeleteForOrgAsync(orgId, ct);

            // Audit on the same connection — the DELETE doesn't take a write lock past the
            // statement, so a fresh INSERT here doesn't risk the BEGIN IMMEDIATE deadlock.
            await _audit.LogSystemAsync(
                action: "tenant.hard_deleted",
                orgId: orgId,
                ct: ct);
            // No actor: this is a background sweep, not an operator action.
            _systemEvents?.Notify(new Dependably.Infrastructure.SystemEvents.SystemEventRecord(
                "tenant.hard_deleted", slug, null, null));
        }
        catch (Exception ex)
        {
            // A transient DB failure (e.g. SQLITE_BUSY under write contention while a large
            // import holds the single writer) on one tenant must not abort the batch or
            // escape RunPassAsync — an unhandled throw here faults the hosted
            // BackgroundService and, under the default StopHost behavior, takes the whole
            // replica down. Log and continue; the next scheduled pass retries this tenant.
            _logger.LogError(ex,
                "TenantHardDelete: hard-delete of tenant {OrgId} failed — skipping; the next pass retries.",
                orgId);
        }
    }
}
