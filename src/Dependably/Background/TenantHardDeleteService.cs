using Cronos;
using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Background;

/// <summary>
/// Background job that hard-deletes tenants whose <c>orgs.deleted_at</c> is older than
/// <c>TENANT_HARD_DELETE_GRACE_DAYS</c> (default 30). Hard delete is a single
/// <c>DELETE FROM orgs WHERE id = @id</c>; FK cascade removes per-tenant data
/// (org_settings, packages, package_versions, tokens, invites, audit_log rows scoped to that
/// org, etc.). Each successful hard-delete writes an <c>audit_log</c> entry with
/// <c>scope='system'</c>, <c>action='tenant.hard_deleted'</c>.
///
/// Also explicitly deletes tenant-scoped banners for the org because <c>banners.org_id</c>
/// carries no FK to <c>orgs</c> (mirrors <c>audit_log.org_id</c>) and won't cascade on its own.
///
/// Schedule: <c>TENANT_HARD_DELETE_SCHEDULE</c> cron (default <c>0 4 * * *</c> — once daily,
/// staggered 1h after the standard retention sweep).
/// </summary>
public sealed class TenantHardDeleteService : BackgroundService
{
    private readonly OrgRepository _orgs;
    private readonly AuditRepository _audit;
    private readonly IMetadataStore _db;
    private readonly BannerRepository _banners;
    private readonly IConfiguration _config;
    private readonly ILogger<TenantHardDeleteService> _logger;
    private readonly TimeProvider _time;

    public TenantHardDeleteService(
        OrgRepository orgs,
        AuditRepository audit,
        IMetadataStore db,
        BannerRepository banners,
        IConfiguration config,
        ILogger<TenantHardDeleteService> logger,
        TimeProvider time)
    {
        _orgs = orgs;
        _audit = audit;
        _db = db;
        _banners = banners;
        _config = config;
        _logger = logger;
        _time = time;
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
        int graceDays = int.TryParse(_config["TENANT_HARD_DELETE_GRACE_DAYS"], out int g) ? g : 30;
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
            // Banners carry no FK to orgs, so delete them explicitly before the org row goes.
            await _banners.DeleteForOrgAsync(orgId, ct);

            // Single statement; FK cascades remove per-tenant data.
            await conn.ExecuteAsync("DELETE FROM orgs WHERE id = @id", new { id = orgId });

            // Audit on the same connection — the DELETE doesn't take a write lock past the
            // statement, so a fresh INSERT here doesn't risk the BEGIN IMMEDIATE deadlock.
            await _audit.LogSystemAsync(
                action: "tenant.hard_deleted",
                orgId: orgId,
                ct: ct);
        }
    }
}
