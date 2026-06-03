using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// Instance-admin endpoints: settings, users, and audit log.
/// All routes require the <c>tenant:admin</c> capability (owner role on the tenant).
/// </summary>
[ApiController]
[Authorize]
public sealed class InstanceController : ControllerBase
{
    private readonly OrgRepository _orgs;
    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;
    private readonly IAirGapMode _airGap;
    private readonly BackgroundJobRunRepository _jobRuns;

    public InstanceController(
        OrgRepository orgs,
        AuditRepository audit,
        OrgAccessGuard guard,
        IAirGapMode airGap,
        BackgroundJobRunRepository jobRuns)
    {
        _orgs = orgs;
        _audit = audit;
        _guard = guard;
        _airGap = airGap;
        _jobRuns = jobRuns;
    }

    // ── Instance Settings ─────────────────────────────────────────────────────

    [HttpGet("api/v1/instance/settings")]
    public async Task<IActionResult> GetSettings(CancellationToken ct)
    {
        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantAdmin, ct);
        if (deny is not null) return deny;
        var settings = await _orgs.ListInstanceSettingsAsync(ct);
        return Ok(settings);
    }

    private static readonly HashSet<string> AllowedSettingKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "max_upload_bytes",
        "max_upload_bytes_pypi",
        "max_upload_bytes_npm",
        "max_upload_bytes_nuget",
        "gc_schedule",
        "siem_max_lookback_days",
    };

    [HttpPut("api/v1/instance/settings")]
    public async Task<IActionResult> UpdateSettings([FromBody] Dictionary<string, string> settings, CancellationToken ct)
    {
        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantAdmin, ct);
        if (deny is not null) return deny;

        foreach (var key in settings.Keys)
        {
            if (!AllowedSettingKeys.Contains(key))
                return BadRequest(new { error = $"Unknown setting key: {key}" });
        }

        foreach (var (key, value) in settings)
            await _orgs.SetInstanceSettingAsync(key, value, ct);

        var actor = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "instance_settings_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                keys = settings.Keys.ToArray(),
                values = settings,
            }),
            ct: ct);

        return NoContent();
    }

    // ── Background Jobs ──────────────────────────────────────────────────────────

    private static readonly string[] AllJobNames =
    [
        "vuln-scan",
        "vuln-rescan",
        "deprecation-refresh",
        "healthcheck-pinger",
        "cache-eviction",
        "retention",
        "orphan-reconciler",
        "tenant-hard-delete",
        "blob-size-poller",
        "tenant-count-poller",
    ];

    /// <summary>GET /api/v1/instance/background-jobs</summary>
    [HttpGet("api/v1/instance/background-jobs")]
    public async Task<IActionResult> GetBackgroundJobs(CancellationToken ct)
    {
        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantAdmin, ct);
        if (deny is not null) return deny;

        var jobStatuses = new List<object>();
        foreach (var jobName in AllJobNames)
        {
            var disabled = _airGap.IsJobDisabled(jobName);
            string disabledReason;
            if (!disabled)
                disabledReason = "none";
            else
                disabledReason = _airGap.IsEnabled ? "AIR_GAPPED=true" : "DISABLE_BACKGROUND_JOBS";

            var (runs, _) = await _jobRuns.ListAsync(
                new BackgroundJobRunQuery(JobName: jobName, Limit: 1, SortBy: "startedAt", SortDir: "desc"), ct);
            var lastRun = runs.Count > 0 ? runs[0] : null;

            jobStatuses.Add(new
            {
                name            = jobName,
                enabled         = !disabled,
                disabled_reason = disabled ? disabledReason : null as string,
                last_run_at     = lastRun?.StartedAt,
                last_outcome    = lastRun?.Outcome,
            });
        }

        return Ok(new { jobs = jobStatuses });
    }

    // The legacy /api/v1/admin/users, /api/v1/admin/users/{id}/role, and /api/v1/admin/audit
    // endpoints are removed: the instance_admin flag no longer exists, and these surfaces are
    // either redundant under the strict-tenant model (admin/users) or moved to the system
    // surface (admin/audit → /api/v1/system/audit, multi mode only).

    // Auth: TenantAdmin capability, which today only owners hold. In multi mode this endpoint
    // is effectively unreachable because the tenant SPA is confined to its tenant subdomain
    // and system_admin tokens are blocked from tenant routes by RouteScopeFilter. Operators of
    // multi-mode installs configure instance settings via /api/v1/system/settings (added
    // separately in the system surface).
}
