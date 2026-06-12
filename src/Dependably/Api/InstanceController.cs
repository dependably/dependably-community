using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Instance-admin endpoints: settings and background-job status.
/// All routes require the <c>tenant:admin</c> capability (owner role on the tenant).
///
/// In multi-tenant deployments (<c>DEPLOYMENT_MODE=multi</c> or <c>header</c>), instance-wide
/// settings and background-job status are control-plane concerns owned by the operator. Those
/// actions return 404 in those modes; operators use the system realm at
/// <c>/api/v1/system/settings</c> and <c>/api/v1/system/background-jobs</c> instead.
/// Single-tenant and bound deployments keep the existing behavior (owner == operator).
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
    private readonly bool _isMultiMode;

    public InstanceController(
        OrgRepository orgs,
        AuditRepository audit,
        OrgAccessGuard guard,
        IAirGapMode airGap,
        BackgroundJobRunRepository jobRuns,
        IConfiguration config)
    {
        _orgs = orgs;
        _audit = audit;
        _guard = guard;
        _airGap = airGap;
        _jobRuns = jobRuns;
        string mode = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        _isMultiMode = mode is "multi" or "header";
    }

    // ── Instance Settings ─────────────────────────────────────────────────────

    [HttpGet("api/v1/instance/settings")]
    public async Task<IActionResult> GetSettings(CancellationToken ct)
    {
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantAdmin, ct);
        if (deny is not null)
        {
            return deny;
        }

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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateSettings([FromBody] Dictionary<string, string> settings, CancellationToken ct)
    {
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantAdmin, ct);
        if (deny is not null)
        {
            return deny;
        }

        foreach (string key in settings.Keys)
        {
            if (!AllowedSettingKeys.Contains(key))
            {
                return BadRequest(new { error = $"Unknown setting key: {key}" });
            }
        }

        foreach (var (key, value) in settings)
        {
            await _orgs.SetInstanceSettingAsync(key, value, ct);
        }

        string? actor = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
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
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantAdmin, ct);
        if (deny is not null)
        {
            return deny;
        }

        var jobStatuses = new List<object>();
        foreach (string jobName in AllJobNames)
        {
            bool disabled = _airGap.IsJobDisabled(jobName);
            string disabledReason = !disabled ? "none" : _airGap.IsEnabled ? "AIR_GAPPED=true" : "DISABLE_BACKGROUND_JOBS";
            var (runs, _) = await _jobRuns.ListAsync(
                new BackgroundJobRunQuery(JobName: jobName, Limit: 1, SortBy: "startedAt", SortDir: "desc"), ct);
            var lastRun = runs.Count > 0 ? runs[0] : null;

            jobStatuses.Add(new
            {
                name = jobName,
                enabled = !disabled,
                disabled_reason = disabled ? disabledReason : null as string,
                last_run_at = lastRun?.StartedAt,
                last_outcome = lastRun?.Outcome,
            });
        }

        return Ok(new { jobs = jobStatuses });
    }

    // The legacy /api/v1/admin/users, /api/v1/admin/users/{id}/role, and /api/v1/admin/audit
    // endpoints are removed: the instance_admin flag no longer exists, and these surfaces are
    // either redundant under the strict-tenant model (admin/users) or moved to the system
    // surface (admin/audit → /api/v1/system/audit).
}
