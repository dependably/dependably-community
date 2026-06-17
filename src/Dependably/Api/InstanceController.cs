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
            if (!InstanceSettingDefaults.AllowedKeys.Contains(key))
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

    // ── /metrics access config ─────────────────────────────────────────────────
    //
    // Single-mode counterpart of the system-realm /api/v1/system/metrics-access. The /metrics
    // gate (MetricsAccessConfig + MetricsAccessMiddleware) reads instance_settings regardless of
    // deployment mode, so the single-tenant owner-operator needs an editing surface too. The
    // request/response shapes and validation match the system surface (shared via
    // MetricsAccessEditing) so the same Svelte form drives both.

    /// <summary>GET /api/v1/instance/metrics-access — resolved /metrics access config + sources.</summary>
    [HttpGet("api/v1/instance/metrics-access")]
    public async Task<IActionResult> GetMetricsAccess(
        [FromServices] MetricsAccessConfig access,
        [FromServices] ScrapeDiagnostics diagnostics,
        CancellationToken ct)
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

        var resolved = await access.ResolveAsync(ct);
        var denied = diagnostics.RecentDeniedIps(10)
            .Select(e => new { ip = e.Ip, lastSeen = e.LastSeen });
        return Ok(new
        {
            enabled = resolved.Enabled,
            enabledSource = resolved.EnabledSource.ToString().ToLowerInvariant(),
            enabledLockedByEnv = resolved.EnabledLockedByEnv,
            allowedIps = resolved.AllowedRaw,
            allowlistSource = resolved.AllowlistSource.ToString().ToLowerInvariant(),
            allowlistLockedByEnv = resolved.AllowlistLockedByEnv,
            recentDeniedIps = denied,
        });
    }

    /// <summary>
    /// PUT /api/v1/instance/metrics-access — update the /metrics access config in
    /// instance_settings. Returns 409 when the corresponding env var locks the knob, 400 on a
    /// malformed CIDR, and 200 with any broad-allowlist warnings on success.
    /// </summary>
    [HttpPut("api/v1/instance/metrics-access")]
    public async Task<IActionResult> UpdateMetricsAccess(
        [FromBody] UpdateMetricsAccessRequest req,
        [FromServices] MetricsAccessConfig access,
        [FromServices] ProblemResults problems,
        CancellationToken ct)
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

        if (req is null)
        {
            return problems.ValidationErrorAction("body", "Request body required.");
        }

        var resolved = await access.ResolveAsync(ct);

        if (req.Enabled.HasValue && resolved.EnabledLockedByEnv)
        {
            return Conflict(MetricsAccessEditing.EnvLockedConflictBody("metrics_enabled", "METRICS_ENABLED"));
        }

        if (req.AllowedIps is not null && resolved.AllowlistLockedByEnv)
        {
            return Conflict(MetricsAccessEditing.EnvLockedConflictBody("metrics_allowed_ips", "METRICS_ALLOWED_IPS"));
        }

        var warnings = new List<string>();
        if (req.AllowedIps is not null)
        {
            string? invalid = MetricsAccessEditing.FindInvalidEntry(req.AllowedIps, warnings);
            if (invalid is not null)
            {
                return problems.ValidationErrorAction("allowedIps", $"\"{invalid}\" is not a valid IP or CIDR.");
            }
        }

        if (req.Enabled.HasValue)
        {
            await _orgs.SetInstanceSettingAsync("metrics_enabled", req.Enabled.Value ? "1" : "0", ct);
        }

        if (req.AllowedIps is not null)
        {
            await _orgs.SetInstanceSettingAsync(
                "metrics_allowed_ips",
                System.Text.Json.JsonSerializer.Serialize(req.AllowedIps),
                ct);
        }

        access.Invalidate();

        string? actor = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "instance_metrics_access_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                allowedIps = req.AllowedIps,
            }),
            ct: ct);

        return Ok(new { warnings });
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
