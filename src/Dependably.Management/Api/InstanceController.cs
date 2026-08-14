using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Instance-admin endpoints: settings, metrics access, the SMTP transport, and background-job
/// status. All routes require <c>tenant:configure</c> — the capability both <c>admin</c> and
/// <c>owner</c> hold.
///
/// These routes only exist in single-tenant mode, where the org *is* the deployment: there is one
/// tenant, and its admins are the people running the instance. Gating them on <c>tenant:admin</c>
/// (owner-only) made an admin who already configures the registry's security posture — block gates,
/// licence enforcement, trust anchors, proxy upstreams — unable to point the mail relay at a host or
/// raise an upload limit, which is a distinction without a difference at that scope.
///
/// In multi-tenant deployments (<c>DEPLOYMENT_MODE=multi</c> or <c>header</c>), instance-wide
/// settings and background-job status are control-plane concerns owned by the operator. Those
/// actions return 404 in those modes; operators use the system realm at
/// <c>/api/v1/system/settings</c> and <c>/api/v1/system/background-jobs</c> instead, behind the
/// separate <c>system_admin</c> identity. So this widening is scoped to single mode by
/// construction — it grants a multi-mode tenant admin nothing.
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
    private readonly ILogger<InstanceController> _logger;
    private readonly IConfiguration _config;
    private readonly bool _isMultiMode;

    public InstanceController(
        OrgRepository orgs,
        AuditRepository audit,
        OrgAccessGuard guard,
        IAirGapMode airGap,
        BackgroundJobRunRepository jobRuns,
        ILogger<InstanceController> logger,
        IConfiguration config)
    {
        _orgs = orgs;
        _audit = audit;
        _guard = guard;
        _airGap = airGap;
        _jobRuns = jobRuns;
        _logger = logger;
        _config = config;
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

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
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

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
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
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return NoContent();
    }

    // ── /metrics access config ─────────────────────────────────────────────────
    //
    // Single-mode counterpart of the system-realm /api/v1/system/metrics-access. The /metrics
    // gate (MetricsAccessConfig + MetricsAccessMiddleware) reads instance_settings regardless of
    // deployment mode, so the single-tenant admin-operator needs an editing surface too. The
    // request/response shapes and validation match the system surface (shared via
    // MetricsAccessEditing) so the same Svelte form drives both.
    //
    // This is the widest of the instance routes: the allowlist it edits is what stands between the
    // public and /metrics, /version, and the management docs/OpenAPI. It is gated on
    // tenant:configure like its siblings rather than being carved out, because in single mode an
    // admin already holds the capabilities that shape the registry's security posture, and a split
    // gate here would be a boundary nobody could state from the role name alone.

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

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return deny;
        }

        var resolved = await access.ResolveAsync(ct);
        return Ok(MetricsAccessView.Build(resolved, diagnostics));
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

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return deny;
        }

        if (req is null)
        {
            return problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
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
                return problems.ValidationErrorActionKey("allowedIps", "error.common.invalidIpOrCidr", invalid);
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
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return Ok(new { warnings });
    }

    // ── Email config ──────────────────────────────────────────────────────────
    //
    // Single-mode counterpart of the system-realm /api/v1/system/email-config. Validation and
    // response shaping are shared with SystemController.EmailConfig via EmailConfigEditing so the
    // two surfaces cannot drift.

    /// <summary>GET /api/v1/instance/email-config — the resolved instance SMTP transport.</summary>
    [HttpGet("api/v1/instance/email-config")]
    public async Task<IActionResult> GetEmailConfig(
        [FromServices] Dependably.Infrastructure.Mail.InstanceSmtpConfig smtp,
        [FromServices] Dependably.Infrastructure.Identity.EnvelopeProtector envelope,
        CancellationToken ct)
    {
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return deny;
        }

        var resolved = await smtp.ResolveAsync(ct);
        return Ok(Dependably.Infrastructure.Mail.EmailConfigEditing.BuildView(resolved, envelope.IsConfigured));
    }

    /// <summary>
    /// PUT /api/v1/instance/email-config — updates the instance SMTP transport. A non-empty
    /// <c>password</c> requires <c>EnvelopeProtector.IsConfigured</c>, otherwise 400
    /// (<c>error.email.masterKeyRequired</c>) — <c>SetInstanceSettingAsync</c> would otherwise
    /// silently store it in plaintext. An IP-literal <c>host</c> in a blocked SSRF range is
    /// rejected unless <c>WEBHOOK_ALLOW_PRIVATE=true</c> (via <see cref="HostSsrfValidator"/>) —
    /// the authoritative, DNS-rebinding-aware gate is the connect-time guard
    /// <c>SmtpMailSender</c> runs on every send. Audits the non-secret fields only.
    /// </summary>
    [HttpPut("api/v1/instance/email-config")]
    public async Task<IActionResult> UpdateEmailConfig(
        [FromBody] Dependably.Infrastructure.Mail.EmailConfigRequest req,
        [FromServices] Dependably.Infrastructure.Mail.InstanceSmtpConfig smtp,
        [FromServices] Dependably.Infrastructure.Identity.EnvelopeProtector envelope,
        [FromServices] ProblemResults problems,
        CancellationToken ct)
    {
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return deny;
        }

        if (req is null)
        {
            return problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
        }

        var (field, resourceKey) = Dependably.Infrastructure.Mail.EmailConfigEditing.Validate(req);
        if (field is not null)
        {
            return problems.ValidationErrorActionKey(field, resourceKey!);
        }

        if (!string.IsNullOrEmpty(req.Password) && !envelope.IsConfigured)
        {
            return problems.ValidationErrorActionKey("password", "error.email.masterKeyRequired");
        }

        bool allowPrivate = string.Equals(
            _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
        Func<System.Net.IPAddress, bool> isBlocked = allowPrivate
            ? SsrfGuard.IsBlockedIpExcludingPrivate
            : SsrfGuard.IsBlockedIp;
        if (HostSsrfValidator.IsHostBlocked(req.Host, isBlocked))
        {
            return problems.ValidationErrorActionKey("host", "error.email.hostBlocked");
        }

        await Dependably.Infrastructure.Mail.EmailConfigEditing.ApplyAsync(_orgs, req, ct);
        smtp.Invalidate();

        // Resolved before auditing so the cleartext-credential finding is read off the transport
        // that actually resulted — a save that omits the password keeps the stored one, which the
        // request body alone cannot tell you.
        var resolved = await smtp.ResolveAsync(ct);
        bool cleartextCredentials = resolved.Transport.SendsCredentialsInCleartext;
        if (cleartextCredentials)
        {
            _logger.LogWarning(
                "Instance SMTP transport saved with security=none and credentials set: AUTH will be "
                + "sent in cleartext. host={Host}",
                resolved.Transport.Host);
        }

        string? actor = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "instance_email_config_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                host = req.Host,
                port = req.Port,
                security = req.Security,
                username = req.Username,
                fromAddress = req.FromAddress,
                passwordRotated = !string.IsNullOrEmpty(req.Password),
                cleartextCredentials,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return Ok(Dependably.Infrastructure.Mail.EmailConfigEditing.BuildView(resolved, envelope.IsConfigured));
    }

    /// <summary>
    /// POST /api/v1/instance/email-config/test — synchronous test send to the configured
    /// from-address (never a caller-supplied target).
    /// </summary>
    [HttpPost("api/v1/instance/email-config/test")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("invite")]
    public async Task<IActionResult> TestEmailConfig(
        [FromServices] Dependably.Infrastructure.Mail.InstanceSmtpConfig smtp,
        [FromServices] Dependably.Infrastructure.Mail.SmtpMailSender sender,
        [FromServices] Microsoft.Extensions.Localization.IStringLocalizer<SharedResource> localizer,
        [FromServices] ProblemResults problems,
        CancellationToken ct)
    {
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return deny;
        }

        var resolved = await smtp.ResolveAsync(ct);
        if (!resolved.Configured || string.IsNullOrWhiteSpace(resolved.Transport.FromAddress))
        {
            return problems.ValidationErrorActionKey("email", "error.email.notConfigured");
        }

        try
        {
            await sender.SendAsync(
                resolved.Transport,
                [resolved.Transport.FromAddress],
                localizer["email.test.subject"],
                localizer["email.test.body"],
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                ex,
                "Instance email test send failed: {ExceptionType} host={Host} port={Port} trace={TraceId}",
                ex.GetType().Name,
                resolved.Transport.Host,
                resolved.Transport.Port,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return problems.ValidationErrorActionKey("email", "error.email.testFailedGeneric");
        }

        return NoContent();
    }

    /// <summary>
    /// GET /api/v1/instance/email-health — the operator's aggregate view of the shared SMTP
    /// relay: how many tenants are currently failing to deliver, the worst consecutive-failure
    /// streak, when it started, and the durable outbox's backlog. Single-mode counterpart of the
    /// system-realm <c>/api/v1/system/email-health</c>; both read the same
    /// <c>RelayHealthAggregator</c> so the two surfaces can't drift. No tenant identifier is ever
    /// included.
    /// </summary>
    [HttpGet("api/v1/instance/email-health")]
    public async Task<IActionResult> GetEmailHealth(
        [FromServices] Dependably.Infrastructure.Mail.RelayHealthAggregator relayHealth,
        CancellationToken ct)
    {
        if (_isMultiMode)
        {
            return NotFound();
        }

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (deny is not null)
        {
            return deny;
        }

        var health = await relayHealth.GetAsync(ct);
        return Ok(health);
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

        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
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
