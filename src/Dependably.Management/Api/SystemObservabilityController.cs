using System.Security.Claims;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only operator observability surface: the <c>/metrics</c> access config (enable + IP
/// allowlist, with the source each knob resolves from) and the Tier 1 in-app operator view.
///
/// <para>Every route requires <c>scope=system</c> + apex context, enforced by
/// <see cref="Dependably.Security.RouteScopeFilter"/> on every <c>/api/v1/system/</c> route —
/// the routes are unchanged from when these three actions lived on
/// <see cref="SystemController"/>, and this is a separate controller rather than another of its
/// partial files because a partial does not reduce a class's own coupling.</para>
///
/// <para>The observability view is deliberately DB-free: it reads the in-memory snapshot, scrape
/// diagnostics, and the resolved access config, and nothing else. Counters are labelled "since
/// startup" — rates and percentiles stay in Grafana.</para>
/// </summary>
[ApiController]
[Authorize]
[Route("api/v1/system")]
public sealed class SystemObservabilityController : ControllerBase
{
    // Number of recent diagnostic events surfaced on the diagnostics endpoint.
    private const int DiagnosticsRecentEventCount = 50;

    private readonly OrgRepository _orgs;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly TimeProvider _time;

    public SystemObservabilityController(
        OrgRepository orgs, AuditRepository audit, ProblemResults problems, TimeProvider time)
    {
        _orgs = orgs;
        _audit = audit;
        _problems = problems;
        _time = time;
    }

    /// <summary>
    /// GET /api/v1/system/metrics-access — current resolved /metrics
    /// access config (enable + IP allowlist) plus which source each
    /// knob is coming from. Used by the sysadmin UI to show the
    /// "locked by env" badges.
    /// </summary>
    [HttpGet("metrics-access")]
    public async Task<IActionResult> GetMetricsAccess(
        [FromServices] Dependably.Security.MetricsAccessConfig access,
        [FromServices] Dependably.Security.ScrapeDiagnostics diagnostics,
        CancellationToken ct)
    {
        var resolved = await access.ResolveAsync(ct);
        return Ok(Dependably.Security.MetricsAccessView.Build(resolved, diagnostics));
    }

    /// <summary>
    /// PUT /api/v1/system/metrics-access — update the /metrics access
    /// config in instance_settings. Returns 409 when the corresponding
    /// env var locks the knob (no silent DB write behind an env
    /// override). Validates each CIDR; rejects malformed with 400.
    /// Accepts and warns on broad /0 entries.
    /// </summary>
    [HttpPut("metrics-access")]
    public async Task<IActionResult> UpdateMetricsAccess(
        [FromBody] UpdateMetricsAccessRequest req,
        [FromServices] Dependably.Security.MetricsAccessConfig access,
        CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
        }

        var resolved = await access.ResolveAsync(ct);

        if (req.Enabled.HasValue && resolved.EnabledLockedByEnv)
        {
            return Conflict(Dependably.Security.MetricsAccessEditing.EnvLockedConflictBody("metrics_enabled", "METRICS_ENABLED"));
        }

        if (req.AllowedIps is not null && resolved.AllowlistLockedByEnv)
        {
            return Conflict(Dependably.Security.MetricsAccessEditing.EnvLockedConflictBody("metrics_allowed_ips", "METRICS_ALLOWED_IPS"));
        }

        var warnings = new List<string>();
        if (req.AllowedIps is not null)
        {
            string? invalid = Dependably.Security.MetricsAccessEditing.FindInvalidEntry(req.AllowedIps, warnings);
            if (invalid is not null)
            {
                return _problems.ValidationErrorActionKey("allowedIps", "error.common.invalidIpOrCidr", invalid);
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

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.metrics_access_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                allowedIps = req.AllowedIps,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return Ok(new { warnings });
    }

    /// <summary>
    /// GET /api/v1/system/observability — Tier 1 in-app operator view.
    /// Reads in-memory snapshot + scrape diagnostics + metrics-access
    /// config; no DB hits, no OTel introspection. Counters are labelled
    /// "since startup" — rates and percentiles stay in Grafana.
    /// </summary>
    [HttpGet("observability")]
    public async Task<IActionResult> GetObservability(
        [FromServices] Dependably.Infrastructure.Observability.MetricsSnapshotProvider snapshots,
        [FromServices] Dependably.Security.ScrapeDiagnostics diagnostics,
        [FromServices] Dependably.Security.MetricsAccessConfig access,
        CancellationToken ct)
    {
        var snap = snapshots.Capture();
        var (allowedTotal, deniedIpTotal, deniedDisabledTotal) = diagnostics.LifetimeCounts();
        var resolved = await access.ResolveAsync(ct);
        var now = _time.GetUtcNow();

        return Ok(new
        {
            numbers = new
            {
                activeTenants = snap.ActiveTenants,
                blobStoreSizesByTier = snap.BlobStoreSizesByTier,
                backgroundJobs = snap.BackgroundJobLastSuccessUnixSeconds.ToDictionary(
                    kv => kv.Key,
                    kv => new
                    {
                        lastSuccessUnixSeconds = kv.Value,
                        ageSeconds = now.ToUnixTimeSeconds() - kv.Value,
                    }),
                sinceStartup = new
                {
                    publishes = snap.PublishCountSinceStartup,
                    proxyFetches = snap.ProxyFetchCountSinceStartup,
                    cacheHits = snap.CacheHitsSinceStartup,
                    cacheMisses = snap.CacheMissesSinceStartup,
                },
                capturedAt = snap.CapturedAt,
            },
            scrapeDiagnostics = new
            {
                recent = diagnostics.Recent(DiagnosticsRecentEventCount).Select(e => new
                {
                    timestamp = e.Timestamp,
                    remoteIp = e.RemoteIp,
                    outcome = e.Outcome.ToString().ToLowerInvariant(),
                }),
                lifetimeCounts = new
                {
                    allowed = allowedTotal,
                    deniedIp = deniedIpTotal,
                    deniedDisabled = deniedDisabledTotal,
                },
            },
            metricsAccess = new
            {
                enabled = resolved.Enabled,
                enabledSource = resolved.EnabledSource.ToString().ToLowerInvariant(),
                allowedIps = resolved.AllowedRaw,
                allowlistSource = resolved.AllowlistSource.ToString().ToLowerInvariant(),
                enabledLockedByEnv = resolved.EnabledLockedByEnv,
                allowlistLockedByEnv = resolved.AllowlistLockedByEnv,
            },
        });
    }
}

public sealed record UpdateMetricsAccessRequest(bool? Enabled, IReadOnlyList<string>? AllowedIps);
