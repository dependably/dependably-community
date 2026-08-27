using System.Security.Claims;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Apex-only vulnerability-tracker connection surface. Multi-mode counterpart of
/// <c>InstanceController</c>'s single-mode <c>/api/v1/instance/vuln-tracker-config</c> routes;
/// both share validation, the write, and response shaping via
/// <see cref="VulnTrackerConfigEditing"/> so the two surfaces can't drift. Every route requires
/// <c>scope=system</c> + apex context, enforced by <see cref="Dependably.Security.RouteScopeFilter"/>
/// on every <c>/api/v1/system/</c> route.
///
/// <para>
/// There is exactly one connection per deployment and it is edited only here. A tenant has no
/// route to this configuration and no read of it: enrichment thresholds are per-org, on the
/// tenant's own proxy settings, while the connection that supplies the signals is the operator's.
/// </para>
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// GET /api/v1/system/vuln-tracker-config — the resolved instance vulnerability-tracker
    /// connection. The token is never echoed, only a computed <c>hasToken</c> boolean.
    /// </summary>
    [HttpGet("vuln-tracker-config")]
    public async Task<IActionResult> GetVulnTrackerConfig(
        [FromServices] InstanceVulnTrackerConfig tracker,
        CancellationToken ct)
    {
        var resolved = await tracker.ResolveAsync(ct);
        return Ok(VulnTrackerConfigEditing.BuildView(resolved, _envelope.IsConfigured));
    }

    /// <summary>
    /// PUT /api/v1/system/vuln-tracker-config — updates the instance vulnerability-tracker
    /// connection in <c>instance_settings</c>. A non-empty <c>token</c> requires
    /// <see cref="Dependably.Infrastructure.Identity.EnvelopeProtector.IsConfigured"/> (otherwise
    /// <c>SetInstanceSettingAsync</c> would silently store the bearer credential in plaintext) —
    /// 422 when absent. An IP-literal <c>baseUrl</c> host in a blocked SSRF range is rejected
    /// unless <c>WEBHOOK_ALLOW_PRIVATE=true</c> (via <see cref="HostSsrfValidator"/>) — the same
    /// save-time posture as the instance SMTP transport; the authoritative, DNS-rebinding-aware
    /// gate is the connect-time guard the tracker client runs on every request. Audits the
    /// non-secret fields only.
    /// </summary>
    [HttpPut("vuln-tracker-config")]
    public async Task<IActionResult> UpdateVulnTrackerConfig(
        [FromBody] VulnTrackerConfigRequest req,
        [FromServices] InstanceVulnTrackerConfig tracker,
        CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
        }

        var (field, resourceKey) = VulnTrackerConfigEditing.Validate(req);
        if (field is not null)
        {
            return _problems.ValidationErrorActionKey(field, resourceKey!);
        }

        if (!string.IsNullOrEmpty(req.Token) && !_envelope.IsConfigured)
        {
            return _problems.ValidationErrorActionKey("token", "error.vulnTracker.masterKeyRequired");
        }

        // Operator-endpoint predicate, not the tenant-facing one: a self-hosted tracker on
        // loopback or a private network is the normal deployment, so only the instance-metadata
        // range is refused here. Deliberately NOT gated on WEBHOOK_ALLOW_PRIVATE — that flag
        // governs tenant-supplied webhook targets, and coupling the two would force an operator
        // to loosen genuine SSRF protection just to reach their own sidecar.
        if (VulnTrackerConfigEditing.IsHostBlocked(
                req.BaseUrl, SsrfGuard.IsBlockedIpForOperatorEndpoint))
        {
            return _problems.ValidationErrorActionKey("baseUrl", "error.vulnTracker.hostBlocked");
        }

        await VulnTrackerConfigEditing.ApplyAsync(_orgs, req, ct);
        tracker.Invalidate();

        // Resolved before auditing so the audited state is the connection that actually resulted,
        // not the request body: a save that omits the token keeps the stored one, and a save that
        // clears the base URL discards it, neither of which the body alone tells you.
        var resolved = await tracker.ResolveAsync(ct);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.vuln_tracker_config_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = resolved.Enabled,
                baseUrl = resolved.Connection.BaseUrl,
                maxStalenessHours = resolved.Connection.MaxStalenessHours,
                batchSize = resolved.Connection.BatchSize,
                tokenRotated = !string.IsNullOrEmpty(req.Token),
                hasToken = !string.IsNullOrEmpty(resolved.Connection.Token),
                configured = resolved.Configured,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return Ok(VulnTrackerConfigEditing.BuildView(resolved, _envelope.IsConfigured));
    }

    /// <summary>
    /// POST /api/v1/system/vuln-tracker-config/test — probes the saved connection and reports
    /// what happened, so an operator does not have to wait for a scan pass to learn that the
    /// credential is wrong.
    ///
    /// <para>
    /// An unreached tracker is a <b>200 carrying <c>reached: false</c></b>, not an error status:
    /// the operation succeeded, and its finding is that the tracker did not answer. Only a
    /// connection with nothing to dial is a 422 — that is the operation failing to run, and it is
    /// a different thing from a tracker that is down. Rate-limited like the invite send path,
    /// because this is an authenticated trigger for an outbound request.
    /// </para>
    ///
    /// <para>
    /// Also fires <see cref="VulnTrackerEnrichmentClient.TryHandshakeAsync"/> alongside the probe —
    /// the deliberate, low-frequency identity announcement the tracker's handshake protocol expects
    /// at config time, distinct from the probe's own lookup. Best-effort: its outcome is recorded
    /// on the audit entry but never affects the probe result or the response status, since a
    /// handshake failure says nothing about whether enrichment itself works.
    /// </para>
    /// </summary>
    [HttpPost("vuln-tracker-config/test")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> TestVulnTrackerConfig(
        [FromServices] InstanceVulnTrackerConfig tracker,
        [FromServices] Dependably.Protocol.IVulnerabilityEnrichmentSource enrichment,
        [FromServices] VulnTrackerEnrichmentClient enrichmentClient,
        [FromServices] VulnTrackerHealthRepository health,
        [FromServices] TimeProvider time,
        CancellationToken ct)
    {
        var probe = await VulnTrackerProbe.TryProbeAsync(tracker, enrichment, health, time, ct);

        if (probe is not null)
        {
            bool handshakeSent = await enrichmentClient.TryHandshakeAsync(ct);

            // Audited even though the probe changes nothing, because it is an authenticated
            // operator causing this deployment to present its bearer credential to the configured
            // host. The fetch log records that a probe happened; only this records who ran it.
            // (The instance SMTP test send has no equivalent entry — that is a gap on that
            // endpoint rather than a precedent to copy.)
            await _audit.LogSystemAsync(
                action: "system_admin.vuln_tracker_config_tested",
                actorId: User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value,
                detail: System.Text.Json.JsonSerializer.Serialize(new
                {
                    reached = probe.Reached,
                    reason = probe.Reason,
                    latencyMs = probe.LatencyMs,
                    handshakeSent,
                }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
                ct: ct);
        }

        // Null means there was nothing to dial. That is the operation failing to run, which is a
        // different answer from a tracker that could not be reached — and reporting the first as
        // the second would render an unconfigured integration as a broken one.
        return probe is null
            ? _problems.ValidationErrorActionKey("baseUrl", "error.vulnTracker.notActive")
            : Ok(VulnTrackerConfigEditing.BuildProbeView(probe));
    }
}
