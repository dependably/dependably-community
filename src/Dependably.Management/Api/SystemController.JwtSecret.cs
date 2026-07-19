using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only operator surface for rotating the instance JWT signing secret. Control plane by
/// definition: <c>jwt_secret</c> signs every session on the instance, tenant and system alike, so
/// it is not a per-tenant setting and has no <c>/api/v1/instance/</c> counterpart. Every route
/// under <c>/api/v1/system/</c> requires <c>scope=system</c> + apex context, enforced globally by
/// <see cref="Dependably.Security.RouteScopeFilter"/> (a missing scope claim is a 401; a tenant
/// session is a 404). <see cref="Dependably.Security.PasswordRotationGuard"/> additionally blocks
/// an admin still holding a first-boot temporary password — the route is not on its allowlist.
///
/// The secret itself is never accepted, echoed, or logged: the new value is generated server-side
/// and only its rotation is reported.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// POST /api/v1/system/jwt-secret/rotate — generates a new instance JWT signing secret,
    /// persists it under the same envelope policy first boot uses, and makes it effective on this
    /// replica before returning.
    ///
    /// <para><b>This signs everybody out, including the caller.</b> There is no old-key grace
    /// period: the previous secret stops validating the moment the rotation lands, so every
    /// outstanding session — the operator's own included — must log in again. That is the point.
    /// Rotation exists for suspected key compromise, and a leaked <c>jwt_secret</c> forges any
    /// session on the instance, so honouring the old key for a window would keep an attacker's
    /// forged tokens alive exactly as long. Callers should expect their next request to 401.</para>
    ///
    /// <para>Other replicas converge within <see cref="JwtSigningKeyProvider.RefreshInterval"/>
    /// (default one second, <c>Auth:JwtSigningKeyRefreshSeconds</c>); the response reports the
    /// window so an operator responding to a compromise knows when it closed.</para>
    /// </summary>
    [HttpPost("jwt-secret/rotate")]
    public async Task<IActionResult> RotateJwtSecret(
        [FromServices] FirstBootService firstBoot,
        [FromServices] JwtSigningKeyProvider signingKeys,
        [FromServices] ILogger<SystemController> logger,
        CancellationToken ct)
    {
        await firstBoot.RotateJwtSecretAsync(ct);

        // Make the new secret effective here before the response is written, so this replica
        // never validates a token against the superseded key after reporting the rotation done.
        // The row was just committed, so a false return means it vanished underneath us —
        // fail loudly rather than serve on with a stale key.
        if (!await signingKeys.TryReloadAsync(ct))
        {
            throw new InvalidOperationException(
                "jwt_secret disappeared from instance_settings immediately after rotation wrote "
                + "it. The signing key on this replica is now stale; restart it and investigate "
                + "concurrent writes to instance_settings.");
        }

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        var rotatedAt = _time.GetUtcNow();

        // actor_kind stays NULL for scope='system' rows by AuditRepository's contract — the
        // system audit list joins system_admins, not users. source_ip is plumbed so the operator
        // audit shows where a break-glass rotation was triggered from.
        await _audit.LogSystemAsync(
            action: "system_admin.jwt_secret_rotated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                envelope_encrypted = _envelope.IsConfigured,
                replica_convergence_seconds = signingKeys.RefreshInterval.TotalSeconds,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        logger.LogWarning(
            "jwt_secret rotated by system_admin {ActorId}. Every session signed under the previous "
            + "secret is now invalid; other replicas converge within {ConvergenceSeconds}s.",
            actor, signingKeys.RefreshInterval.TotalSeconds);

        return Ok(new
        {
            rotatedAt,
            // Both true and unconditional: stated in the payload so an operator UI can warn
            // before the caller's own next request 401s.
            sessionsInvalidated = true,
            callerSessionInvalidated = true,
            replicaConvergenceSeconds = signingKeys.RefreshInterval.TotalSeconds,
            envelopeEncrypted = _envelope.IsConfigured,
        });
    }
}
