using System.Security.Claims;
using Dependably.Infrastructure.Identity;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Apex-only stored-secret verification (multi-tenant deployments). Every route under
/// <c>/api/v1/system/</c> requires <c>scope=system</c> + apex context, enforced globally by
/// <see cref="Dependably.Security.RouteScopeFilter"/> (no session is a 401, a tenant session is a
/// 404). The single-mode counterpart is <c>POST /api/v1/instance/secrets/verify</c> on
/// <see cref="InstanceController"/>; both run the same <see cref="ProtectedSecretVerifier"/>.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// POST /api/v1/system/secrets/verify — tries to decrypt every stored secret on the instance
    /// and lists the rows that cannot be decrypted by table, row id, org id, kind and reason. No
    /// value, ciphertext or fragment of either is ever returned or logged. Values stored
    /// unencrypted are counted separately and are not failures.
    ///
    /// <para>POST rather than GET: each call sweeps every protected table and writes an audit row,
    /// so it is an action, not a cacheable read. Rate-limited per caller by the
    /// <c>secrets-verify</c> policy, and concurrent calls run one at a time.</para>
    /// </summary>
    [HttpPost("secrets/verify")]
    [EnableRateLimiting("secrets-verify")]
    [ProducesResponseType(typeof(ProtectedSecretReport), StatusCodes.Status200OK)]
    public async Task<IActionResult> VerifyProtectedSecrets(
        [FromServices] ProtectedSecretVerifier verifier,
        CancellationToken ct)
    {
        var report = await verifier.VerifyAsync(ct);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;

        // Counts only: the failing rows are in the response, not the audit detail, so the audit
        // log never becomes a second list of which credentials are broken.
        await _audit.LogSystemAsync(
            action: "system_admin.protected_secrets_verified",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                @checked = report.Checked,
                failed = report.Failed,
                legacy_plaintext = report.LegacyPlaintext,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        return Ok(report);
    }
}
