using Dependably.Infrastructure.Mail;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only relay-health surface (multi-tenant deployments). Multi-mode counterpart of
/// <c>InstanceController</c>'s single-mode <c>/api/v1/instance/email-health</c> route; both read
/// the same <see cref="RelayHealthAggregator"/> so the two surfaces can't drift. Every route
/// requires <c>scope=system</c> + apex context, enforced by
/// <see cref="Dependably.Security.RouteScopeFilter"/> on every <c>/api/v1/system/</c> route — the
/// same authorization decision the sibling <c>email-config</c> routes carry.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// GET /api/v1/system/email-health — the operator's aggregate view of the shared SMTP relay:
    /// how many tenants are currently failing to deliver, the worst consecutive-failure streak,
    /// when it started, and the durable outbox's backlog. Every field is a count or an aggregate
    /// timestamp; no tenant identifier is ever included.
    /// </summary>
    [HttpGet("email-health")]
    public async Task<IActionResult> GetEmailHealth(
        [FromServices] RelayHealthAggregator relayHealth,
        CancellationToken ct)
    {
        var health = await relayHealth.GetAsync(ct);
        return Ok(health);
    }
}
