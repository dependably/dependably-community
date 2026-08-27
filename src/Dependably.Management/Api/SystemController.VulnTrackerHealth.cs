using Dependably.Infrastructure.VulnTracker;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only vulnerability-tracker health surface (multi-tenant deployments). Multi-mode
/// counterpart of <c>InstanceController</c>'s single-mode
/// <c>/api/v1/instance/vuln-tracker-health</c> route; both read the same
/// <see cref="VulnTrackerHealthAggregator"/> so the two surfaces can't drift. Every route
/// requires <c>scope=system</c> + apex context, enforced by
/// <see cref="Dependably.Security.RouteScopeFilter"/> on every <c>/api/v1/system/</c> route —
/// the same authorization decision the sibling <c>vuln-tracker-config</c> routes carry.
///
/// <para>
/// Read-only and separate from the config routes on purpose: the connection an operator edits and
/// the health it exhibits are two different questions about the same thing, and a combined
/// payload would make the editor re-read health on every keystroke-triggered save.
/// </para>
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// GET /api/v1/system/vuln-tracker-health — whether the tracker connection is configured, what
    /// the scan path's last lookups did, what the producer asserts its sources are current to, and
    /// how many stored advisories have aged past the horizon. Counts and instants only; no purl,
    /// no advisory id and no tenant identifier.
    /// </summary>
    [HttpGet("vuln-tracker-health")]
    public async Task<IActionResult> GetVulnTrackerHealth(
        [FromServices] VulnTrackerHealthAggregator health,
        CancellationToken ct)
        => Ok(VulnTrackerHealthAggregator.BuildView(await health.GetAsync(ct)));
}
