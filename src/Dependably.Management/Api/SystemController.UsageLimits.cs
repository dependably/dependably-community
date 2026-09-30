using Dependably.Infrastructure.Usage;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only per-meter usage caps (multi-tenant deployments). The operator, or a control plane
/// holding a system token, sets each tenant's caps in meter units; community stores the numbers,
/// never a price or a plan. The hourly usage rollup turns caps and month-to-date usage into
/// <c>orgs.usage_posture</c>, which the protocol plane enforces: uploads are refused at 100 % of any
/// capped meter, and downloads are throttled at 110 % of a capped egress meter.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// GET /api/v1/system/tenants/{slug}/usage-limits — the tenant's explicit caps
    /// (<c>caps</c>), the instance-wide defaults from <c>DEFAULT_USAGE_CAPS</c>
    /// (<c>defaultCaps</c>), the caps that actually apply (<c>effectiveCaps</c>: explicit, plus
    /// the default on each meter with no explicit cap), and its current usage posture. Each map
    /// is keyed by meter, and a meter with no cap is absent. 404 when the slug does not resolve to
    /// a live tenant.
    /// </summary>
    [HttpGet("tenants/{slug}/usage-limits")]
    [Authorize(AuthenticationSchemes = "Bearer," + SystemTokenDefaults.Scheme)]
    public async Task<IActionResult> GetTenantUsageLimits(
        string slug,
        [FromServices] UsagePostureRepository postures,
        CancellationToken ct)
    {
        var org = await _orgs.GetBySlugAsync(slug, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        var caps = await postures.GetCapsAsync(org.Id, ct);
        string posture = await postures.GetPostureAsync(org.Id, ct);
        return Ok(ProjectUsageLimits(org.Slug, caps, postures.Defaults, posture));
    }

    /// <summary>
    /// PATCH /api/v1/system/tenants/{slug}/usage-limits — set or clear the tenant's per-meter usage
    /// caps. Body: <c>{ "caps": { "egress_bytes": 500000000000, "artifact_count": null } }</c>. The
    /// keys are the meter literals <c>egress_bytes</c>, <c>egress_metadata_bytes</c>,
    /// <c>storage_bytes</c> and <c>artifact_count</c>; a positive quantity sets that meter's cap,
    /// an explicit null clears it (the meter falls back to its <c>DEFAULT_USAGE_CAPS</c> default,
    /// if it has one), and a meter left out keeps its current cap. Zero, a negative
    /// quantity, or an unknown meter is rejected as 422 and nothing is changed.
    ///
    /// <para>
    /// The tenant's posture is recomputed before the response, from the new caps and the usage
    /// the rollups have recorded so far, and the tenant resolver's cache for the slug is evicted,
    /// so a lifted cap restores service on the next request to this replica (other replicas pick
    /// it up within their 5-second resolver cache TTL). The response carries the resulting caps
    /// and posture.
    /// </para>
    /// </summary>
    [HttpPatch("tenants/{slug}/usage-limits")]
    [Authorize(AuthenticationSchemes = "Bearer," + SystemTokenDefaults.Scheme)]
    public async Task<IActionResult> SetTenantUsageLimits(
        string slug,
        [FromBody] SetUsageLimitsRequest? req,
        [FromServices] UsagePostureRepository postures,
        CancellationToken ct)
    {
        if (req?.Caps is null)
        {
            return _problems.ValidationErrorActionKey("caps", "error.common.bodyRequired");
        }

        foreach (var (meter, cap) in req.Caps)
        {
            if (!UsageCapMeters.IsKnown(meter))
            {
                return _problems.ValidationErrorActionKey("caps", "error.system.usageMeterUnknown");
            }

            if (cap is long quantity && quantity <= 0)
            {
                return _problems.ValidationErrorActionKey("caps." + meter, "error.system.usageCapInvalid");
            }
        }

        var org = await _orgs.GetBySlugAsync(slug, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        var priorCaps = await postures.GetCapsAsync(org.Id, ct);
        string priorPosture = await postures.GetPostureAsync(org.Id, ct);

        await postures.SetCapsAsync(org.Id, req.Caps, ct);
        string posture = await postures.RecomputeForOrgAsync(org.Id, ct);
        var caps = await postures.GetCapsAsync(org.Id, ct);

        _tenantCache?.InvalidateSlug(org.Slug);

        var actor = SystemActor.From(User);
        await _audit.LogSystemAsync(
            action: "tenant.usage_limits_changed",
            actorId: actor.Id,
            orgId: org.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                slug = org.Slug,
                changes = req.Caps,
                caps,
                priorCaps,
                usagePosture = posture,
                priorUsagePosture = priorPosture,
                via_token_owner = actor.OwnerId,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            actorKind: actor.Kind,
            actorLabel: actor.Label,
            ct: ct);

        return Ok(ProjectUsageLimits(org.Slug, caps, postures.Defaults, posture));
    }

    private static object ProjectUsageLimits(
        string slug, IReadOnlyDictionary<string, long> caps, DefaultUsageCaps defaults, string posture) => new
        {
            slug,
            caps = InMeterOrder(caps),
            defaultCaps = InMeterOrder(defaults.Caps),
            effectiveCaps = InMeterOrder(defaults.Effective(caps)),
            usagePosture = posture,
        };

    private static Dictionary<string, long> InMeterOrder(IReadOnlyDictionary<string, long> caps) =>
        UsageCapMeters.All
            .Where(caps.ContainsKey)
            .ToDictionary(m => m, m => caps[m], StringComparer.Ordinal);
}

/// <summary>
/// Body of <c>PATCH /api/v1/system/tenants/{slug}/usage-limits</c>: meter literal to cap quantity,
/// where null clears that meter's cap and a meter left out is unchanged.
/// </summary>
public sealed record SetUsageLimitsRequest(Dictionary<string, long?>? Caps);
