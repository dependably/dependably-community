using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

public sealed partial class SystemController
{
    // ── Trust-anchor integrity audit on /api/v1/system/trust-anchors/suspect ────
    // Read-only, cross-tenant, and deliberately the only surface that reports these rows: no
    // migration, schema step, or background job touches signature_trust_anchor. A suspect row is
    // an (ecosystem, anchor_kind) pair with no registered material validator, so its material was
    // stored without ever being parsed or strength-checked.
    //
    // Deleting one is an operator decision with a consequence a script cannot weigh. For rpm,
    // maven, npm, nuget and apk, IPerOrgTrustAnchorStore.IsConfiguredForAsync tests only whether
    // any row exists in the ecosystem, so a lone suspect row makes verify_*_signatures='block'
    // read as backed while every artifact resolves to a not-applicable verdict that passes.
    // Removing that row flips IsProvenanceEnforcementUnbackedAsync to true, which synthesizes the
    // blocking 'unverifiable' marker — the tenant goes from serving everything to denying every
    // artifact of that ecosystem in one step. Separately, the npm/nuget/apk material builders do
    // not filter on anchor_kind, so a mislabelled row whose material parses is a live,
    // currently-verifying anchor rather than inert bytes.

    /// <summary>
    /// GET /api/v1/system/trust-anchors/suspect — every signature trust anchor, across all live
    /// tenants, stored under an <c>(ecosystem, anchor_kind)</c> pair that has no registered
    /// material validator. System-admin + apex access enforced by
    /// <see cref="Dependably.Security.RouteScopeFilter"/> plus the class-level
    /// <c>[Authorize]</c>. Never returns <c>material</c> — anchor material is write-only over the
    /// API on every surface, matching <c>GET /api/v1/trust-anchors</c>.
    /// </summary>
    [HttpGet("trust-anchors/suspect")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ListSuspectTrustAnchors(
        [FromServices] TrustAnchorRepository anchors,
        CancellationToken ct = default)
    {
        var items = await anchors.ListSuspectAsync(ct);

        return Ok(new
        {
            items = items.Select(a => new
            {
                id = a.Id,
                orgId = a.OrgId,
                orgSlug = a.OrgSlug,
                ecosystem = a.Ecosystem,
                anchorKind = a.AnchorKind,
                keyId = a.KeyId,
                label = a.Label,
                createdAt = a.CreatedAt,
                createdBy = a.CreatedBy,
            }),
            total = items.Count,
        });
    }
}
