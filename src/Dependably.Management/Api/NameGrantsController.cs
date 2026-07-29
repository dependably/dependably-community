using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Admin surface for the name-binding co-publish grants enforced by
/// <see cref="Dependably.Security.NameBindingGate"/>.
///
/// <para>
/// A name is bound to its first hosted publisher on trust-on-first-use, and thereafter only that
/// principal may publish it. That is the right default for a name published by one CI token, and
/// exactly wrong for a name legitimately published by several — a rotated token, or a package two
/// pipelines both push. A grant is the deliberate operator opt-in that says "this other principal
/// may publish this name too". Until this surface existed the only way to record one was a direct
/// INSERT, which is why <c>PUBLISH_NAME_BINDING</c> could not be turned on in an org with more
/// than one publishing principal.
/// </para>
///
/// <para>
/// The name is carried as a query parameter rather than a route segment throughout: canonical
/// package names contain slashes (<c>@scope/pkg</c>, OCI repository paths) and colons (Maven
/// coordinates), which a path segment cannot hold without double-encoding every caller.
/// </para>
///
/// <para>
/// Both isolation checks matter and neither implies the other. Every read and write is scoped to
/// <c>CurrentTenantId()</c>, resolved from the authenticated principal — so a caller can only see
/// or change their own org's rows. Separately, a grantee id arrives in the request body, and is
/// resolved against this org's own roster before it can be written: without that, an admin could
/// mint a well-scoped-looking grant row pointing at another tenant's user or service token.
/// </para>
/// </summary>
[ApiController]
[Authorize]
public sealed class NameGrantsController : OrgScopedControllerBase
{
    private readonly NameBindingRepository _bindings;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public NameGrantsController(
        NameBindingRepository bindings,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _bindings = bindings;
        _guard = guard;
        _audit = audit;
        _problems = problems;
    }

    /// <summary>The two principal kinds a grant may name, matching the column's CHECK constraint.</summary>
    private static readonly string[] GranteeKinds = [ActorKinds.User, ActorKinds.Service];

    /// <summary>
    /// GET /api/v1/name-bindings — the names bound within the caller's org, optionally narrowed to
    /// one ecosystem. A grant only means anything against an already-bound name, so this is what an
    /// admin reads first.
    /// </summary>
    [HttpGet("api/v1/name-bindings")]
    public async Task<IActionResult> ListBindings([FromQuery] string? ecosystem, CancellationToken ct)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (denied is not null)
        {
            return denied;
        }

        string? normalizedEcosystem = NormalizeEcosystem(ecosystem);
        if (ecosystem is not null && normalizedEcosystem is null)
        {
            return UnsupportedEcosystem();
        }

        var bindings = await _bindings.ListBindingsAsync(CurrentTenantId(), normalizedEcosystem, ct);
        return Ok(bindings.Select(b => new
        {
            b.Id,
            b.Ecosystem,
            Name = b.PurlName,
            b.OwnerKind,
            b.OwnerId,
            b.CreatedAt,
        }));
    }

    /// <summary>
    /// GET /api/v1/name-grants?ecosystem=&amp;name= — the co-publish grants recorded against one
    /// bound name in the caller's org.
    /// </summary>
    [HttpGet("api/v1/name-grants")]
    public async Task<IActionResult> ListGrants(
        [FromQuery] string? ecosystem, [FromQuery] string? name, CancellationToken ct)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (denied is not null)
        {
            return denied;
        }

        string? normalizedEcosystem = NormalizeEcosystem(ecosystem);
        if (normalizedEcosystem is null)
        {
            return UnsupportedEcosystem();
        }

        string trimmedName = (name ?? string.Empty).Trim();
        if (trimmedName.Length == 0)
        {
            return _problems.ValidationErrorActionKey("name", "error.nameGrant.nameRequired");
        }

        var grants = await _bindings.ListGrantsAsync(CurrentTenantId(), normalizedEcosystem, trimmedName, ct);
        return Ok(grants.Select(Project));
    }

    /// <summary>
    /// POST /api/v1/name-grants — authorizes an additional principal to publish an already-bound
    /// name. Idempotent: re-granting an existing pair returns the same 201 rather than a conflict,
    /// matching the repository's <c>ON CONFLICT DO NOTHING</c> insert, so a config-management run
    /// that reapplies its desired state does not have to special-case "already granted".
    ///
    /// Refused when the name is not bound: a grant against an unbound name would silently do
    /// nothing (the gate never consults grants for a name with no owner), and returning success for
    /// an operation with no effect is how an operator ends up believing enforcement is configured
    /// when it is not.
    /// </summary>
    [HttpPost("api/v1/name-grants")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> CreateGrant([FromBody] CreateNameGrantRequest req, CancellationToken ct)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (denied is not null)
        {
            return denied;
        }

        if (req is null)
        {
            return _problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
        }

        string? ecosystem = NormalizeEcosystem(req.Ecosystem);
        if (ecosystem is null)
        {
            return UnsupportedEcosystem();
        }

        string name = (req.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return _problems.ValidationErrorActionKey("name", "error.nameGrant.nameRequired");
        }

        string granteeKind = (req.GranteeKind ?? string.Empty).Trim().ToLowerInvariant();
        if (!GranteeKinds.Contains(granteeKind, StringComparer.Ordinal))
        {
            return _problems.ValidationErrorActionKey(
                "granteeKind", "error.common.mustBeOneOf", string.Join(", ", GranteeKinds));
        }

        string granteeId = (req.GranteeId ?? string.Empty).Trim();
        if (granteeId.Length == 0)
        {
            return _problems.ValidationErrorActionKey("granteeId", "error.nameGrant.granteeIdRequired");
        }

        string orgId = CurrentTenantId();

        var binding = await _bindings.GetBindingAsync(orgId, ecosystem, name, ct);
        if (binding is null)
        {
            return _problems.NotFoundActionKey("error.nameGrant.nameNotBound");
        }

        var grantee = new NamePrincipal(granteeKind, granteeId);
        if (!await _bindings.GranteeExistsInOrgAsync(orgId, grantee, ct))
        {
            // Deliberately the same answer for "no such principal anywhere" and "that principal
            // belongs to another tenant": distinguishing them would turn this field into a probe
            // for whether a given id exists in some other org.
            return _problems.ValidationErrorActionKey("granteeId", "error.nameGrant.granteeUnknown");
        }

        await _bindings.AddGrantAsync(orgId, ecosystem, name, grantee, GetUserId(), ct);

        // Re-read so the response and the audit row carry the persisted row's id and timestamp —
        // including on the idempotent re-grant, where the insert wrote nothing.
        var grants = await _bindings.ListGrantsAsync(orgId, ecosystem, name, ct);
        var created = grants.First(g =>
            string.Equals(g.GranteeKind, granteeKind, StringComparison.Ordinal)
            && string.Equals(g.GranteeId, granteeId, StringComparison.Ordinal));

        await _audit.LogAsync(
            "name_grant_added", orgId, GetUserId(),
            ecosystem: ecosystem,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = created.Id,
                ecosystem,
                purl_name = name,
                grantee_kind = granteeKind,
                grantee_id = granteeId,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return CreatedAtAction(nameof(ListGrants), null, Project(created));
    }

    /// <summary>
    /// DELETE /api/v1/name-grants/{grantId} — revokes a co-publish grant. The grant is read before
    /// deletion so the audit row can say which name and principal lost the authorization; both the
    /// read and the delete carry the org predicate, so a grant id belonging to another tenant is
    /// indistinguishable here from one that does not exist.
    /// </summary>
    [HttpDelete("api/v1/name-grants/{grantId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeGrant(string grantId, CancellationToken ct)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (denied is not null)
        {
            return denied;
        }

        string orgId = CurrentTenantId();
        var existing = await _bindings.GetGrantAsync(orgId, grantId, ct);
        if (existing is null)
        {
            return NotFound();
        }

        await _bindings.RemoveGrantAsync(orgId, grantId, ct);

        await _audit.LogAsync(
            "name_grant_revoked", orgId, GetUserId(),
            ecosystem: existing.Ecosystem,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = existing.Id,
                ecosystem = existing.Ecosystem,
                purl_name = existing.PurlName,
                grantee_kind = existing.GranteeKind,
                grantee_id = existing.GranteeId,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return NoContent();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Lower-cases and validates the ecosystem against the set the name-binding gate actually
    /// enforces. Null for an absent, blank, or unenforced value — an ecosystem with no hosted
    /// publish path can hold no binding, so a grant there would be permanently inert.
    /// </summary>
    private static string? NormalizeEcosystem(string? ecosystem)
    {
        string normalized = (ecosystem ?? string.Empty).Trim().ToLowerInvariant();
        return NameBindingEcosystems.Covers(normalized) ? normalized : null;
    }

    private IActionResult UnsupportedEcosystem() =>
        _problems.ValidationErrorActionKey(
            "ecosystem", "error.common.mustBeOneOf",
            string.Join(", ", NameBindingEcosystems.Enforced.OrderBy(e => e, StringComparer.Ordinal)));

    private static object Project(NameGrant grant) => new
    {
        grant.Id,
        grant.Ecosystem,
        Name = grant.PurlName,
        grant.GranteeKind,
        grant.GranteeId,
        grant.CreatedBy,
        grant.CreatedAt,
    };
}

/// <summary>Request body for <see cref="NameGrantsController.CreateGrant"/>.</summary>
public sealed record CreateNameGrantRequest(
    string? Ecosystem,
    string? Name,
    string? GranteeKind,
    string? GranteeId);
