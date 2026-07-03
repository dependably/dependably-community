using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Tenant membership — list, role patch, removal. Split out of <see cref="OrgController"/>
/// Both <see cref="PatchMemberRole"/> and <see cref="RemoveUser"/> enforce a
/// two-tier authorization gate: tenant:configure to enter, plus tenant:admin to touch
/// owner-role rows or grant the owner role. See <c>project_role_management_policy.md</c>.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgUsersController : OrgScopedControllerBase
{
    private readonly OrgRepository _orgs;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly LoginService _login;
    private readonly IPublicUrlBuilder _urls;

    public OrgUsersController(
        OrgRepository orgs,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        LoginService login,
        IPublicUrlBuilder urls)
    {
        _orgs = orgs;
        _guard = guard;
        _audit = audit;
        _problems = problems;
        _login = login;
        _urls = urls;
    }

    /// <summary>GET /api/v1/orgs/{org}/users</summary>
    [HttpGet("api/v1/users")]
    public async Task<IActionResult> ListUsers(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        return Ok(members);
    }

    /// <summary>PATCH /api/v1/orgs/{org}/users/{userId}/role
    /// — admin can manage members/admins; only owner can touch owners or grant owner.</summary>
    [HttpPatch("api/v1/users/{userId}/role")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> PatchMemberRole(string userId, [FromBody] PatchRoleRequest req, CancellationToken ct)
    {
        // Tier 1: tenant:configure gates entry — admin + owner can reach the endpoint.
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (req.Role is not ("member" or "admin" or "owner" or "auditor"))
        {
            return _problems.ValidationErrorActionKey("role", "error.member.roleInvalid");
        }

        string orgId = CurrentTenantId();
        string callerId = GetUserId()!;

        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        var target = members.FirstOrDefault(m => m.UserId == userId);
        if (target is null)
        {
            return NotFound();
        }

        // Tier 2: owner-only operations — modifying an owner OR granting the owner role —
        // require tenant:admin. Admins (tenant:configure but not tenant:admin) can manage
        // members and admins but cannot touch owners.
        if (target.Role == "owner" || req.Role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, callerId, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed)
            {
                return Forbid();
            }
        }

        // Last-owner invariant: regardless of caller, a tenant must always have at least
        // one owner. Demoting or replacing the last owner is rejected.
        if (req.Role != "owner" && target.Role == "owner"
            && await _orgs.CountOwnersAsync(orgId, ct) <= 1)
        {
            return _problems.ConflictActionKey("error.member.lastOwnerDemote");
        }

        // A same-role PATCH is a no-op: skip the token_version bump — which would otherwise
        // force-log-out every one of the target's sessions — and the role-change audit event.
        if (target.Role == req.Role)
        {
            return NoContent();
        }

        // Bumps token_version and evicts the version cache, so the target's outstanding session
        // JWTs (which snapshot the old role) fail the tver check on their next request — a demotion
        // takes effect immediately rather than persisting for the 8h token lifetime.
        long newTokenVersion = await _orgs.UpdateMemberRoleAsync(orgId, userId, req.Role, ct);
        await _audit.LogAsync("member_role_changed", orgId, callerId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { user_id = userId, new_role = req.Role }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);

        // Self role change: the caller's own session JWT was just staled by the token_version bump.
        // Re-issue their cookie at the new role and version so they stay logged in with the updated
        // (typically lower) privileges rather than being bounced to the login screen.
        if (userId == callerId)
        {
            string fresh = await _login.IssueTenantSessionAsync(callerId, orgId, req.Role, newTokenVersion, ct);
            Response.Cookies.Append("dependably_session", fresh, _urls.SessionCookieOptions(HttpContext));
        }

        return NoContent();
    }

    /// <summary>DELETE /api/v1/orgs/{org}/users/{userId}
    /// — admin can remove members/admins; only owner can remove an owner.</summary>
    [HttpDelete("api/v1/users/{userId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RemoveUser(string userId, CancellationToken ct)
    {
        // Tier 1: tenant:configure entry gate.
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        string callerId = GetUserId()!;

        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        var target = members.FirstOrDefault(m => m.UserId == userId);
        if (target is null)
        {
            return NotFound();
        }

        // Tier 2: removing an owner requires tenant:admin. Admins cannot remove owners.
        if (target.Role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, callerId, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed)
            {
                return Forbid();
            }
        }

        // Last-owner invariant: tenant must always have at least one owner.
        if (target.Role == "owner" && await _orgs.CountOwnersAsync(orgId, ct) <= 1)
        {
            return _problems.ConflictActionKey("error.member.lastOwnerRemove");
        }

        await _orgs.RemoveOrgMemberAsync(orgId, userId, ct);
        await _audit.LogAsync("member_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { user_id = userId }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);
        return NoContent();
    }
}
