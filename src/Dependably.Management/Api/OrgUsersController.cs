using System.Net.Mail;
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

        // login_attempts/account_send_throttle key on the tenant-scoped lockout pseudonym, whose
        // hash helper lives here in Management; compute it and hand the opaque key to Core.
        string loginAttemptKey = LoginService.HashLockoutKey("tenant", orgId, target.Email);
        await _orgs.RemoveOrgMemberAsync(orgId, userId, loginAttemptKey, ct);
        await _audit.LogAsync("member_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { user_id = userId }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);
        return NoContent();
    }
    /// <summary>
    /// PATCH /api/v1/users/{userId}/email — requests an email change (GDPR Art. 16 rectification).
    ///
    /// Nothing changes here. The endpoint issues a one-shot link and mails it to the address being
    /// moved TO; the account keeps its current address until that link is redeemed. Possession of
    /// the new mailbox is what authorizes the move, which is the point: email is the login
    /// identifier and the destination for password-reset links, so a change that needed only a
    /// session would let a hijacked session repoint account recovery to an attacker's mailbox.
    ///
    /// Two callers are allowed — the subject themselves, who must re-enter their password, and an
    /// admin holding tenant:configure, who is fixing someone else's record and is audited doing
    /// it. Self-service reauthentication is the same posture as a password change: a session alone
    /// is not enough to move the account's identity.
    ///
    /// SAML accounts are refused. The IdP is authoritative for those; a local edit would be
    /// overwritten on next login and the account would silently drift back.
    /// </summary>
    [HttpPatch("api/v1/users/{userId}/email")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> RequestEmailChange(
        string userId,
        [FromBody] ChangeEmailRequest req,
        [FromServices] EmailChangeTokenRepository changeTokens,
        [FromServices] UserService users,
        [FromServices] Dependably.Infrastructure.Mail.TransactionalEmailService mailer,
        [FromServices] TimeProvider time,
        CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        string callerId = GetUserId()!;
        bool isSelf = string.Equals(callerId, userId, StringComparison.Ordinal);

        // An admin acting on someone else needs tenant:configure; the subject acting on their own
        // record needs no capability beyond being that subject.
        if (!isSelf)
        {
            var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
            if (denied is not null)
            {
                return denied;
            }
        }

        // Same validation the invite path applies: a bare, deliverable mailbox — MailAddress
        // rejects malformed input and embedded CR/LF (header injection), and comparing the parsed
        // address back rejects the display-name forms it otherwise accepts.
        string email = (req.Email ?? string.Empty).Trim();
        if (!MailAddress.TryCreate(email, out var parsed) || parsed.Address != email)
        {
            return _problems.ValidationErrorActionKey("email", "error.invite.emailInvalid");
        }

        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        var target = members.FirstOrDefault(m => m.UserId == userId);
        if (target is null)
        {
            return NotFound();
        }

        if (string.Equals(target.AccountType, "saml", StringComparison.Ordinal))
        {
            return _problems.ConflictActionKey("error.user.emailManagedByIdp");
        }

        // Self-service requires re-entering the current password. An admin does not supply the
        // subject's password (they do not have it) — their authority is the capability, and the
        // audit row below is what makes the action accountable.
        if (isSelf)
        {
            if (string.IsNullOrEmpty(req.CurrentPassword)
                || !await users.VerifyCurrentPasswordAsync(userId, req.CurrentPassword, ct))
            {
                return _problems.ValidationErrorActionKey("currentPassword", "error.user.reauthRequired");
            }
        }

        // A no-op request still consumes a link and mails the same address; refuse it rather than
        // send a confirmation for a change that would not change anything.
        if (string.Equals(target.Email, email, StringComparison.OrdinalIgnoreCase))
        {
            return _problems.ConflictActionKey("error.user.emailUnchanged");
        }

        // Best-effort pre-check. UNIQUE (tenant_id, email) is the real arbiter at redemption time,
        // because the address can be claimed in the hours between request and confirmation — this
        // just avoids mailing a link that is already doomed. Deliberately reported the same way
        // whether the address is free or taken by another member would be a membership oracle, so
        // it is NOT: an admin-visible conflict here is acceptable, the caller already has the
        // roster via GET /api/v1/users.
        if (members.Any(m => string.Equals(m.Email, email, StringComparison.OrdinalIgnoreCase)))
        {
            return _problems.ConflictActionKey("error.user.emailTaken");
        }

        string raw = await changeTokens.IssueAsync(userId, orgId, email, ct);
        var expiresAt = changeTokens.ExpiryFor(time.GetUtcNow());
        mailer.EnqueueEmailChangeVerification(email, _urls.Absolute(HttpContext, $"/confirm-email?token={raw}"), expiresAt);

        // The NEW address is recorded in the audit detail deliberately: this is an account-identity
        // change, and a record that cannot say what the account was moved to cannot answer the
        // question it exists for. The OLD address is already on the users row.
        await _audit.LogAsync("user.email_change_requested", orgId, callerId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                user_id = userId,
                new_email = email,
                self_service = isSelf,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Accepted();
    }
}

/// <summary>Body of PATCH /api/v1/users/{userId}/email. CurrentPassword is required for a
/// self-service request and ignored for an admin acting on another member.</summary>
public sealed record ChangeEmailRequest(string? Email, string? CurrentPassword);
