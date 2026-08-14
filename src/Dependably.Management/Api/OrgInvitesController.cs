using System.Net.Mail;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Mail;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Tenant invites — create / list / cancel. Split out of <see cref="OrgController"/>.
/// Owner-role invites are gated by tenant:admin (mirrors PatchMemberRole); admins with
/// tenant:configure can invite member / admin / auditor.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgInvitesController : OrgScopedControllerBase
{
    private readonly InviteRepository _invites;
    private readonly OrgRepository _orgs;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ILogger<OrgInvitesController> _logger;
    private readonly IPublicUrlBuilder _urls;
    private readonly ProblemResults _problems;
    private readonly IInviteMailer? _mailer;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Dependency-injection constructor: the parameter list is the declared dependency set; grouping it into an aggregate would hide dependencies without adding cohesion.")]
    public OrgInvitesController(
        InviteRepository invites,
        OrgRepository orgs,
        OrgAccessGuard guard,
        AuditRepository audit,
        ILogger<OrgInvitesController> logger,
        IPublicUrlBuilder urls,
        ProblemResults problems,
        IInviteMailer? mailer = null)
    {
        _invites = invites;
        _orgs = orgs;
        _guard = guard;
        _audit = audit;
        _logger = logger;
        _urls = urls;
        _problems = problems;
        _mailer = mailer;
    }

    /// <summary>GET /api/v1/orgs/{org}/invites</summary>
    [HttpGet("api/v1/invites")]
    public async Task<IActionResult> ListInvites(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var list = await _invites.ListAsync(orgId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/invites</summary>
    [HttpPost("api/v1/invites")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> CreateInvite([FromBody] CreateInviteRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(req.Email))
        {
            return _problems.ValidationErrorActionKey("email", "error.invite.emailRequired");
        }

        // The invite address must be a bare, deliverable mailbox. MailAddress.TryCreate rejects
        // malformed input and embedded CR/LF (header injection); comparing the parsed Address back
        // to the input additionally rejects the display-name forms TryCreate accepts
        // ("Name" <a@b.c>), so the stored value is exactly what the mailer will send to and
        // exactly what the pending-invite uniqueness check compares.
        string email = req.Email.Trim();
        if (!MailAddress.TryCreate(email, out var parsed) || parsed.Address != email)
        {
            return _problems.ValidationErrorActionKey("email", "error.invite.emailInvalid");
        }

        string orgId = CurrentTenantId();
        string? userId = GetUserId();
        string role = string.IsNullOrWhiteSpace(req.Role) ? "member" : req.Role.Trim().ToLowerInvariant();
        if (role is not ("member" or "admin" or "owner" or "auditor"))
        {
            return _problems.ValidationErrorActionKey("role", "error.member.roleInvalid");
        }

        // Inviting at owner is an owner-only operation, matching PatchMemberRole. Admins
        // (tenant:configure) can invite member/admin/auditor; only owners (tenant:admin)
        // can mint an invite that lands the invitee as an owner.
        if (role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, userId!, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed)
            {
                return Forbid();
            }
        }

        // Pending-invite cap. Count+insert is intentionally non-transactional: a small
        // race overshoot (two concurrent creates both reading the same count just below the
        // cap) is acceptable and bounded — the DB grows by at most one row past the cap in
        // a concurrent burst.
        int pendingCount = await _invites.CountPendingAsync(orgId, ct);
        int cap = await _orgs.GetMaxPendingInvitesPerTenantAsync(ct);
        if (pendingCount >= cap)
        {
            return _problems.ValidationErrorActionKey("invites", "error.invite.limitReached", cap);
        }

        // One pending invite per (tenant, address) — the state idx_invites_unique_pending
        // enforces. Pre-check so the common case answers 409 with a message the inviter can act
        // on (cancel the outstanding invite, then re-send) instead of surfacing a store error.
        if (await _invites.HasPendingAsync(orgId, email, ct))
        {
            return _problems.ConflictActionKey("error.invite.duplicatePending", reason: "duplicate_pending_invite");
        }

        // The pre-check is advisory: two concurrent creates for the same address can both pass
        // it. CreateAsync resolves the loser to null via the index's conflict target rather than
        // throwing, so the race lands on the same 409 as the sequential case.
        var created = await _invites.CreateAsync(orgId, email, userId!, role, ct);
        if (created is null)
        {
            return _problems.ConflictActionKey("error.invite.duplicatePending", reason: "duplicate_pending_invite");
        }

        var (raw, record) = created;

        await _audit.LogAsync("invite_created", orgId, userId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                invite_id = record.Id,
                email = record.Email,
                role = record.Role,
                expires_at = record.ExpiresAt,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Join is served by the tenant SPA at the request host: single-mode → the bare host IS the
        // tenant; multi-mode → the admin issuing the invite is already on the tenant subdomain
        // (SubdomainTenantResolver), which is where /join resolves. The apex SystemApp has no join
        // route, so BASE_URL must not win here.
        string inviteLink = _urls.Absolute(HttpContext, $"/join?token={raw}");

        var mailer = await ResolveAvailableMailerAsync(record.Id, orgId, ct);
        if (mailer is null)
        {
            // Invite id + tenant id are enough to correlate without exposing the recipient's
            // email or the invite token. The email lives in the audit_log entry above
            // (intentional, per audit_log vs activity policy); the link — which embeds the
            // raw invite token — is never logged at any level. The API response is the
            // sanctioned channel for the link.
            // Logs only record.Id (invite GUID) and tenant id: the record carries an Email field,
            // but no email, token, or link reaches the log sink.
            _logger.LogInformation("Invite {InviteId} created for tenant {TenantId}; SMTP not configured — retrieve link from API response.", record.Id, orgId);
            return Ok(new { record, invite_link = inviteLink, delivered_via = "link" });
        }

        // SMTP configured — attempt delivery. On failure, fall back to returning the link
        // so the inviter can deliver it manually. The invite token embedded in the link is
        // never written to any log property; only the org/invite-id correlation is logged.
        try
        {
            string orgSlug = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantSlug ?? orgId;
            // The invitee has no account (and no language preference) yet — the tenant's
            // default language is the best signal for the email locale.
            var settings = await _orgs.GetSettingsAsync(orgId, ct);
            string inviteLanguage = settings?.DefaultLanguage ?? LanguageCodes.Default;
            // the mailer logs only the recipient's domain
            // (ExtractDomain) — the email local-part, invite link, and token never reach a log sink.
            await mailer.SendInviteAsync(record.Email, orgSlug, inviteLink, record.ExpiresAt, inviteLanguage, ct);
            return Ok(new { record, invite_link = (string?)null, delivered_via = "email" });
        }
        catch (Exception ex)
        {
            // logs only ExceptionType, record.Id (invite GUID) and tenant id — the tainted record's email/token never reaches the sink.
            _logger.LogWarning(
                ex,
                "ExceptionType={ExceptionType} invite email delivery failed for invite {InviteId} on tenant {TenantId}; returning link as fallback.",
                ex.GetType().Name,
                record.Id,
                orgId);
            return Ok(new { record, invite_link = inviteLink, delivered_via = "link" });
        }
    }

    /// <summary>
    /// Returns the mailer when instance SMTP can deliver, or null when it cannot. The
    /// availability probe reads <c>instance_settings</c> (and decrypts the stored SMTP secret
    /// when a master key is configured), so it has failure modes of its own. It runs after the
    /// invite row is committed, so a throwing probe degrades to the link-in-response path
    /// exactly as a throwing <c>SendInviteAsync</c> does — the alternative is a 500 that hides
    /// an invite the tenant can neither retrieve nor re-issue.
    /// Logs only the invite id and tenant id; no email, token, or link reaches the sink.
    /// </summary>
    private async Task<IInviteMailer?> ResolveAvailableMailerAsync(string inviteId, string orgId, CancellationToken ct)
    {
        if (_mailer is null)
        {
            return null;
        }

        try
        {
            return await _mailer.IsAvailableAsync(ct) ? _mailer : null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "ExceptionType={ExceptionType} instance SMTP availability probe failed for invite {InviteId} on tenant {TenantId}; treating delivery as unavailable and returning link as fallback.",
                ex.GetType().Name,
                inviteId,
                orgId);
            return null;
        }
    }

    /// <summary>DELETE /api/v1/orgs/{org}/invites/{id}</summary>
    [HttpDelete("api/v1/invites/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteInvite(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        // org_id-scoped: a cross-tenant (or unknown) id deletes 0 rows. Delete stays idempotent
        // (204 either way); the org scope is what enforces isolation. Audit only a real removal.
        string orgId = CurrentTenantId();
        if (await _invites.DeleteAsync(orgId, id, ct) > 0)
        {
            await _audit.LogAsync("invite_deleted", orgId, GetUserId(),
                actorKind: ActorKinds.User,
                detail: System.Text.Json.JsonSerializer.Serialize(new { invite_id = id }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
                sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        }

        return NoContent();
    }
}
