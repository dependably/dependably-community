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
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default for the BASE_URL env-var used in invite-link templates; only relevant when running locally without configuration.")]
    private const string DefaultBaseUrl = "http://localhost:8080";

    private readonly InviteRepository _invites;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly IConfiguration _config;
    private readonly ILogger<OrgInvitesController> _logger;
    private readonly IPublicUrlBuilder _urls;
    private readonly ProblemResults _problems;
    private readonly IInviteMailer? _mailer;

    // Dependency-injection constructor; the parameter list is the controller's declared
    // dependency set and grouping it into an aggregate would hide dependencies without
    // adding cohesion.
#pragma warning disable S107
    public OrgInvitesController(
        InviteRepository invites,
        OrgAccessGuard guard,
        AuditRepository audit,
        IConfiguration config,
        ILogger<OrgInvitesController> logger,
        IPublicUrlBuilder urls,
        ProblemResults problems,
        IInviteMailer? mailer = null)
#pragma warning restore S107
    {
        _invites = invites;
        _guard = guard;
        _audit = audit;
        _config = config;
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
            return _problems.ValidationErrorAction("email", "Email is required.");
        }

        string orgId = CurrentTenantId();
        string? userId = GetUserId();
        string role = string.IsNullOrWhiteSpace(req.Role) ? "member" : req.Role.Trim().ToLowerInvariant();
        if (role is not ("member" or "admin" or "owner" or "auditor"))
        {
            return _problems.ValidationErrorAction("role", "Role must be 'member', 'admin', 'owner', or 'auditor'.");
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

        var (raw, record) = await _invites.CreateAsync(orgId, req.Email, userId!, role, ct);

        await _audit.LogAsync("invite_created", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                invite_id = record.Id,
                email = record.Email,
                role = record.Role,
                expires_at = record.ExpiresAt,
            }), ct: ct);

        // Invite links go to the apex (system_admin/landing) for join flows. BASE_URL wins
        // when set so links are stable across hosts; falls back to the request's base.
        string baseUrl = _config.PublicBaseUrl() ?? _urls.BaseUrl(HttpContext);
        string inviteLink = $"{baseUrl}/join?token={raw}";

        if (_mailer is null)
        {
            // Invite id + tenant id are enough to correlate without exposing the recipient's
            // email or the invite token. The email lives in the audit_log entry above
            // (intentional, per audit_log vs activity policy); the link — which embeds the
            // raw invite token — is never logged at any level. The API response is the
            // sanctioned channel for the link.
            _logger.LogInformation("Invite {InviteId} created for tenant {TenantId}; SMTP not configured — retrieve link from API response.", record.Id, orgId);
            return Ok(new { record, invite_link = inviteLink, delivered_via = "link" });
        }

        // SMTP configured — attempt delivery. On failure, fall back to returning the link
        // so the inviter can deliver it manually. The invite token embedded in the link is
        // never written to any log property; only the org/invite-id correlation is logged.
        try
        {
            string orgSlug = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantSlug ?? orgId;
            await _mailer.SendInviteAsync(record.Email, orgSlug, inviteLink, record.ExpiresAt, ct);
            return Ok(new { record, invite_link = (string?)null, delivered_via = "email" });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "ExceptionType={ExceptionType} invite email delivery failed for invite {InviteId} on tenant {TenantId}; returning link as fallback.",
                ex.GetType().Name,
                record.Id,
                orgId);
            return Ok(new { record, invite_link = inviteLink, delivered_via = "link" });
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
                detail: System.Text.Json.JsonSerializer.Serialize(new { invite_id = id }), ct: ct);
        }

        return NoContent();
    }
}
