using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// Tenant invites — create / list / cancel. Split out of <see cref="OrgController"/> (#61).
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

    public OrgInvitesController(
        InviteRepository invites,
        OrgAccessGuard guard,
        AuditRepository audit,
        IConfiguration config,
        ILogger<OrgInvitesController> logger,
        IPublicUrlBuilder urls,
        ProblemResults problems)
    {
        _invites = invites;
        _guard = guard;
        _audit = audit;
        _config = config;
        _logger = logger;
        _urls = urls;
        _problems = problems;
    }

    /// <summary>GET /api/v1/orgs/{org}/invites</summary>
    [HttpGet("api/v1/invites")]
    public async Task<IActionResult> ListInvites(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var list = await _invites.ListAsync(orgId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/invites</summary>
    [HttpPost("api/v1/invites")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> CreateInvite([FromBody] CreateInviteRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.Email))
            return _problems.ValidationErrorAction("email", "Email is required.");

        var orgId = CurrentTenantId();
        var userId = GetUserId();
        var role = string.IsNullOrWhiteSpace(req.Role) ? "member" : req.Role.Trim().ToLowerInvariant();
        if (role is not ("member" or "admin" or "owner" or "auditor"))
            return _problems.ValidationErrorAction("role", "Role must be 'member', 'admin', 'owner', or 'auditor'.");

        // Inviting at owner is an owner-only operation, matching PatchMemberRole. Admins
        // (tenant:configure) can invite member/admin/auditor; only owners (tenant:admin)
        // can mint an invite that lands the invitee as an owner.
        if (role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, userId!, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed) return Forbid();
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
        var baseUrl = _config.PublicBaseUrl() ?? _urls.BaseUrl(HttpContext);
        var inviteLink = $"{baseUrl}/join?token={raw}";

        var smtpHost = _config["SMTP_HOST"];
        if (smtpHost is null)
        {
            // Information-level: invite id + tenant id are enough to correlate without exposing
            // the recipient's email at default verbosity. The email lives in the audit_log entry
            // above (intentional, per audit_log vs activity policy) and on the API response.
            _logger.LogInformation("Invite {InviteId} created for tenant {TenantId}; SMTP not configured — retrieve link from API response.", record.Id, orgId);
            // Debug-level: full link including the token. Only enabled at developer verbosity.
            // deepcode ignore PrivateInformationExposure: Debug-only; gated by log-level config,
            // not emitted in production deployments.
            _logger.LogDebug("Invite link for {Email} (tenant {TenantId}): {Link}", req.Email, orgId, inviteLink);
        }
        // SMTP delivery deferred — until SMTP_HOST wiring lands, callers retrieve the
        // invite link from the response body.

        return Ok(new { record, invite_link = smtpHost is null ? inviteLink : null });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/invites/{id}</summary>
    [HttpDelete("api/v1/invites/{id}")]
    public async Task<IActionResult> DeleteInvite(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _invites.DeleteAsync(id, ct);

        await _audit.LogAsync("invite_deleted", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { invite_id = id }), ct: ct);

        return NoContent();
    }
}
