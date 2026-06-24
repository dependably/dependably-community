using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Tenant-scoped banner endpoints. Tenant admins author banners for their own org.
/// Management (list/create/update/delete) is guarded by the appropriate capability;
/// the read+dismiss endpoints require only authenticated org membership.
/// </summary>
[ApiController]
[Authorize]
public sealed class BannersController : OrgScopedControllerBase
{
    private readonly BannerRepository _banners;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public BannersController(
        BannerRepository banners,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _banners = banners;
        _guard = guard;
        _audit = audit;
        _problems = problems;
    }

    /// <summary>GET /api/v1/banners — management list (all, incl. disabled/expired).</summary>
    [HttpGet("api/v1/banners")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var list = await _banners.ListTenantAsync(CurrentTenantId(), ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/banners — create a tenant-scoped banner.</summary>
    [HttpPost("api/v1/banners")]
    public async Task<IActionResult> Create([FromBody] BannerCreateRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var validationResult = ValidateRequest(req.Severity, req.Body, req.LinkUrl, req.LinkLabel, req.TargetRole, req.StartsAt, req.EndsAt);
        if (validationResult is not null)
        {
            return validationResult;
        }

        string orgId = CurrentTenantId();
        int activeCount = await _banners.CountActiveForScopeAsync("tenant", orgId, ct);
        if (activeCount >= BannerRepository.MaxActiveBannersPerScope)
        {
            return _problems.ValidationErrorAction("banners",
                $"Maximum of {BannerRepository.MaxActiveBannersPerScope} simultaneously active banners per tenant reached. Disable or expire existing banners first.");
        }

        string? userId = GetUserId();
        var banner = await _banners.CreateTenantAsync(orgId, userId ?? "", req, ct);

        await _audit.LogAsync(
            "banner.created",
            orgId: orgId,
            actorId: userId,
            actorKind: ActorKinds.User,
            detail: $"{{\"bannerId\":\"{banner.Id}\",\"severity\":\"{req.Severity}\"}}",
            ct: ct);

        return Created($"/api/v1/banners/{banner.Id}", banner);
    }

    /// <summary>PUT /api/v1/banners/{id} — update a tenant-scoped banner.</summary>
    [HttpPut("api/v1/banners/{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] BannerUpdateRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var validationResult = ValidateRequest(req.Severity, req.Body, req.LinkUrl, req.LinkLabel, req.TargetRole, req.StartsAt, req.EndsAt);
        if (validationResult is not null)
        {
            return validationResult;
        }

        string orgId = CurrentTenantId();
        bool updated = await _banners.UpdateTenantAsync(orgId, id, req, ct);
        if (!updated)
        {
            return NotFound();
        }

        string? userId = GetUserId();
        await _audit.LogAsync(
            "banner.updated",
            orgId: orgId,
            actorId: userId,
            actorKind: ActorKinds.User,
            detail: $"{{\"bannerId\":\"{id}\"}}",
            ct: ct);

        return NoContent();
    }

    /// <summary>DELETE /api/v1/banners/{id} — delete a tenant-scoped banner.</summary>
    [HttpDelete("api/v1/banners/{id}")]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        bool deleted = await _banners.DeleteTenantAsync(orgId, id, ct);
        if (!deleted)
        {
            return NotFound();
        }

        string? userId = GetUserId();
        await _audit.LogAsync(
            "banner.deleted",
            orgId: orgId,
            actorId: userId,
            actorKind: ActorKinds.User,
            detail: $"{{\"bannerId\":\"{id}\"}}",
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// GET /api/v1/banners/active — returns the active, role-filtered, dismissal-filtered
    /// banner stack for the authenticated user. Guarded by org membership only (no capability
    /// required — members and auditors must be able to see banners targeting them).
    /// </summary>
    [HttpGet("api/v1/banners/active")]
    public async Task<IActionResult> GetActive(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeMemberAsync(User, HttpContext, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        string role = CurrentRole();
        var active = await _banners.GetActiveAsync(CurrentTenantId(), userId, role, ct);
        return Ok(active);
    }

    /// <summary>
    /// POST /api/v1/banners/{id}/dismiss — records that the authenticated user dismissed the
    /// given banner. Idempotent. Requires org membership only.
    /// </summary>
    [HttpPost("api/v1/banners/{id}/dismiss")]
    public async Task<IActionResult> Dismiss(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeMemberAsync(User, HttpContext, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        await _banners.DismissAsync(id, userId, ct);
        return NoContent();
    }

    // Shared validation for create and update requests.
    private IActionResult? ValidateRequest(
        string severity, string body, string? linkUrl, string? linkLabel,
        string targetRole, string startsAt, string endsAt)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return _problems.ValidationErrorAction("body", "Banner body is required.");
        }

        if (body.Length > BannerRepository.MaxBodyLength)
        {
            return _problems.ValidationErrorAction("body",
                $"Banner body must not exceed {BannerRepository.MaxBodyLength} characters.");
        }

        if (linkUrl is not null)
        {
            if (linkUrl.Length > BannerRepository.MaxLinkUrlLength)
            {
                return _problems.ValidationErrorAction("linkUrl",
                    $"Link URL must not exceed {BannerRepository.MaxLinkUrlLength} characters.");
            }

            if (!Uri.TryCreate(linkUrl, UriKind.Absolute, out var uri)
                || (uri.Scheme != "http" && uri.Scheme != "https"))
            {
                return _problems.ValidationErrorAction("linkUrl",
                    "Link URL must use the http or https scheme.");
            }
        }

        if (linkLabel is not null && linkLabel.Length > BannerRepository.MaxLinkLabelLength)
        {
            return _problems.ValidationErrorAction("linkLabel",
                $"Link label must not exceed {BannerRepository.MaxLinkLabelLength} characters.");
        }

        if (!DateTimeOffset.TryParse(startsAt, null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsedStart))
        {
            return _problems.ValidationErrorAction("startsAt", "startsAt must be a valid ISO-8601 UTC date-time.");
        }

        if (!DateTimeOffset.TryParse(endsAt, null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsedEnd))
        {
            return _problems.ValidationErrorAction("endsAt", "endsAt must be a valid ISO-8601 UTC date-time.");
        }

        if (parsedEnd <= parsedStart)
        {
            return _problems.ValidationErrorAction("endsAt", "endsAt must be after startsAt.");
        }

        string[] validSeverities = ["info", "warn", "alert"];
        if (!validSeverities.Contains(severity, StringComparer.Ordinal))
        {
            return _problems.ValidationErrorAction("severity",
                "severity must be one of: info, warn, alert.");
        }

        string[] validRoles = ["all", "member", "admin", "owner", "auditor"];
        return !validRoles.Contains(targetRole, StringComparer.Ordinal)
            ? _problems.ValidationErrorAction("targetRole",
                "targetRole must be one of: all, member, admin, owner, auditor.")
            : null;
    }
}
