using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Apex-only system banner endpoints. Routes are under <c>/api/v1/system</c> so
/// <see cref="Dependably.Security.RouteScopeFilter"/> enforces <c>scope=system</c> +
/// <c>TenantContext.IsApex</c> before any handler runs. All mutations write system-scoped
/// audit entries via <see cref="AuditRepository.LogSystemAsync"/>.
/// </summary>
[ApiController]
[Authorize]
[Route("api/v1/system")]
public sealed class SystemBannersController : ControllerBase
{
    private readonly BannerRepository _banners;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public SystemBannersController(
        BannerRepository banners,
        AuditRepository audit,
        ProblemResults problems)
    {
        _banners = banners;
        _audit = audit;
        _problems = problems;
    }

    private string? GetActorId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    /// <summary>GET /api/v1/system/banners — list all system-scoped banners.</summary>
    [HttpGet("banners")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var list = await _banners.ListSystemAsync(ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/system/banners — create a system-scoped banner.</summary>
    [HttpPost("banners")]
    public async Task<IActionResult> Create([FromBody] BannerCreateRequest req, CancellationToken ct)
    {
        var validationResult = ValidateRequest(req.Severity, req.Body, req.LinkUrl, req.LinkLabel, req.TargetRole, req.StartsAt, req.EndsAt);
        if (validationResult is not null)
        {
            return validationResult;
        }

        int activeCount = await _banners.CountActiveForScopeAsync("system", null, ct);
        if (activeCount >= BannerRepository.MaxActiveBannersPerScope)
        {
            return _problems.ValidationErrorActionKey("banners", "error.banner.maxActiveSystem", BannerRepository.MaxActiveBannersPerScope);
        }

        string? actorId = GetActorId();
        var banner = await _banners.CreateSystemAsync(actorId ?? "", req, ct);

        await _audit.LogSystemAsync(
            "banner.created",
            actorId: actorId,
            detail: $"{{\"bannerId\":\"{banner.Id}\",\"severity\":\"{req.Severity}\"}}",
            ct: ct);

        return Created($"/api/v1/system/banners/{banner.Id}", banner);
    }

    /// <summary>PUT /api/v1/system/banners/{id} — update a system-scoped banner.</summary>
    [HttpPut("banners/{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] BannerUpdateRequest req, CancellationToken ct)
    {
        var validationResult = ValidateRequest(req.Severity, req.Body, req.LinkUrl, req.LinkLabel, req.TargetRole, req.StartsAt, req.EndsAt);
        if (validationResult is not null)
        {
            return validationResult;
        }

        bool updated = await _banners.UpdateSystemAsync(id, req, ct);
        if (!updated)
        {
            return NotFound();
        }

        await _audit.LogSystemAsync(
            "banner.updated",
            actorId: GetActorId(),
            detail: $"{{\"bannerId\":\"{id}\"}}",
            ct: ct);

        return NoContent();
    }

    /// <summary>DELETE /api/v1/system/banners/{id} — delete a system-scoped banner.</summary>
    [HttpDelete("banners/{id}")]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        bool deleted = await _banners.DeleteSystemAsync(id, ct);
        if (!deleted)
        {
            return NotFound();
        }

        await _audit.LogSystemAsync(
            "banner.deleted",
            actorId: GetActorId(),
            detail: $"{{\"bannerId\":\"{id}\"}}",
            ct: ct);

        return NoContent();
    }

    // Shared validation for create and update requests.
    private IActionResult? ValidateRequest(
        string severity, string body, string? linkUrl, string? linkLabel,
        string targetRole, string startsAt, string endsAt)
    {
        return ValidateBody(body)
            ?? ValidateLink(linkUrl, linkLabel)
            ?? ValidateWindow(startsAt, endsAt)
            ?? ValidateSeverityAndRole(severity, targetRole);
    }

    private IActionResult? ValidateBody(string body)
    {
        return string.IsNullOrWhiteSpace(body)
            ? _problems.ValidationErrorActionKey("body", "error.banner.bodyRequired")
            : body.Length > BannerRepository.MaxBodyLength
            ? _problems.ValidationErrorActionKey("body", "error.banner.bodyTooLong", BannerRepository.MaxBodyLength)
            : null;
    }

    private IActionResult? ValidateLink(string? linkUrl, string? linkLabel)
    {
        if (linkUrl is not null)
        {
            if (linkUrl.Length > BannerRepository.MaxLinkUrlLength)
            {
                return _problems.ValidationErrorActionKey("linkUrl", "error.banner.linkUrlTooLong", BannerRepository.MaxLinkUrlLength);
            }

            if (!Uri.TryCreate(linkUrl, UriKind.Absolute, out var uri)
                || (uri.Scheme != "http" && uri.Scheme != "https"))
            {
                return _problems.ValidationErrorActionKey("linkUrl", "error.banner.linkUrlScheme");
            }
        }

        return linkLabel is not null && linkLabel.Length > BannerRepository.MaxLinkLabelLength
            ? _problems.ValidationErrorActionKey("linkLabel", "error.banner.linkLabelTooLong", BannerRepository.MaxLinkLabelLength)
            : null;
    }

    private IActionResult? ValidateWindow(string startsAt, string endsAt)
    {
        return !DateTimeOffset.TryParse(startsAt, null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsedStart)
            ? _problems.ValidationErrorActionKey("startsAt", "error.banner.startsAtInvalid")
            : !DateTimeOffset.TryParse(endsAt, null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsedEnd)
            ? _problems.ValidationErrorActionKey("endsAt", "error.banner.endsAtInvalid")
            : parsedEnd <= parsedStart
            ? _problems.ValidationErrorActionKey("endsAt", "error.banner.endsAfterStarts")
            : null;
    }

    private IActionResult? ValidateSeverityAndRole(string severity, string targetRole)
    {
        string[] validSeverities = ["info", "warn", "alert"];
        if (!validSeverities.Contains(severity, StringComparer.Ordinal))
        {
            return _problems.ValidationErrorActionKey("severity", "error.banner.severityInvalid");
        }

        string[] validRoles = ["all", "member", "admin", "owner", "auditor"];
        return !validRoles.Contains(targetRole, StringComparer.Ordinal)
            ? _problems.ValidationErrorActionKey("targetRole", "error.banner.targetRoleInvalid")
            : null;
    }
}
