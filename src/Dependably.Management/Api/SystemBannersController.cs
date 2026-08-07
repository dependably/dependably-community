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
        var validationResult = ValidateRequest(req, out string startsAtUtc, out string endsAtUtc);
        if (validationResult is not null)
        {
            return validationResult;
        }

        req = req with { StartsAt = startsAtUtc, EndsAt = endsAtUtc };

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
        var validationResult = ValidateRequest(req, out string startsAtUtc, out string endsAtUtc);
        if (validationResult is not null)
        {
            return validationResult;
        }

        req = req with { StartsAt = startsAtUtc, EndsAt = endsAtUtc };

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

    // Shared validation for create and update requests. The scheduling window comes back
    // normalized to canonical UTC so the caller persists that rather than the caller-supplied
    // text: banners are selected by a lexicographic `starts_at <= @now` comparison against a
    // UTC `Z` string, which a stored `+02:00` (or offset-less) value does not order against.
    private IActionResult? ValidateRequest(
        IBannerContentRequest req, out string normalizedStartsAt, out string normalizedEndsAt)
    {
        normalizedStartsAt = string.Empty;
        normalizedEndsAt = string.Empty;

        return ValidateBody(req.Body)
            ?? ValidateLink(req.LinkUrl, req.LinkLabel)
            ?? ValidateWindow(req.StartsAt, req.EndsAt, out normalizedStartsAt, out normalizedEndsAt)
            ?? ValidateSeverityAndRole(req.Severity, req.TargetRole);
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

    private IActionResult? ValidateWindow(
        string startsAt, string endsAt, out string normalizedStartsAt, out string normalizedEndsAt)
    {
        normalizedEndsAt = string.Empty;

        return !UtcTimestamp.TryNormalize(startsAt, out normalizedStartsAt)
            ? _problems.ValidationErrorActionKey("startsAt", "error.banner.startsAtInvalid")
            : !UtcTimestamp.TryNormalize(endsAt, out normalizedEndsAt)
            ? _problems.ValidationErrorActionKey("endsAt", "error.banner.endsAtInvalid")
            // Compared as normalized UTC strings, so two instants written with different
            // offsets still order by the instant they denote rather than by wall-clock text.
            : string.CompareOrdinal(normalizedEndsAt, normalizedStartsAt) <= 0
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
