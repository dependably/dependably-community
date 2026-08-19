using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Drill-downs for the Overview dashboard's risk tiles — the rows behind the counts.
///   GET /api/v1/risk/operational — versions at or over the versions-behind threshold
///   GET /api/v1/risk/license     — versions on a blocklisted SPDX identifier, or with no license
/// Read-only end to end: both gate on ReadPackages, the same capability that serves the dashboard
/// stats themselves, so every role that can see a tile can open the list behind it. Acting on a
/// row happens on the version-detail surface, which already carries the manual block override.
/// Both lists union the uploaded and proxy planes exactly as the tiles do, so a list total is the
/// tile's own number (modulo the stats snapshot's refresh interval — the tiles are served from a
/// periodic snapshot, these queries run live).
/// </summary>
[ApiController]
[Authorize]
public sealed class RiskController : OrgScopedControllerBase
{
    // Maximum page size for risk list responses.
    private const int MaxRiskPageSize = 200;

    private readonly PackageAnalyticsRepository _analytics;
    private readonly LicenseRepository _licenses;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;

    public RiskController(
        PackageAnalyticsRepository analytics,
        LicenseRepository licenses,
        OrgAccessGuard guard,
        ProblemResults problems)
    {
        _analytics = analytics;
        _licenses = licenses;
        _guard = guard;
        _problems = problems;
    }

    /// <summary>GET /api/v1/risk/operational?ecosystem=npm&amp;limit=50&amp;page=1</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/risk/operational")]
    public async Task<IActionResult> Operational(
        [FromQuery] string? ecosystem = null,
        [FromQuery] int limit = 50, [FromQuery] int page = 1,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        limit = Math.Clamp(limit, 1, MaxRiskPageSize);
        int offset = PaginationHelper.ComputeOffset(page, limit);

        string orgId = CurrentTenantId();
        var (items, total, packageCount) = await _analytics.ListOperationalRiskAsync(
            orgId, NullIfEmpty(ecosystem), limit, offset, ct);

        return Ok(new
        {
            total,
            packageCount,
            threshold = PackageAnalyticsRepository.VersionsBehindDashboardThreshold,
            limit,
            offset,
            items = items.Select(r => new
            {
                ecosystem = r.Ecosystem,
                name = r.Name,
                displayName = r.DisplayName,
                purl = r.Purl,
                version = r.Version,
                versionsBehind = r.VersionsBehind,
                origin = r.Origin,
                upstreamLatestVersion = r.UpstreamLatestVersion,
                publishedAt = r.PublishedAt,
                deprecated = r.Deprecated,
                revokedAt = r.RevokedAt,
            }),
        });
    }

    /// <summary>GET /api/v1/risk/license?ecosystem=npm&amp;reason=blocklisted&amp;limit=50&amp;page=1.
    /// <c>reason</c> is 'unknown' (no licence recorded), 'blocklisted' (a refused licence), or
    /// 'conditional' (a licence the org marked conditional — the artifact serves, but the org
    /// wrote down a condition somebody should check).</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/risk/license")]
    public async Task<IActionResult> License(
        [FromQuery] string? ecosystem = null, [FromQuery] string? reason = null,
        [FromQuery] int limit = 50, [FromQuery] int page = 1,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        reason = NullIfEmpty(reason);
        if (reason is not (null or "blocklisted" or "unknown" or "conditional"))
        {
            return _problems.ValidationErrorActionKey("reason", "error.risk.reasonInvalid");
        }

        limit = Math.Clamp(limit, 1, MaxRiskPageSize);
        int offset = PaginationHelper.ComputeOffset(page, limit);

        string orgId = CurrentTenantId();
        var (items, total) = await _analytics.ListLicenseRiskAsync(
            orgId, NullIfEmpty(ecosystem), reason, limit, offset, ct);

        // Stitch the SPDX identifiers onto this page's rows only — one round-trip per plane,
        // bounded by the page size. Rows whose reason is "unknown" carry no license by definition
        // and are simply absent from the lookups.
        var uploadedIds = items.Where(r => r.OwnerKind == "package_version").Select(r => r.OwnerId).ToList();
        var proxyIds = items.Where(r => r.OwnerKind == "cache_artifact").Select(r => r.OwnerId).ToList();
        var uploadedLicenses = await _licenses.GetSpdxForVersionsAsync(uploadedIds, ct);
        var proxyLicenses = await _licenses.GetSpdxForCacheArtifactsAsync(proxyIds, ct);

        return Ok(new
        {
            total,
            limit,
            offset,
            items = items.Select(r => new
            {
                ecosystem = r.Ecosystem,
                name = r.Name,
                displayName = r.DisplayName,
                purl = r.Purl,
                version = r.Version,
                filename = r.Filename,
                origin = r.Origin,
                publishedAt = r.PublishedAt,
                reason = r.Reason,
                licenses = (r.OwnerKind == "package_version" ? uploadedLicenses : proxyLicenses)[r.OwnerId].ToList(),
            }),
        });
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
