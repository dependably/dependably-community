using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Cross-entity type-ahead for the global top-bar search box. Packages, projects, and
/// vulnerabilities; the grouped response shape is intentionally extensible so further groups can
/// be added later without a contract change.
/// </summary>
[ApiController]
[Authorize]
public sealed class SearchController : OrgScopedControllerBase
{
    // This feeds a type-ahead overlay, not a list page — keep the suggestion set short.
    private const int MaxResults = 25;

    private readonly PackageRepository _packages;
    private readonly ProjectRepository _projects;
    private readonly VulnerabilityRepository _vulns;
    private readonly OrgAccessGuard _guard;

    public SearchController(PackageRepository packages, ProjectRepository projects, VulnerabilityRepository vulns, OrgAccessGuard guard)
    {
        _packages = packages;
        _projects = projects;
        _vulns = vulns;
        _guard = guard;
    }

    /// <summary>
    /// GET /api/v1/search?q=&amp;limit= — tenant-scoped quick search.
    /// <c>q</c> matches any substring of the package name, case-insensitively; terms shorter than
    /// two characters return no results rather than scanning the tenant's catalogue.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/search")]
    public async Task<IActionResult> Search(
        [FromQuery] string? q = null,
        [FromQuery] int limit = 8,
        CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        string query = (q ?? string.Empty).Trim();
        limit = Math.Clamp(limit, 1, MaxResults);

        // Below two characters the result set is too broad to be useful — return empty
        // groups (no scan) so the overlay shows its "no results" state.
        if (query.Length < 2)
        {
            return Ok(new { query, groups = Array.Empty<object>() });
        }

        var (items, _) = await _packages.ListPaginatedAsync(
            new PackageListQuery(CurrentTenantId(), limit, 0, Ecosystem: null, Search: query, SortBy: "name", SortDir: "asc"),
            ct);

        var results = items.Select(p => new
        {
            p.Ecosystem,
            p.Name,
            p.PurlName,
            version = p.UpstreamLatestVersion,
        });

        var projectRows = await _projects.SearchByNameAsync(CurrentTenantId(), query, limit, ct);
        var projectResults = projectRows.Select(p => new { p.Id, p.Name, p.Kind }).ToList();

        // The vuln report matches by package name, OSV id, or summary substring and is keyed
        // per (version, advisory) pair, so the same advisory can surface once per affected
        // version — overfetch and dedupe by OsvId before trimming to the suggestion limit,
        // rather than truncating the raw rows and then deduping into a short list.
        var (vulnRows, _) = await _vulns.GetVulnReportAsync(
            new VulnReportQuery(CurrentTenantId(), Search: query, Limit: Math.Min(limit * 5, 100)), ct);
        var vulnResults = vulnRows
            .GroupBy(v => v.OsvId)
            .Select(g => g.First())
            .Take(limit)
            .Select(v => new { v.OsvId, v.PackageName, v.Severity, v.Summary })
            .ToList();

        // The packages group is always present, matching the endpoint's shape before project
        // search existed — an empty result set for it is a legitimate "no packages match"
        // answer. The projects and vulnerabilities groups are only added when they have
        // something to say; an always-present-but-empty group would be indistinguishable from
        // that at the type level but is otherwise pure payload noise on the common no-match case.
        var groups = new List<object> { new { kind = "packages", results } };
        if (projectResults.Count > 0)
        {
            groups.Add(new { kind = "projects", results = projectResults });
        }
        if (vulnResults.Count > 0)
        {
            groups.Add(new { kind = "vulnerabilities", results = vulnResults });
        }

        return Ok(new { query, groups });
    }
}
