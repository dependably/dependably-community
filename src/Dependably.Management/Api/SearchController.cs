using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Cross-entity type-ahead for the global top-bar search box. Packages-only for now
/// (reuses the package-list name search); the grouped response shape is intentionally
/// extensible so vulnerability/license groups can be added later without a contract change.
/// </summary>
[ApiController]
[Authorize]
public sealed class SearchController : OrgScopedControllerBase
{
    // This feeds a type-ahead overlay, not a list page — keep the suggestion set short.
    private const int MaxResults = 25;

    private readonly PackageRepository _packages;
    private readonly OrgAccessGuard _guard;

    public SearchController(PackageRepository packages, OrgAccessGuard guard)
    {
        _packages = packages;
        _guard = guard;
    }

    /// <summary>GET /api/v1/search?q=&amp;limit= — tenant-scoped quick search.</summary>
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

        return Ok(new
        {
            query,
            groups = new[] { new { kind = "packages", results } },
        });
    }
}
