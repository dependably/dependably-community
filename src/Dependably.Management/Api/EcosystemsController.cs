using Dependably.Api.Setup;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Publishes the server's ecosystem vocabulary and per-plane support matrix, so a client — the
/// MCP server, the web UI, a future integration — can ask instead of hardcoding a copy that
/// drifts from the three per-plane source constants this endpoint reads:
/// <see cref="UpstreamRegistryRepository.SupportedEcosystems"/> (<c>registry</c>),
/// <see cref="PackageLookupService.SupportedEcosystems"/> (<c>lookup</c>), and
/// <see cref="SetupRecipeCatalog.Ecosystems"/> (<c>setup</c>).
///
/// Instance-wide vocabulary, not tenant configuration — there is no per-org variation today —
/// but the route is authorized and org-guarded exactly like the rest of the read-only inventory
/// surfaces (<see cref="ProjectsController"/>) rather than left open, so the capability model
/// stays uniform across every management endpoint.
/// </summary>
[ApiController]
[Authorize]
public sealed class EcosystemsController : OrgScopedControllerBase
{
    private readonly OrgAccessGuard _guard;

    public EcosystemsController(OrgAccessGuard guard)
    {
        _guard = guard;
    }

    /// <summary>
    /// GET /api/v1/ecosystems
    /// <c>items</c> is ordered by <c>planes.registry</c> order; each <c>planes.*</c> array
    /// preserves its source constant's own order. Every id in <c>planes.lookup</c> and
    /// <c>planes.setup</c> also appears in <c>planes.registry</c> — the three source lists are
    /// controller-authored constants, not user data, so an id absent from the registry list
    /// would be a code defect this endpoint would otherwise render silently.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/ecosystems")]
    public async Task<IActionResult> List(CancellationToken ct = default)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var registry = UpstreamRegistryRepository.SupportedEcosystems;
        var lookup = PackageLookupService.SupportedEcosystems;
        var setup = SetupRecipeCatalog.Ecosystems;

        var lookupSet = lookup.ToHashSet(StringComparer.Ordinal);
        var setupSet = setup.ToHashSet(StringComparer.Ordinal);

        return Ok(new
        {
            items = registry.Select(id => new
            {
                id,
                registry = true,
                lookup = lookupSet.Contains(id),
                setup = setupSet.Contains(id),
            }),
            planes = new
            {
                registry,
                lookup,
                setup,
            },
        });
    }
}
