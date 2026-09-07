using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// "Which of my applications ship this?" — the reverse of the SBOM component cross-link.
///
/// <list type="bullet">
///   <item><c>GET /api/v1/blast-radius/package</c> — the applications shipping one registry
///   coordinate, for the package detail page and the quarantine rows.</item>
///   <item><c>GET /api/v1/blast-radius/advisory</c> — the applications shipping a component the
///   scan has linked to one advisory, for the org vulnerability report.</item>
///   <item><c>GET /api/v1/blast-radius/counts</c> — the affected-application count for a page of
///   coordinates or advisories, one statement per page rather than one request per row.</item>
/// </list>
///
/// <para>The coordinate and the advisory id travel as query parameters, not route segments: a
/// scoped npm name and a Maven coordinate both carry separators the route matcher would split on,
/// and an advisory id is matched verbatim.</para>
///
/// <para><b>The tenant comes from the authenticated principal, never from the request.</b> Every
/// query is filtered on <c>sbom_components.org_id</c> bound from <c>CurrentTenantId()</c>, so
/// naming another tenant's package returns that tenant nothing — an empty list, which is also
/// what a coordinate nobody ships returns, so the endpoint cannot be used to probe for another
/// org's inventory either.</para>
///
/// <para><b>In-service versions only</b>, for the reason
/// <see cref="SbomBlastRadiusRepository"/> documents: a release the tenant no longer runs is
/// neither what the operator ships nor something the nightly scan keeps current, while a
/// superseded release still marked active is both.</para>
/// </summary>
[ApiController]
[Authorize]
public sealed class BlastRadiusController : OrgScopedControllerBase
{
    /// <summary>Which key space <c>GET /counts</c> is being asked about.</summary>
    private const string AdvisoryKind = "advisory";
    private const string PackageKind = "package";

    private readonly SbomBlastRadiusRepository _blastRadius;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;

    public BlastRadiusController(
        SbomBlastRadiusRepository blastRadius, OrgAccessGuard guard, ProblemResults problems)
    {
        _blastRadius = blastRadius;
        _guard = guard;
        _problems = problems;
    }

    /// <summary>
    /// GET /api/v1/blast-radius/package?ecosystem=&amp;name= — the applications shipping one
    /// registry coordinate.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/blast-radius/package")]
    public async Task<IActionResult> ByPackage(
        [FromQuery] BlastRadiusPackageRequest request, CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(request.Ecosystem))
        {
            return _problems.ValidationErrorActionKey("ecosystem", "error.blastRadius.ecosystemRequired");
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return _problems.ValidationErrorActionKey("name", "error.blastRadius.nameRequired");
        }

        var (limit, offset, page) = Paging(request.Page, request.Limit);
        var result = await _blastRadius.ListByCoordinateAsync(
            CurrentTenantId(), request.Ecosystem.Trim(), request.Name.Trim(), limit, offset, ct);
        return Ok(PagePayload(result, page, limit));
    }

    /// <summary>
    /// GET /api/v1/blast-radius/advisory?osvId= — the applications shipping a component linked to
    /// one advisory.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/blast-radius/advisory")]
    public async Task<IActionResult> ByAdvisory(
        [FromQuery] BlastRadiusAdvisoryRequest request, CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        if (string.IsNullOrWhiteSpace(request.OsvId))
        {
            return _problems.ValidationErrorActionKey("osvId", "error.blastRadius.osvIdRequired");
        }

        var (limit, offset, page) = Paging(request.Page, request.Limit);
        var result = await _blastRadius.ListByAdvisoryAsync(
            CurrentTenantId(), request.OsvId.Trim(), limit, offset, ct);
        return Ok(PagePayload(result, page, limit));
    }

    /// <summary>
    /// GET /api/v1/blast-radius/counts?kind=advisory&amp;key=… — the affected-application count for
    /// each supplied key, so a table renders one cell per row from a single request.
    ///
    /// <para>Keys absent from the response are keys nothing ships; the caller renders a zero rather
    /// than an unknown, because the query answered and found none.</para>
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/blast-radius/counts")]
    public async Task<IActionResult> Counts(
        [FromQuery] BlastRadiusCountsRequest request, CancellationToken ct = default)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        string kind = request.Kind ?? AdvisoryKind;
        if (kind is not (AdvisoryKind or PackageKind))
        {
            return _problems.ValidationErrorActionKey("kind", "error.blastRadius.kindInvalid");
        }

        var keys = (request.Key ?? [])
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(k => k.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (keys.Count > SbomBlastRadiusRepository.MaxCountKeys)
        {
            // Rejected rather than silently truncated: a caller that asked about 300 rows and got
            // counts for 200 would render zeros on the rest, which reads as "nothing ships this".
            return _problems.ValidationErrorActionKey(
                "key", "error.blastRadius.tooManyKeys", SbomBlastRadiusRepository.MaxCountKeys);
        }

        string orgId = CurrentTenantId();
        if (kind == AdvisoryKind)
        {
            var byAdvisory = await _blastRadius.CountProjectsByAdvisoryAsync(orgId, keys, ct);
            return Ok(new { kind, counts = byAdvisory });
        }

        // A package key is spelled "{ecosystem}/{name}"; the name itself may carry further slashes
        // (a scoped npm package, a Maven group path), so the split takes only the first segment.
        var coordinates = keys
            .Select(ParseCoordinate)
            .Where(c => c is not null)
            .Select(c => c!)
            .ToList();
        var byCoordinate = await _blastRadius.CountProjectsByCoordinateAsync(orgId, coordinates, ct);
        return Ok(new { kind, counts = byCoordinate });
    }

    private static RegistryCoordinate? ParseCoordinate(string key)
    {
        int separator = key.IndexOf('/', StringComparison.Ordinal);
        return separator <= 0 || separator == key.Length - 1
            ? null
            : new RegistryCoordinate(key[..separator], key[(separator + 1)..]);
    }

    private static (int Limit, int Offset, int Page) Paging(int page, int limit)
    {
        int clampedPage = Math.Max(1, page);
        int clampedLimit = Math.Clamp(
            limit <= 0 ? SbomBlastRadiusRepository.DefaultPageSize : limit,
            1, SbomBlastRadiusRepository.MaxPageSize);
        return (clampedLimit, (clampedPage - 1) * clampedLimit, clampedPage);
    }

    private static object PagePayload(BlastRadiusPage result, int page, int limit) => new
    {
        items = result.Items.Select(row => new
        {
            projectId = row.ProjectId,
            projectName = row.ProjectName,
            classifier = row.Classifier,
            projectVersionId = row.ProjectVersionId,
            projectVersion = row.ProjectVersion,
            policyStatus = row.PolicyStatus,
            componentVersion = row.ComponentVersion,
            componentPurl = row.ComponentPurl,
            dependencyScope = row.DependencyScope,
        }),
        // Distinct applications across the WHOLE result, not across the page that was returned.
        // This is the number the caller headlines, so counting it over `items` would cap it at the
        // page limit and quietly report a smaller blast radius than the tenant has.
        projectCount = result.ProjectTotal,
        total = result.RowTotal,
        page,
        limit,
    };
}

/// <summary>Query state for <c>GET /api/v1/blast-radius/package</c>.</summary>
public sealed class BlastRadiusPackageRequest
{
    /// <summary>Registry ecosystem, as <c>sbom_components.ecosystem</c> spells it.</summary>
    public string? Ecosystem { get; set; }

    /// <summary>Canonical package name, as <c>PurlNormalizer</c> spells it.</summary>
    public string? Name { get; set; }

    /// <summary>1-based page number.</summary>
    public int Page { get; set; } = 1;

    /// <summary>Rows per page, clamped to <see cref="SbomBlastRadiusRepository.MaxPageSize"/>.</summary>
    public int Limit { get; set; } = SbomBlastRadiusRepository.DefaultPageSize;
}

/// <summary>Query state for <c>GET /api/v1/blast-radius/advisory</c>.</summary>
public sealed class BlastRadiusAdvisoryRequest
{
    /// <summary>Advisory id as the feed publishes it, matched verbatim against <c>vulnerabilities.osv_id</c>.</summary>
    public string? OsvId { get; set; }

    /// <summary>1-based page number.</summary>
    public int Page { get; set; } = 1;

    /// <summary>Rows per page, clamped to <see cref="SbomBlastRadiusRepository.MaxPageSize"/>.</summary>
    public int Limit { get; set; } = SbomBlastRadiusRepository.DefaultPageSize;
}

/// <summary>Query state for <c>GET /api/v1/blast-radius/counts</c>.</summary>
public sealed class BlastRadiusCountsRequest
{
    /// <summary><c>advisory</c> (default) or <c>package</c> — which key space <see cref="Key"/> names.</summary>
    public string? Kind { get; set; }

    /// <summary>
    /// Repeated <c>key=</c> parameter: an OSV id per key, or an <c>{ecosystem}/{name}</c>
    /// coordinate per key.
    /// </summary>
    public string[]? Key { get; set; }
}
