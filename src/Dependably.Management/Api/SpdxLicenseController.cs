using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// SPDX license reference data — read-only, member-readable.
///
///   GET /api/v1/spdx-licenses?q=&amp;includeDeprecated=  — typeahead picker source
///   GET /api/v1/spdx-licenses/{identifier}             — single license detail
///
/// Backs the SpdxPicker component in the settings UI and license-detail badges on the
/// member-facing License Policy page. The reference table is instance-wide, but auth is
/// still scoped to a tenant context: members read it, anonymous callers don't.
/// </summary>
[ApiController]
[Authorize]
public sealed class SpdxLicenseController : ControllerBase
{
    private readonly SpdxLicenseRepository _repo;
    private readonly OrgAccessGuard _guard;

    public SpdxLicenseController(SpdxLicenseRepository repo, OrgAccessGuard guard)
    {
        _repo = repo;
        _guard = guard;
    }

    [HttpGet("api/v1/spdx-licenses")]
    public async Task<IActionResult> List(
        [FromQuery] string? q,
        [FromQuery] bool includeDeprecated,
        [FromQuery] int? limit,
        CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        // Clamp limit to a sane upper bound — picker dropdowns shouldn't render thousands.
        int clamped = Math.Clamp(limit ?? 200, 1, 500);

        var rows = await _repo.ListAsync(q, includeDeprecated, clamped, ct);
        return Ok(rows);
    }

    [HttpGet("api/v1/spdx-licenses/{identifier}")]
    public async Task<IActionResult> Get(string identifier, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var row = await _repo.GetAsync(identifier, ct);
        return row is null ? NotFound() : Ok(row);
    }
}
