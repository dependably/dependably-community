using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// Per-org upstream proxy registries, surfaced under Settings → Proxy. Each ecosystem owns a
/// priority-ordered list; the proxy fetch path tries entries top-to-bottom and an ecosystem
/// with no entries has proxying disabled. URLs pass the same SSRF guard
/// (<see cref="UpstreamUrlValidator"/>) used everywhere upstream URLs are accepted.
/// </summary>
[ApiController]
[Authorize]
public sealed class UpstreamRegistryController : OrgScopedControllerBase
{
    private readonly UpstreamRegistryRepository _registries;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public UpstreamRegistryController(
        UpstreamRegistryRepository registries,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _registries = registries;
        _guard = guard;
        _audit = audit;
        _problems = problems;
    }

    /// <summary>GET /api/v1/orgs/{org}/upstream-registries</summary>
    [HttpGet("api/v1/upstream-registries")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var entries = await _registries.ListAsync(CurrentTenantId(), ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/upstream-registries</summary>
    [HttpPost("api/v1/upstream-registries")]
    public async Task<IActionResult> Add([FromBody] AddUpstreamRegistryRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var ecosystem = req.Ecosystem?.Trim().ToLowerInvariant() ?? "";
        if (!UpstreamRegistryRepository.IsSupportedEcosystem(ecosystem))
            return _problems.ValidationErrorAction(
                "ecosystem",
                $"Must be one of: {string.Join(", ", UpstreamRegistryRepository.SupportedEcosystems)}.");

        var urlProblem = UpstreamUrlValidator.ValidateUrl(req.Url);
        if (urlProblem is not null)
            return _problems.ValidationErrorAction("url", urlProblem);

        var name = string.IsNullOrWhiteSpace(req.Name) ? null : req.Name.Trim();
        var orgId = CurrentTenantId();
        var entry = await _registries.AddAsync(orgId, ecosystem, req.Url.Trim(), name, ct);

        await _audit.LogAsync("upstream_registry_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
                url = entry.Url,
                name = entry.Name,
            }), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/upstream-registries/{id}</summary>
    [HttpDelete("api/v1/upstream-registries/{id}")]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        await _registries.DeleteAsync(orgId, id, ct);

        await _audit.LogAsync("upstream_registry_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);

        return NoContent();
    }

    /// <summary>PUT /api/v1/orgs/{org}/upstream-registries/{ecosystem}/order</summary>
    [HttpPut("api/v1/upstream-registries/{ecosystem}/order")]
    public async Task<IActionResult> Reorder(
        string ecosystem, [FromBody] ReorderUpstreamRegistryRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var eco = ecosystem?.Trim().ToLowerInvariant() ?? "";
        if (!UpstreamRegistryRepository.IsSupportedEcosystem(eco))
            return _problems.ValidationErrorAction(
                "ecosystem",
                $"Must be one of: {string.Join(", ", UpstreamRegistryRepository.SupportedEcosystems)}.");

        var ids = req.Ids ?? [];
        var orgId = CurrentTenantId();
        await _registries.ReorderAsync(orgId, eco, ids, ct);

        await _audit.LogAsync("upstream_registry_reordered", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { ecosystem = eco, ids }), ct: ct);

        return NoContent();
    }
}
