using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// License governance endpoints.
///
///   GET    /api/v1/orgs/{org}/license-policy                              — get mode + lists (member+)
///   PUT    /api/v1/orgs/{org}/license-policy/mode                         — set enforcement mode (admin+)
///   GET    /api/v1/orgs/{org}/license-policy/allowlist                    — list allowlist (member+)
///   POST   /api/v1/orgs/{org}/license-policy/allowlist                    — add entry (admin+)
///   DELETE /api/v1/orgs/{org}/license-policy/allowlist/{spdx}             — remove entry (admin+)
///   GET    /api/v1/orgs/{org}/license-policy/blocklist                    — list blocklist (member+)
///   POST   /api/v1/orgs/{org}/license-policy/blocklist                    — add entry (admin+)
///   DELETE /api/v1/orgs/{org}/license-policy/blocklist/{spdx}             — remove entry (admin+)
///   GET    /api/v1/orgs/{org}/packages/{eco}/{name}/{version}/licenses     — licenses for a version (member+)
/// </summary>
[ApiController]
[Authorize]
public sealed class LicenseController : ControllerBase
{
    private readonly LicenseRepository _licenses;
    private readonly OrgRepository _orgs;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;
    private readonly AuditRepository _audit;

    public LicenseController(
        LicenseRepository licenses,
        OrgRepository orgs,
        OrgAccessGuard guard,
        ProblemResults problems,
        AuditRepository audit)
    {
        _licenses = licenses;
        _orgs = orgs;
        _guard = guard;
        _problems = problems;
        _audit = audit;
    }

    private string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    // ── Policy summary ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy</summary>
    [HttpGet("api/v1/license-policy")]
    public async Task<IActionResult> GetPolicy(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null) return authResult;

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var allowlist = await _licenses.GetAllowlistAsync(orgId, ct);
        var blocklist = await _licenses.GetBlocklistAsync(orgId, ct);

        return Ok(new
        {
            mode = settings?.LicenseEnforcementMode ?? "off",
            allowlist,
            blocklist
        });
    }

    // ── Review queue ──────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy/review — licenses observed during
    /// ingestion that are on neither the allow- nor block-list. Admin-only because the UI
    /// surfaces it next to mutating Approve/Block actions.</summary>
    [HttpGet("api/v1/license-policy/review")]
    public async Task<IActionResult> GetReviewQueue(
        [FromQuery] bool includeDeprecated, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null) return authResult;

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
        var entries = await _licenses.GetReviewQueueAsync(orgId, includeDeprecated, ct);
        return Ok(entries);
    }

    // ── Enforcement mode ──────────────────────────────────────────────────────

    /// <summary>PUT /api/v1/orgs/{org}/license-policy/mode</summary>
    [HttpPut("api/v1/license-policy/mode")]
    public async Task<IActionResult> SetMode([FromBody] SetModeRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null) return authResult;

        if (req.Mode is not ("off" or "warn" or "block"))
            return _problems.ValidationErrorAction("mode", "Mode must be 'off', 'warn', or 'block'.");

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        await _orgs.UpsertLicensePolicyModeAsync(orgId, req.Mode, ct);

        await _audit.LogAsync("license_policy_mode_changed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { mode = req.Mode }), ct: ct);

        return Ok(new { mode = req.Mode });
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy/allowlist</summary>
    [HttpGet("api/v1/license-policy/allowlist")]
    public async Task<IActionResult> GetAllowlist(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null) return authResult;

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entries = await _licenses.GetAllowlistAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/license-policy/allowlist</summary>
    [HttpPost("api/v1/license-policy/allowlist")]
    public async Task<IActionResult> AddAllowlist([FromBody] LicenseSpdxRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null) return authResult;

        if (string.IsNullOrWhiteSpace(req.LicenseSpdx))
            return _problems.ValidationErrorAction("license_spdx", "SPDX identifier is required.");

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entry = await _licenses.AddAllowlistAsync(orgId, req.LicenseSpdx.Trim(), ct);
        if (entry is null)
            return _problems.ConflictAction($"'{req.LicenseSpdx}' is already on the allowlist.");

        await _audit.LogAsync("license_allowlist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx = req.LicenseSpdx.Trim() }), ct: ct);

        return CreatedAtAction(nameof(GetAllowlist), null, entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/license-policy/allowlist/{spdx}</summary>
    [HttpDelete("api/v1/license-policy/allowlist/{spdx}")]
    public async Task<IActionResult> RemoveAllowlist(string spdx, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null) return authResult;

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var removed = await _licenses.RemoveAllowlistAsync(orgId, spdx, ct);
        if (!removed) return NotFound();

        await _audit.LogAsync("license_allowlist_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx }), ct: ct);

        return NoContent();
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy/blocklist</summary>
    [HttpGet("api/v1/license-policy/blocklist")]
    public async Task<IActionResult> GetBlocklist(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null) return authResult;

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entries = await _licenses.GetBlocklistAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/license-policy/blocklist</summary>
    [HttpPost("api/v1/license-policy/blocklist")]
    public async Task<IActionResult> AddBlocklist([FromBody] LicenseSpdxRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null) return authResult;

        if (string.IsNullOrWhiteSpace(req.LicenseSpdx))
            return _problems.ValidationErrorAction("license_spdx", "SPDX identifier is required.");

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entry = await _licenses.AddBlocklistAsync(orgId, req.LicenseSpdx.Trim(), ct);
        if (entry is null)
            return _problems.ConflictAction($"'{req.LicenseSpdx}' is already on the blocklist.");

        await _audit.LogAsync("license_blocklist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx = req.LicenseSpdx.Trim() }), ct: ct);

        return CreatedAtAction(nameof(GetBlocklist), null, entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/license-policy/blocklist/{spdx}</summary>
    [HttpDelete("api/v1/license-policy/blocklist/{spdx}")]
    public async Task<IActionResult> RemoveBlocklist(string spdx, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null) return authResult;

        var orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var removed = await _licenses.RemoveBlocklistAsync(orgId, spdx, ct);
        if (!removed) return NotFound();

        await _audit.LogAsync("license_blocklist_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx }), ct: ct);

        return NoContent();
    }

}

public record SetModeRequest(string Mode);
public record LicenseSpdxRequest(string LicenseSpdx);
