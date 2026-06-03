using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// Tenant allowlist + blocklist. Split out of <see cref="OrgController"/>. Both lists
/// share the same shape (list / add / delete) and live alongside each other as policy lists
/// — the only difference is allowlist takes PURL prefix patterns and blocklist takes regular
/// expressions on the package name.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgListsController : OrgScopedControllerBase
{
    private readonly AllowlistRepository _allowlist;
    private readonly BlocklistRepository _blocklist;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public OrgListsController(
        AllowlistRepository allowlist,
        BlocklistRepository blocklist,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _allowlist = allowlist;
        _blocklist = blocklist;
        _guard = guard;
        _audit = audit;
        _problems = problems;
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/allowlist</summary>
    [HttpGet("api/v1/allowlist")]
    public async Task<IActionResult> GetAllowlist(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var entries = await _allowlist.ListAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/allowlist</summary>
    [HttpPost("api/v1/allowlist")]
    public async Task<IActionResult> AddAllowlist([FromBody] AllowlistRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.PurlPattern))
            return _problems.ValidationErrorAction("purl_pattern", "purl_pattern is required.");

        var orgId = CurrentTenantId();
        var entry = await _allowlist.AddAsync(orgId, req.PurlPattern, ct);

        await _audit.LogAsync("allowlist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                purl_pattern = entry.PurlPattern,
            }), ct: ct);

        return CreatedAtAction(nameof(GetAllowlist), null, entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/allowlist/{id}</summary>
    [HttpDelete("api/v1/allowlist/{id}")]
    public async Task<IActionResult> DeleteAllowlist(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _allowlist.DeleteAsync(id, ct);

        await _audit.LogAsync("allowlist_removed", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);

        return NoContent();
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/blocklist</summary>
    [HttpGet("api/v1/blocklist")]
    public async Task<IActionResult> GetBlocklist(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var entries = await _blocklist.ListAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/blocklist</summary>
    [HttpPost("api/v1/blocklist")]
    public async Task<IActionResult> AddBlocklist([FromBody] BlocklistRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.Pattern))
            return _problems.ValidationErrorAction("pattern", "pattern is required.");

        // Length-cap: bounds worst-case compile + match cost. 512 chars is generous for
        // package-name / version globs and far below pathological-regex territory.
        if (req.Pattern.Length > 512)
            return _problems.ValidationErrorAction("pattern", "Pattern must be 512 characters or fewer.");

        // Reject patterns that fail to compile within 2 s — bounds the worst-case
        // validation cost without dropping legitimate complex regexes. Compile-time
        // timeout + length cap together neutralise the ReDoS surface; runtime matches
        // re-apply the 2 s timeout per call (see PackageBlocklistMatcher).
        // deepcode ignore RegexInjection: input is gated by tenant:configure capability,
        // length-capped above, and compiled with a 2 s match-timeout that propagates to
        // every downstream Match invocation.
        try { _ = new System.Text.RegularExpressions.Regex(req.Pattern, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2)); }
        catch { return _problems.ValidationErrorAction("pattern", "Pattern is not a valid regular expression."); }

        var orgId = CurrentTenantId();
        var entry = await _blocklist.AddAsync(orgId, req.Pattern, ct);

        await _audit.LogAsync("blocklist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                pattern = entry.Pattern,
            }), ct: ct);

        return CreatedAtAction(nameof(GetBlocklist), null, entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/blocklist/{id}</summary>
    [HttpDelete("api/v1/blocklist/{id}")]
    public async Task<IActionResult> DeleteBlocklist(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _blocklist.DeleteAsync(id, ct);

        await _audit.LogAsync("blocklist_removed", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);

        return NoContent();
    }
}
