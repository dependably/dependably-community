using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Tenant policy lists: allowlist, blocklist, reserved namespaces, and install-script
/// allowlist. All share the same shape (list / add / delete) and live alongside each other
/// as policy lists — allowlist takes PURL prefix patterns, blocklist takes regular expressions
/// on the package PURL, reserved namespaces take per-ecosystem name patterns that must never
/// consult upstream (dependency-confusion guard), and install-script allowlist exempts specific
/// packages from the install-script block-gate arm.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgListsController : OrgScopedControllerBase
{
    // Maximum allowed pattern lengths for allowlist/blocklist entries.
    private const int AllowlistPatternMaxLength = 512;
    private const int BlocklistPatternMaxLength = 256;

    // Maximum lengths for install-script allowlist fields.
    private const int InstallScriptNameMaxLength = 512;
    private const int InstallScriptVersionPatternMaxLength = 128;

    private readonly AllowlistRepository _allowlist;
    private readonly BlocklistRepository _blocklist;
    private readonly Protocol.ReservedNamespaceService _reserved;
    private readonly Protocol.InstallScriptAllowlistService _installScriptAllowlist;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public OrgListsController(
        AllowlistRepository allowlist,
        BlocklistRepository blocklist,
        Protocol.ReservedNamespaceService reserved,
        Protocol.InstallScriptAllowlistService installScriptAllowlist,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _allowlist = allowlist;
        _blocklist = blocklist;
        _reserved = reserved;
        _installScriptAllowlist = installScriptAllowlist;
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
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var entries = await _allowlist.ListAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/allowlist</summary>
    [HttpPost("api/v1/allowlist")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> AddAllowlist([FromBody] AllowlistRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(req.PurlPattern))
        {
            return _problems.ValidationErrorAction("purl_pattern", "purl_pattern is required.");
        }

        string orgId = CurrentTenantId();
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteAllowlist(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        // org_id-scoped: a cross-tenant (or unknown) id deletes 0 rows. Delete stays idempotent
        // (204 either way); the org scope is what enforces isolation. Audit only a real removal.
        string orgId = CurrentTenantId();
        if (await _allowlist.DeleteAsync(orgId, id, ct) > 0)
        {
            await _audit.LogAsync("allowlist_removed", orgId, GetUserId(),
                detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);
        }

        return NoContent();
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/blocklist</summary>
    [HttpGet("api/v1/blocklist")]
    public async Task<IActionResult> GetBlocklist(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var entries = await _blocklist.ListAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/blocklist</summary>
    [HttpPost("api/v1/blocklist")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> AddBlocklist([FromBody] BlocklistRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(req.Pattern))
        {
            return _problems.ValidationErrorAction("pattern", "pattern is required.");
        }

        // Length-cap: bounds worst-case compile + match cost. 512 chars is generous for
        // package-name / version globs and far below pathological-regex territory.
        if (req.Pattern.Length > AllowlistPatternMaxLength)
        {
            return _problems.ValidationErrorAction("pattern", "Pattern must be 512 characters or fewer.");
        }

        // Reject patterns that fail to compile within 2 s — bounds the worst-case
        // validation cost without dropping legitimate complex regexes. Compile-time
        // timeout + length cap together neutralise the ReDoS surface; runtime matches
        // re-apply the 2 s timeout per call (see PackageBlocklistMatcher).
        // deepcode ignore RegexInjection: input is gated by tenant:configure capability,
        // length-capped above, and compiled with a 2 s match-timeout that propagates to
        // every downstream Match invocation.
        try { _ = new System.Text.RegularExpressions.Regex(req.Pattern, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2)); }
        catch { return _problems.ValidationErrorAction("pattern", "Pattern is not a valid regular expression."); }

        string orgId = CurrentTenantId();
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteBlocklist(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        // org_id-scoped: a cross-tenant (or unknown) id deletes 0 rows. Delete stays idempotent
        // (204 either way); the org scope is what enforces isolation. Audit only a real removal.
        string orgId = CurrentTenantId();
        if (await _blocklist.DeleteAsync(orgId, id, ct) > 0)
        {
            await _audit.LogAsync("blocklist_removed", orgId, GetUserId(),
                detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);
        }

        return NoContent();
    }

    // ── Reserved namespaces ───────────────────────────────────────────────────

    /// <summary>GET /api/v1/reserved-namespaces</summary>
    [HttpGet("api/v1/reserved-namespaces")]
    public async Task<IActionResult> GetReservedNamespaces(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var entries = await _reserved.ListAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/reserved-namespaces</summary>
    [HttpPost("api/v1/reserved-namespaces")]
    public async Task<IActionResult> AddReservedNamespace(
        [FromBody] ReservedNamespaceRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string ecosystem = (req.Ecosystem ?? "").Trim().ToLowerInvariant();
        if (!Protocol.ReservedNamespaceService.SupportedEcosystems.Contains(ecosystem))
        {
            return _problems.ValidationErrorAction("ecosystem",
                "ecosystem must be one of: npm, pypi, nuget, maven, cargo, golang.");
        }

        string pattern = (req.Pattern ?? "").Trim();
        if (pattern.Length == 0)
        {
            return _problems.ValidationErrorAction("pattern", "pattern is required.");
        }

        // Length-cap keeps patterns in package-name territory; matching is a plain prefix
        // compare so this is a sanity bound, not a ReDoS guard.
        if (pattern.Length > BlocklistPatternMaxLength)
        {
            return _problems.ValidationErrorAction("pattern", "Pattern must be 256 characters or fewer.");
        }

        // Globs are trailing-only: '*' anywhere else would silently match nothing.
        int star = pattern.IndexOf('*');
        if (star >= 0 && star != pattern.Length - 1)
        {
            return _problems.ValidationErrorAction("pattern",
                "'*' is only supported as the final character (trailing glob).");
        }

        string orgId = CurrentTenantId();
        var entry = await _reserved.AddAsync(orgId, ecosystem, pattern, GetUserId(), ct);

        await _audit.LogAsync("reserved_namespace_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
                pattern = entry.Pattern,
            }), ct: ct);

        return CreatedAtAction(nameof(GetReservedNamespaces), null, entry);
    }

    /// <summary>DELETE /api/v1/reserved-namespaces/{id}</summary>
    [HttpDelete("api/v1/reserved-namespaces/{id}")]
    public async Task<IActionResult> DeleteReservedNamespace(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        // org_id-scoped: a cross-tenant (or unknown) id deletes 0 rows. Delete stays idempotent
        // (204 either way); the org scope is what enforces isolation. Audit only a real removal.
        string orgId = CurrentTenantId();
        if (await _reserved.DeleteAsync(orgId, id, ct) > 0)
        {
            await _audit.LogAsync("reserved_namespace_removed", orgId, GetUserId(),
                detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);
        }

        return NoContent();
    }

    // ── Install-script allowlist ───────────────────────────────────────────────

    /// <summary>GET /api/v1/install-script-allowlist</summary>
    [HttpGet("api/v1/install-script-allowlist")]
    public async Task<IActionResult> GetInstallScriptAllowlist(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var entries = await _installScriptAllowlist.ListAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/install-script-allowlist</summary>
    [HttpPost("api/v1/install-script-allowlist")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> AddInstallScriptAllowlist(
        [FromBody] InstallScriptAllowlistRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string ecosystem = (req.Ecosystem ?? "").Trim().ToLowerInvariant();
        if (!Protocol.InstallScriptAllowlistService.SupportedEcosystems.Contains(ecosystem))
        {
            return _problems.ValidationErrorAction("ecosystem",
                "ecosystem must be one of: npm, pypi, nuget, maven, cargo, golang, rpm, oci.");
        }

        string name = (req.Name ?? "").Trim();
        if (name.Length == 0)
        {
            return _problems.ValidationErrorAction("name", "name is required.");
        }

        if (name.Length > InstallScriptNameMaxLength)
        {
            return _problems.ValidationErrorAction("name", "name must be 512 characters or fewer.");
        }

        // version_pattern is optional; validate length when present.
        string? versionPattern = req.VersionPattern?.Trim();
        if (versionPattern is not null && versionPattern.Length == 0)
        {
            versionPattern = null;
        }

        if (versionPattern is not null && versionPattern.Length > InstallScriptVersionPatternMaxLength)
        {
            return _problems.ValidationErrorAction("version_pattern",
                "version_pattern must be 128 characters or fewer.");
        }

        // Globs are trailing-only: '*' anywhere else would silently match nothing useful.
        if (versionPattern is not null)
        {
            int star = versionPattern.IndexOf('*');
            if (star >= 0 && star != versionPattern.Length - 1)
            {
                return _problems.ValidationErrorAction("version_pattern",
                    "'*' is only supported as the final character (trailing glob).");
            }
        }

        string orgId = CurrentTenantId();
        var entry = await _installScriptAllowlist.AddAsync(
            orgId, ecosystem, name, versionPattern, GetUserId(), ct);

        await _audit.LogAsync("install_script_allowlist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
                name = entry.Name,
                version_pattern = entry.VersionPattern,
            }), ct: ct);

        return CreatedAtAction(nameof(GetInstallScriptAllowlist), null, entry);
    }

    /// <summary>DELETE /api/v1/install-script-allowlist/{id}</summary>
    [HttpDelete("api/v1/install-script-allowlist/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteInstallScriptAllowlist(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        // org_id-scoped: a cross-tenant (or unknown) id deletes 0 rows. Delete stays idempotent
        // (204 either way); the org scope is what enforces isolation. Audit only a real removal.
        string orgId = CurrentTenantId();
        if (await _installScriptAllowlist.DeleteAsync(orgId, id, ct) > 0)
        {
            await _audit.LogAsync("install_script_allowlist_removed", orgId, GetUserId(),
                detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);
        }

        return NoContent();
    }
}
