using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// SIEM integration API — read-only, machine-to-machine.
/// Accepts JWT (system_admin operator or any role with read:audit) or a Bearer token
/// carrying read:audit. Platform admins (capability <c>platform:*</c>) get cross-tenant
/// access; everyone else is scoped to their own tenant.
///
///   GET /api/v1/siem/events/auth          — auth event stream from audit_log
///   GET /api/v1/siem/vulnerabilities/summary — vuln severity totals
/// </summary>
[ApiController]
[AllowAnonymous] // Auth is checked manually to support both JWT and siem:read tokens
public sealed class SiemController : ControllerBase
{
    private readonly AuditRepository _audit;
    private readonly VulnerabilityRepository _vulns;
    private readonly OrgRepository _orgs;
    private readonly TokenRepository _tokens;
    private readonly IConfiguration _config;

    public SiemController(
        AuditRepository audit,
        VulnerabilityRepository vulns,
        OrgRepository orgs,
        TokenRepository tokens,
        IConfiguration config)
    {
        _audit = audit;
        _vulns = vulns;
        _orgs = orgs;
        _tokens = tokens;
        _config = config;
    }

    /// <summary>
    /// GET /api/v1/siem/events/auth
    /// Returns auth-relevant audit events (login, lockout, token, rbac actions).
    ///
    /// Query parameters:
    ///   since  — ISO 8601 start time (default: 24 h ago)
    ///   until  — ISO 8601 end time (default: now)
    ///   org    — org slug filter; instance_admin only
    ///   action — repeatable; prefix filter (e.g. action=login. action=lockout.)
    ///   limit  — page size, 1–500 (default: 100)
    ///   cursor — opaque pagination cursor from previous response
    ///
    /// Accept header controls output format:
    ///   application/json (default) — JSON array
    ///   application/x-ndjson      — newline-delimited JSON (one object per line)
    ///   application/x-cef         — Common Event Format (one record per line)
    /// </summary>
    [HttpGet("api/v1/siem/events/auth")]
    public async Task<IActionResult> GetAuthEvents(
        [FromQuery] string? since,
        [FromQuery] string? until,
        [FromQuery] string? org,
        [FromQuery(Name = "action")] IReadOnlyList<string>? action,
        [FromQuery] int limit = 100,
        [FromQuery] string? cursor = null,
        CancellationToken ct = default)
    {
        var authResult = await AuthenticateAsync(ct);
        if (authResult.Error is not null)
            return authResult.Error;

        var range = ParseAuthEventDateRange(since, until);
        if (range.Error is not null) return range.Error;

        var (orgId, orgError) = await ResolveOrgFilterAsync(authResult, org, ct);
        if (orgError is not null) return orgError;

        var (items, nextCursor) = await _audit.ListAuthEventsAsync(
            range.Since, range.Until, orgId, action, Math.Clamp(limit, 1, 500), cursor, ct);

        return RenderAuthEventsResponse(items, nextCursor);
    }

    private (DateTimeOffset Since, DateTimeOffset Until, IActionResult? Error) ParseAuthEventDateRange(string? since, string? until)
    {
        var now = DateTimeOffset.UtcNow;
        var maxLookbackDays = _config.GetValue<int>("SIEM_MAX_LOOKBACK_DAYS", 90);

        if (!TryParseIso(since, now.AddDays(-1), out var sinceDto))
            return (default, default, BadRequest(new { detail = "Invalid 'since' date format. Use ISO 8601." }));
        if (!TryParseIso(until, now, out var untilDto))
            return (default, default, BadRequest(new { detail = "Invalid 'until' date format. Use ISO 8601." }));

        var earliest = now.AddDays(-maxLookbackDays);
        if (sinceDto < earliest) sinceDto = earliest;
        if (untilDto > now) untilDto = now;
        if (sinceDto >= untilDto)
            return (default, default, BadRequest(new { detail = "since must be before until." }));

        return (sinceDto, untilDto, null);
    }

    private static bool TryParseIso(string? raw, DateTimeOffset fallback, out DateTimeOffset value)
    {
        if (raw is null) { value = fallback; return true; }
        return DateTimeOffset.TryParse(raw, null, System.Globalization.DateTimeStyles.RoundtripKind, out value);
    }

    private async Task<(string? OrgId, IActionResult? Error)> ResolveOrgFilterAsync(SiemAuthResult authResult, string? org, CancellationToken ct)
    {
        // Token callers are locked to their org; JWT callers may filter via ?org=
        if (authResult.TokenOrgId is not null) return (authResult.TokenOrgId, null);
        if (org is null) return (null, null); // instance_admin with no filter → all orgs
        if (!authResult.IsInstanceAdmin) return (null, Forbid());
        var orgRecord = await _orgs.GetBySlugAsync(org, ct: ct);
        return orgRecord is null ? (null, NotFound()) : (orgRecord.Id, null);
    }

    private IActionResult RenderAuthEventsResponse(IReadOnlyList<AuditEntry> items, string? nextCursor)
    {
        var accept = Request.Headers.Accept.FirstOrDefault() ?? "";
        if (accept.Contains("application/x-ndjson", StringComparison.OrdinalIgnoreCase))
            return NdjsonResult(items, nextCursor);
        if (accept.Contains("application/x-cef", StringComparison.OrdinalIgnoreCase))
            return CefResult(items, nextCursor);
        return Ok(new { items, next_cursor = nextCursor });
    }

    /// <summary>
    /// GET /api/v1/siem/vulnerabilities/summary
    /// Returns vuln severity counts grouped by ecosystem.
    ///
    /// Query parameters:
    ///   org        — org slug filter; instance_admin only
    ///   ecosystem  — optional ecosystem filter
    /// </summary>
    [HttpGet("api/v1/siem/vulnerabilities/summary")]
    public async Task<IActionResult> GetVulnSummary(
        [FromQuery] string? org,
        [FromQuery] string? ecosystem,
        CancellationToken ct = default)
    {
        var authResult = await AuthenticateAsync(ct);
        if (authResult.Error is not null)
            return authResult.Error;

        string? orgId = null;
        if (authResult.TokenOrgId is not null)
        {
            orgId = authResult.TokenOrgId;
        }
        else if (org is not null)
        {
            if (!authResult.IsInstanceAdmin)
                return Forbid();
            var orgRecord = await _orgs.GetBySlugAsync(org, ct: ct);
            if (orgRecord is null) return NotFound();
            orgId = orgRecord.Id;
        }

        var summary = await _vulns.GetVulnSummaryAsync(orgId, ct);

        // Pivot severity rows into nested structure: { ecosystem: { severity: count } }
        var bySeverity = new Dictionary<string, Dictionary<string, long>>();
        foreach (var (eco, sev, count) in summary.Rows)
        {
            if (ecosystem is not null && !string.Equals(eco, ecosystem, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!bySeverity.TryGetValue(eco, out var sevMap))
                bySeverity[eco] = sevMap = new Dictionary<string, long>();
            sevMap[sev ?? "unknown"] = count;
        }

        return Ok(new
        {
            by_ecosystem = bySeverity,
            packages_total = summary.PackageTotal,
            packages_affected = summary.PackageAffected,
        });
    }

    // ── Auth helpers ─────────────────────────────────────────────────────────

    private sealed record SiemAuthResult(
        bool IsInstanceAdmin,
        string? TokenOrgId,
        IActionResult? Error);

    /// <summary>
    /// Resolves SIEM auth from either JWT or a Bearer token with read:audit capability.
    /// Returns error result if not authenticated. Platform admin (system_admin role / any
    /// principal carrying <c>platform:*</c>) gets cross-tenant access; tenant-scoped
    /// principals are limited to their own tenant.
    /// </summary>
    private async Task<SiemAuthResult> AuthenticateAsync(CancellationToken ct)
    {
        // JWT path — set by the normal JWT middleware. Compute the effective cap set the
        // same way CapabilityHandler does so SIEM auth stays in lockstep with the
        // [RequireCapability] path on protocol routes.
        if (User.Identity?.IsAuthenticated == true)
        {
            var role = User.FindFirst("role")?.Value;
            var granted = role == "system_admin"
                ? Capabilities.ForPlatformAdmin()
                : Capabilities.ForRole(role ?? "member");

            // Authenticated-but-uncapped (e.g. tenant member) must not reach SIEM data —
            // there's a dedicated /api/v1/audit endpoint for tenant-scoped audit reads.
            if (!Capabilities.Grants(granted, Capabilities.ReadAudit))
                return new SiemAuthResult(false, null,
                    new ObjectResult(new { detail = "read:audit capability required." })
                    { StatusCode = StatusCodes.Status403Forbidden });

            // Platform admin gets cross-tenant access. Everyone else (tenant admin/owner/
            // auditor with read:audit) is pinned to their own tenant by setting TokenOrgId
            // from the JWT — otherwise ResolveOrgFilterAsync's no-org-filter fallback would
            // leak rows across tenants via AuditRepository's `WHERE (@orgId IS NULL OR ...)`.
            if (Capabilities.Grants(granted, Capabilities.PlatformAll))
                return new SiemAuthResult(true, null, null);

            var jwtOrgId = User.FindFirst("org_id")?.Value ?? User.FindFirst("tid")?.Value;
            if (string.IsNullOrEmpty(jwtOrgId))
                return new SiemAuthResult(false, null,
                    new ObjectResult(new { detail = "JWT missing tenant claim." })
                    { StatusCode = StatusCodes.Status401Unauthorized });
            return new SiemAuthResult(false, jwtOrgId, null);
        }

        // Token path — Bearer carrying read:audit.
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is not null && token.HasCapability(Capabilities.ReadAudit))
            return new SiemAuthResult(false, token.OrgId, null);

        return new SiemAuthResult(false, null, Unauthorized(new { detail = "Authentication required. Provide a JWT or a Bearer token with read:audit capability." }));
    }

    // ── Output formatters ────────────────────────────────────────────────────

    private ContentResult NdjsonResult(IReadOnlyList<AuditEntry> items, string? nextCursor)
    {
        var sb = new StringBuilder();
        var opts = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        foreach (var item in items)
            sb.AppendLine(JsonSerializer.Serialize(item, opts));
        if (nextCursor is not null)
            sb.AppendLine(JsonSerializer.Serialize(new { next_cursor = nextCursor }, opts));
        return Content(sb.ToString(), "application/x-ndjson", Encoding.UTF8);
    }

    private ContentResult CefResult(IReadOnlyList<AuditEntry> items, string? nextCursor)
    {
        // CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
        var sb = new StringBuilder();
        foreach (var item in items)
        {
            var sig = CefEscape(item.Action);
            var name = CefFriendlyName(item.Action);
            var sev = CefSeverity(item.Action);
            var ext = new StringBuilder();
            ext.Append($"rt={item.CreatedAt:yyyyMMddHHmmss.fffZ}");
            if (item.ActorId is not null) ext.Append($" suid={CefEscape(item.ActorId)}");
            if (item.OrgId is not null) ext.Append($" cs1={CefEscape(item.OrgId)} cs1Label=OrgId");
            if (item.Ecosystem is not null) ext.Append($" cs2={CefEscape(item.Ecosystem)} cs2Label=Ecosystem");
            if (item.Purl is not null) ext.Append($" cs3={CefEscape(item.Purl)} cs3Label=Purl");
            if (item.Detail is not null) ext.Append($" msg={CefEscape(item.Detail)}");
            sb.AppendLine($"CEF:0|Dependably|dependably|1.0|{sig}|{name}|{sev}|{ext}");
        }
        if (nextCursor is not null)
            sb.AppendLine($"# next_cursor={nextCursor}");
        return Content(sb.ToString(), "application/x-cef", Encoding.UTF8);
    }

    private static string CefEscape(string s) =>
        s.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=").Replace("\n", "\\n").Replace("\r", "\\r");

    private static string CefFriendlyName(string action) => action switch
    {
        "login.success"      => "Login Success",
        "login.failure"      => "Login Failure",
        "lockout.triggered"  => "Account Lockout",
        "token.created"      => "Token Created",
        "token.revoked"      => "Token Revoked",
        "rbac.role_changed"  => "Role Changed",
        "rbac.member_added"  => "Member Added",
        "rbac.member_removed"=> "Member Removed",
        _                    => action,
    };

    private static int CefSeverity(string action) => action switch
    {
        "lockout.triggered" => 7,
        "login.failure"     => 5,
        "login.success"     => 3,
        "token.revoked"     => 4,
        "rbac.role_changed" => 6,
        _                   => 3,
    };
}
