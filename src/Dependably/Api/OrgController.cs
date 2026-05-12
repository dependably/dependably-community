using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

/// <summary>
/// Management API for orgs, packages, tokens, invites, allowlist, activity.
/// All routes require JWT cookie auth; org-scoped routes also enforce OrgAccessGuard.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgController : ControllerBase
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default value for the BASE_URL env-var used in invite-link templates; only relevant when running locally without configuration. Override in production via BASE_URL.")]
    private const string DefaultBaseUrl = "http://localhost:8080";

    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly TokenRepository _tokens;
    private readonly InviteRepository _invites;
    private readonly AllowlistRepository _allowlist;
    private readonly BlocklistRepository _blocklist;
    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;
    private readonly IBlobStore _blobs;
    private readonly IConfiguration _config;
    private readonly ILogger<OrgController> _logger;
    private readonly ProblemResults _problems;
    private readonly LicenseRepository _licenses;
    private readonly SamlConfigRepository _samlConfig;
    private readonly VulnerabilityRepository _vulns;
    private readonly IPublicUrlBuilder _urls;
    private readonly Dependably.Infrastructure.Audit.IAuditEmitter _auditEmitter;

    public OrgController(OrgControllerServices svc)
    {
        _orgs = svc.Orgs;
        _packages = svc.Packages;
        _tokens = svc.Tokens;
        _invites = svc.Invites;
        _allowlist = svc.Allowlist;
        _blocklist = svc.Blocklist;
        _audit = svc.Audit;
        _guard = svc.Guard;
        _blobs = svc.Blobs;
        _config = svc.Config;
        _logger = svc.Logger;
        _problems = svc.Problems;
        _licenses = svc.Licenses;
        _samlConfig = svc.SamlConfig;
        _vulns = svc.Vulns;
        _urls = svc.Urls;
        _auditEmitter = svc.AuditEmitter;
    }

    // Org CRUD moved to SystemController (/api/v1/system/tenants). Tenant users have no
    // authority to list, create, or delete orgs — those are operator concerns.

    // ── Org Settings ──────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/settings</summary>
    [HttpGet("api/v1/settings")]
    public async Task<IActionResult> GetOrgSettings(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        return Ok(settings);
    }

    /// <summary>PUT /api/v1/orgs/{org}/settings</summary>
    [HttpPut("api/v1/settings")]
    public async Task<IActionResult> UpdateOrgSettings([FromBody] UpdateOrgSettingsRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        foreach (var url in new[] { req.PyPiUpstream, req.NpmUpstream, req.NuGetUpstream })
        {
            if (url is null) continue;
            var problem = UpstreamUrlValidator.ValidateUrl(url);
            if (problem is not null)
                return BadRequest(new { error = problem });
        }

        if (req.DefaultLanguage is { } lang && !LanguageCodes.IsSupported(lang))
            return BadRequest(new { detail = $"Unsupported language code '{lang}'. Allowed: {string.Join(", ", LanguageCodes.Supported)}." });

        var orgId = CurrentTenantId();
        var instanceMax = _config["MAX_UPLOAD_BYTES"] is { } s && long.TryParse(s, out var v) ? (long?)v : null;

        // Read prior allow_version_overwrite so we can emit tenant.setting.change with the
        // before/after pair when the toggle actually moves. The wider org_settings_updated
        // audit covers everything else; this targeted event is what audit reviewers grep for
        // because it's the supply-chain-shaped surface (#45).
        var prior = await _orgs.GetSettingsAsync(orgId, ct);
        var priorOverwrite = prior?.AllowVersionOverwrite ?? false;

        await _orgs.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId,
            req.AnonymousPull,
            req.AllowlistMode,
            req.MaxUploadBytes,
            req.MaxUploadBytesPyPi,
            req.MaxUploadBytesNpm,
            req.MaxUploadBytesNuGet,
            instanceMax,
            req.DefaultLanguage,
            req.AllowVersionOverwrite), ct);

        await _audit.LogAsync("org_settings_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                anonymous_pull = req.AnonymousPull,
                allowlist_mode = req.AllowlistMode,
                max_upload_bytes = req.MaxUploadBytes,
                max_upload_bytes_pypi = req.MaxUploadBytesPyPi,
                max_upload_bytes_npm = req.MaxUploadBytesNpm,
                max_upload_bytes_nuget = req.MaxUploadBytesNuGet,
                pypi_upstream = req.PyPiUpstream,
                npm_upstream = req.NpmUpstream,
                nuget_upstream = req.NuGetUpstream,
                default_language = req.DefaultLanguage,
                allow_version_overwrite = req.AllowVersionOverwrite,
            }), ct: ct);

        if (req.AllowVersionOverwrite is { } newOverwrite && newOverwrite != priorOverwrite)
        {
            await _audit.LogAsync("tenant.setting.change", orgId, GetUserId(),
                detail: System.Text.Json.JsonSerializer.Serialize(new
                {
                    key = "allow_version_overwrite",
                    prior_value = priorOverwrite,
                    new_value = newOverwrite,
                }), ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.TenantEvents.TypeSettingChange,
                orgId, "user", GetUserId(), "accepted",
                new Dependably.Infrastructure.Audit.Events.TenantEvents.SettingChange(
                    "allow_version_overwrite", priorOverwrite, newOverwrite).ToJson(), ct);
        }

        return NoContent();
    }

    // ── Retention Settings ────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/retention</summary>
    [HttpGet("api/v1/retention")]
    public async Task<IActionResult> GetRetention(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        return Ok(new
        {
            keep_versions = settings?.KeepVersions,
            keep_days = settings?.KeepDays,
            activity_retention_days = settings?.ActivityRetentionDays,
        });
    }

    /// <summary>PUT /api/v1/orgs/{org}/retention</summary>
    [HttpPut("api/v1/retention")]
    public async Task<IActionResult> UpdateRetention([FromBody] UpdateRetentionRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        await _orgs.UpsertRetentionAsync(orgId, req.KeepVersions, req.KeepDays, req.ActivityRetentionDays, ct);

        await _audit.LogAsync("retention_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                keep_versions = req.KeepVersions,
                keep_days = req.KeepDays,
                activity_retention_days = req.ActivityRetentionDays,
            }), ct: ct);

        return NoContent();
    }

    // ── Proxy Settings ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/proxy-settings</summary>
    [HttpGet("api/v1/proxy-settings")]
    public async Task<IActionResult> GetProxySettings(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        return Ok(new
        {
            proxy_passthrough_enabled = settings?.ProxyPassthroughEnabled ?? true,
            max_osv_score_tolerance   = settings?.MaxOsvScoreTolerance   ?? 10.0,
        });
    }

    /// <summary>PUT /api/v1/orgs/{org}/proxy-settings</summary>
    [HttpPut("api/v1/proxy-settings")]
    public async Task<IActionResult> UpdateProxySettings([FromBody] UpdateProxySettingsRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (req.MaxOsvScoreTolerance is < 0.0 or > 10.0)
            return _problems.ValidationErrorAction("max_osv_score_tolerance", "Must be between 0.0 and 10.0.");

        var orgId = CurrentTenantId();
        await _orgs.UpsertProxySettingsAsync(orgId, req.ProxyPassthroughEnabled, req.MaxOsvScoreTolerance, ct);

        await _audit.LogAsync("proxy_settings_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                proxy_passthrough_enabled = req.ProxyPassthroughEnabled,
                max_osv_score_tolerance = req.MaxOsvScoreTolerance,
            }), ct: ct);

        return NoContent();
    }

    // ── Packages ──────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/packages</summary>
    [HttpGet("api/v1/packages")]
    public async Task<IActionResult> ListPackages(
        [FromQuery] int limit = 50,
        [FromQuery] int page = 1,
        [FromQuery] string? ecosystem = null,
        [FromQuery] string? search = null,
        [FromQuery] string sortBy = "created",
        [FromQuery] string sortDir = "asc",
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        limit  = Math.Clamp(limit, 1, 200);
        page   = Math.Max(page, 1);
        var offset = (page - 1) * limit;

        var (items, total) = await _packages.ListPaginatedAsync(
            new PackageListQuery(orgId, limit, offset, ecosystem, search, sortBy, sortDir), ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>GET /api/v1/orgs/{org}/packages/{ecosystem}/{name}</summary>
    [HttpGet("api/v1/packages/{ecosystem}/{name}")]
    public async Task<IActionResult> GetPackage(string ecosystem, string name, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null) return NotFound();

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var licenseMap = await _licenses.GetSpdxForVersionsAsync(versions.Select(v => v.Id), ct);
        var scoreMap = await _vulns.GetMaxScoresForVersionsAsync(versions.Select(v => v.Id), ct);
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var tolerance = settings?.MaxOsvScoreTolerance ?? 10.0;

        var versionsWithLicenses = versions.Select(v => {
            scoreMap.TryGetValue(v.Id, out var maxScore);
            var hasMax = scoreMap.ContainsKey(v.Id);
            var status = ComputeVersionStatus(v, hasMax ? maxScore : (double?)null, tolerance);
            return new {
                v.Id, v.PackageId, v.Version, v.Purl, v.BlobKey,
                v.SizeBytes, v.ChecksumSha256, v.Yanked, v.YankReason,
                v.FirstFetch, v.CreatedAt, v.VulnCheckedAt,
                v.ManualBlockState,
                v.Deprecated,
                MaxOsvScore = hasMax ? maxScore : (double?)null,
                Status = status,
                Licenses = licenseMap[v.Id].ToArray()
            };
        });
        return Ok(new { package = pkg, versions = versionsWithLicenses });
    }

    private static string ComputeVersionStatus(PackageVersion v, double? maxScore, double tolerance)
    {
        if (v.ManualBlockState == "blocked") return "blocked";
        var autoBlocked = v.VulnCheckedAt is not null && maxScore.HasValue && maxScore.Value > tolerance;
        if (v.ManualBlockState == "allowed") return autoBlocked ? "allowed" : "clean";
        if (autoBlocked) return "blocked";
        if (v.VulnCheckedAt is null) return "unscanned";
        return "clean";
    }

    /// <summary>DELETE /api/v1/orgs/{org}/packages/{ecosystem}/{name}/{version}</summary>
    [HttpDelete("api/v1/packages/{ecosystem}/{name}/{version}")]
    public async Task<IActionResult> DeleteVersion(string ecosystem, string name, string version, CancellationToken ct)
    {
        // Per-ecosystem yank capability — admin/owner role sets enumerate yank:npm/pypi/nuget.
        // Unknown ecosystem names fail the lookup below, but we 404 here so an invalid path
        // doesn't read as 403.
        var yankCap = ecosystem switch
        {
            "npm" => Capabilities.YankNpm,
            "pypi" => Capabilities.YankPypi,
            "nuget" => Capabilities.YankNuget,
            _ => null
        };
        if (yankCap is null) return NotFound();
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, yankCap, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null) return NotFound();

        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null) return NotFound();

        await _blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        await _packages.DeleteVersionAsync(ver.Id, ct);
        // GC the parent row when this was the last version. Orphan packages rows otherwise
        // accumulate across delete/republish cycles and cause "empty package" UI cards.
        // Atomic NOT EXISTS guard handles the race against a concurrent publish.
        await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct);

        // Activity is the right sink for a per-version operator action — audit_log is for
        // tenant-level config/security events. Never dual-write the same event to both.
        await _audit.LogActivityAsync(orgId, ecosystem, ver.Purl, "delete", GetUserId(), ct: ct);

        return NoContent();
    }

    // ── Activity & Audit ──────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/activity</summary>
    [HttpGet("api/v1/activity")]
    public async Task<IActionResult> GetActivity(
        [FromQuery] int limit = 50,
        [FromQuery] int page = 1,
        [FromQuery(Name = "event_type")] string? eventType = null,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadAudit, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        limit  = Math.Clamp(limit, 1, 200);
        page   = Math.Max(page, 1);
        var offset = (page - 1) * limit;
        if (string.IsNullOrEmpty(eventType)) eventType = null;
        var (items, total) = await _audit.ListActivityAsync(orgId, limit, offset, eventType, ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>GET /api/v1/orgs/{org}/audit</summary>
    [HttpGet("api/v1/audit")]
    public async Task<IActionResult> GetAudit(
        [FromQuery] int limit = 50, [FromQuery] int page = 1, CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadAudit, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        limit  = Math.Clamp(limit, 1, 200);
        page   = Math.Max(page, 1);
        var offset = (page - 1) * limit;
        var (items, total) = await _audit.ListAuditAsync(orgId, limit, offset, ct);
        return Ok(new { items, total, limit, offset });
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

        if (string.IsNullOrWhiteSpace(req.Ecosystem) || string.IsNullOrWhiteSpace(req.PurlPattern))
            return _problems.ValidationErrorAction("purl_pattern", "ecosystem and purl_pattern are required.");

        var orgId = CurrentTenantId();
        var entry = await _allowlist.AddAsync(orgId, req.Ecosystem, req.PurlPattern, ct);

        await _audit.LogAsync("allowlist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
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

        if (string.IsNullOrWhiteSpace(req.Ecosystem) || string.IsNullOrWhiteSpace(req.Pattern))
            return _problems.ValidationErrorAction("pattern", "ecosystem and pattern are required.");

        try { _ = new System.Text.RegularExpressions.Regex(req.Pattern, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2)); }
        catch { return _problems.ValidationErrorAction("pattern", "Pattern is not a valid regular expression."); }

        var orgId = CurrentTenantId();
        var entry = await _blocklist.AddAsync(orgId, req.Ecosystem, req.Pattern, ct);

        await _audit.LogAsync("blocklist_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
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

    // ── User Tokens ───────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/tokens</summary>
    [HttpGet("api/v1/tokens")]
    public async Task<IActionResult> ListTokens(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ManageOwnTokens, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var userId = GetUserId();
        if (userId is null) return Forbid();
        var list = await _tokens.ListUserTokensAsync(orgId, userId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/tokens</summary>
    [HttpPost("api/v1/tokens")]
    [EnableRateLimiting("token-create")]
    public async Task<IActionResult> CreateToken([FromBody] CreateTokenRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ManageOwnTokens, ct);
        if (result is not null) return result;

        // Retired field guard: the legacy `scope` shorthand is no longer accepted. Reject
        // explicitly so callers updating from the old API see a clear 400 instead of
        // silently dropping their intent.
        if (req.Scope is not null)
            return _problems.ValidationErrorAction("scope",
                "The 'scope' field is no longer accepted. Send 'capabilities' instead.");

        var orgId = CurrentTenantId();
        var userId = GetUserId();
        if (userId is null) return Forbid();

        var role = User.FindFirst("role")?.Value ?? "member";
        var callerGrants = Capabilities.ForRole(role);

        if (!Capabilities.TryNormalizeAndAuthorize(
                req.Capabilities, callerGrants,
                out var canonicalJson, out var caps, out var error, out var field))
            return _problems.ValidationErrorAction(field ?? "capabilities", error!);

        var (raw, record) = await _tokens.CreateUserTokenAsync(
            orgId, userId, canonicalJson, req.ExpiresAt, ct);

        // Audit captures the canonical JSON (byte-equal to the DB row) AND the structured
        // array so SIEM tooling can query either shape.
        await _audit.LogAsync("token_created", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                capabilities_json = canonicalJson,
                capabilities = caps,
                expires_at = record.ExpiresAt,
            }), ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.TenantEvents.TypeTokenCreate,
            orgId, "user", userId, "accepted",
            new Dependably.Infrastructure.Audit.Events.TenantEvents.TokenCreate(
                record.Id, canonicalJson, caps, "user", record.ExpiresAt).ToJson(), ct);

        // Return raw token once — never stored in plaintext
        return Ok(new { token = raw, record });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/tokens/{id} — members may revoke their own; admin/owner may revoke any</summary>
    [HttpDelete("api/v1/tokens/{id}")]
    public async Task<IActionResult> DeleteToken(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ManageOwnTokens, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var userId = GetUserId()!;

        // Admin/owner can revoke any token in the org; members can only revoke their own.
        // tenant:configure is the management-override cap (admin + owner both have it).
        var adminCheck = await _guard.CheckCapAsync(User, userId, orgId, Capabilities.TenantConfigure, ct);
        if (adminCheck != OrgAccessGuard.AccessResult.Allowed)
        {
            var token = await _tokens.GetTokenByIdAsync(id, ct);
            if (token is null || token.UserId != userId)
                return Forbid();
        }

        await _tokens.DeleteTokenAsync(id, ct);

        await _audit.LogAsync("token_revoked", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { token_id = id }), ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.TenantEvents.TypeTokenRevoke,
            orgId, "user", userId, "accepted",
            new Dependably.Infrastructure.Audit.Events.TenantEvents.TokenRevoke(id, "user").ToJson(), ct);

        return NoContent();
    }

    // ── CI/CD Tokens ──────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/cicd-tokens</summary>
    [HttpGet("api/v1/cicd-tokens")]
    public async Task<IActionResult> ListCicdTokens(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var list = await _tokens.ListCicdTokensAsync(orgId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/cicd-tokens</summary>
    [HttpPost("api/v1/cicd-tokens")]
    [EnableRateLimiting("token-create")]
    public async Task<IActionResult> CreateCicdToken([FromBody] CreateCicdTokenRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.Name))
            return _problems.ValidationErrorAction("name", "Name is required.");

        if (req.Scope is not null)
            return _problems.ValidationErrorAction("scope",
                "The 'scope' field is no longer accepted. Send 'capabilities' instead.");

        // CI/CD tokens are minted by an admin/owner under tenant:configure; the caller's
        // role grants are the ceiling. The minted token still gets its own narrowed cap set.
        var role = User.FindFirst("role")?.Value ?? "member";
        var callerGrants = Capabilities.ForRole(role);

        if (!Capabilities.TryNormalizeAndAuthorize(
                req.Capabilities, callerGrants,
                out var canonicalJson, out var caps, out var error, out var field))
            return _problems.ValidationErrorAction(field ?? "capabilities", error!);

        var orgId = CurrentTenantId();
        var (raw, record) = await _tokens.CreateCicdTokenAsync(orgId, req.Name, canonicalJson, req.ExpiresAt, ct);

        await _audit.LogAsync("cicd_token_created", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                name = record.Name,
                capabilities_json = canonicalJson,
                capabilities = caps,
                expires_at = record.ExpiresAt,
            }), ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.TenantEvents.TypeTokenCreate,
            orgId, "user", GetUserId(), "accepted",
            new Dependably.Infrastructure.Audit.Events.TenantEvents.TokenCreate(
                record.Id, canonicalJson, caps, "cicd", record.ExpiresAt).ToJson(), ct);

        return Ok(new { token = raw, record });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/cicd-tokens/{id}</summary>
    [HttpDelete("api/v1/cicd-tokens/{id}")]
    public async Task<IActionResult> DeleteCicdToken(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _tokens.DeleteCicdTokenAsync(id, ct);

        await _audit.LogAsync("cicd_token_revoked", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { token_id = id }), ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.TenantEvents.TypeTokenRevoke,
            CurrentTenantId(), "user", GetUserId(), "accepted",
            new Dependably.Infrastructure.Audit.Events.TenantEvents.TokenRevoke(id, "cicd").ToJson(), ct);

        return NoContent();
    }

    // ── Invites ───────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/invites</summary>
    [HttpGet("api/v1/invites")]
    public async Task<IActionResult> ListInvites(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var list = await _invites.ListAsync(orgId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/invites</summary>
    [HttpPost("api/v1/invites")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> CreateInvite([FromBody] CreateInviteRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.Email))
            return _problems.ValidationErrorAction("email", "Email is required.");

        var orgId = CurrentTenantId();
        var userId = GetUserId();
        var role = string.IsNullOrWhiteSpace(req.Role) ? "member" : req.Role.Trim().ToLowerInvariant();
        if (role is not ("member" or "admin" or "owner" or "auditor"))
            return _problems.ValidationErrorAction("role", "Role must be 'member', 'admin', 'owner', or 'auditor'.");

        // Inviting at the owner role is an owner-only operation, matching PatchMemberRole.
        // Admins (who have tenant:configure) can invite member/admin/auditor; only owners
        // (tenant:admin) can mint an invite that lands the invitee as an owner.
        if (role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, userId!, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed) return Forbid();
        }

        var (raw, record) = await _invites.CreateAsync(orgId, req.Email, userId!, role, ct);

        await _audit.LogAsync("invite_created", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                invite_id = record.Id,
                email = record.Email,
                role = record.Role,
                expires_at = record.ExpiresAt,
            }), ct: ct);

        // Invite links go to the apex (system_admin/landing) for join flows. Prefer BASE_URL
        // when set so links are stable across hosts; fall back to the request's base.
        var baseUrl = _config["BASE_URL"] ?? _urls.BaseUrl(HttpContext);
        var inviteLink = $"{baseUrl}/join?token={raw}";

        var smtpHost = _config["SMTP_HOST"];
        if (smtpHost is null)
        {
            _logger.LogInformation("Invite created for {Email} (tenant {TenantId}); SMTP not configured — retrieve link from API response.", req.Email, orgId);
            _logger.LogDebug("Invite link for {Email} (tenant {TenantId}): {Link}", req.Email, orgId, inviteLink);
        }
        // SMTP delivery is deferred — until SMTP_HOST wiring lands, callers retrieve the
        // invite link from the response body (the `invite_link` field above).

        return Ok(new { record, invite_link = smtpHost is null ? inviteLink : null });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/invites/{id}</summary>
    [HttpDelete("api/v1/invites/{id}")]
    public async Task<IActionResult> DeleteInvite(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _invites.DeleteAsync(id, ct);

        await _audit.LogAsync("invite_deleted", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { invite_id = id }), ct: ct);

        return NoContent();
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/users</summary>
    [HttpGet("api/v1/users")]
    public async Task<IActionResult> ListUsers(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        return Ok(members);
    }

    /// <summary>PATCH /api/v1/orgs/{org}/users/{userId}/role
    /// — admin can manage members/admins; only owner can touch owners or grant owner.</summary>
    [HttpPatch("api/v1/users/{userId}/role")]
    public async Task<IActionResult> PatchMemberRole(string userId, [FromBody] PatchRoleRequest req, CancellationToken ct)
    {
        // Tier 1: tenant:configure gates entry — admin + owner can reach the endpoint.
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (req.Role is not ("member" or "admin" or "owner" or "auditor"))
            return _problems.ValidationErrorAction("role", "Role must be 'member', 'admin', 'owner', or 'auditor'.");

        var orgId = CurrentTenantId();
        var callerId = GetUserId()!;

        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        var target = members.FirstOrDefault(m => m.UserId == userId);
        if (target is null) return NotFound();

        // Tier 2: owner-only operations — modifying an owner OR granting the owner role —
        // require tenant:admin. Admins (who have tenant:configure but not tenant:admin)
        // can manage members and admins but cannot touch owners.
        if (target.Role == "owner" || req.Role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, callerId, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed) return Forbid();
        }

        // Last-owner invariant: regardless of caller, the tenant must always have at least
        // one owner. Demoting or replacing the last owner is rejected.
        if (req.Role != "owner" && target.Role == "owner"
            && await _orgs.CountOwnersAsync(orgId, ct) <= 1)
            return _problems.ConflictAction("Cannot demote the last owner of an org.");

        await _orgs.UpdateMemberRoleAsync(orgId, userId, req.Role, ct);
        await _audit.LogAsync("member_role_changed", orgId, callerId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { user_id = userId, new_role = req.Role }), ct: ct);

        return NoContent();
    }

    /// <summary>DELETE /api/v1/orgs/{org}/users/{userId}
    /// — admin can remove members/admins; only owner can remove an owner.</summary>
    [HttpDelete("api/v1/users/{userId}")]
    public async Task<IActionResult> RemoveUser(string userId, CancellationToken ct)
    {
        // Tier 1: tenant:configure entry gate.
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var callerId = GetUserId()!;

        var members = await _orgs.ListOrgMembersAsync(orgId, ct);
        var target = members.FirstOrDefault(m => m.UserId == userId);
        if (target is null) return NotFound();

        // Tier 2: removing an owner requires tenant:admin. Admins cannot remove owners.
        if (target.Role == "owner")
        {
            var ownerCheck = await _guard.CheckCapAsync(User, callerId, orgId, Capabilities.TenantAdmin, ct);
            if (ownerCheck != OrgAccessGuard.AccessResult.Allowed) return Forbid();
        }

        // Last-owner invariant: tenant must always have at least one owner.
        if (target.Role == "owner" && await _orgs.CountOwnersAsync(orgId, ct) <= 1)
            return _problems.ConflictAction("Cannot remove the last owner of an org.");

        await _orgs.RemoveOrgMemberAsync(orgId, userId, ct);
        await _audit.LogAsync("member_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { user_id = userId }), ct: ct);
        return NoContent();
    }

    // ── SAML / Auth Config ────────────────────────────────────────────────────

    /// <summary>GET /api/v1/auth-config — returns the tenant's SAML config for the settings UI.</summary>
    [HttpGet("api/v1/auth-config")]
    public async Task<IActionResult> GetAuthConfig(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var cfg = await _samlConfig.GetAsync(orgId, ct);
        var defaultSpEntityId = _urls.Absolute(HttpContext, "/saml/metadata");
        var acsUrl = _urls.Absolute(HttpContext, "/saml/acs");
        var metadataUrl = defaultSpEntityId;

        // Surface the SP-side URLs the IdP admin needs to register, regardless of whether the
        // tenant has uploaded IdP metadata yet.
        return Ok(new
        {
            enabled = cfg?.Enabled ?? false,
            formsLoginEnabled = cfg?.FormsLoginEnabled ?? true,
            idpEntityId = cfg?.IdpEntityId,
            idpSsoUrl = cfg?.IdpSsoUrl,
            idpSigningCertThumbprint = ThumbprintOrNull(cfg?.IdpSigningCert),
            spEntityId = cfg?.SpEntityId ?? defaultSpEntityId,
            nameIdFormat = cfg?.NameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = cfg?.EmailAttribute,
            buttonLabel = cfg?.ButtonLabel,
            lastTestAt = cfg?.LastTestAt,
            lastTestEmail = cfg?.LastTestEmail,
            spInfo = new { acsUrl, metadataUrl, defaultSpEntityId },
        });
    }

    /// <summary>PUT /api/v1/auth-config — update toggles + SP settings.</summary>
    [HttpPut("api/v1/auth-config")]
    public async Task<IActionResult> PutAuthConfig([FromBody] UpdateAuthConfigRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.NameIdFormat))
            return _problems.ValidationErrorAction("nameIdFormat", "nameIdFormat is required.");

        var orgId = CurrentTenantId();
        var existing = await _samlConfig.GetAsync(orgId, ct);

        // Lockout guard: disabling forms login requires SAML to be enabled AND a successful
        // test within the last 10 minutes. Otherwise a misconfigured IdP locks the tenant out.
        var disablingForms = (existing?.FormsLoginEnabled ?? true) && !req.FormsLoginEnabled;
        if (disablingForms)
        {
            if (!req.Enabled)
                return _problems.ValidationErrorAction("formsLoginEnabled",
                    "Forms login can only be disabled when SAML is enabled.");

            var samlReady = existing is not null
                && !string.IsNullOrWhiteSpace(existing.IdpEntityId)
                && !string.IsNullOrWhiteSpace(existing.IdpSigningCert);
            if (!samlReady)
                return _problems.ValidationErrorAction("formsLoginEnabled",
                    "Upload IdP metadata before disabling forms login.");

            var lastTest = existing!.LastTestAt;
            if (lastTest is null || DateTimeOffset.UtcNow - lastTest.Value > TimeSpan.FromMinutes(10))
                return _problems.ValidationErrorAction("formsLoginEnabled",
                    "Run a successful SAML test within the last 10 minutes before disabling forms login.");
        }

        await _samlConfig.UpsertSettingsAsync(new SamlSettingsUpdate(
            orgId,
            req.Enabled,
            req.FormsLoginEnabled,
            string.IsNullOrWhiteSpace(req.SpEntityId) ? null : req.SpEntityId,
            req.NameIdFormat,
            string.IsNullOrWhiteSpace(req.EmailAttribute) ? null : req.EmailAttribute,
            string.IsNullOrWhiteSpace(req.ButtonLabel) ? null : req.ButtonLabel), ct);

        await _audit.LogAsync("saml.config_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                forms_login_enabled = req.FormsLoginEnabled,
                sp_entity_id = req.SpEntityId,
                name_id_format = req.NameIdFormat,
                email_attribute = req.EmailAttribute,
                button_label = req.ButtonLabel,
            }), ct: ct);

        return NoContent();
    }

    /// <summary>POST /api/v1/auth-config/metadata — upload IdP metadata XML.</summary>
    [HttpPost("api/v1/auth-config/metadata")]
    public async Task<IActionResult> UploadSamlMetadata([FromBody] UploadSamlMetadataRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.MetadataXml))
            return _problems.ValidationErrorAction("metadataXml", "metadataXml is required.");

        IdpMetadataParser.ParsedIdp parsed;
        try { parsed = IdpMetadataParser.Parse(req.MetadataXml); }
        catch (Exception ex) { return _problems.ValidationErrorAction("metadataXml", ex.Message); }

        var orgId = CurrentTenantId();
        await _samlConfig.UpsertMetadataAsync(orgId, parsed.EntityId, parsed.SsoUrl, parsed.SigningCertBase64, req.MetadataXml, ct);

        await _audit.LogAsync("saml.metadata_uploaded", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                idp_entity_id = parsed.EntityId,
                idp_sso_url = parsed.SsoUrl,
                cert_thumbprint = ThumbprintOrNull(parsed.SigningCertBase64),
            }), ct: ct);

        return Ok(new
        {
            idpEntityId = parsed.EntityId,
            idpSsoUrl = parsed.SsoUrl,
            idpSigningCertThumbprint = ThumbprintOrNull(parsed.SigningCertBase64),
        });
    }

    /// <summary>DELETE /api/v1/auth-config — wipe SAML config (re-enables forms login).</summary>
    [HttpDelete("api/v1/auth-config")]
    public async Task<IActionResult> DeleteAuthConfig(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        await _samlConfig.DeleteAsync(orgId, ct);
        await _audit.LogAsync("saml.config_deleted", orgId, GetUserId(), ct: ct);
        return NoContent();
    }

    private static string? ThumbprintOrNull(string? base64Cert)
    {
        if (string.IsNullOrWhiteSpace(base64Cert)) return null;
        try
        {
            var bytes = Convert.FromBase64String(base64Cert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
            return cert.Thumbprint;
        }
        catch { return null; }
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/stats</summary>
    [HttpGet("api/v1/stats")]
    public async Task<IActionResult> GetStats(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var stats = await _packages.GetOrgStatsAsync(orgId, ct);
        return Ok(stats);
    }

    // ── Setup snippets ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/setup/{ecosystem}</summary>
    [HttpGet("api/v1/setup/{ecosystem}")]
    public async Task<IActionResult> GetSetup(string ecosystem, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        // Tenant-implicit URLs: every request is already on the tenant's host (multi mode) or
        // the single-tenant install. Snippets use the request's host directly.
        var baseUrl = _urls.BaseUrl(HttpContext);
        var slug = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantSlug ?? "";

        var snippet = ecosystem switch
        {
            "pypi" => GeneratePyPiSnippet(baseUrl, slug, settings),
            "npm"  => GenerateNpmSnippet(baseUrl, slug, settings),
            "nuget" => GenerateNuGetSnippet(baseUrl, slug, settings),
            _ => null
        };

        if (snippet is null) return NotFound();
        return Ok(new { ecosystem, snippet });
    }

    // Snippet generators emit tenant-implicit URLs (host-relative). The tenant slug parameter
    // is unused at the URL level but kept so the future-multi-mode form `slug.apex/simple/`
    // could be reconstructed if needed; today the request's host already carries the right
    // tenant in both single and multi mode.
    private static string GeneratePyPiSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        var trustedHost = uri.Scheme == "http" ? $" --trusted-host {uri.Host}" : "";
        var indexUrl = $"{baseUrl}/simple/";
        return $"""
            # pip.conf / pyproject.toml
            [global]
            index-url = {indexUrl}

            # One-liner install example:
            pip install <package>==<version> --index-url {indexUrl}{trustedHost} --no-deps
            # Max upload: {s?.MaxUploadBytesPyPi ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    private static string GenerateNpmSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        return $"""
            # .npmrc
            registry={baseUrl}/npm/
            # Max upload: {s?.MaxUploadBytesNpm ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    private static string GenerateNuGetSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        return $"""
            <!-- nuget.config -->
            <configuration>
              <packageSources>
                <add key="dependably" value="{baseUrl}/nuget/v3/index.json" />
              </packageSources>
            </configuration>
            <!-- Max upload: {s?.MaxUploadBytesNuGet ?? s?.MaxUploadBytes ?? 0} bytes -->
            """;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    /// <summary>
    /// Reads the resolved tenant id from <c>HttpContext.Items[TenantContext.HttpItemsKey]</c>.
    /// Should only be called after <c>OrgAccessGuard.AuthorizeCapAsync(User, HttpContext, ...)</c>
    /// returns null (which guarantees the context is a valid tenant).
    /// </summary>
    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    private static string AsPurlName(string ecosystem, string name) =>
        ecosystem == "npm" ? NpmRouteHelper.DecodeRouteName(name) : name;
}

// ── Request DTOs ──────────────────────────────────────────────────────────────

public sealed record CreateOrgRequest(string Slug);

public sealed record UpdateOrgSettingsRequest(
    bool AnonymousPull,
    bool AllowlistMode,
    long? MaxUploadBytes,
    long? MaxUploadBytesPyPi,
    long? MaxUploadBytesNpm,
    long? MaxUploadBytesNuGet,
    string? PyPiUpstream = null,
    string? NpmUpstream = null,
    string? NuGetUpstream = null,
    string? DefaultLanguage = null,
    bool? AllowVersionOverwrite = null);

public sealed record UpdateRetentionRequest(
    int? KeepVersions,
    int? KeepDays,
    int? ActivityRetentionDays);

public sealed record UpdateProxySettingsRequest(bool ProxyPassthroughEnabled, double MaxOsvScoreTolerance);

// Scope is retained as a nullable field purely so the controller can detect callers still
// sending the retired field and return a clear 400. The repository never sees it.
public sealed record CreateTokenRequest(
    DateTimeOffset? ExpiresAt,
    IReadOnlyList<string>? Capabilities = null,
    string? Scope = null);

public sealed record CreateCicdTokenRequest(
    string Name,
    DateTimeOffset? ExpiresAt,
    IReadOnlyList<string>? Capabilities = null,
    string? Scope = null);

public sealed record CreateInviteRequest(string Email, string? Role = "member");

public sealed record AllowlistRequest(string Ecosystem, string PurlPattern);

public sealed record BlocklistRequest(string Ecosystem, string Pattern);

public sealed record PatchRoleRequest(string Role);

public sealed record UpdateAuthConfigRequest(
    bool Enabled,
    bool FormsLoginEnabled,
    string? SpEntityId,
    string NameIdFormat,
    string? EmailAttribute,
    string? ButtonLabel);

public sealed record UploadSamlMetadataRequest(string MetadataXml);

// DI-injected dependency aggregate for OrgController. Single param avoids S107.
public sealed record OrgControllerServices(
    OrgRepository Orgs,
    PackageRepository Packages,
    TokenRepository Tokens,
    InviteRepository Invites,
    AllowlistRepository Allowlist,
    BlocklistRepository Blocklist,
    AuditRepository Audit,
    OrgAccessGuard Guard,
    IBlobStore Blobs,
    IConfiguration Config,
    ILogger<OrgController> Logger,
    ProblemResults Problems,
    LicenseRepository Licenses,
    SamlConfigRepository SamlConfig,
    VulnerabilityRepository Vulns,
    IPublicUrlBuilder Urls,
    Dependably.Infrastructure.Audit.IAuditEmitter AuditEmitter);
