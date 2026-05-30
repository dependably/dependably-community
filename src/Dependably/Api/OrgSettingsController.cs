using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// Tenant-scoped configuration endpoints. Split out of <see cref="OrgController"/> (#61):
/// org settings, retention, and proxy settings are all the same "configuration of a single
/// org row" shape, and they share a single dependency surface (OrgSettingsRepository,
/// OrgAccessGuard, AuditRepository). Tenant role-management remains in OrgController for
/// now; it's a separate resource shape (members, not config keys).
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgSettingsController : OrgScopedControllerBase
{
    private readonly OrgSettingsRepository _settings;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly IAuditEmitter _auditEmitter;
    private readonly IConfiguration _config;
    private readonly ProblemResults _problems;

    public OrgSettingsController(
        OrgSettingsRepository settings,
        OrgAccessGuard guard,
        AuditRepository audit,
        IAuditEmitter auditEmitter,
        IConfiguration config,
        ProblemResults problems)
    {
        _settings = settings;
        _guard = guard;
        _audit = audit;
        _auditEmitter = auditEmitter;
        _config = config;
        _problems = problems;
    }

    /// <summary>GET /api/v1/orgs/{org}/settings</summary>
    [HttpGet("api/v1/settings")]
    public async Task<IActionResult> GetOrgSettings(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _settings.GetSettingsAsync(orgId, ct);
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

        // Capture prior allow_version_overwrite so the targeted tenant.setting.change event
        // can carry before/after when the toggle moves — that's the supply-chain-shaped
        // surface (#45) audit reviewers grep for.
        var prior = await _settings.GetSettingsAsync(orgId, ct);
        var priorOverwrite = prior?.AllowVersionOverwrite ?? false;

        await _settings.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId,
            req.AnonymousPull,
            req.AllowlistMode,
            req.MaxUploadBytes,
            req.MaxUploadBytesPyPi,
            req.MaxUploadBytesNpm,
            req.MaxUploadBytesNuGet,
            instanceMax,
            req.DefaultLanguage,
            req.AllowVersionOverwrite,
            MaxUploadBytesMaven: req.MaxUploadBytesMaven,
            MaxUploadBytesRpm:   req.MaxUploadBytesRpm,
            MaxUploadBytesOci:   req.MaxUploadBytesOci), ct);

        await _audit.LogAsync("org_settings_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                anonymous_pull = req.AnonymousPull,
                allowlist_mode = req.AllowlistMode,
                max_upload_bytes = req.MaxUploadBytes,
                max_upload_bytes_pypi = req.MaxUploadBytesPyPi,
                max_upload_bytes_npm = req.MaxUploadBytesNpm,
                max_upload_bytes_nuget = req.MaxUploadBytesNuGet,
                max_upload_bytes_maven = req.MaxUploadBytesMaven,
                max_upload_bytes_rpm = req.MaxUploadBytesRpm,
                max_upload_bytes_oci = req.MaxUploadBytesOci,
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

    /// <summary>GET /api/v1/orgs/{org}/retention</summary>
    [HttpGet("api/v1/retention")]
    public async Task<IActionResult> GetRetention(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _settings.GetSettingsAsync(orgId, ct);
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
        await _settings.UpsertRetentionAsync(orgId, req.KeepVersions, req.KeepDays, req.ActivityRetentionDays, ct);

        await _audit.LogAsync("retention_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                keep_versions = req.KeepVersions,
                keep_days = req.KeepDays,
                activity_retention_days = req.ActivityRetentionDays,
            }), ct: ct);

        return NoContent();
    }

    /// <summary>GET /api/v1/orgs/{org}/proxy-settings</summary>
    [HttpGet("api/v1/proxy-settings")]
    public async Task<IActionResult> GetProxySettings(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _settings.GetSettingsAsync(orgId, ct);
        return Ok(new
        {
            proxy_passthrough_enabled = settings?.ProxyPassthroughEnabled ?? true,
            max_osv_score_tolerance   = settings?.MaxOsvScoreTolerance   ?? 10.0,
            min_release_age_hours     = settings?.MinReleaseAgeHours,
        });
    }

    // 8760 = 365*24; sanity cap to keep the UI from accepting decade-scale values that would
    // never be useful (and would mask an accidental day↔hour confusion at the call site).
    private const int MaxReleaseAgeHours = 8760;

    /// <summary>PUT /api/v1/orgs/{org}/proxy-settings</summary>
    [HttpPut("api/v1/proxy-settings")]
    public async Task<IActionResult> UpdateProxySettings([FromBody] UpdateProxySettingsRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (req.MaxOsvScoreTolerance is < 0.0 or > 10.0)
            return _problems.ValidationErrorAction("max_osv_score_tolerance", "Must be between 0.0 and 10.0.");

        if (req.MinReleaseAgeHours is { } age && (age < 0 || age > MaxReleaseAgeHours))
            return _problems.ValidationErrorAction(
                "min_release_age_hours",
                $"Must be between 0 and {MaxReleaseAgeHours} hours (1 year), or null to disable.");

        var orgId = CurrentTenantId();
        await _settings.UpsertProxySettingsAsync(
            orgId, req.ProxyPassthroughEnabled, req.MaxOsvScoreTolerance, req.MinReleaseAgeHours, ct);

        await _audit.LogAsync("proxy_settings_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                proxy_passthrough_enabled = req.ProxyPassthroughEnabled,
                max_osv_score_tolerance = req.MaxOsvScoreTolerance,
                min_release_age_hours = req.MinReleaseAgeHours,
            }), ct: ct);

        return NoContent();
    }
}
