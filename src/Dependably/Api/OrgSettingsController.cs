using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Tenant-scoped configuration endpoints. Split out of <see cref="OrgController"/>:
/// org settings, retention, and proxy settings are all the same "configuration of a single
/// org row" shape, and they share a single dependency surface (OrgSettingsRepository,
/// OrgAccessGuard, AuditRepository). Tenant role-management remains in OrgController for
/// now; it's a separate resource shape (members, not config keys).
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgSettingsController : OrgScopedControllerBase
{
    // Maximum OSV score on the 0.0–10.0 CVSS scale.
    private const double MaxOsvScore = 10.0;

    private readonly OrgSettingsRepository _settings;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly IAuditEmitter _auditEmitter;
    private readonly IConfiguration _config;
    private readonly ProblemResults _problems;
    private readonly IAirGapMode _airGap;

    public OrgSettingsController(
        OrgSettingsRepository settings,
        OrgAccessGuard guard,
        AuditRepository audit,
        IAuditEmitter auditEmitter,
        IConfiguration config,
        ProblemResults problems,
        IAirGapMode airGap)
    {
        _settings = settings;
        _guard = guard;
        _audit = audit;
        _auditEmitter = auditEmitter;
        _config = config;
        _problems = problems;
        _airGap = airGap;
    }

    /// <summary>GET /api/v1/orgs/{org}/settings</summary>
    [HttpGet("api/v1/settings")]
    public async Task<IActionResult> GetOrgSettings(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var settings = await _settings.GetSettingsAsync(orgId, ct);

        // Serialize the settings model verbatim (camelCase, all fields the UI reads) and add
        // airGappedEnforced — the instance-level AIR_GAPPED posture. The UI renders the
        // air-gap checkbox checked + read-only when enforced; the tenant flag (airGapped)
        // remains the editable per-tenant value.
        var node = System.Text.Json.JsonSerializer.SerializeToNode(settings, SettingsJsonOptions)
                   ?? new System.Text.Json.Nodes.JsonObject();
        node["airGappedEnforced"] = _airGap.IsEnabled;
        return new JsonResult(node);
    }

    private static readonly System.Text.Json.JsonSerializerOptions SettingsJsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    /// <summary>PUT /api/v1/orgs/{org}/settings</summary>
    [HttpPut("api/v1/settings")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateOrgSettings([FromBody] UpdateOrgSettingsRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (req.DefaultLanguage is { } lang && !LanguageCodes.IsSupported(lang))
        {
            return BadRequest(new { detail = $"Unsupported language code '{lang}'. Allowed: {string.Join(", ", LanguageCodes.Supported)}." });
        }

        string orgId = CurrentTenantId();
        long? instanceMax = _config["MAX_UPLOAD_BYTES"] is { } s && long.TryParse(s, out long v) ? (long?)v : null;

        // Capture prior allow_version_overwrite + air_gapped so the targeted
        // tenant.setting.change events can carry before/after when a toggle moves — that's the
        // supply-chain-shaped surface audit reviewers grep for.
        var prior = await _settings.GetSettingsAsync(orgId, ct);
        bool priorOverwrite = prior?.AllowVersionOverwrite ?? false;
        bool priorAirGapped = prior?.AirGapped ?? false;

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
            MaxUploadBytesRpm: req.MaxUploadBytesRpm,
            MaxUploadBytesOci: req.MaxUploadBytesOci,
            MaxUploadBytesCargo: req.MaxUploadBytesCargo,
            AirGapped: req.AirGapped), ct);

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
                max_upload_bytes_cargo = req.MaxUploadBytesCargo,
                default_language = req.DefaultLanguage,
                allow_version_overwrite = req.AllowVersionOverwrite,
                air_gapped = req.AirGapped,
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

        if (req.AirGapped is { } newAirGapped && newAirGapped != priorAirGapped)
        {
            await _audit.LogAsync("tenant.setting.change", orgId, GetUserId(),
                detail: System.Text.Json.JsonSerializer.Serialize(new
                {
                    key = "air_gapped",
                    prior_value = priorAirGapped,
                    new_value = newAirGapped,
                }), ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.TenantEvents.TypeSettingChange,
                orgId, "user", GetUserId(), "accepted",
                new Dependably.Infrastructure.Audit.Events.TenantEvents.SettingChange(
                    "air_gapped", priorAirGapped, newAirGapped).ToJson(), ct);
        }

        return NoContent();
    }

    /// <summary>GET /api/v1/orgs/{org}/retention</summary>
    [HttpGet("api/v1/retention")]
    public async Task<IActionResult> GetRetention(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateRetention([FromBody] UpdateRetentionRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
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
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var settings = await _settings.GetSettingsAsync(orgId, ct);
        return Ok(new
        {
            proxy_passthrough_enabled = settings?.ProxyPassthroughEnabled ?? true,
            max_osv_score_tolerance = settings?.MaxOsvScoreTolerance ?? MaxOsvScore,
            min_release_age_hours = settings?.MinReleaseAgeHours,
            block_deprecated = settings?.BlockDeprecated ?? "off",
            block_malicious = settings?.BlockMalicious ?? "block",
            block_kev = settings?.BlockKev ?? "off",
            max_epss_tolerance = settings?.MaxEpssTolerance,
        });
    }

    // 8760 = 365*24; sanity cap to keep the UI from accepting decade-scale values that would
    // never be useful (and would mask an accidental day↔hour confusion at the call site).
    private const int MaxReleaseAgeHours = 8760;

    /// <summary>PUT /api/v1/orgs/{org}/proxy-settings</summary>
    [HttpPut("api/v1/proxy-settings")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateProxySettings([FromBody] UpdateProxySettingsRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (req.MaxOsvScoreTolerance is < 0.0 or > MaxOsvScore)
        {
            return _problems.ValidationErrorAction("max_osv_score_tolerance", "Must be between 0.0 and 10.0.");
        }

        if (req.MinReleaseAgeHours is { } age && (age < 0 || age > MaxReleaseAgeHours))
        {
            return _problems.ValidationErrorAction(
                "min_release_age_hours",
                $"Must be between 0 and {MaxReleaseAgeHours} hours (1 year), or null to disable.");
        }

        // Normalize the retired 'block' value (deny-everything) to its successor 'block_all' so
        // existing automation keeps working after the new/all split.
        string blockDeprecated = req.BlockDeprecated ?? "off";
        if (blockDeprecated == "block")
        {
            blockDeprecated = "block_all";
        }

        if (blockDeprecated is not ("off" or "warn" or "block_new" or "block_all"))
        {
            return _problems.ValidationErrorAction(
                "block_deprecated", "Must be 'off', 'warn', 'block_new', or 'block_all'.");
        }

        // Absent field keeps the secure default — a client still sending the pre-gate payload
        // shape must not silently disable malware blocking.
        string blockMalicious = req.BlockMalicious ?? "block";
        if (blockMalicious is not ("off" or "warn" or "block"))
        {
            return _problems.ValidationErrorAction(
                "block_malicious", "Must be 'off', 'warn', or 'block'.");
        }

        // Absent = off, matching the column default — both KEV and EPSS are opt-in policies.
        string blockKev = req.BlockKev ?? "off";
        if (blockKev is not ("off" or "warn" or "block"))
        {
            return _problems.ValidationErrorAction(
                "block_kev", "Must be 'off', 'warn', or 'block'.");
        }

        if (req.MaxEpssTolerance is < 0.0 or > 1.0)
        {
            return _problems.ValidationErrorAction(
                "max_epss_tolerance", "Must be between 0.0 and 1.0 (EPSS probability), or null to disable.");
        }

        string orgId = CurrentTenantId();
        await _settings.UpsertProxySettingsAsync(
            orgId,
            new ProxyPolicySettings(
                req.ProxyPassthroughEnabled, req.MaxOsvScoreTolerance, req.MinReleaseAgeHours,
                blockDeprecated, blockMalicious, blockKev, req.MaxEpssTolerance),
            ct);

        await _audit.LogAsync("proxy_settings_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                proxy_passthrough_enabled = req.ProxyPassthroughEnabled,
                max_osv_score_tolerance = req.MaxOsvScoreTolerance,
                min_release_age_hours = req.MinReleaseAgeHours,
                block_deprecated = blockDeprecated,
                block_malicious = blockMalicious,
                block_kev = blockKev,
                max_epss_tolerance = req.MaxEpssTolerance,
            }), ct: ct);

        return NoContent();
    }
}
