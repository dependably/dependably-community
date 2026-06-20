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
    private readonly Dependably.Protocol.Provenance.NpmSignatureKeyStore _npmKeys;
    private readonly Dependably.Protocol.Provenance.NuGetSignatureTrustStore _nugetCerts;
    private readonly Dependably.Protocol.Provenance.PyPiSigstoreTrustStore _pypiRoots;
    private readonly Dependably.Protocol.Provenance.RpmProvenanceVerifier _rpmProvenance;
    private readonly Dependably.Protocol.Provenance.MavenSignatureKeyStore _mavenKeys;

    // Dependency-injection constructor; the parameter list is the controller's declared
    // dependency set and grouping it into an aggregate would hide dependencies without
    // adding cohesion.
#pragma warning disable S107
    public OrgSettingsController(
        OrgSettingsRepository settings,
        OrgAccessGuard guard,
        AuditRepository audit,
        IAuditEmitter auditEmitter,
        IConfiguration config,
        ProblemResults problems,
        IAirGapMode airGap,
        Dependably.Protocol.Provenance.NpmSignatureKeyStore npmKeys,
        Dependably.Protocol.Provenance.NuGetSignatureTrustStore nugetCerts,
        Dependably.Protocol.Provenance.PyPiSigstoreTrustStore pypiRoots,
        Dependably.Protocol.Provenance.RpmProvenanceVerifier rpmProvenance,
        Dependably.Protocol.Provenance.MavenSignatureKeyStore mavenKeys)
#pragma warning restore S107
    {
        _settings = settings;
        _guard = guard;
        _audit = audit;
        _auditEmitter = auditEmitter;
        _config = config;
        _problems = problems;
        _airGap = airGap;
        _npmKeys = npmKeys;
        _nugetCerts = nugetCerts;
        _pypiRoots = pypiRoots;
        _rpmProvenance = rpmProvenance;
        _mavenKeys = mavenKeys;
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
            block_install_scripts = settings?.BlockInstallScripts ?? "off",
            verify_npm_signatures = settings?.VerifyNpmSignatures ?? "off",
            // Surfaces whether operator-pinned npm trust anchors exist, so the UI can disable the
            // verify control (and explain why) when enabling it would be a fail-closed error.
            npm_signature_keys_configured = _npmKeys.IsConfigured,
            verify_nuget_signatures = settings?.VerifyNuGetSignatures ?? "off",
            // Same surface for NuGet: whether operator-pinned signing certificates exist, so the UI
            // can disable the verify control when enabling it would be a fail-closed error.
            nuget_signature_certs_configured = _nugetCerts.IsConfigured,
            verify_pypi_attestations = settings?.VerifyPyPiAttestations ?? "off",
            // Same surface for PyPI: whether operator-pinned Sigstore roots AND a Trusted Publisher
            // allowlist exist, so the UI can disable the verify control when enabling it would be a
            // fail-closed error.
            pypi_sigstore_roots_configured = _pypiRoots.IsConfigured,
            verify_rpm_signatures = settings?.VerifyRpmSignatures ?? "off",
            // Surfaces whether the operator-pinned Rpm:GpgKey is loaded so the UI can disable the
            // verify control and explain why when enabling it would be a fail-closed error.
            rpm_gpg_key_configured = _rpmProvenance.IsConfigured,
            verify_maven_signatures = settings?.VerifyMavenSignatures ?? "off",
            // Same surface for Maven: whether operator-pinned Maven:SignatureKeys are loaded.
            maven_signature_keys_configured = _mavenKeys.IsConfigured,
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

        var numericError = ValidateProxyNumericFields(req);
        if (numericError is not null)
        {
            return numericError;
        }

        var blockDeprecatedError = NormalizeAndValidateBlockDeprecated(req.BlockDeprecated, out string blockDeprecated);
        if (blockDeprecatedError is not null)
        {
            return blockDeprecatedError;
        }

        var blockPolicyError = ValidateBlockPolicyFields(req,
            out string blockMalicious, out string blockKev, out string blockInstallScripts);
        if (blockPolicyError is not null)
        {
            return blockPolicyError;
        }

        var sigVerifyError = ValidateSignatureVerificationFields(req,
            out string verifyNpmSignatures, out string verifyNuGetSignatures,
            out string verifyPyPiAttestations, out string verifyRpmSignatures,
            out string verifyMavenSignatures);
        if (sigVerifyError is not null)
        {
            return sigVerifyError;
        }

        string orgId = CurrentTenantId();
        await _settings.UpsertProxySettingsAsync(
            orgId,
            new ProxyPolicySettings(
                req.ProxyPassthroughEnabled, req.MaxOsvScoreTolerance, req.MinReleaseAgeHours,
                blockDeprecated, blockMalicious, blockKev, req.MaxEpssTolerance, blockInstallScripts,
                verifyNpmSignatures, verifyNuGetSignatures, verifyPyPiAttestations,
                verifyRpmSignatures, verifyMavenSignatures),
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
                block_install_scripts = blockInstallScripts,
                verify_npm_signatures = verifyNpmSignatures,
                verify_nuget_signatures = verifyNuGetSignatures,
                verify_pypi_attestations = verifyPyPiAttestations,
                verify_rpm_signatures = verifyRpmSignatures,
                verify_maven_signatures = verifyMavenSignatures,
            }), ct: ct);

        return NoContent();
    }

    // Validates numeric range fields on the proxy settings request. Returns a validation error
    // result when any field is out of range, or null when all pass.
    private IActionResult? ValidateProxyNumericFields(UpdateProxySettingsRequest req)
        => req.MaxOsvScoreTolerance is < 0.0 or > MaxOsvScore
            ? _problems.ValidationErrorAction("max_osv_score_tolerance", "Must be between 0.0 and 10.0.")
            : req.MinReleaseAgeHours is { } age && (age < 0 || age > MaxReleaseAgeHours)
                ? _problems.ValidationErrorAction(
                    "min_release_age_hours",
                    $"Must be between 0 and {MaxReleaseAgeHours} hours (1 year), or null to disable.")
                : req.MaxEpssTolerance is < 0.0 or > 1.0
                    ? _problems.ValidationErrorAction(
                        "max_epss_tolerance", "Must be between 0.0 and 1.0 (EPSS probability), or null to disable.")
                    : null;

    // Normalizes the block_deprecated field (maps retired 'block' alias to 'block_all') and
    // validates the final value. Returns a validation error when invalid, or null when the value
    // is accepted, writing the normalized value into the out parameter.
    private IActionResult? NormalizeAndValidateBlockDeprecated(string? raw, out string normalized)
    {
        // Normalize the retired 'block' value (deny-everything) to its successor 'block_all' so
        // existing automation keeps working after the new/all split.
        normalized = raw ?? "off";
        if (normalized == "block")
        {
            normalized = "block_all";
        }

        return normalized is not ("off" or "warn" or "block_new" or "block_all")
            ? _problems.ValidationErrorAction(
                "block_deprecated", "Must be 'off', 'warn', 'block_new', or 'block_all'.")
            : null;
    }

    // Validates the block-policy enum fields (malicious, KEV, install-scripts). Returns a
    // validation error on the first invalid field, or null when all pass. Writes normalized
    // values into the out parameters.
    private IActionResult? ValidateBlockPolicyFields(
        UpdateProxySettingsRequest req,
        out string blockMalicious, out string blockKev, out string blockInstallScripts)
    {
        // Absent field keeps the secure default — a client still sending the pre-gate payload
        // shape must not silently disable malware blocking.
        blockMalicious = req.BlockMalicious ?? "block";
        blockKev = req.BlockKev ?? "off";
        blockInstallScripts = req.BlockInstallScripts ?? "off";

        if (blockMalicious is not ("off" or "warn" or "block"))
        {
            return _problems.ValidationErrorAction(
                "block_malicious", "Must be 'off', 'warn', or 'block'.");
        }

        // Absent = off, matching the column default — both KEV and EPSS are opt-in policies.
        if (blockKev is not ("off" or "warn" or "block"))
        {
            return _problems.ValidationErrorAction(
                "block_kev", "Must be 'off', 'warn', or 'block'.");
        }

        // Absent = off, matching the column default — install-script blocking is opt-in.
        return blockInstallScripts is not ("off" or "warn" or "block")
            ? _problems.ValidationErrorAction(
                "block_install_scripts", "Must be 'off', 'warn', or 'block'.")
            : null;
    }

    // Validates all five per-ecosystem signature verification fields. Returns a validation
    // error on the first invalid or unconfigured field, or null when all pass. Writes
    // normalized values into the out parameters.
    private IActionResult? ValidateSignatureVerificationFields(
        UpdateProxySettingsRequest req,
        out string verifyNpmSignatures, out string verifyNuGetSignatures,
        out string verifyPyPiAttestations, out string verifyRpmSignatures,
        out string verifyMavenSignatures)
    {
        // Absent = off for all verification fields, matching the column defaults — each is opt-in.
        verifyNpmSignatures = req.VerifyNpmSignatures ?? "off";
        verifyNuGetSignatures = req.VerifyNuGetSignatures ?? "off";
        verifyPyPiAttestations = req.VerifyPyPiAttestations ?? "off";
        verifyRpmSignatures = req.VerifyRpmSignatures ?? "off";
        verifyMavenSignatures = req.VerifyMavenSignatures ?? "off";

        return ValidateOneSigVerifyField(verifyNpmSignatures, "verify_npm_signatures",
                   _npmKeys.IsConfigured,
                   "Cannot enable npm signature verification: no trust anchors are configured. "
                   + "Pin the registry's public keys via Npm:SignatureKeys first.")
               ?? ValidateOneSigVerifyField(verifyNuGetSignatures, "verify_nuget_signatures",
                   _nugetCerts.IsConfigured,
                   "Cannot enable NuGet signature verification: no trust anchors are configured. "
                   + "Pin the registry's signing certificates via NuGet:SignatureCertificates first.")
               ?? ValidateOneSigVerifyField(verifyPyPiAttestations, "verify_pypi_attestations",
                   _pypiRoots.IsConfigured,
                   "Cannot enable PyPI attestation verification: no Sigstore roots and Trusted "
                   + "Publishers are configured. Pin them via PyPI:SigstoreRoots and "
                   + "PyPI:TrustedPublishers first.")
               ?? ValidateOneSigVerifyField(verifyRpmSignatures, "verify_rpm_signatures",
                   _rpmProvenance.IsConfigured,
                   "Cannot enable RPM signature verification: no trust anchor is configured. "
                   + "Pin the operator GPG key via Rpm:GpgKey first.")
               ?? ValidateOneSigVerifyField(verifyMavenSignatures, "verify_maven_signatures",
                   _mavenKeys.IsConfigured,
                   "Cannot enable Maven signature verification: no trust anchors are configured. "
                   + "Pin the publisher keys via Maven:SignatureKeys first.");
    }

    // Validates one sig-verify field: rejects values outside the allowed enum and, when
    // the value is non-off, rejects if the operator trust anchor is not configured.
    private IActionResult? ValidateOneSigVerifyField(
        string value, string field, bool isConfigured, string trustMsg)
    {
        if (value is not ("off" or "warn" or "block"))
        {
            return _problems.ValidationErrorAction(field, "Must be 'off', 'warn', or 'block'.");
        }

        // Fail closed: enabling verification without a configured trust anchor would silently
        // pass all versions as not-applicable. The trust root must be configured first.
        return value != "off" && !isConfigured
            ? _problems.ValidationErrorAction(field, trustMsg)
            : null;
    }
}
