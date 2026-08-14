using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Caching;
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
    private readonly IRequireMfaMode _requireMfa;
    private readonly Dependably.Protocol.Provenance.NpmProvenanceVerifier _npmProvenance;
    private readonly Dependably.Protocol.Provenance.NuGetProvenanceVerifier _nugetProvenance;
    private readonly Dependably.Protocol.Provenance.PyPiProvenanceVerifier _pypiProvenance;
    private readonly Dependably.Protocol.Provenance.RpmProvenanceVerifier _rpmProvenance;
    private readonly Dependably.Protocol.Provenance.MavenProvenanceVerifier _mavenProvenance;
    private readonly Dependably.Protocol.Provenance.TerraformProvenanceVerifier _terraformProvenance;
    private readonly OrgCacheEpochStore _cacheEpoch;

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
        IRequireMfaMode requireMfa,
        Dependably.Protocol.Provenance.NpmProvenanceVerifier npmProvenance,
        Dependably.Protocol.Provenance.NuGetProvenanceVerifier nugetProvenance,
        Dependably.Protocol.Provenance.PyPiProvenanceVerifier pypiProvenance,
        Dependably.Protocol.Provenance.RpmProvenanceVerifier rpmProvenance,
        Dependably.Protocol.Provenance.MavenProvenanceVerifier mavenProvenance,
        Dependably.Protocol.Provenance.TerraformProvenanceVerifier terraformProvenance,
        OrgCacheEpochStore cacheEpoch)
#pragma warning restore S107
    {
        _settings = settings;
        _guard = guard;
        _audit = audit;
        _auditEmitter = auditEmitter;
        _config = config;
        _problems = problems;
        _airGap = airGap;
        _requireMfa = requireMfa;
        _npmProvenance = npmProvenance;
        _nugetProvenance = nugetProvenance;
        _pypiProvenance = pypiProvenance;
        _rpmProvenance = rpmProvenance;
        _mavenProvenance = mavenProvenance;
        _terraformProvenance = terraformProvenance;
        _cacheEpoch = cacheEpoch;
    }

    /// <summary>GET /api/v1/orgs/{org}/settings</summary>
    // Read-only: accepts a PAT/service token carrying read:tenant. Returns policy values and
    // *_configured booleans only — never a secret.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
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
        var node = System.Text.Json.JsonSerializer.SerializeToNode(settings, JsonContracts.Web)
                   ?? new System.Text.Json.Nodes.JsonObject();
        node["airGappedEnforced"] = _airGap.IsEnabled;
        node["requireMfaEnforced"] = _requireMfa.IsEnabled;

        // rpmUpstreamMode is a nullable per-org override (null = inherit). Surface the resolved
        // instance default and the resulting effective mode alongside the raw override so the RPM
        // upstream card can render "Inherit (currently: passthrough)" instead of misreporting the
        // override as the live behaviour. Mirrors RpmController.IsRpmPassthroughEffective's
        // normalization: any instance value other than 'merged' resolves to 'passthrough'.
        string rpmInstanceDefault = string.Equals(_config["Rpm:UpstreamMode"], "merged", StringComparison.OrdinalIgnoreCase)
            ? "merged" : "passthrough";
        node["rpmUpstreamModeInstanceDefault"] = rpmInstanceDefault;
        node["rpmUpstreamModeEffective"] = settings?.RpmUpstreamMode ?? rpmInstanceDefault;
        return new JsonResult(node);
    }

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

        var validationProblem = ValidateOrgSettingsRequest(req);
        if (validationProblem is not null)
        {
            return validationProblem;
        }

        string orgId = CurrentTenantId();
        long? instanceMax = _config["MAX_UPLOAD_BYTES"] is { } s && long.TryParse(s, out long v) ? (long?)v : null;

        // Capture prior values so the targeted tenant.setting.change events can carry before/after.
        var prior = await _settings.GetSettingsAsync(orgId, ct);

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
            MaxUploadBytesMaven: req.MaxUploadBytesMaven,
            MaxUploadBytesRpm: req.MaxUploadBytesRpm,
            MaxUploadBytesOci: req.MaxUploadBytesOci,
            MaxUploadBytesCargo: req.MaxUploadBytesCargo,
            AirGapped: req.AirGapped,
            VersionOverwritePolicy: req.VersionOverwritePolicy,
            RequireMfa: req.RequireMfa,
            DefaultTimezone: req.DefaultTimezone), ct);

        // Every leave-unchanged-on-absent field below is logged as the raw request value, so a
        // field the caller didn't address in this write is recorded as null — chosen, not leaked:
        // "null = not addressed by this PUT" is the truthful reading of what was sent, and none of
        // these columns has a domain-null for it to collide with.
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
                default_timezone = req.DefaultTimezone,
                version_overwrite_policy = req.VersionOverwritePolicy,
                air_gapped = req.AirGapped,
                require_mfa = req.RequireMfa,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        await EmitOrgSettingsChangeEventsAsync(orgId, req, prior, ct);

        return NoContent();
    }

    private IActionResult? ValidateOrgSettingsRequest(UpdateOrgSettingsRequest req) =>
        req.DefaultLanguage is { } lang && !LanguageCodes.IsSupported(lang)
            ? BadRequest(new { detail = $"Unsupported language code '{lang}'. Allowed: {string.Join(", ", LanguageCodes.Supported)}." })
            : req.DefaultTimezone is { } tz && !TimeZoneCodes.IsSupported(tz)
                ? BadRequest(new { detail = $"Unrecognised timezone '{tz}'. Use an IANA zone name, e.g. 'America/Toronto'." })
                : req.VersionOverwritePolicy is { } pol && pol is not ("block" or "exception" or "allow")
                    ? _problems.ValidationErrorActionKey("version_overwrite_policy", "error.settings.overwritePolicyInvalid")
                    : null;

    // Emits a tenant.setting.change event for each of the three toggleable settings that actually
    // changed in this update, comparing the request against the pre-update snapshot.
    private async Task EmitOrgSettingsChangeEventsAsync(
        string orgId, UpdateOrgSettingsRequest req, OrgSettings? prior, CancellationToken ct)
    {
        bool priorAirGapped = prior?.AirGapped ?? false;
        bool priorRequireMfa = prior?.RequireMfa ?? false;
        string priorPolicy = prior?.VersionOverwritePolicy ?? "block";

        if (req.VersionOverwritePolicy is { } newPolicy && newPolicy != priorPolicy)
        {
            await EmitSettingChangeAsync(orgId, "version_overwrite_policy", priorPolicy, newPolicy, ct);
        }

        if (req.AirGapped is { } newAirGapped && newAirGapped != priorAirGapped)
        {
            await EmitSettingChangeAsync(orgId, "air_gapped", priorAirGapped, newAirGapped, ct);
        }

        if (req.RequireMfa is { } newRequireMfa && newRequireMfa != priorRequireMfa)
        {
            await EmitSettingChangeAsync(orgId, "require_mfa", priorRequireMfa, newRequireMfa, ct);
        }
    }

    // Records a single tenant setting change to both the audit log and the audit-event emitter,
    // carrying the before/after values.
    // `key` is a tenant-setting name (e.g. "air_gapped"),
    // not a credential — the literals flowing in are setting identifiers.
    private async Task EmitSettingChangeAsync(
        string orgId, string key, object? priorValue, object? newValue, CancellationToken ct)
    {
        string? userId = GetUserId();
        await _audit.LogAsync("tenant.setting.change", orgId, userId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                key,
                prior_value = priorValue,
                new_value = newValue,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.TenantEvents.TypeSettingChange,
            orgId, "user", userId, "accepted",
            new Dependably.Infrastructure.Audit.Events.TenantEvents.SettingChange(key, priorValue, newValue).ToJson(), ct);
    }

    /// <summary>GET /api/v1/orgs/{org}/retention</summary>
    // Read-only: accepts a PAT/service token carrying read:tenant.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
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
            purge_unlisted_after_days = settings?.PurgeUnlistedAfterDays,
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

        var validationError = ValidateRetentionFields(req);
        if (validationError is not null)
        {
            return validationError;
        }

        string orgId = CurrentTenantId();
        await _settings.UpsertRetentionAsync(orgId, req.KeepVersions, req.KeepDays, req.ActivityRetentionDays,
            req.PurgeUnlistedAfterDays, ct);

        await _audit.LogAsync("retention_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                keep_versions = req.KeepVersions,
                keep_days = req.KeepDays,
                activity_retention_days = req.ActivityRetentionDays,
                purge_unlisted_after_days = req.PurgeUnlistedAfterDays,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    // Every field is a day/version count fed straight into a retention purge job; a negative value
    // has no meaning here and would either no-op the purge or underflow it, depending on the reader.
    private IActionResult? ValidateRetentionFields(UpdateRetentionRequest req)
        => req.KeepVersions is < 0
            ? _problems.ValidationErrorActionKey("keep_versions", "error.settings.retentionRange")
            : req.KeepDays is < 0
                ? _problems.ValidationErrorActionKey("keep_days", "error.settings.retentionRange")
                : req.ActivityRetentionDays is < 0
                    ? _problems.ValidationErrorActionKey("activity_retention_days", "error.settings.retentionRange")
                    : req.PurgeUnlistedAfterDays is < 0
                        ? _problems.ValidationErrorActionKey("purge_unlisted_after_days", "error.settings.retentionRange")
                        : null;

    /// <summary>GET /api/v1/orgs/{org}/proxy-settings</summary>
    // Read-only: accepts a PAT/service token carrying read:tenant.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
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
            block_revoked = settings?.BlockRevoked ?? "warn",
            block_malicious = settings?.BlockMalicious ?? "block",
            block_kev = settings?.BlockKev ?? "off",
            max_epss_tolerance = settings?.MaxEpssTolerance,
            block_install_scripts = settings?.BlockInstallScripts ?? "off",
            verify_npm_signatures = settings?.VerifyNpmSignatures ?? "off",
            // Surfaces whether this org has at least one npm SPKI trust anchor configured, so the UI
            // can disable the verify control and explain why when enabling it would be a fail-closed
            // error.
            npm_signature_keys_configured = await _npmProvenance.IsConfiguredForAsync(orgId, ct),
            verify_nuget_signatures = settings?.VerifyNuGetSignatures ?? "off",
            // Surfaces whether this org has at least one NuGet X.509 trust anchor configured, so
            // the UI can disable the verify control and explain why when enabling it would be a
            // fail-closed error.
            nuget_signature_certs_configured = await _nugetProvenance.IsConfiguredForAsync(orgId, ct),
            verify_pypi_attestations = settings?.VerifyPyPiAttestations ?? "off",
            // Surfaces whether this org has at least one sigstore_root anchor AND at least one
            // trusted_publisher anchor configured, so the UI can disable the verify control when
            // enabling it would be a fail-closed error.
            pypi_sigstore_roots_configured = await _pypiProvenance.IsConfiguredForAsync(orgId, ct),
            verify_rpm_signatures = settings?.VerifyRpmSignatures ?? "off",
            // Surfaces whether this org has at least one RPM PGP trust anchor configured, so the UI
            // can disable the verify control and explain why when enabling it would be a fail-closed
            // error.
            rpm_gpg_key_configured = await _rpmProvenance.IsConfiguredForAsync(orgId, ct),
            verify_maven_signatures = settings?.VerifyMavenSignatures ?? "off",
            // Surfaces whether this org has at least one Maven PGP trust anchor configured, so the
            // UI can disable the verify control and explain why when enabling it would be a
            // fail-closed error.
            maven_signature_keys_configured = await _mavenProvenance.IsConfiguredForAsync(orgId, ct),
            verify_terraform_signatures = settings?.VerifyTerraformSignatures ?? "off",
            // Surfaces whether this org has at least one Terraform PGP trust anchor configured, so
            // the UI can disable the verify control and explain why when enabling it would be a
            // fail-closed error.
            terraform_signature_keys_configured = await _terraformProvenance.IsConfiguredForAsync(orgId, ct),
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

        var blockDeprecatedError = NormalizeAndValidateBlockDeprecated(req.BlockDeprecated, out string? blockDeprecated);
        if (blockDeprecatedError is not null)
        {
            return blockDeprecatedError;
        }

        var blockPolicyError = ValidateBlockPolicyFields(req,
            out string? blockMalicious, out string? blockKev, out string? blockInstallScripts,
            out string? blockRevoked);
        if (blockPolicyError is not null)
        {
            return blockPolicyError;
        }

        string orgId = CurrentTenantId();

        var sigVerify = await ValidateSignatureVerificationFieldsAsync(req, orgId, ct);
        if (sigVerify.Error is not null)
        {
            return sigVerify.Error;
        }
        await _settings.UpsertProxySettingsAsync(
            orgId,
            new ProxyPolicySettings(
                req.ProxyPassthroughEnabled, req.MaxOsvScoreTolerance, req.MinReleaseAgeHours,
                blockDeprecated, blockMalicious, blockKev, req.MaxEpssTolerance, blockInstallScripts,
                sigVerify.VerifyNpmSignatures, sigVerify.VerifyNuGetSignatures, sigVerify.VerifyPyPiAttestations,
                sigVerify.VerifyRpmSignatures, sigVerify.VerifyMavenSignatures, blockRevoked,
                sigVerify.VerifyTerraformSignatures),
            ct);

        // The block/verify gates and thresholds just persisted can flip the advertised state of
        // every version across every package this org has published or proxied. There is no
        // enumerable list of affected cache keys to Evict one at a time (the way publish/unpublish
        // do), so instead bump the org's rendered-cache policy epoch: every npm packument, NuGet
        // registration, PyPI simple index, and Maven metadata document cached for this org expires
        // immediately rather than serving the pre-flip gate state until its TTL.
        _cacheEpoch.Invalidate(orgId);

        // Every leave-unchanged-on-absent field below (all but the six verify_* fields, which
        // sigVerify already normalizes the same way) is logged as the raw request value, so a
        // field the caller didn't address in this write is recorded as null here — chosen, not
        // leaked: "null = not addressed by this PUT" is the truthful reading of what was sent,
        // distinct from "null = turned off" (AuditProxySettingValue's "unchanged" sentinel makes
        // that distinction explicit for the two Optional<T> fields; the plain-nullable fields
        // below don't have a domain-null to collide with, so a bare null is unambiguous).
        await _audit.LogAsync("proxy_settings_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                proxy_passthrough_enabled = req.ProxyPassthroughEnabled,
                max_osv_score_tolerance = req.MaxOsvScoreTolerance,
                min_release_age_hours = AuditProxySettingValue(req.MinReleaseAgeHours),
                block_deprecated = blockDeprecated,
                block_revoked = blockRevoked,
                block_malicious = blockMalicious,
                block_kev = blockKev,
                max_epss_tolerance = AuditProxySettingValue(req.MaxEpssTolerance),
                block_install_scripts = blockInstallScripts,
                verify_npm_signatures = sigVerify.VerifyNpmSignatures,
                verify_nuget_signatures = sigVerify.VerifyNuGetSignatures,
                verify_pypi_attestations = sigVerify.VerifyPyPiAttestations,
                verify_rpm_signatures = sigVerify.VerifyRpmSignatures,
                verify_maven_signatures = sigVerify.VerifyMavenSignatures,
                verify_terraform_signatures = sigVerify.VerifyTerraformSignatures,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>
    /// PUT /api/v1/rpm-upstream-mode — sets the per-tenant RPM hosted-publishing posture override
    /// without touching any other setting. Accepts null to clear the override back to "inherit the
    /// instance Rpm:UpstreamMode env value", or an explicit 'passthrough' | 'merged' that overrides
    /// the env value in either direction — letting an operator enable (or disable) hosted RPM
    /// publishing for this org from the UI without an instance restart.
    /// </summary>
    [HttpPut("api/v1/rpm-upstream-mode")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateRpmUpstreamMode([FromBody] UpdateRpmUpstreamModeRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (req.Mode is not (null or "passthrough" or "merged"))
        {
            return _problems.ValidationErrorActionKey("rpm_upstream_mode", "error.settings.rpmUpstreamModeInvalid");
        }

        string orgId = CurrentTenantId();
        var prior = await _settings.GetSettingsAsync(orgId, ct);
        string? priorMode = prior?.RpmUpstreamMode;

        await _settings.UpsertRpmUpstreamModeAsync(orgId, req.Mode, ct);

        if (req.Mode != priorMode)
        {
            await EmitSettingChangeAsync(orgId, "rpm_upstream_mode", priorMode, req.Mode, ct);
        }

        return NoContent();
    }

    // Validates numeric range fields on the proxy settings request. Returns a validation error
    // result when any field is out of range, or null when all pass. MinReleaseAgeHours and
    // MaxEpssTolerance are Optional<T>: a field the caller didn't mention (IsPresent = false)
    // is not being changed, so it's exempt from range validation the same as an absent
    // block_kev is exempt from enum validation.
    private IActionResult? ValidateProxyNumericFields(UpdateProxySettingsRequest req)
        => req.MaxOsvScoreTolerance is < 0.0 or > MaxOsvScore
            ? _problems.ValidationErrorActionKey("max_osv_score_tolerance", "error.settings.osvScoreRange")
            : req.MinReleaseAgeHours.IsPresent && req.MinReleaseAgeHours.Value is { } age && (age < 0 || age > MaxReleaseAgeHours)
                ? _problems.ValidationErrorActionKey("min_release_age_hours", "error.settings.releaseAgeRange", MaxReleaseAgeHours)
                : req.MaxEpssTolerance.IsPresent && req.MaxEpssTolerance.Value is < 0.0 or > 1.0
                    ? _problems.ValidationErrorActionKey("max_epss_tolerance", "error.settings.epssRange")
                    : null;

    // Projects an Optional<T> proxy-settings field for the audit-log detail blob: "unchanged"
    // when the caller didn't mention the field, otherwise the value that was written (which may
    // itself be null — an explicit clear-to-off is a real, auditable state change).
    private static object? AuditProxySettingValue<T>(Optional<T> field) =>
        field.IsPresent ? field.Value : "unchanged";

    // Normalizes the block_deprecated field (maps retired 'block' alias to 'block_all') and
    // validates the final value. An omitted field means "leave the stored value unchanged" — it
    // is not validated and flows through as null (matching air_gapped / require_mfa / verify_*).
    // Returns a validation error when a present value is invalid, or null otherwise.
    private IActionResult? NormalizeAndValidateBlockDeprecated(string? raw, out string? normalized)
    {
        if (raw is null)
        {
            normalized = null;
            return null;
        }

        // Normalize the retired 'block' value (deny-everything) to its successor 'block_all' so
        // existing automation keeps working after the new/all split.
        normalized = raw == "block" ? "block_all" : raw;

        return normalized is not ("off" or "warn" or "block_new" or "block_all")
            ? _problems.ValidationErrorActionKey("block_deprecated", "error.settings.deprecatedPolicyInvalid")
            : null;
    }

    // Validates the block-policy enum fields (malicious, KEV, install-scripts, revoked). An
    // omitted field means "leave the stored value unchanged" — a client still sending the
    // pre-gate payload shape (or a partial PUT touching an unrelated field) must not silently
    // reset an enforcing gate to its default. Returns a validation error on the first invalid
    // (present-but-out-of-range) field, or null when all pass. Writes the normalized values
    // (null = unchanged) into the out parameters.
    private IActionResult? ValidateBlockPolicyFields(
        UpdateProxySettingsRequest req,
        out string? blockMalicious, out string? blockKev, out string? blockInstallScripts,
        out string? blockRevoked)
    {
        blockMalicious = req.BlockMalicious;
        blockKev = req.BlockKev;
        blockInstallScripts = req.BlockInstallScripts;
        blockRevoked = req.BlockRevoked;

        if (blockMalicious is not (null or "off" or "warn" or "block"))
        {
            return _problems.ValidationErrorActionKey("block_malicious", "error.settings.offWarnBlock");
        }

        if (blockKev is not (null or "off" or "warn" or "block"))
        {
            return _problems.ValidationErrorActionKey("block_kev", "error.settings.offWarnBlock");
        }

        if (blockInstallScripts is not (null or "off" or "warn" or "block"))
        {
            return _problems.ValidationErrorActionKey("block_install_scripts", "error.settings.offWarnBlock");
        }

        // Three values (no block_new analog — revocation is always a full upstream removal).
        return blockRevoked is not (null or "off" or "warn" or "block")
            ? _problems.ValidationErrorActionKey("block_revoked", "error.settings.offWarnBlock")
            : null;
    }

    // Validates all six per-ecosystem signature verification fields. Returns a SigVerifyResult
    // whose Error is non-null on the first invalid or unconfigured field, or null when all pass.
    // The normalized field values are always present in the result regardless of error state.
    private async Task<SigVerifyResult> ValidateSignatureVerificationFieldsAsync(
        UpdateProxySettingsRequest req,
        string orgId,
        CancellationToken ct)
    {
        // An absent verification field means "leave as stored", not "off" — same posture as the
        // block-policy fields above. These six are security controls whose stored value may
        // already be 'block'; defaulting an omitted field to 'off' would let a client sending a
        // payload shape that predates them silently disable signature and attestation
        // verification tenant-wide. Null flows through to the repository, which COALESCEs it
        // against the stored column (falling back to 'off' on first insert).
        string? verifyNpmSignatures = req.VerifyNpmSignatures;
        string? verifyNuGetSignatures = req.VerifyNuGetSignatures;
        string? verifyPyPiAttestations = req.VerifyPyPiAttestations;
        string? verifyRpmSignatures = req.VerifyRpmSignatures;
        string? verifyMavenSignatures = req.VerifyMavenSignatures;
        string? verifyTerraformSignatures = req.VerifyTerraformSignatures;

        bool npmConfigured = await _npmProvenance.IsConfiguredForAsync(orgId, ct);
        bool nugetConfigured = await _nugetProvenance.IsConfiguredForAsync(orgId, ct);
        bool pypiConfigured = await _pypiProvenance.IsConfiguredForAsync(orgId, ct);
        bool rpmConfigured = await _rpmProvenance.IsConfiguredForAsync(orgId, ct);
        bool mavenConfigured = await _mavenProvenance.IsConfiguredForAsync(orgId, ct);
        bool terraformConfigured = await _terraformProvenance.IsConfiguredForAsync(orgId, ct);

        var error = ValidateOneSigVerifyField(verifyNpmSignatures, "verify_npm_signatures",
                        npmConfigured,
                        "Cannot enable npm signature verification: no trust anchors are configured. "
                        + "Add an npm SPKI trust anchor for this org first.")
                    ?? ValidateOneSigVerifyField(verifyNuGetSignatures, "verify_nuget_signatures",
                        nugetConfigured,
                        "Cannot enable NuGet signature verification: no trust anchors are configured. "
                        + "Add a NuGet X.509 trust anchor for this org first.")
                    ?? ValidateOneSigVerifyField(verifyPyPiAttestations, "verify_pypi_attestations",
                        pypiConfigured,
                        "Cannot enable PyPI attestation verification: no trust anchors are configured for "
                        + "this org. Add a sigstore_root and a trusted_publisher anchor first.")
                    ?? ValidateOneSigVerifyField(verifyRpmSignatures, "verify_rpm_signatures",
                        rpmConfigured,
                        "Cannot enable RPM signature verification: no trust anchor is configured. "
                        + "Add an RPM GPG trust anchor for this org first.")
                    ?? ValidateOneSigVerifyField(verifyMavenSignatures, "verify_maven_signatures",
                        mavenConfigured,
                        "Cannot enable Maven signature verification: no trust anchors are configured. "
                        + "Add a Maven PGP trust anchor for this org first.")
                    ?? ValidateOneSigVerifyField(verifyTerraformSignatures, "verify_terraform_signatures",
                        terraformConfigured,
                        "Cannot enable Terraform signature verification: no trust anchors are configured. "
                        + "Add a Terraform PGP trust anchor for this org first.");

        return new SigVerifyResult(
            error, verifyNpmSignatures, verifyNuGetSignatures,
            verifyPyPiAttestations, verifyRpmSignatures, verifyMavenSignatures, verifyTerraformSignatures);
    }

    // Return type for ValidateSignatureVerificationFieldsAsync. Bundles the validation error
    // (null = pass) together with the normalized field values so the method can be async.
    // A null field value means the caller omitted it and the stored value is preserved.
    private sealed record SigVerifyResult(
        IActionResult? Error,
        string? VerifyNpmSignatures,
        string? VerifyNuGetSignatures,
        string? VerifyPyPiAttestations,
        string? VerifyRpmSignatures,
        string? VerifyMavenSignatures,
        string? VerifyTerraformSignatures);

    // Validates one sig-verify field: rejects values outside the allowed enum and, when
    // the value is non-off, rejects if the operator trust anchor is not configured. An omitted
    // (null) field is not validated — nothing is being changed.
    private IActionResult? ValidateOneSigVerifyField(
        string? value, string field, bool isConfigured, string trustMsg)
    {
        if (value is null)
        {
            return null;
        }

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
