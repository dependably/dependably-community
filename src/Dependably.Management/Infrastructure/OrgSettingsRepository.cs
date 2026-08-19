using Dapper;
using Dependably.Api;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-tenant configuration store. Separated from <see cref="OrgRepository"/> (which owns
/// the org entity lifecycle: list / soft-delete / restore / membership, and also owns
/// <c>instance_settings</c> listing via <see cref="OrgRepository.ListInstanceSettingsAsync"/>)
/// so the two concerns can evolve independently — settings change frequently, the entity rarely.
/// </summary>
public sealed class OrgSettingsRepository
{
    private readonly IMetadataStore _db;
    // OrgRepository holds the hot-path memory cache for OrgSettings. When this
    // repository writes new settings we have to evict the cached entry too — otherwise
    // controllers reading via OrgRepository.GetSettingsAsync would serve a stale value
    // until the TTL elapses, which is exactly what an admin updating the policy doesn't
    // want.
    private readonly OrgRepository? _orgs;

    public OrgSettingsRepository(IMetadataStore db, OrgRepository? orgs = null)
    {
        _db = db;
        _orgs = orgs;
    }

    public async Task<OrgSettings?> GetSettingsAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<OrgSettings>(
            OrgRepository.OrgSettingsSelect,
            new { orgId });
    }

    public async Task UpsertSettingsAsync(OrgSettingsUpdate update, CancellationToken ct = default)
    {
        static long? Clamp(long? orgVal, long? instanceMax)
        {
            return orgVal is null ? null : instanceMax is null ? orgVal : Math.Min(orgVal.Value, instanceMax.Value);
        }

        await using var conn = await _db.OpenAsync(ct);
        // anonymous_pull and allowlist_mode are COALESCEd like every other gate on this row: an
        // absent field leaves the stored value alone, and on first insert falls back to the
        // schema default (0) rather than to a CLR default that may not match it. The upload-cap
        // columns below are deliberately NOT COALESCEd — null is their own domain value ("no
        // org-level cap, fall back to the instance limit"), so a caller clearing a cap has to be
        // able to send it. The consequence, stated plainly rather than assumed away: an omitted
        // cap clears it, so a partial write must carry the caps it wants kept. Distinguishing
        // absent from explicitly-null for those columns needs the tri-state Optional<T> carrier
        // the proxy-settings surface uses, which lives in the management assembly and so cannot
        // appear on this record.
        string? lang = string.IsNullOrWhiteSpace(update.DefaultLanguage) ? null : update.DefaultLanguage;
        string? timezone = string.IsNullOrWhiteSpace(update.DefaultTimezone) ? null : update.DefaultTimezone;
        // Resolve the effective legacy boolean and policy from whichever field the caller set.
        // If VersionOverwritePolicy is supplied it is authoritative; allow_version_overwrite
        // is derived from it for blue-green compatibility. If only AllowVersionOverwrite is
        // supplied (legacy callers) we preserve the legacy bool directly and leave the policy
        // unchanged (null → COALESCE falls through to the current row value).
        int? legacyOverwrite = update.VersionOverwritePolicy is not null
            ? (update.VersionOverwritePolicy == "allow" ? 1 : 0)
            : ToBoolFlag(update.AllowVersionOverwrite);
        string? policy = update.VersionOverwritePolicy;

        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode,
                max_upload_bytes, max_upload_bytes_pypi, max_upload_bytes_npm, max_upload_bytes_nuget,
                max_upload_bytes_maven, max_upload_bytes_rpm, max_upload_bytes_oci, max_upload_bytes_cargo,
                default_language, default_timezone, allow_version_overwrite, version_overwrite_policy,
                air_gapped, require_mfa, rpm_upstream_mode)
            VALUES (@orgId, COALESCE(@anonPull, 0), COALESCE(@allowlist, 0), @maxBytes, @maxBytesPyPi, @maxBytesNpm, @maxBytesNuGet,
                @maxBytesMaven, @maxBytesRpm, @maxBytesOci, @maxBytesCargo,
                COALESCE(@lang, 'en'), COALESCE(@timezone, 'UTC'), COALESCE(@legacyOverwrite, 0),
                COALESCE(@policy, 'block'), COALESCE(@airGapped, 0), COALESCE(@requireMfa, 0),
                COALESCE(@rpmUpstreamMode, 'passthrough'))
            ON CONFLICT(org_id) DO UPDATE SET
                anonymous_pull      = COALESCE(@anonPull, anonymous_pull),
                allowlist_mode      = COALESCE(@allowlist, allowlist_mode),
                max_upload_bytes    = @maxBytes,
                max_upload_bytes_pypi  = @maxBytesPyPi,
                max_upload_bytes_npm   = @maxBytesNpm,
                max_upload_bytes_nuget = @maxBytesNuGet,
                max_upload_bytes_maven = @maxBytesMaven,
                max_upload_bytes_rpm   = @maxBytesRpm,
                max_upload_bytes_oci   = @maxBytesOci,
                max_upload_bytes_cargo = @maxBytesCargo,
                default_language    = COALESCE(@lang, default_language),
                default_timezone    = COALESCE(@timezone, default_timezone),
                version_overwrite_policy = COALESCE(@policy, version_overwrite_policy),
                allow_version_overwrite  = CASE WHEN @legacyOverwrite IS NULL THEN allow_version_overwrite
                                                ELSE @legacyOverwrite END,
                air_gapped          = COALESCE(@airGapped, air_gapped),
                require_mfa         = COALESCE(@requireMfa, require_mfa),
                rpm_upstream_mode   = COALESCE(@rpmUpstreamMode, rpm_upstream_mode)
            """,
            new
            {
                orgId = update.OrgId,
                anonPull = ToBoolFlag(update.AnonymousPull),
                allowlist = ToBoolFlag(update.AllowlistMode),
                maxBytes = Clamp(update.MaxUploadBytes, update.InstanceMaxUploadBytes),
                maxBytesPyPi = Clamp(update.MaxUploadBytesPyPi, update.InstanceMaxUploadBytes),
                maxBytesNpm = Clamp(update.MaxUploadBytesNpm, update.InstanceMaxUploadBytes),
                maxBytesNuGet = Clamp(update.MaxUploadBytesNuGet, update.InstanceMaxUploadBytes),
                maxBytesMaven = Clamp(update.MaxUploadBytesMaven, update.InstanceMaxUploadBytes),
                maxBytesRpm = Clamp(update.MaxUploadBytesRpm, update.InstanceMaxUploadBytes),
                maxBytesOci = Clamp(update.MaxUploadBytesOci, update.InstanceMaxUploadBytes),
                maxBytesCargo = Clamp(update.MaxUploadBytesCargo, update.InstanceMaxUploadBytes),
                lang,
                timezone,
                legacyOverwrite,
                policy,
                airGapped = ToBoolFlag(update.AirGapped),
                requireMfa = ToBoolFlag(update.RequireMfa),
                rpmUpstreamMode = update.RpmUpstreamMode,
            });

        _orgs?.InvalidateSettingsCache(update.OrgId);
    }

    private static int? ToBoolFlag(bool? value)
    {
        return value is null ? null : value.Value ? 1 : 0;
    }

    /// <summary>
    /// Leave-unchanged-on-absent for all four retention dimensions. Each is
    /// <see cref="Optional{T}"/> rather than a plain nullable because null is a real value here
    /// ("unlimited"/"off"), so an omitted field and an explicit clear are different intents that
    /// a plain nullable cannot tell apart. A parameterized <c>CASE WHEN @xSet = 1</c> picks the
    /// branch — <c>COALESCE</c> cannot, since it would read a deliberate clear-to-unlimited as
    /// "absent" and keep the old limit forever.
    ///
    /// The INSERT arm binds the value directly: a first-ever write for an org has no prior row to
    /// preserve, so an absent field correctly lands the column default (SQL NULL for three of the
    /// four; 90 for activity_retention_days, which is bounded by default on purpose).
    /// </summary>
    public async Task UpsertRetentionAsync(
        string orgId, Optional<int?> keepVersions, Optional<int?> keepDays,
        Optional<int?> activityRetentionDays, Optional<int?> purgeUnlistedAfterDays,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, keep_versions, keep_days, activity_retention_days, purge_unlisted_after_days)
            VALUES (@orgId, @keepVersions, @keepDays, @activityDays, @purgeUnlistedAfterDays)
            ON CONFLICT(org_id) DO UPDATE SET
                keep_versions             = CASE WHEN @keepVersionsSet = 1 THEN @keepVersions ELSE keep_versions END,
                keep_days                 = CASE WHEN @keepDaysSet = 1 THEN @keepDays ELSE keep_days END,
                activity_retention_days   = CASE WHEN @activityDaysSet = 1 THEN @activityDays ELSE activity_retention_days END,
                purge_unlisted_after_days = CASE WHEN @purgeUnlistedAfterDaysSet = 1 THEN @purgeUnlistedAfterDays ELSE purge_unlisted_after_days END
            """,
            new
            {
                orgId,
                keepVersions = keepVersions.IsPresent ? keepVersions.Value : null,
                keepVersionsSet = keepVersions.IsPresent ? 1 : 0,
                keepDays = keepDays.IsPresent ? keepDays.Value : null,
                keepDaysSet = keepDays.IsPresent ? 1 : 0,
                activityDays = activityRetentionDays.IsPresent ? activityRetentionDays.Value : null,
                activityDaysSet = activityRetentionDays.IsPresent ? 1 : 0,
                purgeUnlistedAfterDays = purgeUnlistedAfterDays.IsPresent ? purgeUnlistedAfterDays.Value : null,
                purgeUnlistedAfterDaysSet = purgeUnlistedAfterDays.IsPresent ? 1 : 0,
            });
        _orgs?.InvalidateSettingsCache(orgId);
    }

    public async Task UpsertProxySettingsAsync(
        string orgId, ProxyPolicySettings policy,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // MinReleaseAgeHours/MaxEpssTolerance can't use COALESCE(@x, column) like every other
        // field here: COALESCE only has one NULL to work with, and for these two columns NULL is
        // both "absent" and the legitimate "gate disabled" value. A parameterized CASE WHEN keyed
        // on a companion @<field>Set flag keeps the three states (absent / explicit-null / value)
        // distinguishable — the flag picks the branch, @minAgeHours/@maxEpss carry the value (or
        // NULL) untouched either way. On INSERT there's no prior row to preserve, so both "absent"
        // and "explicit null" collapse to the same NULL — no CASE needed there.
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (
                org_id, proxy_passthrough_enabled, max_osv_score_tolerance, min_release_age_hours,
                block_deprecated, block_malicious, block_kev, max_epss_tolerance,
                block_install_scripts, verify_npm_signatures, verify_nuget_signatures,
                verify_pypi_attestations, verify_rpm_signatures, verify_maven_signatures,
                verify_terraform_signatures, block_revoked)
            VALUES (
                @orgId, COALESCE(@proxyEnabled, 1), COALESCE(@maxScore, 10.0), @minAgeHours,
                COALESCE(@blockDeprecated, 'off'), COALESCE(@blockMalicious, 'block'),
                COALESCE(@blockKev, 'off'), @maxEpss,
                COALESCE(@blockInstallScripts, 'off'),
                COALESCE(@verifyNpmSignatures, 'off'), COALESCE(@verifyNuGetSignatures, 'off'),
                COALESCE(@verifyPyPiAttestations, 'off'), COALESCE(@verifyRpmSignatures, 'off'),
                COALESCE(@verifyMavenSignatures, 'off'), COALESCE(@verifyTerraformSignatures, 'off'),
                COALESCE(@blockRevoked, 'warn'))
            ON CONFLICT(org_id) DO UPDATE SET
                proxy_passthrough_enabled = COALESCE(@proxyEnabled, proxy_passthrough_enabled),
                max_osv_score_tolerance   = COALESCE(@maxScore, max_osv_score_tolerance),
                min_release_age_hours     = CASE WHEN @minAgeHoursSet = 1 THEN @minAgeHours ELSE min_release_age_hours END,
                block_deprecated          = COALESCE(@blockDeprecated, block_deprecated),
                block_revoked             = COALESCE(@blockRevoked, block_revoked),
                block_malicious           = COALESCE(@blockMalicious, block_malicious),
                block_kev                 = COALESCE(@blockKev, block_kev),
                max_epss_tolerance        = CASE WHEN @maxEpssSet = 1 THEN @maxEpss ELSE max_epss_tolerance END,
                block_install_scripts     = COALESCE(@blockInstallScripts, block_install_scripts),
                verify_npm_signatures     = COALESCE(@verifyNpmSignatures, verify_npm_signatures),
                verify_nuget_signatures   = COALESCE(@verifyNuGetSignatures, verify_nuget_signatures),
                verify_pypi_attestations  = COALESCE(@verifyPyPiAttestations, verify_pypi_attestations),
                verify_rpm_signatures     = COALESCE(@verifyRpmSignatures, verify_rpm_signatures),
                verify_maven_signatures   = COALESCE(@verifyMavenSignatures, verify_maven_signatures),
                verify_terraform_signatures = COALESCE(@verifyTerraformSignatures, verify_terraform_signatures)
            """,
            new
            {
                orgId,
                proxyEnabled = policy.ProxyPassthroughEnabled is null ? (int?)null : policy.ProxyPassthroughEnabled.Value ? 1 : 0,
                maxScore = policy.MaxOsvScoreTolerance,
                minAgeHours = policy.MinReleaseAgeHours.IsPresent ? policy.MinReleaseAgeHours.Value : null,
                minAgeHoursSet = policy.MinReleaseAgeHours.IsPresent ? 1 : 0,
                blockDeprecated = policy.BlockDeprecated,
                blockRevoked = policy.BlockRevoked,
                blockMalicious = policy.BlockMalicious,
                blockKev = policy.BlockKev,
                maxEpss = policy.MaxEpssTolerance.IsPresent ? policy.MaxEpssTolerance.Value : null,
                maxEpssSet = policy.MaxEpssTolerance.IsPresent ? 1 : 0,
                blockInstallScripts = policy.BlockInstallScripts,
                verifyNpmSignatures = policy.VerifyNpmSignatures,
                verifyNuGetSignatures = policy.VerifyNuGetSignatures,
                verifyPyPiAttestations = policy.VerifyPyPiAttestations,
                verifyRpmSignatures = policy.VerifyRpmSignatures,
                verifyMavenSignatures = policy.VerifyMavenSignatures,
                verifyTerraformSignatures = policy.VerifyTerraformSignatures,
            });
        _orgs?.InvalidateSettingsCache(orgId);
    }

    public async Task UpsertLicensePolicyModeAsync(
        string orgId, string mode, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, license_enforcement_mode)
            VALUES (@orgId, @mode)
            ON CONFLICT(org_id) DO UPDATE SET license_enforcement_mode = @mode
            """,
            new { orgId, mode });
        _orgs?.InvalidateSettingsCache(orgId);
    }

    /// <summary>
    /// Targeted single-column write for the RPM upstream mode override, used by the RPM upstream
    /// card so it never has to round-trip the whole settings blob. Every other column keeps its
    /// current value (INSERT applies the schema defaults for a first-time row). Unlike
    /// <see cref="UpsertSettingsAsync"/>'s COALESCE-preserve-on-null semantics, this always SETs
    /// the column verbatim — including to NULL — so an operator can explicitly clear the override
    /// back to "inherit the instance Rpm:UpstreamMode env value".
    /// </summary>
    public async Task UpsertRpmUpstreamModeAsync(
        string orgId, string? mode, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, rpm_upstream_mode)
            VALUES (@orgId, @mode)
            ON CONFLICT(org_id) DO UPDATE SET rpm_upstream_mode = @mode
            """,
            new { orgId, mode });
        _orgs?.InvalidateSettingsCache(orgId);
    }
}

/// <summary>
/// Proxy and block-gate policy values written by <see cref="OrgSettingsRepository.UpsertProxySettingsAsync"/>.
/// Grouped as a record to keep the method within a sane parameter count.
///
/// <c>ProxyPassthroughEnabled</c>, <c>MaxOsvScoreTolerance</c>, and the six <c>Block*</c> /
/// <c>Verify*</c> enum/flag gates are nullable and mean <em>leave unchanged</em> when null,
/// matching how <c>air_gapped</c> / <c>require_mfa</c> behave: a client PUTting a partial
/// payload — or one whose shape predates a given field — must not silently downgrade a stored
/// 'block' to 'off'. On a first insert (no stored row to preserve) null falls back to the
/// column default (documented per field below).
///
/// <c>MinReleaseAgeHours</c> and <c>MaxEpssTolerance</c> are <see cref="Optional{T}"/> instead
/// of a plain nullable: for every other field here, "off" is a distinct non-null value (the
/// string <c>"off"</c>, or the schema default), which leaves null free to mean "absent — leave
/// unchanged". For these two, the domain's own "gate disabled" state <em>is</em> SQL NULL, so a
/// plain nullable primitive cannot tell "the caller omitted this field" apart from "the caller
/// explicitly cleared this field back to disabled" — <see cref="Optional{T}.IsPresent"/> carries
/// that distinction instead, so the field stays genuinely tri-state: absent (leave unchanged),
/// present-and-null (clear the gate), present-with-a-value (set it).
/// </summary>
public sealed record ProxyPolicySettings(
    bool? ProxyPassthroughEnabled = null,
    double? MaxOsvScoreTolerance = null,
    Optional<int?> MinReleaseAgeHours = default,
    string? BlockDeprecated = null,
    string? BlockMalicious = null,
    string? BlockKev = null,
    Optional<double?> MaxEpssTolerance = default,
    string? BlockInstallScripts = null,
    string? VerifyNpmSignatures = null,
    string? VerifyNuGetSignatures = null,
    string? VerifyPyPiAttestations = null,
    string? VerifyRpmSignatures = null,
    string? VerifyMavenSignatures = null,
    string? BlockRevoked = null,
    string? VerifyTerraformSignatures = null);
