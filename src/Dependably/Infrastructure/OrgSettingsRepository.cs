using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-tenant configuration store. Separated from <see cref="OrgRepository"/> (which owns
/// the org entity lifecycle: list / soft-delete / restore / membership) so the two concerns
/// can evolve independently — settings change frequently, the entity rarely.
///
/// Also owns <c>instance_settings</c> reads and writes: those rows are tenancy-independent
/// but conceptually configuration, so they sit alongside the per-tenant settings rather
/// than alongside the org entity. Note: <c>jwt_secret</c> is intentionally excluded from
/// <see cref="ListInstanceSettingsAsync"/> — read it only through the dedicated path.
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
            """
            SELECT org_id as OrgId, anonymous_pull as AnonymousPull, allowlist_mode as AllowlistMode,
                   max_upload_bytes as MaxUploadBytes,
                   max_upload_bytes_pypi as MaxUploadBytesPyPi,
                   max_upload_bytes_npm as MaxUploadBytesNpm,
                   max_upload_bytes_nuget as MaxUploadBytesNuGet,
                   max_upload_bytes_maven as MaxUploadBytesMaven,
                   max_upload_bytes_rpm as MaxUploadBytesRpm,
                   max_upload_bytes_oci as MaxUploadBytesOci,
                   max_upload_bytes_cargo as MaxUploadBytesCargo,
                   keep_versions as KeepVersions, keep_days as KeepDays,
                   activity_retention_days as ActivityRetentionDays,
                   COALESCE(license_enforcement_mode, 'off') as LicenseEnforcementMode,
                   COALESCE(proxy_passthrough_enabled, 1) as ProxyPassthroughEnabled,
                   COALESCE(max_osv_score_tolerance, 10.0) as MaxOsvScoreTolerance,
                   min_release_age_hours as MinReleaseAgeHours,
                   COALESCE(default_language, 'en') as DefaultLanguage,
                   COALESCE(allow_version_overwrite, 0) as AllowVersionOverwrite,
                   COALESCE(air_gapped, 0) as AirGapped,
                   COALESCE(block_deprecated, 'off') as BlockDeprecated,
                   COALESCE(block_malicious, 'block') as BlockMalicious,
                   COALESCE(block_kev, 'off') as BlockKev,
                   max_epss_tolerance as MaxEpssTolerance,
                   COALESCE(storage_used_bytes, 0) as StorageUsedBytes
            FROM org_settings WHERE org_id = @orgId
            """,
            new { orgId });
    }

    public async Task UpsertSettingsAsync(OrgSettingsUpdate update, CancellationToken ct = default)
    {
        static long? Clamp(long? orgVal, long? instanceMax)
        {
            return orgVal is null ? null : instanceMax is null ? orgVal : Math.Min(orgVal.Value, instanceMax.Value);
        }

        await using var conn = await _db.OpenAsync(ct);
        string? lang = string.IsNullOrWhiteSpace(update.DefaultLanguage) ? null : update.DefaultLanguage;
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode,
                max_upload_bytes, max_upload_bytes_pypi, max_upload_bytes_npm, max_upload_bytes_nuget,
                max_upload_bytes_maven, max_upload_bytes_rpm, max_upload_bytes_oci, max_upload_bytes_cargo,
                default_language, allow_version_overwrite, air_gapped)
            VALUES (@orgId, @anonPull, @allowlist, @maxBytes, @maxBytesPyPi, @maxBytesNpm, @maxBytesNuGet,
                @maxBytesMaven, @maxBytesRpm, @maxBytesOci, @maxBytesCargo,
                COALESCE(@lang, 'en'), COALESCE(@overwrite, 0), COALESCE(@airGapped, 0))
            ON CONFLICT(org_id) DO UPDATE SET
                anonymous_pull      = @anonPull,
                allowlist_mode      = @allowlist,
                max_upload_bytes    = @maxBytes,
                max_upload_bytes_pypi  = @maxBytesPyPi,
                max_upload_bytes_npm   = @maxBytesNpm,
                max_upload_bytes_nuget = @maxBytesNuGet,
                max_upload_bytes_maven = @maxBytesMaven,
                max_upload_bytes_rpm   = @maxBytesRpm,
                max_upload_bytes_oci   = @maxBytesOci,
                max_upload_bytes_cargo = @maxBytesCargo,
                default_language    = COALESCE(@lang, default_language),
                allow_version_overwrite = COALESCE(@overwrite, allow_version_overwrite),
                air_gapped          = COALESCE(@airGapped, air_gapped)
            """,
            new
            {
                orgId = update.OrgId,
                anonPull = update.AnonymousPull ? 1 : 0,
                allowlist = update.AllowlistMode ? 1 : 0,
                maxBytes = Clamp(update.MaxUploadBytes, update.InstanceMaxUploadBytes),
                maxBytesPyPi = Clamp(update.MaxUploadBytesPyPi, update.InstanceMaxUploadBytes),
                maxBytesNpm = Clamp(update.MaxUploadBytesNpm, update.InstanceMaxUploadBytes),
                maxBytesNuGet = Clamp(update.MaxUploadBytesNuGet, update.InstanceMaxUploadBytes),
                maxBytesMaven = Clamp(update.MaxUploadBytesMaven, update.InstanceMaxUploadBytes),
                maxBytesRpm = Clamp(update.MaxUploadBytesRpm, update.InstanceMaxUploadBytes),
                maxBytesOci = Clamp(update.MaxUploadBytesOci, update.InstanceMaxUploadBytes),
                maxBytesCargo = Clamp(update.MaxUploadBytesCargo, update.InstanceMaxUploadBytes),
                lang,
                overwrite = ToBoolFlag(update.AllowVersionOverwrite),
                airGapped = ToBoolFlag(update.AirGapped),
            });

        _orgs?.InvalidateSettingsCache(update.OrgId);
    }

    private static int? ToBoolFlag(bool? value)
    {
        return value is null ? null : value.Value ? 1 : 0;
    }

    public async Task UpsertRetentionAsync(
        string orgId, int? keepVersions, int? keepDays, int? activityRetentionDays,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, keep_versions, keep_days, activity_retention_days)
            VALUES (@orgId, @keepVersions, @keepDays, @activityDays)
            ON CONFLICT(org_id) DO UPDATE SET
                keep_versions           = @keepVersions,
                keep_days               = @keepDays,
                activity_retention_days = @activityDays
            """,
            new { orgId, keepVersions, keepDays, activityDays = activityRetentionDays });
        _orgs?.InvalidateSettingsCache(orgId);
    }

    public async Task UpsertProxySettingsAsync(
        string orgId, ProxyPolicySettings policy,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, proxy_passthrough_enabled, max_osv_score_tolerance, min_release_age_hours, block_deprecated, block_malicious, block_kev, max_epss_tolerance)
            VALUES (@orgId, @proxyEnabled, @maxScore, @minAgeHours, @blockDeprecated, @blockMalicious, @blockKev, @maxEpss)
            ON CONFLICT(org_id) DO UPDATE SET
                proxy_passthrough_enabled = @proxyEnabled,
                max_osv_score_tolerance   = @maxScore,
                min_release_age_hours     = @minAgeHours,
                block_deprecated          = @blockDeprecated,
                block_malicious           = @blockMalicious,
                block_kev                 = @blockKev,
                max_epss_tolerance        = @maxEpss
            """,
            new
            {
                orgId,
                proxyEnabled = policy.ProxyPassthroughEnabled ? 1 : 0,
                maxScore = policy.MaxOsvScoreTolerance,
                minAgeHours = policy.MinReleaseAgeHours,
                blockDeprecated = policy.BlockDeprecated,
                blockMalicious = policy.BlockMalicious,
                blockKev = policy.BlockKev,
                maxEpss = policy.MaxEpssTolerance,
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

    public async Task<string?> GetInstanceSettingAsync(string key, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key });
    }

    public async Task<IReadOnlyDictionary<string, string>> ListInstanceSettingsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Key, string Value)>(
            "SELECT key as Key, value as Value FROM instance_settings WHERE key != 'jwt_secret'");
        return rows.ToDictionary(r => r.Key, r => r.Value);
    }

    public async Task SetInstanceSettingAsync(string key, string value, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES (@key, @value) ON CONFLICT(key) DO UPDATE SET value = @value",
            new { key, value });
    }
}

/// <summary>
/// Proxy and block-gate policy values written by <see cref="OrgSettingsRepository.UpsertProxySettingsAsync"/>.
/// Grouped as a record to keep the method within a sane parameter count.
/// </summary>
public sealed record ProxyPolicySettings(
    bool ProxyPassthroughEnabled,
    double MaxOsvScoreTolerance,
    int? MinReleaseAgeHours = null,
    string BlockDeprecated = "off",
    string BlockMalicious = "block",
    string BlockKev = "off",
    double? MaxEpssTolerance = null);
