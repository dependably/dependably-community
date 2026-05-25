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

    public OrgSettingsRepository(IMetadataStore db) => _db = db;

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
                   keep_versions as KeepVersions, keep_days as KeepDays,
                   activity_retention_days as ActivityRetentionDays,
                   COALESCE(license_enforcement_mode, 'off') as LicenseEnforcementMode,
                   COALESCE(proxy_passthrough_enabled, 1) as ProxyPassthroughEnabled,
                   COALESCE(max_osv_score_tolerance, 10.0) as MaxOsvScoreTolerance,
                   min_release_age_hours as MinReleaseAgeHours,
                   COALESCE(default_language, 'en') as DefaultLanguage,
                   COALESCE(allow_version_overwrite, 0) as AllowVersionOverwrite
            FROM org_settings WHERE org_id = @orgId
            """,
            new { orgId });
    }

    public async Task UpsertSettingsAsync(OrgSettingsUpdate update, CancellationToken ct = default)
    {
        static long? Clamp(long? orgVal, long? instanceMax)
        {
            if (orgVal is null) return null;
            if (instanceMax is null) return orgVal;
            return Math.Min(orgVal.Value, instanceMax.Value);
        }

        await using var conn = await _db.OpenAsync(ct);
        var lang = string.IsNullOrWhiteSpace(update.DefaultLanguage) ? null : update.DefaultLanguage;
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode,
                max_upload_bytes, max_upload_bytes_pypi, max_upload_bytes_npm, max_upload_bytes_nuget,
                default_language, allow_version_overwrite)
            VALUES (@orgId, @anonPull, @allowlist, @maxBytes, @maxBytesPyPi, @maxBytesNpm, @maxBytesNuGet,
                COALESCE(@lang, 'en'), COALESCE(@overwrite, 0))
            ON CONFLICT(org_id) DO UPDATE SET
                anonymous_pull      = @anonPull,
                allowlist_mode      = @allowlist,
                max_upload_bytes    = @maxBytes,
                max_upload_bytes_pypi  = @maxBytesPyPi,
                max_upload_bytes_npm   = @maxBytesNpm,
                max_upload_bytes_nuget = @maxBytesNuGet,
                default_language    = COALESCE(@lang, default_language),
                allow_version_overwrite = COALESCE(@overwrite, allow_version_overwrite)
            """,
            new
            {
                orgId         = update.OrgId,
                anonPull      = update.AnonymousPull ? 1 : 0,
                allowlist     = update.AllowlistMode ? 1 : 0,
                maxBytes      = Clamp(update.MaxUploadBytes,      update.InstanceMaxUploadBytes),
                maxBytesPyPi  = Clamp(update.MaxUploadBytesPyPi,  update.InstanceMaxUploadBytes),
                maxBytesNpm   = Clamp(update.MaxUploadBytesNpm,   update.InstanceMaxUploadBytes),
                maxBytesNuGet = Clamp(update.MaxUploadBytesNuGet, update.InstanceMaxUploadBytes),
                lang,
                overwrite     = ToOverwriteFlag(update.AllowVersionOverwrite),
            });
    }

    private static int? ToOverwriteFlag(bool? value)
    {
        if (value is null) return null;
        return value.Value ? 1 : 0;
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
    }

    public async Task UpsertProxySettingsAsync(
        string orgId, bool proxyPassthroughEnabled, double maxOsvScoreTolerance,
        int? minReleaseAgeHours, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, proxy_passthrough_enabled, max_osv_score_tolerance, min_release_age_hours)
            VALUES (@orgId, @proxyEnabled, @maxScore, @minAgeHours)
            ON CONFLICT(org_id) DO UPDATE SET
                proxy_passthrough_enabled = @proxyEnabled,
                max_osv_score_tolerance   = @maxScore,
                min_release_age_hours     = @minAgeHours
            """,
            new
            {
                orgId,
                proxyEnabled = proxyPassthroughEnabled ? 1 : 0,
                maxScore = maxOsvScoreTolerance,
                minAgeHours = minReleaseAgeHours,
            });
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
