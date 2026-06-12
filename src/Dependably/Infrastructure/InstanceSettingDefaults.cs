namespace Dependably.Infrastructure;

/// <summary>
/// Default values for the instance-wide settings surfaced on the system_admin
/// <c>/settings</c> page. Seeded into <c>instance_settings</c> at first boot
/// when the matching env var is absent, and mirrored in the Svelte UI so the
/// placeholder/caption shows the same number an operator sees in the DB.
/// </summary>
public static class InstanceSettingDefaults
{
    public const string MaxUploadBytes = "524288000";        // 500 MB
    public const string MaxUploadBytesPyPi = "104857600";    // 100 MB — matches pypi.org
    public const string MaxUploadBytesNpm = "52428800";      //  50 MB
    public const string MaxUploadBytesNuGet = "262144000";   // 250 MB — matches nuget.org
    public const string GcSchedule = "0 3 * * *";            // 03:00 UTC daily
    public const string SiemMaxLookbackDays = "90";

    // No hard-coded default for storage quota: unset instance_settings key = unlimited
    // (back-compat with pre-existing single-tenant installs).
    // Operators set DEFAULT_STORAGE_QUOTA_BYTES to impose a floor across all tenants.
    public const string DefaultStorageQuotaBytes = "";       // empty = unlimited

    // 1 000 tokens per tenant — generous enough not to affect normal use while bounding
    // the DB surface area for pooled multi-tenant deployments.
    public const string MaxActiveTokensPerTenant = "1000";
}
