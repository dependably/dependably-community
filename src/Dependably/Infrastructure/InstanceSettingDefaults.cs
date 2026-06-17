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

    // 100 pending invites per tenant — bounds the invites table against admin-initiated
    // flooding while allowing large onboarding batches.
    public const string MaxPendingInvitesPerTenant = "100";

    // 32 concurrent OCI upload sessions per tenant — bounds staging-volume exposure from
    // abandoned docker-push sessions while allowing large parallel layer pushes. Each session
    // holds an open staging file on the shared PROXY_STAGING_PATH volume, so the cap limits
    // the worst-case staging footprint per tenant.
    public const string MaxConcurrentOciUploadsPerTenant = "32";

    /// <summary>
    /// Canonical set of instance-setting keys an operator may write through the management API.
    /// Both the multi-mode system surface (<c>/api/v1/system/settings</c>) and the single-mode
    /// instance surface (<c>/api/v1/instance/settings</c>) validate against this one set so the
    /// two surfaces never drift. The per-ecosystem upload caps (maven/rpm/oci) are honoured by
    /// <c>OrgRepository.GetUploadLimitAsync</c> regardless of deployment mode, so they belong here
    /// even though they have no hard-coded default above.
    /// </summary>
    public static readonly IReadOnlySet<string> AllowedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "max_upload_bytes",
        "max_upload_bytes_pypi",
        "max_upload_bytes_npm",
        "max_upload_bytes_nuget",
        "max_upload_bytes_maven",
        "max_upload_bytes_rpm",
        "max_upload_bytes_oci",
        "gc_schedule",
        "siem_max_lookback_days",
        "default_storage_quota_bytes",
        "max_active_tokens_per_tenant",
        "max_pending_invites_per_tenant",
        "max_concurrent_oci_uploads_per_tenant",
    };
}
