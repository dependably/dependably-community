using System.Text.Json;

namespace Dependably.Infrastructure.Audit.Events;

/// <summary>
/// Typed payloads for MFA lifecycle events. All records serialize via
/// <see cref="EventJsonOptions.Snake"/> so the audit_log.detail column is greppable.
/// </summary>
public static class MfaEvents
{
    public const string TypeEnrolled = "mfa.enrolled";
    public const string TypeDisabled = "mfa.disabled";
    public const string TypeRecoveryCodesRegenerated = "mfa.recovery_codes_regenerated";

    /// <summary>Reserved for use by the two-step login flow.</summary>
    public const string TypeRecoveryCodeUsed = "mfa.recovery_code_used";

    public sealed record Enrolled(int RecoveryCodesGenerated)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Disabled(string Method)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record RecoveryCodesRegenerated(int Count, string Method)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record RecoveryCodeUsed(int Remaining)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public const string TypeTrustedDeviceAdded = "mfa.trusted_device_added";
    public const string TypeTrustedDeviceUsed = "mfa.trusted_device_used";

    public sealed record TrustedDeviceAdded(string Realm)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record TrustedDeviceUsed(string Realm)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }
}
