namespace Dependably.Infrastructure;

/// <summary>
/// Reports whether the deployment requires MFA enrollment for all users. When true, every
/// authenticated user in every tenant must enroll in MFA before accessing any API endpoint,
/// enforced by <see cref="Dependably.Security.MfaEnrollmentGuard"/>.
///
/// Configured via the <c>REQUIRE_MFA</c> environment variable. Read once at startup; the
/// setting does not change at runtime.
///
/// Composes with the per-tenant <c>org_settings.require_mfa</c> column: the effective
/// requirement is instance OR tenant (either signal triggers enforcement).
/// </summary>
public interface IRequireMfaMode
{
    bool IsEnabled { get; }
}

/// <summary>
/// Reads <c>REQUIRE_MFA</c> from configuration at startup. Accepts <c>true</c> or <c>1</c>
/// (case-insensitive). Any other value (including absent) leaves the instance-level override off.
/// </summary>
public sealed class RequireMfaMode : IRequireMfaMode
{
    public bool IsEnabled { get; }

    public RequireMfaMode(IConfiguration config)
    {
        string? raw = config["REQUIRE_MFA"];
        IsEnabled = string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase);
    }
}
