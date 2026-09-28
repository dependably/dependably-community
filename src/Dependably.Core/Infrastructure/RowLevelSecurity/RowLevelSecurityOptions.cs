using System.Text.RegularExpressions;

namespace Dependably.Infrastructure.RowLevelSecurity;

/// <summary>Whether Postgres row-level security backs the application-level tenant filter.</summary>
public enum RowLevelSecurityMode
{
    /// <summary>Every connection runs as the connecting (owner) role; the policies are not consulted.</summary>
    Off,

    /// <summary>
    /// Tenant connections switch to the non-owner RLS role and carry the tenant, so the policies
    /// installed by <see cref="PostgresRowLevelSecurityInstaller"/> refuse any row of another tenant.
    /// </summary>
    Enforce,
}

/// <summary>
/// Postgres row-level security settings, read from <c>DB_ROW_LEVEL_SECURITY</c>
/// (<c>off</c> | <c>enforce</c>) and <c>DB_ROW_LEVEL_SECURITY_ROLE</c> (the non-owner role tenant
/// connections switch to, default <c>dependably_rls</c>).
///
/// <para>Unset, the mode follows the deployment: <c>enforce</c> when Postgres serves more than one
/// tenant (<c>DEPLOYMENT_MODE</c> <c>multi</c> or <c>header</c>), where a forgotten tenant filter is
/// a cross-tenant leak, and <c>off</c> otherwise. An explicit <c>off</c> on such a deployment is
/// honoured and reported by <see cref="DisabledOnMultiTenantPostgres"/>, which startup logs as a
/// warning. An unrecognised mode fails startup rather than falling back to either: an operator who
/// mistypes the value must not run believing the backstop is on.</para>
///
/// <para>The default never makes a deployment unbootable: a defaulted <c>enforce</c> whose database
/// cannot support it (no <c>CREATEROLE</c>, Postgres older than 15, a multiplexed connection) falls
/// back to <c>off</c> with a startup warning, leaving the application's <c>org_id</c> filter as the
/// isolation layer it always was. Only an explicit <c>enforce</c> fails closed —
/// <see cref="Explicit"/> tells the two apart.</para>
/// </summary>
public sealed partial record RowLevelSecurityOptions(RowLevelSecurityMode Mode, string RoleName)
{
    public const string ModeKey = "DB_ROW_LEVEL_SECURITY";
    public const string RoleKey = "DB_ROW_LEVEL_SECURITY_ROLE";
    public const string DefaultRoleName = "dependably_rls";

    public static RowLevelSecurityOptions Disabled { get; } = new(RowLevelSecurityMode.Off, DefaultRoleName);

    public bool Enforced => Mode == RowLevelSecurityMode.Enforce;

    /// <summary>True when an operator turned the backstop off on a deployment that defaults it on.</summary>
    public bool DisabledOnMultiTenantPostgres { get; init; }

    /// <summary>
    /// True when <c>DB_ROW_LEVEL_SECURITY</c> was set rather than defaulted. An explicit
    /// <c>enforce</c> refuses to boot without the backstop; a defaulted one falls back to off.
    /// </summary>
    public bool Explicit { get; init; }

    public static RowLevelSecurityOptions FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        bool multiTenantPostgres = IsMultiTenantPostgres(configuration);
        string rawMode = (configuration[ModeKey] ?? "").Trim();
        var mode = rawMode.ToLowerInvariant() switch
        {
            "" => multiTenantPostgres ? RowLevelSecurityMode.Enforce : RowLevelSecurityMode.Off,
            "off" => RowLevelSecurityMode.Off,
            "enforce" => RowLevelSecurityMode.Enforce,
            _ => throw new InvalidOperationException(
                $"{ModeKey} must be 'off' or 'enforce' (got '{rawMode}')."),
        };

        string role = (configuration[RoleKey] ?? "").Trim();
        if (role.Length == 0)
        {
            role = DefaultRoleName;
        }

        return RoleNameRegex().IsMatch(role)
            ? new RowLevelSecurityOptions(mode, role)
            {
                DisabledOnMultiTenantPostgres = multiTenantPostgres && mode == RowLevelSecurityMode.Off,
                Explicit = rawMode.Length > 0,
            }
            : throw new InvalidOperationException(
                $"{RoleKey} must be a lower-case Postgres identifier of at most 63 characters (got '{role}').");
    }

    private static bool IsMultiTenantPostgres(IConfiguration configuration) =>
        DbProviderSetting.FromConfiguration(configuration) == DbProvider.Postgres
        && (configuration["DEPLOYMENT_MODE"] ?? "").Trim().ToLowerInvariant() is "multi" or "header";

    [GeneratedRegex(@"\A[a-z_][a-z0-9_]{0,62}\z")]
    private static partial Regex RoleNameRegex();
}
