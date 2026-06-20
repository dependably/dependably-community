namespace Dependably.Infrastructure.Siem;

/// <summary>
/// Shared CEF (Common Event Format) helpers used by both the pull-API formatter
/// (<c>SiemController</c>) and the push forwarder (<c>SyslogSiemForwarder</c>).
/// All values are defined by the ArcSight CEF specification and must not be
/// changed without verifying downstream SIEM parser compatibility.
/// </summary>
internal static class CefFormat
{
    // CEF severity values per the ArcSight specification (0=Unknown, 1-3=Low,
    // 4-6=Medium, 7-8=High, 9-10=Very-High). Each auth event maps to the most
    // appropriate level.
    internal const int SeverityHigh = 7;
    internal const int SeverityMediumHigh = 6;
    internal const int SeverityMedium = 5;
    internal const int SeverityMediumLow = 4;
    internal const int SeverityLow = 3;

    /// <summary>
    /// Escapes a value for use in a CEF field per the CEF specification:
    /// backslash, pipe, equals, CR, and LF are all backslash-escaped.
    /// </summary>
    internal static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=").Replace("\n", "\\n").Replace("\r", "\\r");

    /// <summary>
    /// Maps a Dependably audit action string to a human-readable CEF event name.
    /// Unmapped actions fall through to the raw action string.
    /// </summary>
    internal static string FriendlyName(string action) => action switch
    {
        "login.success" => "Login Success",
        "login.failure" => "Login Failure",
        "lockout.triggered" => "Account Lockout",
        "token.created" => "Token Created",
        "token.revoked" => "Token Revoked",
        "rbac.role_changed" => "Role Changed",
        "rbac.member_added" => "Member Added",
        "rbac.member_removed" => "Member Removed",
        _ => action,
    };

    /// <summary>
    /// Maps a Dependably audit action string to a CEF severity integer.
    /// Unmapped actions default to <see cref="SeverityLow"/>.
    /// </summary>
    internal static int Severity(string action) => action switch
    {
        "lockout.triggered" => SeverityHigh,
        "login.failure" => SeverityMedium,
        "login.success" => SeverityLow,
        "token.revoked" => SeverityMediumLow,
        "rbac.role_changed" => SeverityMediumHigh,
        _ => SeverityLow,
    };
}
