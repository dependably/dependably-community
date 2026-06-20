namespace Dependably.Security;

/// <summary>
/// Builds the <c>metrics-access</c> response object consumed by the sysadmin UI.
/// Produces camelCase-keyed fields so the browser can read them directly.
/// </summary>
internal static class MetricsAccessView
{
    /// <summary>
    /// Returns an anonymous object with the resolved metrics-access config and up to
    /// <paramref name="recentDeniedMax"/> recent denied IPs. The exact shape must stay
    /// stable — it is the frontend JSON contract for the metrics-access settings panel.
    /// </summary>
    internal static object Build(
        MetricsAccessConfig.ResolvedConfig resolved,
        ScrapeDiagnostics diagnostics,
        int recentDeniedMax = 10)
    {
        var denied = diagnostics.RecentDeniedIps(recentDeniedMax)
            .Select(e => new { ip = e.Ip, lastSeen = e.LastSeen });
        return new
        {
            enabled = resolved.Enabled,
            enabledSource = resolved.EnabledSource.ToString().ToLowerInvariant(),
            enabledLockedByEnv = resolved.EnabledLockedByEnv,
            allowedIps = resolved.AllowedRaw,
            allowlistSource = resolved.AllowlistSource.ToString().ToLowerInvariant(),
            allowlistLockedByEnv = resolved.AllowlistLockedByEnv,
            recentDeniedIps = denied,
        };
    }
}
