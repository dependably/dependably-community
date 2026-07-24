namespace Dependably.Infrastructure;

/// <summary>
/// Single source of truth for the locale codes the SPA renders. Mirrored on the frontend
/// at web/src/lib/LocaleSwitcher.svelte. Keep these in sync.
/// </summary>
public static class LanguageCodes
{
    public static readonly string[] Supported = ["en", "fr"];
    public const string Default = "en";

    public static bool IsSupported(string code) => Array.IndexOf(Supported, code) >= 0;

    /// <summary>
    /// Resolves the effective render language for a background/notification send where there is
    /// no request culture to consult: the per-user override wins when set and supported, else the
    /// org's default language when set and supported, else <see cref="Default"/>. Used by
    /// account-security event email (MFA enabled/disabled, password changed) — the per-user →
    /// org → instance chain that <c>UserService.GetUserContextAsync</c> already surfaces as
    /// <c>Language</c>/<c>TenantDefaultLanguage</c>.
    /// </summary>
    public static string ResolveEffective(string? userLanguage, string? fallbackLanguage = null) =>
        !string.IsNullOrEmpty(userLanguage) && IsSupported(userLanguage) ? userLanguage
        : !string.IsNullOrEmpty(fallbackLanguage) && IsSupported(fallbackLanguage) ? fallbackLanguage
        : Default;
}
