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
}
