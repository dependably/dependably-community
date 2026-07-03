namespace Dependably.Security;

/// <summary>
/// Strips CR, LF, and NUL from a value before it is written into an HTTP response header,
/// closing the header-injection / response-splitting vector for any PURL or coordinate that
/// reaches a <c>X-Dependably-PURL</c>-style header. Single home for the sanitiser so every
/// ecosystem serve path shares one implementation instead of re-declaring it.
/// </summary>
public static class HeaderSanitizer
{
    public static string Sanitize(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}
