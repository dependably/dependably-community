namespace Dependably.Infrastructure;

/// <summary>
/// Configuration read helpers that normalize operator-supplied values so a stray trailing
/// slash (or other forgivable typo) does not silently break URL construction.
/// </summary>
public static class ConfigurationExtensions
{
    /// <summary>
    /// Returns <c>BASE_URL</c> with any trailing slash(es) removed, or null when unset/blank.
    ///
    /// A trailing slash is an easy mistake to make (<c>https://repo.example.com/</c>) and silently
    /// breaks the two places BASE_URL is consumed by string concatenation rather than
    /// <see cref="Uri"/> parsing: CORS origins (an origin with a trailing slash never matches the
    /// browser-sent <c>Origin</c> header) and templated links such as invite URLs (which would
    /// otherwise become <c>https://host//join</c>). Stripping it here means it does not matter
    /// whether the operator includes one.
    /// </summary>
    public static string? PublicBaseUrl(this IConfiguration config)
    {
        var raw = config["BASE_URL"];
        return string.IsNullOrWhiteSpace(raw) ? null : raw.TrimEnd('/');
    }
}
