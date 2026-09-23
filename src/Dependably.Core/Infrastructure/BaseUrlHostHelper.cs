using Microsoft.Extensions.Configuration;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the apex hostname. Single source of truth for the apex used by tenant resolution,
/// host-header filtering, and the bootstrap endpoint.
///
/// The apex is <c>APEX_HOST</c> when that is set, and otherwise the host portion of
/// <c>BASE_URL</c>. Most deployments set only <c>BASE_URL</c>; <c>APEX_HOST</c> is an optional
/// override for a deployment whose tenant apex is not the host it publishes as its base URL.
///
/// Both values go through the same parsing rules (string-based to tolerate scheme-less values):
/// Parsing rules (string-based to tolerate scheme-less values):
/// 1. Trim; return null if empty.
/// 2. Strip a leading scheme: if the value contains <c>://</c>, drop everything up to and
///    including <c>://</c>.
/// 3. Strip credentials: if a <c>@</c> appears before the first path/port delimiter, drop
///    everything up to and including it.
/// 4. Strip path, query, and fragment: cut at the first <c>/</c>, <c>?</c>, or <c>#</c>.
/// 5. Strip port: IPv6 literals (<c>[…]</c>) take everything through the closing <c>]</c>;
///    all other values cut at the first <c>:</c>.
/// 6. Lowercase; return null if the result is empty.
/// </summary>
internal static class BaseUrlHostHelper
{
    /// <summary>
    /// Extracts the bare hostname from <paramref name="baseUrl"/>.
    /// Returns <c>null</c> when <paramref name="baseUrl"/> is null, empty, or whitespace-only.
    /// Tolerates fully-absolute URIs (<c>https://host:port/path</c>), scheme-less host:port
    /// values (<c>example.com:8080</c>), and bare hostnames (<c>dependably.example.com</c>).
    /// </summary>
    internal static string? ExtractHost(string? baseUrl)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return null;
        }

        string value = baseUrl.Trim();

        // Strip scheme (e.g. "https://").
        const string schemeSeparator = "://";
        int schemeEnd = value.IndexOf(schemeSeparator, StringComparison.Ordinal);
        if (schemeEnd >= 0)
        {
            value = value[(schemeEnd + schemeSeparator.Length)..];
        }

        // Strip credentials ("user:pass@host" → "host").
        int atSign = value.IndexOfAny(['/', '?', '#']);
        int limit = atSign >= 0 ? atSign : value.Length;
        int credEnd = value.LastIndexOf('@', limit - 1);
        if (credEnd >= 0)
        {
            value = value[(credEnd + 1)..];
        }

        // Strip path, query, and fragment.
        int pathStart = value.IndexOfAny(['/', '?', '#']);
        if (pathStart >= 0)
        {
            value = value[..pathStart];
        }

        // Strip port — IPv6 literals keep their brackets.
        string host;
        if (value.StartsWith('['))
        {
            int closeBracket = value.IndexOf(']');
            host = closeBracket >= 0 ? value[..(closeBracket + 1)] : value;
        }
        else
        {
            int colon = value.IndexOf(':');
            host = colon >= 0 ? value[..colon] : value;
        }

        host = host.ToLowerInvariant();
        return string.IsNullOrEmpty(host) ? null : host;
    }

    /// <summary>
    /// Returns the apex hostname: the host portion of <c>APEX_HOST</c> when that key is set to a
    /// non-blank value, otherwise the host portion of <c>BASE_URL</c>. Null when neither yields a
    /// host.
    /// </summary>
    internal static string? ResolveApexHost(IConfiguration config)
        => ExtractHost(config["APEX_HOST"]) ?? ExtractHost(config["BASE_URL"]);

    /// <summary>
    /// Returns the apex hostname from <see cref="ResolveApexHost"/> when it is a real,
    /// non-localhost host, otherwise null. Loopback names are not an apex for host filtering or
    /// subdomain tenancy.
    /// </summary>
    internal static string? ResolveUsableApexHost(IConfiguration config)
    {
        string? host = ResolveApexHost(config);
        return IsUsableHost(host) ? host : null;
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="baseUrl"/> contains a non-localhost hostname
    /// suitable for use as a real apex in multi-tenant deployments (i.e. not a local/dev URL).
    /// </summary>
    internal static bool IsUsableApexHost(string? baseUrl) => IsUsableHost(ExtractHost(baseUrl));

    private static bool IsUsableHost(string? host) =>
        host is not null
            and not "localhost"
            and not "127.0.0.1"
            and not "[::1]";
}
