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
        string? raw = config["BASE_URL"];
        return string.IsNullOrWhiteSpace(raw) ? null : raw.TrimEnd('/');
    }

    /// <summary>
    /// Parses a <c>TRUSTED_PROXIES</c> value — a comma-separated list of single IP addresses
    /// and/or CIDR networks (e.g. <c>10.0.0.0/8,172.18.0.1,fd00::/8</c>) — into the known
    /// networks and known proxy addresses that <c>ForwardedHeadersOptions</c> trusts. Entries
    /// containing <c>/</c> are networks; the rest are single addresses. A malformed entry throws
    /// at startup (fail fast) rather than silently degrading the trust boundary. Returns empty
    /// lists when the value is null/blank.
    ///
    /// <para>A network with prefix length 0 (<c>0.0.0.0/0</c> or <c>::/0</c>) also throws: it
    /// trusts every possible peer address as a forwarding proxy, so any client — not just the
    /// declared reverse proxy — can inject <c>X-Forwarded-For</c>/<c>-Proto</c>/<c>-Host</c> and
    /// spoof the caller IP that the <c>/metrics</c>, <c>/version</c>, and management-docs
    /// allowlists (and the tenant subdomain resolver) authorize against. Narrower ranges (a
    /// specific proxy fleet's subnet, a VPC CIDR) are the operator's call and are not rejected
    /// here.</para>
    /// </summary>
    public static (List<System.Net.IPNetwork> Networks, List<System.Net.IPAddress> Proxies) ParseTrustedProxies(string? value)
    {
        var networks = new List<System.Net.IPNetwork>();
        var proxies = new List<System.Net.IPAddress>();
        if (string.IsNullOrWhiteSpace(value))
        {
            return (networks, proxies);
        }

        foreach (string entry in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (entry.Contains('/'))
            {
                var network = System.Net.IPNetwork.Parse(entry);
                if (network.PrefixLength == 0)
                {
                    throw new InvalidOperationException(
                        $"TRUSTED_PROXIES entry '{entry}' trusts every possible address as a forwarding " +
                        "proxy (prefix length 0). Any client could then spoof X-Forwarded-For/-Proto/-Host " +
                        "and bypass the /metrics, /version, and management-docs IP allowlists. Scope " +
                        "TRUSTED_PROXIES to the actual reverse-proxy address(es) or subnet instead of the " +
                        "whole address space.");
                }
                networks.Add(network);
            }
            else
            {
                proxies.Add(System.Net.IPAddress.Parse(entry));
            }
        }
        return (networks, proxies);
    }
}
