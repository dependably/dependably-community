namespace Dependably.Infrastructure;

/// <summary>
/// Configuration read helpers that normalize operator-supplied values so a stray trailing
/// slash (or other forgivable typo) does not silently break URL construction.
/// </summary>
public static class ConfigurationExtensions
{
    /// <summary>
    /// The narrowest IPv4 prefix length still considered "broad" for a <c>TRUSTED_PROXIES</c>
    /// entry: an IPv4 network wider than a /22 (more than 1024 addresses) trusts enough hosts
    /// that "the reverse proxy" and "an arbitrary in-subnet client" become indistinguishable.
    /// </summary>
    public const int BroadIpv4PrefixThreshold = 22;

    /// <summary>
    /// The narrowest IPv6 prefix length still considered "broad" for a <c>TRUSTED_PROXIES</c>
    /// entry. IPv6 subnets are conventionally routed in /64 units (one subnet per /64), so a
    /// network wider than /64 spans more than one routed subnet — the same "whole VPC/site
    /// CIDR" shape as an overly broad IPv4 range, just expressed in IPv6's larger addressing unit.
    /// </summary>
    public const int BroadIpv6PrefixThreshold = 64;

    /// <summary>
    /// Normalizes an IPv4-mapped IPv6 network (<c>::ffff:a.b.c.d/N</c>, <c>N &gt;= 96</c>) to the
    /// IPv4 family and the equivalent IPv4 prefix length (<c>N - 96</c>); any other network is
    /// returned unchanged. Below /96 the mapped-address marker itself falls inside the host
    /// part, so <c>IPNetwork.Parse</c> zeroes it out and the network no longer reports
    /// <c>IsIPv4MappedToIPv6</c> — the equivalent IPv4 prefix length is therefore always in
    /// [0, 32]. Normalizing lets a mapped network be judged on its IPv4-equivalent terms: e.g.
    /// <c>::ffff:10.0.0.0/104</c> is exactly as broad as IPv4 <c>10.0.0.0/8</c> (verified against
    /// <c>ForwardedHeadersMiddleware</c>'s live matching), and <c>::ffff:0:0/96</c> is the
    /// mapped form of a zero-length (<c>/0</c>) IPv4 prefix and is refused on that structural
    /// basis — a fail-closed, forward-looking rejection independent of any one runtime's exact
    /// matching behaviour for that specific mapped form.
    /// </summary>
    public static (System.Net.Sockets.AddressFamily Family, int PrefixLength) NormalizeTrustedProxyNetwork(
        System.Net.IPNetwork network)
    {
        if (network.BaseAddress.IsIPv4MappedToIPv6)
        {
            return (System.Net.Sockets.AddressFamily.InterNetwork, Math.Max(0, network.PrefixLength - 96));
        }

        return (network.BaseAddress.AddressFamily, network.PrefixLength);
    }

    /// <summary>
    /// True when <paramref name="network"/> is wider than the per-family broad-network
    /// threshold above — i.e. it trusts more addresses than a single proxy subnet plausibly
    /// needs, so every host inside it can forge its own <c>X-Forwarded-For</c> source address.
    /// Used only to warn; a broad but non-zero CIDR is a legitimate (if risky) operator choice.
    /// An IPv4-mapped IPv6 network is normalized to its equivalent IPv4 prefix length first, so
    /// e.g. <c>::ffff:10.0.0.0/104</c> (equivalent to IPv4 <c>10.0.0.0/8</c>) is judged against
    /// the IPv4 threshold, not the IPv6 one.
    /// </summary>
    public static bool IsBroadTrustedProxyNetwork(System.Net.IPNetwork network)
    {
        var (family, prefixLength) = NormalizeTrustedProxyNetwork(network);
        int threshold = family == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? BroadIpv6PrefixThreshold
            : BroadIpv4PrefixThreshold;
        return prefixLength < threshold;
    }

    /// <summary>
    /// The broad-network threshold (in the effective/normalized family's own prefix units) that
    /// <paramref name="network"/> was judged against by <see cref="IsBroadTrustedProxyNetwork"/>
    /// — exposed so callers can name the right number (/22 or /64) in an operator-facing message.
    /// </summary>
    public static int BroadThresholdFor(System.Net.IPNetwork network)
    {
        var (family, _) = NormalizeTrustedProxyNetwork(network);
        return family == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? BroadIpv6PrefixThreshold
            : BroadIpv4PrefixThreshold;
    }

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
    /// <para>A network whose effective prefix length is 0 (<c>0.0.0.0/0</c>, <c>::/0</c>, or the
    /// IPv4-mapped equivalent <c>::ffff:0:0/96</c>) also throws: it declares every possible peer
    /// address a forwarding proxy, so — were the forwarded-header middleware to match it as
    /// written — any client, not just the declared reverse proxy, could inject
    /// <c>X-Forwarded-For</c>/<c>-Proto</c>/<c>-Host</c> and spoof the caller IP that the
    /// <c>/metrics</c>, <c>/version</c>, and management-docs allowlists (and the tenant subdomain
    /// resolver) authorize against. The rejection is fail-closed and structural (a network is
    /// refused for declaring the whole address space, independent of how any particular runtime
    /// currently matches that declaration) rather than a claim that every listed form is an
    /// exploitable bypass today. Narrower ranges (a specific proxy fleet's subnet, a VPC CIDR)
    /// are the operator's call and are not rejected here.</para>
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
                var (_, effectivePrefixLength) = NormalizeTrustedProxyNetwork(network);
                if (effectivePrefixLength == 0)
                {
                    throw new InvalidOperationException(
                        $"TRUSTED_PROXIES entry '{entry}' has an effective prefix length of 0 — it " +
                        "declares every possible address a forwarding proxy. Any client could then spoof " +
                        "X-Forwarded-For/-Proto/-Host and bypass the /metrics, /version, and " +
                        "management-docs IP allowlists. Scope TRUSTED_PROXIES to the actual reverse-proxy " +
                        "address(es) or subnet instead of the whole address space.");
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

    /// <summary>
    /// True when <paramref name="peer"/> is one of the addresses/networks parsed out of
    /// <c>TRUSTED_PROXIES</c> by <see cref="ParseTrustedProxies"/> — the same question
    /// <c>ForwardedHeadersMiddleware</c> asks of the immediate peer before it honours any
    /// <c>X-Forwarded-*</c> header, matched the same way (an IPv4-mapped IPv6 peer is also tried in
    /// its IPv4 form, so <c>::ffff:10.0.0.1</c> matches a <c>10.0.0.0/8</c> entry). Sharing one
    /// matcher is what keeps every header the edge injects on one trust boundary instead of two
    /// that can drift apart.
    ///
    /// <para>A null peer, or an empty trusted set (<c>TRUSTED_PROXIES</c> unset), is never trusted:
    /// forwarded-header processing is disabled in that configuration, so nothing else may treat a
    /// caller-supplied header as proxy-injected either.</para>
    /// </summary>
    public static bool IsTrustedProxyPeer(
        System.Net.IPAddress? peer,
        IReadOnlyList<System.Net.IPNetwork> networks,
        IReadOnlyList<System.Net.IPAddress> proxies)
    {
        return peer is not null
            && ((peer.IsIPv4MappedToIPv6 && IsTrustedProxyPeer(peer.MapToIPv4(), networks, proxies))
                || proxies.Contains(peer)
                || networks.Any(n => n.Contains(peer)));
    }
}
