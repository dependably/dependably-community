using System.Net;
using NetTools;

namespace Dependably.Security;

/// <summary>
/// Single source of truth for the blocked IP ranges that SSRF defenses enforce. Both the
/// save-/request-time URL check (<see cref="UpstreamUrlValidator"/>) and the connect-time
/// socket guard (<see cref="SsrfConnectCallback"/>) consult this predicate, so the decision
/// can never diverge between when a URL is validated and when its connection is actually
/// dialed (the DNS-rebinding window).
/// </summary>
public static class SsrfGuard
{
    // RFC 1918 private, loopback, link-local (incl. cloud metadata 169.254.169.254),
    // CGNAT shared address space, IPv6 loopback / unique-local / link-local, the
    // "this host" 0/8 range (Linux routes 0.x.x.x to loopback), and IPv6 unspecified
    // (:: / ::/128) which also reaches loopback on Linux.
    private static readonly IPAddressRange[] BlockedRanges =
    [
        IPAddressRange.Parse("0.0.0.0/8"),       // "this host" — kernel routes to loopback
        IPAddressRange.Parse("127.0.0.0/8"),
        IPAddressRange.Parse("10.0.0.0/8"),
        IPAddressRange.Parse("172.16.0.0/12"),
        IPAddressRange.Parse("192.168.0.0/16"),
        IPAddressRange.Parse("169.254.0.0/16"),
        IPAddressRange.Parse("100.64.0.0/10"),
        IPAddressRange.Parse("192.0.0.0/24"),    // IETF protocol assignments
        IPAddressRange.Parse("192.0.2.0/24"),    // TEST-NET-1 (documentation)
        IPAddressRange.Parse("198.18.0.0/15"),   // benchmarking
        IPAddressRange.Parse("198.51.100.0/24"), // TEST-NET-2 (documentation)
        IPAddressRange.Parse("203.0.113.0/24"),  // TEST-NET-3 (documentation)
        IPAddressRange.Parse("240.0.0.0/4"),     // reserved / Class E
        IPAddressRange.Parse("255.255.255.255/32"),
        IPAddressRange.Parse("::/128"),          // IPv6 unspecified — routes to loopback
        IPAddressRange.Parse("::1/128"),
        IPAddressRange.Parse("fc00::/7"),
        IPAddressRange.Parse("fe80::/10"),
    ];

    // Loopback, link-local (incl. cloud metadata), CGNAT, the "this host" 0/8 range,
    // IPv6 unspecified, and IPv6 special ranges that are always blocked — even when RFC
    // 1918 private ranges are permitted (e.g. for on-premise SIEM collectors). Does NOT
    // include 10/8, 172.16/12, or 192.168/16.
    private static readonly IPAddressRange[] AlwaysBlockedRanges =
    [
        IPAddressRange.Parse("0.0.0.0/8"),       // "this host" — kernel routes to loopback
        IPAddressRange.Parse("127.0.0.0/8"),
        IPAddressRange.Parse("169.254.0.0/16"),
        IPAddressRange.Parse("100.64.0.0/10"),
        IPAddressRange.Parse("::/128"),          // IPv6 unspecified — routes to loopback
        IPAddressRange.Parse("::1/128"),
        IPAddressRange.Parse("fc00::/7"),
        IPAddressRange.Parse("fe80::/10"),
    ];

    /// <summary>
    /// Returns true if the address falls in a blocked (private/internal/metadata) range.
    /// IPv4-mapped IPv6 forms (<c>::ffff:a.b.c.d</c>) are collapsed to their IPv4 address
    /// first, so a mapped loopback/private address cannot slip past the IPv4 ranges.
    /// </summary>
    public static bool IsBlockedIp(IPAddress ip)
    {
        var candidate = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        return BlockedRanges.Any(range => range.Contains(candidate));
    }

    /// <summary>
    /// Returns true if the address is in a range that is always blocked regardless of
    /// private-IP opt-in. Blocks loopback, link-local (including cloud metadata at
    /// 169.254.169.254), CGNAT, and IPv6 special ranges, but allows RFC 1918 addresses
    /// (10/8, 172.16/12, 192.168/16) for on-premise deployments that route to self-hosted
    /// collectors inside the private network.
    /// </summary>
    public static bool IsBlockedIpExcludingPrivate(IPAddress ip)
    {
        var candidate = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        return AlwaysBlockedRanges.Any(range => range.Contains(candidate));
    }
}
