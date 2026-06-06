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
    // CGNAT shared address space, and IPv6 loopback / unique-local / link-local.
    private static readonly IPAddressRange[] BlockedRanges =
    [
        IPAddressRange.Parse("127.0.0.0/8"),
        IPAddressRange.Parse("10.0.0.0/8"),
        IPAddressRange.Parse("172.16.0.0/12"),
        IPAddressRange.Parse("192.168.0.0/16"),
        IPAddressRange.Parse("169.254.0.0/16"),
        IPAddressRange.Parse("100.64.0.0/10"),
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
}
