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
    /// first, so a mapped loopback/private address cannot slip past the IPv4 ranges. IPv6
    /// transitional/embedding forms (6to4, Teredo, NAT64) are decoded to their carried IPv4
    /// address and re-checked the same way, so an attacker cannot smuggle a blocked target
    /// past the guard by wrapping it in one of those encodings.
    /// </summary>
    public static bool IsBlockedIp(IPAddress ip) =>
        Candidates(ip).Any(candidate => BlockedRanges.Any(range => range.Contains(candidate)));

    /// <summary>
    /// Returns true if the address is in a range that is always blocked regardless of
    /// private-IP opt-in. Blocks loopback, link-local (including cloud metadata at
    /// 169.254.169.254), CGNAT, and IPv6 special ranges, but allows RFC 1918 addresses
    /// (10/8, 172.16/12, 192.168/16) for on-premise deployments that route to self-hosted
    /// collectors inside the private network. IPv6 transitional/embedding forms are decoded
    /// the same way as <see cref="IsBlockedIp"/>.
    /// </summary>
    public static bool IsBlockedIpExcludingPrivate(IPAddress ip) =>
        Candidates(ip).Any(candidate => AlwaysBlockedRanges.Any(range => range.Contains(candidate)));

    /// <summary>
    /// Yields every address form to check a candidate IP against the blocklists: the address
    /// itself (or its IPv4-mapped collapse), plus — when the address is one of the IPv6
    /// transitional/embedding encodings below — the IPv4 address it carries. Checking both the
    /// wrapper and the embedded address closes the gap where a blocked target (loopback,
    /// link-local metadata, RFC 1918) is reachable only when addressed through the encoding:
    /// <list type="bullet">
    /// <item><description>6to4 (<c>2002::/16</c>): embeds the IPv4 address in bits 16-47, unobfuscated.</description></item>
    /// <item><description>Teredo (<c>2001:0000::/32</c>): embeds the client IPv4 address in the low 32 bits, XORed with <c>0xFFFFFFFF</c> per RFC 4380.</description></item>
    /// <item><description>NAT64 well-known prefix (<c>64:ff9b::/96</c>, RFC 6052): embeds the IPv4 address in the low 32 bits, unobfuscated.</description></item>
    /// </list>
    /// </summary>
    private static IEnumerable<IPAddress> Candidates(IPAddress ip)
    {
        var mapped = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        yield return mapped;

        if (TryExtractEmbeddedIPv4(ip, out var embedded))
        {
            yield return embedded!;
        }
    }

    /// <summary>
    /// Decodes the IPv4 address embedded in a 6to4, Teredo, or NAT64 IPv6 address. Returns
    /// false (with <paramref name="embedded"/> null) for every other address, including plain
    /// IPv4 and IPv4-mapped IPv6 (already handled by the caller via <see cref="IPAddress.MapToIPv4"/>).
    /// </summary>
    // Every literal below is a documented IPv6-prefix byte value or its fixed array offset
    // (6to4, Teredo, NAT64 well-known prefix — RFC 3056 / RFC 4380 / RFC 6052); naming each
    // one individually would multiply the constant count without adding clarity over the
    // prefix comments already in place, so the block is kept together for auditability.
#pragma warning disable S109 // documented IPv6-prefix byte/offset constants, self-evident in context
    private static bool TryExtractEmbeddedIPv4(IPAddress ip, out IPAddress? embedded)
    {
        embedded = null;
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return false;
        }

        byte[] bytes = ip.GetAddressBytes();

        // 6to4: 2002::/16 — IPv4 address in bytes 2-5, unobfuscated.
        if (bytes[0] == 0x20 && bytes[1] == 0x02)
        {
            embedded = new IPAddress(bytes[2..6]);
            return true;
        }

        // Teredo: 2001:0000::/32 — client IPv4 address in bytes 12-15, XORed with 0xFF
        // per RFC 4380 (obfuscation to survive NAT rewriting).
        if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] == 0x00)
        {
            byte[] client = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                client[i] = (byte)(bytes[12 + i] ^ 0xFF);
            }

            embedded = new IPAddress(client);
            return true;
        }

        // NAT64 well-known prefix: 64:ff9b::/96 — IPv4 address in bytes 12-15, unobfuscated.
        if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b
            && bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0
            && bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0)
        {
            embedded = new IPAddress(bytes[12..16]);
            return true;
        }

        return false;
    }
#pragma warning restore S109
}
