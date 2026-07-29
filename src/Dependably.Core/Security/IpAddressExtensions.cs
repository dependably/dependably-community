using System.Net;
using System.Net.Sockets;

namespace Dependably.Security;

/// <summary>
/// On dual-stack sockets (the default on Linux/macOS), Kestrel reports incoming IPv4
/// connections as <c>::ffff:&lt;v4&gt;</c> — the IPv4-mapped IPv6 representation. The mapped
/// form is correct but unhelpful for audit display, range checks, and grep-the-logs
/// triage. This helper collapses the mapped form to its plain IPv4 string before it ever
/// leaves the request boundary, so downstream code (audit rows, rate-limit keys, structured
/// audit envelopes) all see the same canonical shape.
/// </summary>
public static class IpAddressExtensions
{
    /// <summary>
    /// Returns the connection's remote IP as a canonical string, mapping IPv4-in-IPv6
    /// addresses back to their dotted-quad form. Returns null if no address is available
    /// (in-process / unit-test connections).
    /// </summary>
    public static string? GetNormalizedRemoteIp(this HttpContext? context)
    {
        var ip = context?.Connection?.RemoteIpAddress;
        return Normalize(ip);
    }

    /// <summary>
    /// Returns the canonical string for an <see cref="IPAddress"/>, collapsing IPv4-mapped
    /// IPv6 addresses to dotted-quad. Returns null if the input is null.
    /// </summary>
    public static string? Normalize(IPAddress? ip)
    {
        return ip is null ? null : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    /// <summary>
    /// The IPv6 network prefix (in bits) a rate-limit partition key collapses to by default.
    /// A routed <c>/64</c> is the smallest allocation an ISP hands a single subscriber (the
    /// standard VPS and residential IPv6 assignment), so it — not the full <c>/128</c> — is the
    /// meaningful rate-limiting subject. Keying on the full <c>/128</c> lets one attacker mint a
    /// fresh full budget from each of 2^64 source addresses in their own <c>/64</c>.
    /// </summary>
    public const int DefaultIpv6PartitionPrefixBits = 64;

    /// <summary>
    /// Returns the connection's remote IP normalized for use as a RATE-LIMIT PARTITION KEY:
    /// IPv4 keeps its full <c>/32</c>, IPv6 collapses to its <c>/<paramref name="ipv6PrefixBits"/></c>
    /// network (default <c>/64</c>). Returns null when no address is available (in-process /
    /// unit-test connections).
    ///
    /// <para>
    /// This is deliberately NOT <see cref="GetNormalizedRemoteIp"/>: audit <c>source_ip</c> fields
    /// record the full address for forensics, whereas partition keys must aggregate so a single
    /// routed <c>/64</c> resolves to one budget instead of 2^64. Keeping the two helpers distinct
    /// stops a future edit from collapsing the audit trail to a subnet by accident.
    /// </para>
    /// </summary>
    public static string? GetRateLimitPartitionIp(
        this HttpContext? context, int ipv6PrefixBits = DefaultIpv6PartitionPrefixBits)
    {
        var ip = context?.Connection?.RemoteIpAddress;
        return NormalizeForRateLimit(ip, ipv6PrefixBits);
    }

    /// <summary>
    /// Returns the rate-limit partition string for an <see cref="IPAddress"/>. IPv4 (including the
    /// IPv4-mapped-IPv6 form Kestrel reports on dual-stack sockets) is returned as its full
    /// dotted-quad — no <c>/24</c> aggregation. IPv6 is masked to its network prefix and rendered
    /// as <c>network/prefix</c> (e.g. <c>2001:db8:1:2::/64</c>) so two addresses in the same
    /// allocation share a key while two different allocations do not. Returns null if the input is
    /// null.
    /// </summary>
    public static string? NormalizeForRateLimit(
        IPAddress? ip, int ipv6PrefixBits = DefaultIpv6PartitionPrefixBits)
    {
        if (ip is null)
        {
            return null;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        // IPv4 stays at its full /32 — the per-host granularity is already the right subject.
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            return ip.ToString();
        }

        int prefix = Math.Clamp(ipv6PrefixBits, 0, 128);
        return MaskIpv6(ip, prefix).ToString() + "/" + prefix;
    }

    /// <summary>
    /// The IPv4 network prefix (in bits) an audit-minimized <c>source_ip</c> collapses to when
    /// truncation is enabled. A <c>/24</c> keeps the address useful for locating traffic to an
    /// office, a VPN egress, or a cloud range while no longer identifying a single host.
    /// </summary>
    public const int DefaultAuditIpv4PrefixBits = 24;

    /// <summary>
    /// The IPv6 network prefix (in bits) an audit-minimized <c>source_ip</c> collapses to. A
    /// <c>/48</c> is the site allocation — coarser than the <c>/64</c> rate limiting keys on,
    /// because the purposes differ: rate limiting must bound one subscriber's budget, minimization
    /// must stop the record identifying one subscriber.
    /// </summary>
    public const int DefaultAuditIpv6PrefixBits = 48;

    /// <summary>
    /// Returns the audit <c>source_ip</c> string with the host portion masked off: IPv4 rendered
    /// as <c>192.0.2.0/24</c>, IPv6 as <c>2001:db8:1::/48</c>. Returns null if the input is null.
    ///
    /// <para>
    /// This is the OPT-IN minimized form. <see cref="GetNormalizedRemoteIp"/> remains the default
    /// because an audit trail's job is attribution, and a truncated address cannot answer "which
    /// host did this". An operator who has decided their retention posture outweighs that turns
    /// truncation on; the choice is theirs to make, not one to make silently on their behalf.
    /// Distinct from <see cref="NormalizeForRateLimit"/>, which aggregates for a different reason
    /// and at a different prefix — see that method.
    /// </para>
    /// </summary>
    public static string? NormalizeForAuditMinimization(
        IPAddress? ip,
        int ipv4PrefixBits = DefaultAuditIpv4PrefixBits,
        int ipv6PrefixBits = DefaultAuditIpv6PrefixBits)
    {
        if (ip is null)
        {
            return null;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            int v4Prefix = Math.Clamp(ipv4PrefixBits, 0, 32);
            return MaskIpv4(ip, v4Prefix).ToString() + "/" + v4Prefix;
        }

        int v6Prefix = Math.Clamp(ipv6PrefixBits, 0, 128);
        return MaskIpv6(ip, v6Prefix).ToString() + "/" + v6Prefix;
    }

    // Zeroes every bit of an IPv4 address below the given prefix length.
    private static IPAddress MaskIpv4(IPAddress ip, int prefixBits)
    {
        Span<byte> bytes = stackalloc byte[4];
        if (!ip.TryWriteBytes(bytes, out int written) || written != 4)
        {
            return ip;
        }

        int fullBytes = prefixBits / 8;
        int remainderBits = prefixBits % 8;

        for (int i = fullBytes + (remainderBits > 0 ? 1 : 0); i < 4; i++)
        {
            bytes[i] = 0;
        }

        if (remainderBits > 0 && fullBytes < 4)
        {
            bytes[fullBytes] &= (byte)(0xFF << (8 - remainderBits));
        }

        return new IPAddress(bytes);
    }

    // Zeroes every bit of an IPv6 address below the given prefix length, yielding the network
    // address of the containing /prefix block.
    private static IPAddress MaskIpv6(IPAddress ip, int prefixBits)
    {
        Span<byte> bytes = stackalloc byte[16];
        if (!ip.TryWriteBytes(bytes, out int written) || written != 16)
        {
            return ip;
        }

        int fullBytes = prefixBits / 8;
        int remainderBits = prefixBits % 8;

        // Zero whole bytes past the prefix.
        for (int i = fullBytes + (remainderBits > 0 ? 1 : 0); i < 16; i++)
        {
            bytes[i] = 0;
        }

        // Zero the sub-byte tail of the boundary byte, if the prefix falls mid-byte.
        if (remainderBits > 0 && fullBytes < 16)
        {
            bytes[fullBytes] &= (byte)(0xFF << (8 - remainderBits));
        }

        return new IPAddress(bytes);
    }
}
