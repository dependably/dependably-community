using System.Net;
using Microsoft.AspNetCore.Http;

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
        if (ip is null) return null;
        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }
}
