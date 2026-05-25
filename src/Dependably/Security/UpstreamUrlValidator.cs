using System.Net;
using NetTools;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;

namespace Dependably.Security;

/// <summary>
/// Validates upstream registry URLs to prevent SSRF attacks (OWASP API7:2023).
/// Blocks all private, loopback, link-local, and cloud-metadata IP ranges.
/// Re-validates via DNS resolution on every proxy request to prevent DNS rebinding.
/// </summary>
public sealed class UpstreamUrlValidator : IUpstreamUrlValidator
{
    // Blocked ranges: RFC 1918 private, loopback, link-local, cloud metadata, shared address space
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

    private readonly AuditRepository _audit;

    public UpstreamUrlValidator(AuditRepository audit) => _audit = audit;

    /// <summary>
    /// Validates a URL string for use as an upstream registry URL (save-time check).
    /// Returns a problem detail string on failure, or null on success.
    /// </summary>
    public static string? ValidateUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return "Upstream URL must not be empty.";

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return "Invalid URL format.";

        if (uri.Scheme != "http" && uri.Scheme != "https")
            return "Only http:// and https:// schemes are accepted.";

        // Static host check (IP addresses only — hostnames checked at request time)
        if (IPAddress.TryParse(uri.Host, out var ip) && IsBlocked(ip))
            return $"Upstream URL resolves to a blocked IP range: {ip}";

        return null;
    }

    /// <summary>
    /// Re-validates at request time via DNS resolution to prevent DNS rebinding.
    /// Returns false and records an audit event if blocked.
    /// </summary>
    public async Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(uri.Host, ct);
            var blocked = addresses.FirstOrDefault(IsBlocked);
            if (blocked is null) return true;

            DependablyMeter.UpstreamUrlBlocks.Add(1);
            await _audit.LogAsync(
                "ssrf_blocked",
                orgId: orgId,
                detail: $"{{\"url\":\"{uri.Host}\",\"resolved\":\"{blocked}\"}}",
                ct: ct);
            return false;
        }
        catch (Exception)
        {
            // DNS resolution failure — fail closed
            return false;
        }
    }

    private static bool IsBlocked(IPAddress ip) =>
        BlockedRanges.Any(range => range.Contains(ip));
}
