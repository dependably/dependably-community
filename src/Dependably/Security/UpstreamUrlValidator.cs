using System.Net;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;

namespace Dependably.Security;

/// <summary>
/// Validates upstream registry URLs to prevent SSRF attacks (OWASP API7:2023).
/// Blocks all private, loopback, link-local, and cloud-metadata IP ranges via
/// <see cref="SsrfGuard"/>. This URL-level check is a cheap fail-fast plus audit emitter;
/// the authoritative gate against DNS rebinding is <see cref="SsrfConnectCallback"/>, which
/// validates the IP actually dialed at connect time.
/// </summary>
public sealed class UpstreamUrlValidator : IUpstreamUrlValidator
{
    private readonly AuditRepository _audit;

    public UpstreamUrlValidator(AuditRepository audit) => _audit = audit;

    /// <summary>
    /// Validates a URL string for use as an upstream registry URL (save-time check).
    /// Returns a problem detail string on failure, or null on success.
    /// </summary>
    public static string? ValidateUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return "Upstream URL must not be empty.";
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return "Invalid URL format.";
        }

        if (uri.Scheme is not "http" and not "https")
        {
            return "Only http:// and https:// schemes are accepted.";
        }

        // Static host check (IP addresses only — hostnames checked at request time)
        return IPAddress.TryParse(uri.Host, out var ip) && SsrfGuard.IsBlockedIp(ip)
            ? $"Upstream URL resolves to a blocked IP range: {ip}"
            : null;
    }

    /// <summary>
    /// Re-validates at request time via DNS resolution to prevent DNS rebinding.
    /// Returns false and records an audit event if blocked.
    /// </summary>
    public async Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(uri.Host, ct);
            var blocked = addresses.FirstOrDefault(SsrfGuard.IsBlockedIp);
            if (blocked is null)
            {
                return true;
            }

            DependablyMeter.UpstreamUrlBlocks.Add(1);
            await _audit.LogAsync(
                "ssrf_blocked",
                orgId: orgId,
                detail: JsonSerializer.Serialize(new { url = uri.Host, resolved = blocked.ToString() }),
                ct: ct);
            return false;
        }
        catch (Exception)
        {
            // DNS resolution failure — fail closed
            return false;
        }
    }
}
