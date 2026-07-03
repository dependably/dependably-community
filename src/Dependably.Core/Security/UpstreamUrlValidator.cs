using System.Net;
using System.Text.Json;
using Dependably.Infrastructure;

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
    private readonly string? _allowedHost;

    public UpstreamUrlValidator(AuditRepository audit, IEdgeMode edge)
    {
        _audit = audit;
        // Edge mode admits exactly the master host at the request-time DNS check so an internal
        // master resolves through; null (non-edge) leaves the block check fully in force.
        _allowedHost = edge.IsEdge && !string.IsNullOrEmpty(edge.MasterHost) ? edge.MasterHost : null;
    }

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
    /// Returns <see cref="UpstreamUrlBlock.BlockedRange"/> and records an audit event if
    /// a resolved address is blocked; returns <see cref="UpstreamUrlBlock.DnsFailure"/> when
    /// resolution fails (fail-closed); returns <see cref="UpstreamUrlBlock.None"/> when allowed.
    /// Emits no metric — the caller owns reason-tagged counter emission.
    /// </summary>
    public async Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return UpstreamUrlBlock.DnsFailure;
        }

        // Edge allowlist: the exact master host is an operator-pinned trusted upstream, so it
        // bypasses the private-range DNS check that would otherwise block an internal master.
        if (_allowedHost is not null
            && string.Equals(uri.Host, _allowedHost, StringComparison.OrdinalIgnoreCase))
        {
            return UpstreamUrlBlock.None;
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(uri.Host, ct);
            var blocked = addresses.FirstOrDefault(SsrfGuard.IsBlockedIp);
            if (blocked is null)
            {
                return UpstreamUrlBlock.None;
            }

            await _audit.LogAsync(
                "ssrf_blocked",
                orgId: orgId,
                detail: JsonSerializer.Serialize(new { url = uri.Host, resolved = blocked.ToString() }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
                ct: ct);
            return UpstreamUrlBlock.BlockedRange;
        }
        catch (Exception)
        {
            // DNS resolution failure — fail closed
            return UpstreamUrlBlock.DnsFailure;
        }
    }
}
