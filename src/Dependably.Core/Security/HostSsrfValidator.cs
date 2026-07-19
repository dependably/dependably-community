using System.Net;

namespace Dependably.Security;

/// <summary>
/// Save-time SSRF validation for a bare host (no scheme, no URL) — the shape a caller-supplied
/// SMTP relay host takes, as opposed to the full upstream-registry URLs
/// <see cref="UpstreamUrlValidator"/> covers. Deliberately IP-literal only, mirroring
/// <see cref="UpstreamUrlValidator.ValidateUrl"/> and
/// <c>WebhookDeliveryClient.ValidateWebhookUrl</c>: a hostname is not resolved here, both because
/// DNS can legitimately change between save time and send time (so a save-time hostname check is
/// never authoritative) and because it would need real DNS resolution for every value an operator
/// or org admin ever tests with, including hosts that intentionally do not resolve. The
/// authoritative, DNS-rebinding-aware gate for a hostname is <see cref="SsrfConnectCallback"/> at
/// actual connect time — this check exists purely to fail fast on an obviously-bad literal.
/// </summary>
public static class HostSsrfValidator
{
    /// <summary>
    /// Returns true when <paramref name="host"/> is an IP literal that <paramref name="isBlocked"/>
    /// rejects. Returns false for a null/blank host (callers apply their own required-field
    /// validation separately) and for any non-literal hostname (left to the connect-time gate).
    /// </summary>
    public static bool IsHostBlocked(string? host, Func<IPAddress, bool> isBlocked) =>
        !string.IsNullOrWhiteSpace(host) && IPAddress.TryParse(host, out var literal) && isBlocked(literal);
}
