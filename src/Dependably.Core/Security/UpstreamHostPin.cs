namespace Dependably.Security;

/// <summary>
/// Single source of truth for the upstream credential host-pin invariant: an operator-configured
/// upstream's stored credential (Authorization header, API key, etc.) may only ride along to a
/// fetch whose host matches the configured upstream's own host. Upstream-controlled content (a
/// PEP 503 simple-index href, an RPM <c>primary.xml</c> <c>&lt;location href&gt;</c>, a sparse
/// registry's crate-download base) can name an arbitrary third-party host, and attaching a
/// credential there would leak it to a host the operator never trusted.
/// </summary>
public static class UpstreamHostPin
{
    /// <summary>
    /// True only when both <paramref name="configuredUrl"/> and <paramref name="candidateUrl"/>
    /// parse as absolute URIs and their <see cref="Uri.Host"/> values match case-insensitively.
    /// Port and scheme are ignored — upstream-controlled hrefs never carry credentials, so pinning
    /// on host alone matches the trust boundary an operator sets by configuring an upstream URL.
    /// Either URL failing to parse as absolute is treated as untrusted (fail-closed).
    /// </summary>
    public static bool IsSameHost(string configuredUrl, string candidateUrl)
    {
        return Uri.TryCreate(configuredUrl, UriKind.Absolute, out var configured)
            && Uri.TryCreate(candidateUrl, UriKind.Absolute, out var candidate)
            && string.Equals(configured.Host, candidate.Host, StringComparison.OrdinalIgnoreCase);
    }
}
