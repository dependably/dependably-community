namespace Dependably.Security;

/// <summary>
/// Single source of truth for the upstream credential pin: an operator-configured upstream's
/// stored credential (Authorization header, API key, etc.) may only ride along to a fetch on the
/// same origin — scheme, host and port — as the configured upstream URL. Upstream-controlled
/// content (a PEP 503 simple-index href, an RPM <c>primary.xml</c> <c>&lt;location href&gt;</c>, a
/// sparse registry's crate-download base, a NuGet registration page <c>@id</c>) can name any URL,
/// and attaching a credential to one the operator never configured would leak it.
///
/// <para>
/// <b>Why the whole origin, not just the host.</b> A hostile or compromised index that names
/// <c>http://</c> on the configured <c>https://</c> host would otherwise pull the credential over
/// plaintext, readable by anyone on the path. An explicit different port on the same host is a
/// different service, possibly run by a different principal, so it does not inherit the credential
/// either. Default ports are filled in before comparing (<see cref="Uri.Port"/>), so
/// <c>https://feed.example</c> and <c>https://feed.example:443</c> are the same origin.
/// </para>
/// </summary>
public static class UpstreamHostPin
{
    /// <summary>
    /// True only when both <paramref name="configuredUrl"/> and <paramref name="candidateUrl"/>
    /// parse as absolute URIs with the same scheme, the same host (case-insensitive) and the same
    /// effective port. Path and query are ignored. Either URL failing to parse as absolute is
    /// treated as untrusted (fail-closed). No scheme upgrade is admitted either: an
    /// <c>http://</c>-configured upstream does not extend its credential to <c>https://</c> on the
    /// same host, because that is a different port and so a different service.
    /// </summary>
    public static bool IsSameOrigin(string configuredUrl, string candidateUrl)
    {
        return Uri.TryCreate(configuredUrl, UriKind.Absolute, out var configured)
            && Uri.TryCreate(candidateUrl, UriKind.Absolute, out var candidate)
            && string.Equals(configured.Scheme, candidate.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(configured.Host, candidate.Host, StringComparison.OrdinalIgnoreCase)
            && configured.Port == candidate.Port;
    }
}
