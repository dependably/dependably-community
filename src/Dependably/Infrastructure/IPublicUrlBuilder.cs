namespace Dependably.Infrastructure;

/// <summary>
/// Builds public URLs from the inbound request context. Centralizes the scheme/host derivation
/// previously scattered across protocol controllers (npm tarball base, NuGet service-index base,
/// SAML metadata/ACS, install snippets, invite links).
///
/// Scheme precedence: <c>BASE_URL</c>'s scheme when set (e.g. https behind a TLS-terminating
/// proxy), otherwise the request's scheme. Host always comes from the inbound request — this is
/// what makes transparent intercept work, where the host the client reached us on is the
/// host we must echo back in metadata documents.
/// </summary>
public interface IPublicUrlBuilder
{
    /// <summary>Returns "{scheme}://{host}" for the inbound request.</summary>
    string BaseUrl(HttpContext context);

    /// <summary>Returns "{scheme}://{host}{path}" for the inbound request. <paramref name="path"/> must start with "/".</summary>
    string Absolute(HttpContext context, string path);

    /// <summary>
    /// True when BASE_URL is configured with an https scheme, indicating the operator
    /// has declared this an HTTPS deployment (e.g. behind a TLS-terminating proxy).
    /// </summary>
    bool IsHttpsDeployment { get; }

    /// <summary>
    /// Returns CookieOptions for a session cookie. Secure is set when either the runtime
    /// request is HTTPS or the operator declared BASE_URL as https — blending both signals
    /// so neither proxy misconfiguration nor stale config causes a silent regression.
    /// SameSite defaults to Strict; pass Lax for SAML flows where the IdP redirect must
    /// deliver the cookie on the first cross-site request.
    /// </summary>
    CookieOptions SessionCookieOptions(HttpContext ctx, SameSiteMode sameSite = SameSiteMode.Strict);
}
