namespace Dependably.Infrastructure;

/// <summary>
/// Default <see cref="IPublicUrlBuilder"/>. Reads scheme from <c>BASE_URL</c> when configured
/// (preserves https behind a TLS-terminating proxy that forwards http internally), falling back
/// to the request's own scheme. Host is always the inbound request host so transparent-intercept
/// deployments echo back the impersonated registry hostname.
/// </summary>
public sealed class RequestPublicUrlBuilder : IPublicUrlBuilder
{
    private readonly string? _configuredScheme;
    private readonly bool _requireSecureCookies;

    public RequestPublicUrlBuilder(IConfiguration config)
    {
        _configuredScheme = config["BASE_URL"] is { } bu && Uri.TryCreate(bu, UriKind.Absolute, out var uri)
            ? uri.Scheme
            : null;
        _requireSecureCookies = string.Equals(config["REQUIRE_SECURE_COOKIES"], "true", StringComparison.OrdinalIgnoreCase);
    }

    public string BaseUrl(HttpContext context) => $"{Scheme(context)}://{context.Request.Host}";

    public string Absolute(HttpContext context, string path)
    {
        return string.IsNullOrEmpty(path)
            ? BaseUrl(context)
            : path[0] != '/'
            ? throw new ArgumentException("Path must start with '/'.", nameof(path))
            : $"{Scheme(context)}://{context.Request.Host}{path}";
    }

    public bool IsHttpsDeployment =>
        string.Equals(_configuredScheme, "https", StringComparison.OrdinalIgnoreCase);

    public CookieOptions SessionCookieOptions(HttpContext ctx, SameSiteMode sameSite = SameSiteMode.Strict) =>
        new()
        {
            HttpOnly = true,
            // REQUIRE_SECURE_COOKIES pins Secure=true unconditionally so an operator-declared
            // HTTPS-only deployment never ships a session/MFA/device cookie without Secure, even
            // if a misconfigured proxy or a downgraded request makes ctx.Request.IsHttps false.
            Secure = _requireSecureCookies || ctx.Request.IsHttps || IsHttpsDeployment
                     || ClaimsForwardedHttps(ctx.Request),
            SameSite = sameSite,
            IsEssential = true,
        };

    /// <summary>
    /// True when the request carries <c>X-Forwarded-Proto: https</c>, whether or not that header
    /// was trusted.
    ///
    /// <para>The three signals above can all be false in one plausible, entirely accidental
    /// deployment: <c>TRUSTED_PROXIES</c> unset is the documented fail-closed default, which makes
    /// <c>ForwardedHeadersMiddleware</c> discard <c>X-Forwarded-Proto</c> so
    /// <c>Request.IsHttps</c> describes the plaintext proxy-to-app hop rather than the browser's
    /// TLS one; <c>BASE_URL</c> is optional; and <c>REQUIRE_SECURE_COOKIES</c> is opt-in. The
    /// result is a session cookie issued without <c>Secure</c> to a browser that is on HTTPS —
    /// so it will also be attached to any plaintext request an attacker can provoke to the same
    /// host. Reading the raw header closes that, and it is safe to read untrusted <em>for this
    /// decision specifically</em>: the only thing a forged header can do is add the
    /// <c>Secure</c> attribute to the forger's own cookies, which restricts them rather than
    /// granting anything. It is deliberately not used for URL building, where a forged value
    /// would be reflected back to other callers.</para>
    /// </summary>
    private static bool ClaimsForwardedHttps(HttpRequest request)
    {
        if (!request.Headers.TryGetValue("X-Forwarded-Proto", out var values))
        {
            return false;
        }

        // A chained proxy appends, so the header can be "https, http"; the left-most entry is the
        // scheme the client actually used, which is the hop the cookie has to survive.
        foreach (string? value in values)
        {
            if (value is null)
            {
                continue;
            }

            var first = value.AsSpan();
            int comma = first.IndexOf(',');
            if (comma >= 0)
            {
                first = first[..comma];
            }

            if (first.Trim().Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private string Scheme(HttpContext context) => _configuredScheme ?? context.Request.Scheme;
}
