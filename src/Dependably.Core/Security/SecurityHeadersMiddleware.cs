namespace Dependably.Security;

/// <summary>
/// Adds HTTP security headers to every response (OWASP A05).
/// Registered early in Program.cs — after UseForwardedHeaders (so the HSTS decision
/// sees the client-facing scheme) but before any middleware that writes a response.
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private const string Csp =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'";

    // sha256 pins the inline theme-bootstrap in wwwroot/index.html. Must be regenerated
    // (browser dev tools report the required hash on CSP violation) if that script body changes.
    private const string FrontendCsp =
        "default-src 'self'; " +
        "script-src 'self' 'sha256-xF8s42kh/0+SuaBY4Q15LZGGKtszNqP3TLZJtgGeG0g='; " +
        "style-src 'self'; " +
        "font-src 'self'; " +
        "img-src 'self' data:; " +
        "connect-src 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'";

    // Registry responses are consumed by package managers, but the PEP 503 simple
    // index is HTML a browser will render. A locked-down policy is correct for the
    // whole surface: binary artifacts ignore it, and the index pages carry only
    // anchor links, so 'none' costs nothing and closes the XSS vector.
    // frame-ancestors and form-action are stated explicitly because they do not
    // fall back to default-src.
    private const string RegistryCsp = "default-src 'none'; frame-ancestors 'none'; form-action 'none'";

    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var headers = ctx.Response.Headers;
        string path = ctx.Request.Path.Value ?? "";

        // Applied to all responses — must be set before _next so they're present even
        // when the response body starts writing inside the handler.
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()";

        // HSTS — only when the client-facing connection is TLS. Request.IsHttps reflects
        // X-Forwarded-Proto from a trusted reverse proxy because ForwardedHeadersMiddleware
        // runs earlier in the pipeline (and consumes the raw header), and is also correct
        // when TLS terminates at Kestrel directly.
        if (ctx.Request.IsHttps)
        {
            headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";
        }

        // Per-path headers set before _next so they're not affected by response-started guard
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
        {
            headers.ContentSecurityPolicy = Csp;
        }
        else if (IsRegistryPath(path))
        {
            headers.CacheControl = "no-store";
            headers.ContentSecurityPolicy = RegistryCsp;
        }
        else
        {
            headers.ContentSecurityPolicy = FrontendCsp;
        }

        await _next(ctx);
    }

    // Registry routes are always root-level — tenancy is host/subdomain-resolved, never
    // path-prefixed — so anchor on the prefix. A substring match would wrongly classify the
    // SPA route /package/npm/... as registry (it contains "/npm/") and serve it the locked-down
    // RegistryCsp, which blocks the SPA bundle and renders a blank page.
    private static bool IsRegistryPath(string path) =>
        path.StartsWith("/simple/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/packages/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/npm/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/nuget/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/pypi/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/v2/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/maven/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/rpm/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/cargo/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/go/", StringComparison.OrdinalIgnoreCase);
}
