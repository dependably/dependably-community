namespace Dependably.Security;

/// <summary>
/// Adds HTTP security headers to every response (OWASP A05).
/// Must be registered first in Program.cs, before all other middleware.
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
        "style-src 'self' https://fonts.googleapis.com; " +
        "font-src https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'";

    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var headers = ctx.Response.Headers;
        var path = ctx.Request.Path.Value ?? "";

        // Applied to all responses — must be set before _next so they're present even
        // when the response body starts writing inside the handler.
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()";

        // HSTS — only when TLS is confirmed via reverse proxy
        if (ctx.Request.Headers["X-Forwarded-Proto"] == "https")
            headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";

        // Per-path headers set before _next so they're not affected by response-started guard
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            headers.ContentSecurityPolicy = Csp;
        else if (IsRegistryPath(path))
            headers.CacheControl = "no-store";
        else
            headers.ContentSecurityPolicy = FrontendCsp;

        await _next(ctx);
    }

    private static bool IsRegistryPath(string path) =>
        path.Contains("/simple/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/packages/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/npm/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/nuget/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/pypi/", StringComparison.OrdinalIgnoreCase);
}
