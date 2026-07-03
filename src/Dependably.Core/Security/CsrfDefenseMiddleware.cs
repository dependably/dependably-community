using Serilog;

namespace Dependably.Security;

/// <summary>
/// Enforces CSRF defense-in-depth on management API write requests authenticated via the session
/// cookie. Checks Sec-Fetch-Site first (modern browsers), then falls back to Origin header.
///
/// Rules:
///   1. GET, HEAD, OPTIONS → skip (safe methods, no state change).
///   2. Authorization header present → skip (API tokens / protocol clients carry no CSRF exposure).
///   3. SAML ACS path (/saml/acs) → skip (cross-site POST from IdP is intentional).
///   4. Sec-Fetch-Site: same-origin or none → allow.
///   5. Sec-Fetch-Site: cross-site or same-site → reject 403.
///   6. Origin present, host matches request host → allow.
///   7. Origin present, host mismatch → reject 403.
///   8. Neither header → allow (additive layer; SameSite=Strict is the primary guard).
/// </summary>
public sealed class CsrfDefenseMiddleware
{
    private readonly RequestDelegate _next;

    public CsrfDefenseMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (ShouldCheck(ctx.Request) && IsRejected(ctx.Request, out string? reason))
        {
            Log.Warning(
                "CSRF check rejected {Method} {Path}: {Reason}",
                ctx.Request.Method,
                ctx.Request.Path,
                reason);

            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            ctx.Response.ContentType = "application/problem+json";
            await ctx.Response.WriteAsync(
                """{"type":"about:blank","title":"Forbidden","status":403,"detail":"CSRF check failed."}""",
                ctx.RequestAborted);
            return;
        }

        await _next(ctx);
    }

    // Returns true when this request should be evaluated for CSRF.
    private static bool ShouldCheck(HttpRequest req)
    {
        // Safe methods carry no state-change risk.
        if (HttpMethods.IsGet(req.Method)
            || HttpMethods.IsHead(req.Method)
            || HttpMethods.IsOptions(req.Method))
        {
            return false;
        }

        // API token / protocol clients authenticate via Authorization header and have no
        // CSRF exposure — the bearer token is not a cookie, so a cross-site form cannot
        // trigger it. Skip so protocol endpoints (npm PUT, NuGet push, etc.) are unaffected.
        if (req.Headers.ContainsKey("Authorization"))
        {
            return false;
        }

        // NuGet push authenticates via X-NuGet-ApiKey rather than Authorization.
        // NuGet CLI clients are not browsers and carry no CSRF exposure.
        if (req.Headers.ContainsKey("X-NuGet-ApiKey"))
        {
            return false;
        }

        // SAML ACS receives a cross-site POST from the IdP by design.
        return !req.Path.StartsWithSegments("/saml/acs", StringComparison.OrdinalIgnoreCase);
    }

    // Returns true (and sets reason) when the request should be blocked.
    private static bool IsRejected(HttpRequest req, out string? reason)
    {
        string? fetchSite = req.Headers["Sec-Fetch-Site"].FirstOrDefault();
        if (fetchSite is not null)
        {
            // "same-origin" and "none" (direct navigation, e.g. bookmark) are safe.
            if (string.Equals(fetchSite, "same-origin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fetchSite, "none", StringComparison.OrdinalIgnoreCase))
            {
                reason = null;
                return false;
            }

            // "cross-site" and "same-site" (different subdomain) are rejected.
            reason = $"Sec-Fetch-Site={fetchSite}";
            return true;
        }

        string? origin = req.Headers.Origin.FirstOrDefault();
        if (origin is not null)
        {
            // Origin header value is an ASCII serialization of the origin; compare only the
            // host portion against Request.Host (which ForwardedHeadersMiddleware has already
            // resolved to the client-facing host when a trusted proxy sets X-Forwarded-Host).
            if (Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
            {
                string requestHost = req.Host.Host;
                if (string.Equals(originUri.Host, requestHost, StringComparison.OrdinalIgnoreCase))
                {
                    reason = null;
                    return false;
                }

                reason = $"Origin host mismatch: origin={originUri.Host} request={requestHost}";
                return true;
            }

            // Unparseable Origin header is treated as a mismatch.
            reason = $"Origin header not parseable as absolute URI: {origin}";
            return true;
        }

        // No CSRF-related header present — allow. The session cookie's strict SameSite
        // attribute remains the primary guard; this middleware is defence-in-depth only.
        reason = null;
        return false;
    }
}
