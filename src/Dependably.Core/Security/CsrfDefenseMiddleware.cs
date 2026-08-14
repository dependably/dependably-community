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
///   8. Neither header, a session cookie is present, and the body is one a cross-site HTML form
///      can produce → reject 403.
///   9. Neither header, anything else → allow.
///
/// Rules 8 and 9 split what would otherwise be a blanket allow, because SameSite is scoped to the
/// registrable domain rather than the exact host: a page on a sibling tenant subdomain is
/// <em>same-site</em>, so a SameSite=Strict session cookie is attached to its requests. Rule 5 is
/// what closes that for browsers that send Fetch Metadata; a client that sends neither header
/// falls back to no cross-origin signal at all.
///
/// The residual is bounded by what such a client can actually send. Without CORS approval — and
/// the management policy allowlists exactly one origin — a browser can only reach this endpoint
/// cross-site through an HTML form, whose body is limited to
/// <c>application/x-www-form-urlencoded</c>, <c>multipart/form-data</c>, or <c>text/plain</c>;
/// anything else (a JSON body, a custom header) is a preflighted request the policy refuses
/// before it is ever sent. Rule 8 therefore rejects exactly the shape the attack needs, and only
/// when the request actually carries the credential the attack rides — a request with no session
/// cookie has nothing to confuse the deputy with, so an anonymous or mis-targeted upload still
/// gets its real answer (405/401) rather than a misleading CSRF refusal. Rule 9 keeps the
/// JSON-bodied scripted callers working: none of them is a CSRF vector either, since nothing
/// attaches their cookies for them.
/// </summary>
public sealed class CsrfDefenseMiddleware
{
    // The session cookie a browser would attach to a cross-site request on the victim's behalf.
    // Minted by the management-plane auth controllers; named here because Core owns this
    // middleware and must not take a dependency on that assembly.
    private const string SessionCookieName = "dependably_session";

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

        // Neither header. A form-submittable content type on a request that carries the session
        // cookie is the one shape a browser can aim at this endpoint from another origin without
        // a CORS preflight, and it is indistinguishable from a cross-site form post — refuse it.
        // Everything else is either unreachable cross-site from a browser or carries no cookie
        // for a cross-site page to spend, so it stays allowed.
        if (req.Cookies.ContainsKey(SessionCookieName) && IsFormSubmittableContentType(req.ContentType))
        {
            reason = $"No Sec-Fetch-Site or Origin on a cookie-authenticated form request: content-type={req.ContentType}";
            return true;
        }

        reason = null;
        return false;
    }

    // The three content types an HTML form can produce (the "simple request" set that needs no
    // CORS preflight). Matched on the media type only — parameters such as a multipart boundary
    // or a charset follow a ';' and are ignored.
    private static bool IsFormSubmittableContentType(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
        {
            // A bodyless state-changing request cannot carry form fields, and a body with no
            // declared type is not something a form produces.
            return false;
        }

        var mediaType = contentType.AsSpan();
        int semicolon = mediaType.IndexOf(';');
        if (semicolon >= 0)
        {
            mediaType = mediaType[..semicolon];
        }

        mediaType = mediaType.Trim();
        return mediaType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals("text/plain", StringComparison.OrdinalIgnoreCase);
    }
}
