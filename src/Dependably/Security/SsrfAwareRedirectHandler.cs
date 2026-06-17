using System.Net;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;

namespace Dependably.Security;

/// <summary>
/// A <see cref="DelegatingHandler"/> that follows HTTP redirects while validating each
/// redirect target URL through <see cref="IUpstreamUrlValidator.IsAllowedAsync"/> before
/// opening a connection. The underlying <see cref="System.Net.Http.SocketsHttpHandler"/>
/// must be configured with <c>AllowAutoRedirect = false</c> so that this handler controls
/// every hop rather than delegating silently to the transport layer.
///
/// For each 3xx response the handler:
///   1. Extracts the <c>Location</c> header and resolves it against the request URI.
///   2. Calls <see cref="IUpstreamUrlValidator.IsAllowedAsync"/> — which re-resolves
///      the target host via DNS and checks the result against <see cref="SsrfGuard"/>.
///   3. Throws <see cref="SsrfBlockedException"/> if the target is in a blocked range,
///      or proceeds with a new GET request if allowed.
///
/// This is a defense-in-depth layer: an upstream configured as
/// <c>https://attacker.com/</c> that returns <c>302 Location: http://169.254.169.254/…</c>
/// is blocked here before the TCP connection to the metadata endpoint is attempted.
/// The <see cref="SsrfConnectCallback"/> remains as the authoritative gate at the
/// socket level.
///
/// Org attribution: callers that know the org context set <see cref="OrgIdOption"/> on the
/// outgoing <see cref="HttpRequestMessage"/> so that blocked-redirect audit events carry the
/// tenant identifier. When the option is absent the audit event is recorded without an org.
/// </summary>
public sealed class SsrfAwareRedirectHandler : DelegatingHandler
{
    private readonly IUpstreamUrlValidator _urlValidator;

    /// <summary>Maximum number of redirects to follow before returning the last response.</summary>
    public const int MaxRedirects = 3;

    /// <summary>
    /// Request option key for propagating org context into the handler. Set on the
    /// <see cref="HttpRequestMessage"/> by callers that know the tenant identifier.
    /// </summary>
    public static readonly HttpRequestOptionsKey<string?> OrgIdOption =
        new("SsrfAwareRedirectHandler.OrgId");

    /// <summary>
    /// Status codes that carry a <c>Location</c> header this handler will follow.
    /// 307 and 308 preserve the original method; all others are followed as GET.
    /// </summary>
    private static readonly HashSet<HttpStatusCode> RedirectCodes =
    [
        HttpStatusCode.MovedPermanently,   // 301
        HttpStatusCode.Found,              // 302
        HttpStatusCode.SeeOther,           // 303
        HttpStatusCode.TemporaryRedirect,  // 307
        HttpStatusCode.PermanentRedirect,  // 308
    ];

    public SsrfAwareRedirectHandler(IUpstreamUrlValidator urlValidator)
    {
        _urlValidator = urlValidator;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Read org context from request options (set by the caller when available).
        request.Options.TryGetValue(OrgIdOption, out string? orgId);

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        for (int hop = 0; hop < MaxRedirects && RedirectCodes.Contains(response.StatusCode); hop++)
        {
            var location = response.Headers.Location;
            if (location is null)
            {
                break;
            }

            // Resolve relative Location URIs against the request URI (RFC 7231 §6.4).
            var redirectUri = location.IsAbsoluteUri
                ? location
                : new Uri(request.RequestUri!, location);

            // Validate the redirect target before connecting. Throws SsrfBlockedException
            // when the resolved host falls inside a blocked range; throws on DNS failure
            // (fails closed). This is the defense-in-depth layer that catches redirect-based
            // SSRF attacks targeting cloud metadata endpoints.
            if (!await _urlValidator.IsAllowedAsync(redirectUri.AbsoluteUri, orgId, cancellationToken)
                    .ConfigureAwait(false))
            {
                response.Dispose();
                DependablyMeter.UpstreamUrlBlocks.Add(1);
                throw new SsrfBlockedException(redirectUri.AbsoluteUri);
            }

            response.Dispose();

            var next = BuildRedirectRequest(request, response.StatusCode, redirectUri, orgId);
            response = await base.SendAsync(next, cancellationToken).ConfigureAwait(false);
            request = next;
        }

        return response;
    }

    // Builds the HttpRequestMessage for a redirect hop. Preserves the original method for
    // 307/308 (method-preserving redirects); uses GET for all other 3xx codes. Propagates
    // org context and safe headers from the original request, excluding Authorization.
    private static HttpRequestMessage BuildRedirectRequest(
        HttpRequestMessage original, HttpStatusCode statusCode, Uri redirectUri, string? orgId)
    {
        // 307 Temporary Redirect and 308 Permanent Redirect preserve the original
        // method and body; all other redirect codes (301, 302, 303) switch to GET.
        var method = statusCode is HttpStatusCode.TemporaryRedirect
                  or HttpStatusCode.PermanentRedirect
            ? original.Method
            : HttpMethod.Get;

        var next = new HttpRequestMessage(method, redirectUri);

        // Propagate org context to the next hop's request options.
        if (orgId is not null)
        {
            next.Options.Set(OrgIdOption, orgId);
        }

        // Copy headers that are safe to forward across redirects, excluding
        // Authorization to prevent credential leakage to a third-party origin.
        foreach (var header in original.Headers)
        {
            if (!string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
            {
                next.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return next;
    }
}
