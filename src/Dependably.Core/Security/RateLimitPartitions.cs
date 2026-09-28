using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Security;

/// <summary>
/// Partition-key derivation for the download / push rate limiters.
///
/// Bucketing strategy: prefer the validated principal identity (<c>sub</c> claim from
/// <c>httpContext.User</c>, populated by <c>UseAuthentication</c> before the rate limiter
/// runs) so that each authenticated user gets a private, NAT-safe budget. Unauthenticated
/// requests fall back to the remote IP. Raw Authorization headers are never hashed:
/// an attacker sending unique forged headers has no validated <c>sub</c> claim, so all
/// such requests land in the same IP bucket — the per-principal unlimited-bucket attack
/// is closed without collapsing legitimate users behind the same NAT into one shared budget.
/// </summary>
public static class RateLimitPartitions
{
    // Number of SHA-256 bytes taken for the token partition key prefix (6 bytes = 12 hex chars).
    // Used by GetManagementPartitionKey, which partitions management-API traffic by raw
    // Authorization header (highest priority) then by validated sub claim, then by IP.
    private const int TokenHashPrefixBytes = 6;

    /// <summary>
    /// Returns a partition key for the request, in preference order:
    /// <list type="number">
    ///   <item><c>user:{sub}</c> — the validated principal's <c>sub</c> claim (populated by
    ///     <c>UseAuthentication</c> before the rate limiter runs). Each authenticated user
    ///     gets a private budget regardless of NAT; forged Authorization headers yield no
    ///     validated claim and therefore do not produce a fresh bucket.</item>
    ///   <item><c>ip:1.2.3.4</c> — unauthenticated requests fall back to the remote IP.</item>
    ///   <item><c>unknown</c> — no authenticated principal and no resolvable IP (in-process
    ///     test probes).</item>
    /// </list>
    /// Raw Authorization headers are intentionally ignored: a forged or invalid token fails
    /// authentication, so <c>httpContext.User</c> carries no <c>sub</c> claim and the request
    /// shares the IP bucket with every other unauthenticated probe from the same address.
    /// </summary>
    public static string GetPartitionKey(
        HttpContext httpContext, int ipv6PrefixBits = IpAddressExtensions.DefaultIpv6PartitionPrefixBits)
    {
        // Validated principal: UseAuthentication runs before UseRateLimiter, so User is
        // already populated for any endpoint that opted in to an authentication scheme.
        // MapInboundClaims=false keeps the JWT "sub" as-is; NameIdentifier covers schemes
        // that map claims to the URI type.
        string? sub = httpContext.User.FindFirst("sub")?.Value
            ?? httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(sub))
        {
            return "user:" + sub;
        }

        // Unauthenticated fallback keys on the source subnet, not the full /128: an attacker with
        // a routed IPv6 /64 must not buy a fresh budget per source address (see GetRateLimitPartitionIp).
        string? ip = httpContext.GetRateLimitPartitionIp(ipv6PrefixBits);
        return !string.IsNullOrWhiteSpace(ip) ? "ip:" + ip : "unknown";
    }

    /// <summary>
    /// Partition-key derivation for the management API GlobalLimiter. Preference order:
    /// <list type="number">
    ///   <item><c>token:HHHHHHHHHHHH</c> — an API token in the Authorization header gives
    ///     each automation client its own bucket, independent of the originating IP.</item>
    ///   <item><c>user:{sub}</c> — a cookie-session SPA user is identified by the JWT
    ///     <c>sub</c> claim on <c>ctx.User</c> (populated by <c>UseAuthentication</c>/
    ///     <c>UseAuthorization</c> before the GlobalLimiter runs). Each tenant user gets a
    ///     private budget; NAT'd offices sharing one egress IP no longer collapse into a
    ///     single bucket.</item>
    ///   <item><c>ip:1.2.3.4</c> — unauthenticated requests fall back to the remote IP.</item>
    ///   <item><c>unknown</c> — no Authorization header, no authenticated principal, and no
    ///     resolvable IP (in-process test probes).</item>
    /// </list>
    /// The token and user branches only apply once <c>ctx.User.Identity.IsAuthenticated</c>
    /// is true — i.e. an endpoint-declared scheme (JWT or ApiToken) already validated the
    /// credential earlier in the pipeline (<c>UseAuthorization</c> runs before the
    /// GlobalLimiter and 401s an invalid credential before it ever reaches here). Anonymous-
    /// accessible <c>/api/v1/</c> routes never invoke a scheme at all, so without this gate a
    /// single attacker could mint unlimited fresh <c>token:</c> partitions by varying an
    /// unvalidated Authorization header — every unauthenticated request, garbage token or
    /// not, shares its caller's IP bucket instead.
    /// </summary>
    public static string GetManagementPartitionKey(
        HttpContext httpContext, int ipv6PrefixBits = IpAddressExtensions.DefaultIpv6PartitionPrefixBits)
    {
        if (httpContext.User.Identity?.IsAuthenticated == true)
        {
            // API token in Authorization header — highest priority so CI automation clients
            // get their own per-token budget regardless of whether a session is also present.
            // Reached only for a credential a scheme has already validated (see above), so
            // the raw header value here is exactly the token that authenticated this request.
            string? raw = ExtractRawTokenIfAny(httpContext);
            if (raw is not null)
            {
                byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
                return "token:" + Convert.ToHexString(hashBytes, 0, TokenHashPrefixBytes).ToLowerInvariant();
            }

            // Authenticated SPA session: MapInboundClaims=false keeps the JWT "sub" as-is;
            // the NameIdentifier fallback covers any scheme that does map to the URI claim type.
            string? sub = httpContext.User.FindFirst("sub")?.Value
                ?? httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(sub))
            {
                return "user:" + sub;
            }
        }

        string? ip = httpContext.GetRateLimitPartitionIp(ipv6PrefixBits);
        return !string.IsNullOrWhiteSpace(ip) ? "ip:" + ip : "unknown";
    }

    /// <summary>
    /// The bounded metric label for a rejected request: the <em>kind</em> of partition the
    /// request was bucketed into (<c>token</c>, <c>user</c>, <c>ip</c>, or <c>unknown</c>),
    /// never the partition key itself. The key embeds a token-hash prefix, a user id, or a
    /// caller-controlled source address, so emitting it as a metric attribute mints one time
    /// series per distinct caller — an attacker varying source IPs against a rate-limited
    /// route would grow the TSDB working set without bound. The identity of a throttled
    /// caller belongs on the audit record and the log line, where high cardinality is cheap;
    /// the metric answers "which class of partition is being throttled, how often". A rejection by
    /// the tenant dimension (<see cref="GetTenantPartitionKey"/>) is labelled <c>tenant</c> by the
    /// rejection callback instead, whichever of the two tenant partitions refused it.
    /// </summary>
    public static string GetMetricLabel(
        HttpContext httpContext, int ipv6PrefixBits = IpAddressExtensions.DefaultIpv6PartitionPrefixBits)
    {
        string key = GetPartitionKey(httpContext, ipv6PrefixBits);
        int separator = key.IndexOf(':', StringComparison.Ordinal);
        return separator < 0 ? "unknown" : key[..separator];
    }

    /// <summary>
    /// The three ways the GlobalLimiter treats a request. The GlobalLimiter runs for EVERY
    /// request in addition to any endpoint policy, so its job is to be a fail-closed backstop
    /// without double-counting against endpoints that already govern themselves.
    /// </summary>
    public enum GlobalScope
    {
        /// <summary>The endpoint declares its own <c>[EnableRateLimiting]</c> / <c>[DisableRateLimiting]</c>
        /// policy (or is a Swagger-UI docs asset): the GlobalLimiter defers with NoLimiter so it never
        /// stacks on top of download/push/metadata/login/etc.</summary>
        Deferred,

        /// <summary>An authenticated management surface (<c>/api/v1/*</c>, non-docs) with no endpoint
        /// policy: per-principal management default.</summary>
        ManagementApi,

        /// <summary>Any other surface with no endpoint policy — protocol routes that carry no explicit
        /// rate-limit attribute. Default-deny: a per-IP default limit rather than NoLimiter, so a newly
        /// added unmetered route is never entirely unbounded.</summary>
        ProtocolDefault,
    }

    /// <summary>
    /// Classifies a request for the GlobalLimiter. Pure and side-effect free so the default-deny
    /// posture is unit-testable without standing up the whole limiter pipeline.
    ///
    /// <para>
    /// Order matters. Swagger docs are exempt. The <c>/api/v1/</c> management surface ALWAYS takes
    /// the management default — even when the endpoint also declares its own policy (login/anon/…):
    /// the management global is a per-principal ceiling that deliberately stacks on top of the
    /// endpoint policy, so an authenticated principal can't exhaust the management plane by pounding
    /// one loosely-capped endpoint. Outside <c>/api/v1/</c>, an endpoint's own policy defers the
    /// global (protocol download/metadata/push must not be double-counted by the default).
    /// </para>
    ///
    /// <para>
    /// The default-deny <see cref="GlobalScope.ProtocolDefault"/> limit applies ONLY to a routed
    /// MVC controller action (a registry endpoint carries a <see cref="ControllerActionDescriptor"/>)
    /// that declares no policy. The frontend/static plane — the embedded SPA served by
    /// <c>UseStaticFiles</c> (index.html, hashed <c>/assets/*</c> bundles, favicon, fonts, css; no
    /// endpoint at all at limiter time), the Swagger <c>/docs</c> assets, and the <c>MapFallback</c>
    /// SPA routes (an endpoint with no controller-action descriptor) — is NOT the abuse surface and
    /// must never consume the protocol abuse budget: a browser loading the dashboard fires dozens of
    /// asset requests per navigation from one IP, so a shared per-IP protocol cap would 429 the SPA
    /// and break login. Those all defer. A brand-new unmetered registry controller action still hits
    /// the default (and the reflection-based compliance gate still fails the build for it).
    /// </para>
    /// </summary>
    public static GlobalScope ClassifyGlobalScope(HttpContext httpContext)
    {
        string? path = httpContext.Request.Path.Value;

        if (path is not null
            && (path.StartsWith("/api/v1/docs/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/api/v1/docs", StringComparison.OrdinalIgnoreCase)))
        {
            // Swagger UI assets are IP-allowlisted, not API traffic, and must not consume budget.
            return GlobalScope.Deferred;
        }

        if (IsManagementApiPath(path))
        {
            // Management plane: the per-principal ceiling applies regardless of any endpoint policy.
            return GlobalScope.ManagementApi;
        }

        var endpoint = httpContext.GetEndpoint();

        // An endpoint that governs itself (download/metadata/push/anon) defers so the default never
        // stacks on top of it.
        if (endpoint?.Metadata.GetMetadata<EnableRateLimitingAttribute>() is not null
            || endpoint?.Metadata.GetMetadata<DisableRateLimitingAttribute>() is not null)
        {
            return GlobalScope.Deferred;
        }

        // Default-deny, but ONLY for a routed protocol controller action. Static-file serving (no
        // endpoint) and non-controller endpoints (the SPA MapFallback) are the frontend plane, not
        // the registry abuse surface, and must not be throttled by the protocol default.
        return endpoint?.Metadata.GetMetadata<ControllerActionDescriptor>() is not null
            ? GlobalScope.ProtocolDefault
            : GlobalScope.Deferred;
    }

    /// <summary>Partition-key prefix for the per-tenant budget.</summary>
    public const string TenantPartitionPrefix = "tenant:";

    /// <summary>Partition-key prefix for a <c>downloads_throttled</c> tenant.</summary>
    public const string TenantThrottledPartitionPrefix = "tenant-throttled:";

    /// <summary>
    /// The tenant-dimension partition for a request, or null when the tenant limiter does not apply
    /// to it. It applies only to a protocol controller action (<see cref="IsProtocolControllerRequest"/>)
    /// on a resolved tenant: never the
    /// management plane, the frontend and docs assets, or the exempt operator probes
    /// (<c>/health</c>, <c>/ready</c>, <c>/metrics</c>, <c>/version</c>, <c>/edge/status</c>), which
    /// single mode resolves to the one tenant and must stay reachable. Under a
    /// <c>downloads_throttled</c> usage posture the key is <c>tenant-throttled:{id}</c>, whether or
    /// not the budget is on; otherwise it is <c>tenant:{id}</c> when
    /// <paramref name="tenantBudgetEnabled"/>, else null. The key carries the org id, so it is for the
    /// limiter and the denial audit only — never a metric attribute.
    /// </summary>
    public static string? GetTenantPartitionKey(HttpContext httpContext, bool tenantBudgetEnabled)
    {
        if (httpContext.Items[Infrastructure.TenantContext.HttpItemsKey] is not Infrastructure.TenantContext
            {
                IsTenant: true, TenantId: { Length: > 0 } tenantId,
            } tenant)
        {
            return null;
        }

        bool throttled = tenant.UsagePosture == Infrastructure.Usage.UsagePostures.DownloadsThrottled;
        return !IsTenantProtocolRequest(httpContext) ? null
            : throttled ? TenantThrottledPartitionPrefix + tenantId
            : tenantBudgetEnabled ? TenantPartitionPrefix + tenantId
            : null;
    }

    // A protocol controller action, outside the exempt operator probes.
    private static bool IsTenantProtocolRequest(HttpContext httpContext) =>
        !Infrastructure.TenantStatusEnforcementMiddleware.IsExemptPath(httpContext.Request.Path)
        && IsProtocolControllerRequest(httpContext);

    /// <summary>
    /// True when the request is routed to a registry protocol controller action — one of the
    /// controllers <see cref="Infrastructure.Edge.EdgeProtocolSurface"/> classifies as protocol,
    /// the explicit, gate-enforced list every controller must be sorted into. The classification
    /// is by endpoint, not path prefix: a management controller routed outside <c>/api/v1/</c>
    /// (SAML's <c>/saml/acs</c> sign-in POST) is management plane, and a request that routed to no
    /// controller (the SPA, static assets, a 404) is neither. Needs the routed endpoint, so it
    /// is only meaningful after <c>UseRouting</c>; the rate limiter and the tenant status gate
    /// both run after it.
    /// </summary>
    public static bool IsProtocolControllerRequest(HttpContext httpContext) =>
        httpContext.GetEndpoint()?.Metadata.GetMetadata<ControllerActionDescriptor>() is { ControllerTypeInfo: { } controller }
        && Infrastructure.Edge.EdgeProtocolSurface.IsProtocol(controller.AsType());

    /// <summary>
    /// True for a request under the management API prefix (<c>/api/v1/</c>) — the same
    /// path-based rule <see cref="ClassifyGlobalScope"/> uses to route management traffic to the
    /// per-principal ceiling regardless of endpoint policy. Shared here so any other caller
    /// needing a management-vs-protocol plane distinction (e.g.
    /// <c>TenantStatusEnforcementMiddleware</c>'s read-only write gate) reuses this one
    /// classification instead of growing its own ad-hoc prefix check that can drift from it.
    /// </summary>
    public static bool IsManagementApiPath(string? path) =>
        path is not null && path.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractRawTokenIfAny(HttpContext ctx)
    {
        string? auth = ctx.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(auth))
        {
            return null;
        }

        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return auth["Bearer ".Length..].Trim();
        }

        if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                string encoded = auth["Basic ".Length..].Trim();
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                int colon = decoded.IndexOf(':');
                return colon >= 0 ? decoded[(colon + 1)..] : null;
            }
            catch
            {
                return null;
            }
        }

        return null;
    }
}
