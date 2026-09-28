using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dependably.Security;

/// <summary>
/// Decides, before the rate limiter runs, whether a protocol request to a resolved tenant is
/// traffic that tenant serves as its own, and marks it under
/// <see cref="TenantRateLimiter.NotTenantTrafficItemKey"/> when it is not. A marked request is
/// never charged to the tenant budget (<c>tenant:{id}</c> or <c>tenant-throttled:{id}</c>); it is
/// still held to every per-caller limit.
///
/// <para>
/// A request is the tenant's own traffic when the org serves it: any request while the org
/// allows anonymous pull, since the org serves it anonymously and pays its egress; otherwise
/// only a request carrying a live credential of that org. A request with no credential, an
/// unresolvable one, or another org's credential, to an org that refuses anonymous pull, is one
/// the org will refuse, and charging it would let any anonymous source drain the org's window
/// and turn its own clients away with 429.
/// </para>
///
/// <para>
/// Charging is the default. The marker is an exemption, so a request that never passes this
/// middleware, or whose lookups fail, is charged exactly as it would be without it. A principal
/// already authenticated for this tenant (an <c>[Authorize]</c>d write) is charged without any
/// lookup. A credential resolved here is recorded on the request for
/// <see cref="TokenAuthExtensions.ResolveTokenAsync(HttpRequest, TokenRepository, CancellationToken)"/>
/// to reuse, so a valid token costs no second resolution. This middleware never records an
/// authentication denial: the handler's own resolution remains the one place that does.
/// </para>
///
/// <para>
/// Registered after <c>UseRouting</c> (the protocol classification reads the routed endpoint)
/// and <c>UseAuthorization</c> (so a validated principal is visible and a refused write never
/// reaches it), immediately before <c>UseRateLimiter</c>.
/// </para>
/// </summary>
public sealed class TenantBudgetAttributionMiddleware
{
    /// <summary>
    /// The <c>HttpContext.Items</c> key a live same-org credential resolved here is recorded
    /// under, as a <see cref="PreResolvedToken"/>.
    /// </summary>
    internal const string ResolvedTokenItemKey = "Dependably.RateLimit.PreResolvedToken";

    private readonly RequestDelegate _next;
    private readonly ILogger<TenantBudgetAttributionMiddleware> _logger;

    public TenantBudgetAttributionMiddleware(RequestDelegate next, ILogger<TenantBudgetAttributionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    /// <summary>A credential this middleware resolved, and the raw value it was resolved from.</summary>
    internal sealed record PreResolvedToken(string RawToken, TokenRecord Token);

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Items[TenantContext.HttpItemsKey] is TenantContext { IsTenant: true, TenantId: { Length: > 0 } tenantId }
            && RateLimitPartitions.IsProtocolControllerRequest(context)
            && !TenantStatusEnforcementMiddleware.IsExemptPath(context.Request.Path)
            && !IsAuthenticatedFor(context, tenantId)
            && !await IsServedAsOwnTrafficAsync(context, tenantId))
        {
            context.Items[TenantRateLimiter.NotTenantTrafficItemKey] = true;
        }

        await _next(context);
    }

    private static bool IsAuthenticatedFor(HttpContext context, string tenantId) =>
        context.User.Identity?.IsAuthenticated == true
        && (string.Equals(context.User.FindFirst("tid")?.Value, tenantId, StringComparison.Ordinal)
            || string.Equals(context.User.FindFirst("org_id")?.Value, tenantId, StringComparison.Ordinal));

    // Every credential shape a protocol handler resolves against the org: the Authorization forms
    // TokenAuthExtensions.ResolveTokenAsync reads (Bearer, Basic, and the bare Cargo/Hex form),
    // read through that resolver's own extractor so the two cannot drift, then the NuGet API key.
    // A credential the handlers would resolve but this method missed would exempt the org's own
    // traffic, including from its throttled budget.
    private static string? ExtractCredential(HttpRequest request)
    {
        string? auth = request.Headers.Authorization.FirstOrDefault();
        string? raw = auth is null ? null : TokenAuthExtensions.ExtractAuthorizationToken(auth);
        if (!string.IsNullOrEmpty(raw))
        {
            return raw;
        }

        string? apiKey = request.Headers["X-NuGet-ApiKey"].FirstOrDefault();
        return string.IsNullOrEmpty(apiKey) ? null : apiKey;
    }

    // True when the org serves this request as its own. Any failure answers true, so the request
    // is charged as it would be with no attribution at all.
    private async Task<bool> IsServedAsOwnTrafficAsync(HttpContext context, string tenantId)
    {
        var ct = context.RequestAborted;
        try
        {
            var orgs = context.RequestServices.GetRequiredService<OrgRepository>();
            var settings = await orgs.GetSettingsAsync(tenantId, ct);
            if (settings is null || settings.AnonymousPull)
            {
                return true;
            }

            string? raw = ExtractCredential(context.Request);
            if (raw is null)
            {
                return false;
            }

            var tokens = context.RequestServices.GetRequiredService<TokenRepository>();
            var token = await tokens.ResolveAsync(raw, ct);
            if (token is null || !string.Equals(token.OrgId, tenantId, StringComparison.Ordinal))
            {
                return false;
            }

            context.Items[ResolvedTokenItemKey] = new PreResolvedToken(raw, token);
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Tenant budget attribution failed with {ExceptionType}; charging the request to tenant {TenantId}",
                ex.GetType().Name, tenantId);
            return true;
        }
    }
}
