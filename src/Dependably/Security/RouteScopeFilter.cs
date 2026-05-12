using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Dependably.Infrastructure;

namespace Dependably.Security;

/// <summary>
/// Global authorization filter enforcing the scope claim on JWTs.
///
/// Scopes:
///   - <c>tenant</c> — user JWTs scoped to one tenant. Allowed on tenant routes only.
///   - <c>system</c> — system_admin JWTs (multi mode). Allowed on system routes only.
///
/// Phase 2 behavior (strict): every authenticated /api/v1/ request must carry a <c>scope</c>
/// claim. Missing claim → 401. Wrong scope for the route → 404 (mirrors the existing
/// 404-not-403 stance from OrgAccessGuard so cross-realm probing reveals nothing). The filter
/// is the structural realm boundary; per-controller <c>OrgAccessGuard.AuthorizeCapAsync</c>
/// calls remain as belt-and-suspenders for capability-within-tenant checks.
///
/// Routes excluded from scope enforcement:
///   - <c>[AllowAnonymous]</c> endpoints (login, accept-invite, bootstrap).
///   - Anything outside <c>/api/v1/</c> — package-manager routes use Bearer tokens with their
///     own per-controller resolution.
/// </summary>
public sealed class RouteScopeFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var endpoint = context.HttpContext.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null) return;

        var path = context.HttpContext.Request.Path.Value ?? "";

        // Bootstrap is the only [AllowAnonymous] /api/v1/ route; the metadata check above
        // already lets it pass. This explicit guard is defense-in-depth.
        if (path.StartsWith("/api/v1/bootstrap", StringComparison.OrdinalIgnoreCase)) return;

        // Only enforce scope on management API routes; leave package-manager routes (/o/{slug}/...,
        // /simple/, /npm/, /nuget/) to their existing per-controller token resolution.
        if (!path.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase)) return;

        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true) return;

        var scope = user.FindFirst("scope")?.Value;

        // Phase 2: missing scope claim = unauthorized. All freshly-issued JWTs (Phase 1+) carry
        // scope; tokens older than 8h have already expired by the time Phase 2 ships.
        if (scope is null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var ctx = context.HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;

        if (path.StartsWith("/api/v1/system/", StringComparison.OrdinalIgnoreCase))
        {
            // System routes require scope=system AND apex context.
            if (scope != "system" || ctx is null || !ctx.IsApex)
            {
                context.Result = new NotFoundResult();
                return;
            }
            return;
        }

        // Tenant routes (everything else under /api/v1/) require scope=tenant AND tid match.
        if (scope != "tenant")
        {
            context.Result = new NotFoundResult();
            return;
        }

        // tid must match the resolved tenant. When no TenantContext is wired (e.g. bare unit
        // tests), allow through — per-controller OrgAccessGuard remains the safety net.
        if (ctx is null) return;

        if (!ctx.IsTenant) { context.Result = new NotFoundResult(); return; }

        var tid = user.FindFirst("tid")?.Value;
        if (tid is not null && tid != ctx.TenantId)
        {
            context.Result = new NotFoundResult();
            return;
        }
    }
}
