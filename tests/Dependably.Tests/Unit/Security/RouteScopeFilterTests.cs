using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Unit tests for <see cref="RouteScopeFilter"/> — the global JWT scope enforcement filter.
/// Tests cover every branch: AllowAnonymous bypass, non-/api/v1/ bypass, bootstrap bypass,
/// unauthenticated passthrough, missing scope → 401, and correct/wrong scope → 404 / pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RouteScopeFilterTests
{
    private static AuthorizationFilterContext BuildContext(
        string path,
        ClaimsPrincipal? user = null,
        TenantContext? tenantContext = null,
        IAllowAnonymous? allowAnonymous = null)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = path;

        if (user is not null)
            httpContext.User = user;

        if (tenantContext is not null)
            httpContext.Items[TenantContext.HttpItemsKey] = tenantContext;

        if (allowAnonymous is not null)
        {
            httpContext.SetEndpoint(new Endpoint(
                null,
                new EndpointMetadataCollection(allowAnonymous),
                "test"));
        }

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        return new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());
    }

    private static ClaimsPrincipal AuthenticatedUser(params Claim[] claims)
    {
        var allClaims = new List<Claim>(claims);
        return new ClaimsPrincipal(new ClaimsIdentity(allClaims, "jwt"));
    }

    // ── Bypass branches ────────────────────────────────────────────────────────

    [Fact]
    public void OnAuthorization_AllowAnonymousEndpoint_SkipsFilter()
    {
        var filter = new RouteScopeFilter();
        var context = BuildContext(
            "/api/v1/settings",
            allowAnonymous: new AllowAnonymousAttribute());

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void OnAuthorization_NonApiV1Path_SkipsFilter()
    {
        var filter = new RouteScopeFilter();
        var context = BuildContext("/npm/pkg");

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void OnAuthorization_BootstrapPath_SkipsFilter()
    {
        var filter = new RouteScopeFilter();
        var context = BuildContext("/api/v1/bootstrap/anything");

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void OnAuthorization_UnauthenticatedUser_SkipsFilter()
    {
        var filter = new RouteScopeFilter();
        // Default DefaultHttpContext has an unauthenticated user (no identity / IsAuthenticated=false)
        var context = BuildContext("/api/v1/settings");

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    // ── Missing scope → 401 ───────────────────────────────────────────────────

    [Fact]
    public void OnAuthorization_NoScopeClaim_Returns401()
    {
        var filter = new RouteScopeFilter();
        // Authenticated user with no "scope" claim
        var user = AuthenticatedUser(new Claim("sub", "user-1"));
        var context = BuildContext("/api/v1/settings", user: user);

        filter.OnAuthorization(context);

        Assert.IsType<UnauthorizedResult>(context.Result);
    }

    // ── System routes ─────────────────────────────────────────────────────────

    [Fact]
    public void OnAuthorization_SystemRoute_WrongScope_Returns404()
    {
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "tenant"));
        var context = BuildContext("/api/v1/system/x", user: user);

        filter.OnAuthorization(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    [Fact]
    public void OnAuthorization_SystemRoute_SystemScopeAndApex_Passes()
    {
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "system"));
        var context = BuildContext(
            "/api/v1/system/x",
            user: user,
            tenantContext: TenantContext.Apex);

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void OnAuthorization_SystemRoute_SystemScopeNotApex_Returns404()
    {
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "system"));
        // IsTenant=true, IsApex=false
        var tenantCtx = TenantContext.ForTenant("tid-1", "acme");
        var context = BuildContext("/api/v1/system/x", user: user, tenantContext: tenantCtx);

        filter.OnAuthorization(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    [Fact]
    public void OnAuthorization_SystemRoute_SystemScopeNullContext_Returns404()
    {
        // scope=system but no TenantContext at all → ctx is null → !ctx.IsApex fails
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "system"));
        var context = BuildContext("/api/v1/system/x", user: user);

        filter.OnAuthorization(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    // ── Tenant routes ─────────────────────────────────────────────────────────

    [Fact]
    public void OnAuthorization_TenantRoute_SystemScope_Returns404()
    {
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "system"));
        var context = BuildContext("/api/v1/settings", user: user);

        filter.OnAuthorization(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    [Fact]
    public void OnAuthorization_TenantRoute_TenantScope_TidMatch_Passes()
    {
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(
            new Claim("scope", "tenant"),
            new Claim("tid", "tid-1"));
        var tenantCtx = TenantContext.ForTenant("tid-1", "acme");
        var context = BuildContext("/api/v1/settings", user: user, tenantContext: tenantCtx);

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void OnAuthorization_TenantRoute_TenantScope_TidMismatch_Returns404()
    {
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(
            new Claim("scope", "tenant"),
            new Claim("tid", "tid-other"));
        var tenantCtx = TenantContext.ForTenant("tid-1", "acme");
        var context = BuildContext("/api/v1/settings", user: user, tenantContext: tenantCtx);

        filter.OnAuthorization(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    [Fact]
    public void OnAuthorization_TenantRoute_TenantScope_NoContext_Passes()
    {
        // No TenantContext in Items → ctx is null → allow through (per-controller guard is the safety net)
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(
            new Claim("scope", "tenant"),
            new Claim("tid", "tid-1"));
        var context = BuildContext("/api/v1/settings", user: user);

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void OnAuthorization_TenantRoute_TenantScope_ContextNotTenant_Returns404()
    {
        // TenantContext exists but IsTenant=false (e.g. Uninitialized)
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "tenant"));
        var context = BuildContext(
            "/api/v1/settings",
            user: user,
            tenantContext: TenantContext.Uninitialized);

        filter.OnAuthorization(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    [Fact]
    public void OnAuthorization_TenantRoute_TenantScope_NoTidClaim_Passes()
    {
        // tid claim absent entirely → no mismatch possible → allow through
        var filter = new RouteScopeFilter();
        var user = AuthenticatedUser(new Claim("scope", "tenant"));
        var tenantCtx = TenantContext.ForTenant("tid-1", "acme");
        var context = BuildContext("/api/v1/settings", user: user, tenantContext: tenantCtx);

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }

    // ── Edge-condition coverage ───────────────────────────────────────────────

    [Fact]
    public void OnAuthorization_EndpointWithoutAllowAnonymousMetadata_ContinuesFilter()
    {
        // Endpoint is present but carries NO IAllowAnonymous metadata: the
        // `endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null` check evaluates
        // its non-null-endpoint+null-metadata branch and falls through to the rest of the
        // filter. With an authenticated user + missing scope, this should yield 401.
        var filter = new RouteScopeFilter();
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/api/v1/settings";
        httpContext.User = AuthenticatedUser(new Claim("sub", "user-1"));
        httpContext.SetEndpoint(new Endpoint(
            null,
            new EndpointMetadataCollection(),  // empty metadata — no IAllowAnonymous
            "test"));

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());

        filter.OnAuthorization(context);

        Assert.IsType<UnauthorizedResult>(context.Result);
    }

    [Fact]
    public void OnAuthorization_EmptyRequestPath_SkipsFilter()
    {
        // Default DefaultHttpContext has Path = "" (PathString.Empty), Path.Value = null.
        // Exercises the `?? ""` null-coalesce branch of the path read. Empty path does not
        // start with /api/v1/ so the filter should pass through cleanly.
        var filter = new RouteScopeFilter();
        var httpContext = new DefaultHttpContext();
        // Do NOT set Path — leave as the default empty PathString whose .Value is null.
        httpContext.User = AuthenticatedUser(new Claim("scope", "tenant"));

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());

        filter.OnAuthorization(context);

        Assert.Null(context.Result);
    }
}
