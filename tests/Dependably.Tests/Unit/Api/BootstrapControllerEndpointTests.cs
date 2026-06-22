using Dependably.Api;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Covers the BootstrapController.Get endpoint (existing tests only hit the
/// internal static helpers). The endpoint is exercised by direct controller construction
/// with a DefaultHttpContext — no scenario or DB required, just IAirGapMode +
/// IPublicUrlBuilder mocks.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BootstrapControllerEndpointTests
{
    private static IConfiguration Cfg(params (string K, string? V)[] entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            entries.Select(e => new KeyValuePair<string, string?>(e.K, e.V))).Build();

    private static BootstrapController NewCtrl(
        IConfiguration config, bool airGapped = false, bool isHttpsDeployment = false,
        TenantContext? tenant = null, bool requestIsHttps = false)
    {
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsEnabled.Returns(airGapped);
        var urls = Substitute.For<IPublicUrlBuilder>();
        urls.IsHttpsDeployment.Returns(isHttpsDeployment);

        var ctx = new DefaultHttpContext();
        ctx.Request.Scheme = requestIsHttps ? "https" : "http";
        if (tenant is not null)
        {
            ctx.Items[TenantContext.HttpItemsKey] = tenant;
        }

        return new BootstrapController(config, airGap, urls) { ControllerContext = new ControllerContext { HttpContext = ctx } };
    }

    private static dynamic Body(IActionResult result) => ((OkObjectResult)result).Value!;
    private static T Prop<T>(object obj, string name) => (T)obj.GetType().GetProperty(name)!.GetValue(obj)!;

    [Fact]
    public void SingleMode_ReturnsTenantSlug_FromTenantContext()
    {
        var result = NewCtrl(Cfg(("DEPLOYMENT_MODE", "single")),
            tenant: TenantContext.ForTenant("o-1", "acme")).Get();

        var body = Body(result);
        Assert.Equal("single", Prop<string>(body, "mode"));
        Assert.Equal("acme", Prop<string?>(body, "tenantSlug"));
        Assert.False(Prop<bool>(body, "isApex"));
    }

    [Fact]
    public void SingleMode_NoTenantContext_TenantSlugIsNull()
    {
        var result = NewCtrl(Cfg(("DEPLOYMENT_MODE", "single"))).Get();
        Assert.Null(Prop<string?>(Body(result), "tenantSlug"));
    }

    [Fact]
    public void MultiMode_Apex_IncludesApexHost_OmitsTenantSlug()
    {
        var result = NewCtrl(Cfg(
                ("DEPLOYMENT_MODE", "multi"),
                ("BASE_URL", "https://dependably.example.com")),
            tenant: TenantContext.Apex).Get();

        var body = Body(result);
        Assert.Equal("multi", Prop<string>(body, "mode"));
        Assert.True(Prop<bool>(body, "isApex"));
        Assert.Equal("dependably.example.com", Prop<string?>(body, "apexHost"));
        // tenantSlug intentionally omitted in multi mode — exposing it would turn the
        // public endpoint into an existence oracle for tenants.
        Assert.Null(body.GetType().GetProperty("tenantSlug"));
    }

    [Fact]
    public void MultiMode_TenantSubdomain_ReportsIsApexFalse_AndOmitsTenantSlug()
    {
        var result = NewCtrl(Cfg(
                ("DEPLOYMENT_MODE", "multi"),
                ("BASE_URL", "https://dependably.example.com")),
            tenant: TenantContext.ForTenant("o-1", "acme")).Get();

        var body = Body(result);
        Assert.Equal("multi", Prop<string>(body, "mode"));
        Assert.False(Prop<bool>(body, "isApex"));
        Assert.Equal("dependably.example.com", Prop<string?>(body, "apexHost"));
        Assert.Null(body.GetType().GetProperty("tenantSlug"));
    }

    [Fact]
    public void AirGapped_FlagPropagates()
    {
        var result = NewCtrl(Cfg(("DEPLOYMENT_MODE", "single")), airGapped: true).Get();
        Assert.True(Prop<bool>(Body(result), "airGapped"));
    }

    [Fact]
    public void InsecureHttp_IsTrue_OnlyWhenBothRequestAndDeploymentAreHttp()
    {
        // Plain http request + http-only deployment → insecureHttp = true.
        var both = NewCtrl(Cfg(), requestIsHttps: false, isHttpsDeployment: false).Get();
        Assert.True(Prop<bool>(Body(both), "insecureHttp"));

        // https request → false even with http deployment URL.
        var requestSecure = NewCtrl(Cfg(), requestIsHttps: true, isHttpsDeployment: false).Get();
        Assert.False(Prop<bool>(Body(requestSecure), "insecureHttp"));

        // https deployment overrides request scheme (reverse-proxy case).
        var deploymentSecure = NewCtrl(Cfg(), requestIsHttps: false, isHttpsDeployment: true).Get();
        Assert.False(Prop<bool>(Body(deploymentSecure), "insecureHttp"));
    }

    [Fact]
    public void Response_HeaderSetsCacheControlNoStore()
    {
        var ctrl = NewCtrl(Cfg());
        ctrl.Get();
        Assert.Equal("no-store", ctrl.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public void MultiMode_NoTenantContext_TreatedAsTenantSubdomainBranch()
    {
        // Covers the `ctx is null` short-circuit in `if (ctx is not null && ctx.IsApex)`
        // within multi-mode: with no resolved tenant context, the controller falls through
        // to the tenant-subdomain response shape (isApex=false, no tenantSlug echoed).
        var result = NewCtrl(Cfg(
            ("DEPLOYMENT_MODE", "multi"),
            ("BASE_URL", "https://dependably.example.com"))).Get();

        var body = Body(result);
        Assert.Equal("multi", Prop<string>(body, "mode"));
        Assert.False(Prop<bool>(body, "isApex"));
        Assert.Equal("dependably.example.com", Prop<string?>(body, "apexHost"));
        Assert.Null(body.GetType().GetProperty("tenantSlug"));
    }
}
