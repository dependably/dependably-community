using System.Reflection;
using Dependably.Api;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage closing two pre-release review findings on <see cref="NpmController"/>:
/// <list type="bullet">
///   <item>The dist-tag PUT/DELETE and unpublish mutation routes carry no rate-limiter policy.
///   They route under <c>/npm/-/package/...</c> and <c>/npm/{pkg}/-rev/{rev}</c>, which the
///   management GlobalLimiter never covers (it only applies to <c>/api/v1/</c>), so a
///   publish/yank-capable token could issue unbounded writes/deletes with no per-token ceiling.
///   Every mutation action must carry <see cref="EnableRateLimitingAttribute"/> bound to the
///   "push" policy, matching the publish route.</item>
///   <item><c>npm audit</c>/audit-on-install POSTs to the bulk-advisories endpoint, and an npm
///   6-era client POSTs to quick-audit. Both routes must exist at the exact paths npm hardcodes:
///   bulk serves the projected advisory report, quick-audit returns a deliberate 501 problem
///   response, and neither falls through to an unexplained 404.</item>
/// </list>
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmControllerReviewFixTests
{
    // ── Finding 1: dist-tag + unpublish mutation routes must carry the "push" rate-limit policy ──

    [Theory]
    [InlineData(nameof(NpmController.PutDistTag))]
    [InlineData(nameof(NpmController.PutScopedDistTag))]
    [InlineData(nameof(NpmController.DeleteDistTag))]
    [InlineData(nameof(NpmController.DeleteScopedDistTag))]
    [InlineData(nameof(NpmController.Unpublish))]
    [InlineData(nameof(NpmController.UnpublishScoped))]
    public void DistTagMutationAction_HasPushRateLimitPolicy(string methodName)
    {
        var method = typeof(NpmController).GetMethod(methodName);
        Assert.NotNull(method);

        var attr = method!.GetCustomAttribute<EnableRateLimitingAttribute>();
        Assert.True(attr is not null,
            $"{methodName} is a token-authenticated mutation route outside /api/v1/ (never " +
            "covered by the management GlobalLimiter) and must carry [EnableRateLimiting(\"push\")].");
        Assert.Equal("push", attr!.PolicyName);
    }

    // ── Finding 2: npm audit endpoints must exist and refuse deliberately, not 404 ───────

    [Fact]
    public void AuditAdvisoriesBulk_Action_RoutesToBulkAdvisoriesPath()
    {
        var method = typeof(NpmController).GetMethod(nameof(NpmController.AuditAdvisoriesBulk));
        Assert.NotNull(method);

        var route = method!.GetCustomAttribute<HttpPostAttribute>();
        Assert.NotNull(route);
        Assert.Equal("/npm/-/npm/v1/security/advisories/bulk", route!.Template);
    }

    [Fact]
    public void AuditQuick_Action_RoutesToQuickAuditPath()
    {
        var method = typeof(NpmController).GetMethod(nameof(NpmController.AuditQuick));
        Assert.NotNull(method);

        var route = method!.GetCustomAttribute<HttpPostAttribute>();
        Assert.NotNull(route);
        Assert.Equal("/npm/-/npm/v1/security/audits/quick", route!.Template);
    }

    /// <summary>
    /// Quick-audit is the npm 6-era shape; every supported npm version audits exclusively through
    /// the bulk-advisories endpoint. The route stays as a deliberate 501 so an npm 6 client gets
    /// an explicit refusal to degrade on rather than a bare 404.
    /// </summary>
    [Fact]
    public void AuditQuick_Returns501ProblemDetails()
    {
        var controller = CreateController();
        var result = controller.AuditQuick();

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status501NotImplemented, obj.StatusCode);
        var problem = Assert.IsType<ProblemDetails>(obj.Value);
        Assert.Equal(StatusCodes.Status501NotImplemented, problem.Status);
    }

    private static NpmController CreateController()
    {
        // AuditQuick is static-dispatch (no DI dependency touched), so a minimally-constructed
        // handler aggregate is enough to invoke it directly.
        var handlers = new NpmControllerHandlers(null!, null!, null!, null!, null!);
        return new NpmController(handlers);
    }
}
