using System.Reflection;
using Dependably.Api;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage closing a pre-release review finding on <see cref="NpmController"/>:
/// the dist-tag PUT/DELETE and unpublish mutation routes carry no rate-limiter policy. They
/// route under <c>/npm/-/package/...</c> and <c>/npm/{pkg}/-rev/{rev}</c>, which the
/// management GlobalLimiter never covers (it only applies to <c>/api/v1/</c>), so a
/// publish/yank-capable token could issue unbounded writes/deletes with no per-token ceiling.
/// Every mutation action must carry <see cref="EnableRateLimitingAttribute"/> bound to the
/// "push" policy, matching the publish route.
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

    // ── npm audit endpoint must exist at the exact path npm hardcodes ───────

    [Fact]
    public void AuditAdvisoriesBulk_Action_RoutesToBulkAdvisoriesPath()
    {
        var method = typeof(NpmController).GetMethod(nameof(NpmController.AuditAdvisoriesBulk));
        Assert.NotNull(method);

        var route = method!.GetCustomAttribute<HttpPostAttribute>();
        Assert.NotNull(route);
        Assert.Equal("/npm/-/npm/v1/security/advisories/bulk", route!.Template);
    }
}
