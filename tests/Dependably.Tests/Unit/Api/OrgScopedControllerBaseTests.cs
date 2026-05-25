using System.Security.Claims;
using Dependably.Api;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// OrgScopedControllerBase is a tiny base with two protected helpers: CurrentTenantId()
/// (pulls TenantContext out of HttpContext.Items) and GetUserId() (NameIdentifier with
/// "sub" fallback). Covered branches:
///  - CurrentTenantId returns the resolved tenant id when TenantContext is present
///  - CurrentTenantId throws when TenantContext is missing (Items[..] null → cast NRE)
///  - GetUserId returns NameIdentifier claim value when present
///  - GetUserId falls back to "sub" claim when NameIdentifier is absent
///  - GetUserId returns null when neither claim is present
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgScopedControllerBaseTests
{
    private sealed class TestController : OrgScopedControllerBase
    {
        public string PublicCurrentTenantId() => CurrentTenantId();
        public string? PublicGetUserId() => GetUserId();
    }

    private static TestController NewController(HttpContext ctx) =>
        new()
        {
            ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
            {
                HttpContext = ctx,
            },
        };

    [Fact]
    public void CurrentTenantId_TenantContextPresent_ReturnsTenantId()
    {
        var ctx = new DefaultHttpContext();
        ctx.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("tenant-123", "acme");
        var sut = NewController(ctx);

        var result = sut.PublicCurrentTenantId();

        Assert.Equal("tenant-123", result);
    }

    [Fact]
    public void CurrentTenantId_TenantContextMissing_Throws()
    {
        // Items[..] returns null when key absent; the `!` then casts null to TenantContext
        // and chains .TenantId — NullReferenceException is the documented contract
        // ("only valid after OrgAccessGuard.AuthorizeCapAsync returned null").
        var ctx = new DefaultHttpContext();
        var sut = NewController(ctx);

        Assert.Throws<NullReferenceException>(() => sut.PublicCurrentTenantId());
    }

    [Fact]
    public void GetUserId_NameIdentifierClaimPresent_ReturnsValue()
    {
        var ctx = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.NameIdentifier, "user-1") })),
        };
        var sut = NewController(ctx);

        Assert.Equal("user-1", sut.PublicGetUserId());
    }

    [Fact]
    public void GetUserId_OnlySubClaimPresent_FallsBackToSub()
    {
        var ctx = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("sub", "user-sub-2") })),
        };
        var sut = NewController(ctx);

        Assert.Equal("user-sub-2", sut.PublicGetUserId());
    }

    [Fact]
    public void GetUserId_NoClaims_ReturnsNull()
    {
        var ctx = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity()),
        };
        var sut = NewController(ctx);

        Assert.Null(sut.PublicGetUserId());
    }

    [Fact]
    public void GetUserId_BothClaimsPresent_PrefersNameIdentifier()
    {
        // FindFirst(NameIdentifier) wins; the "sub" fallback only fires when the first
        // lookup returns null. Pinning this prevents accidental reorderings.
        var ctx = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "preferred"),
                    new Claim("sub", "fallback"),
                })),
        };
        var sut = NewController(ctx);

        Assert.Equal("preferred", sut.PublicGetUserId());
    }
}
