using Dependably.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Shared base for the controllers split out of the original <see cref="OrgController"/>
/// god-controller. Carries the two pieces of state every org-scoped endpoint needs
/// after authorization: the resolved tenant id (from <c>TenantContext</c>) and the caller's
/// user id (from the JWT claims). Both helpers assume <c>OrgAccessGuard.AuthorizeCapAsync</c>
/// has already run and returned null; callers must enforce that ordering.
/// </summary>
public abstract class OrgScopedControllerBase : ControllerBase
{
    /// <summary>
    /// Reads the resolved tenant id from <c>HttpContext.Items[TenantContext.HttpItemsKey]</c>.
    /// Only valid once a tenant is known to be resolved: after <c>OrgAccessGuard.AuthorizeCapAsync</c>
    /// has returned null on the management plane, or on any protocol controller, which
    /// <c>TenantStatusEnforcementMiddleware</c> never lets a request without a tenant reach.
    /// Throws rather than returning null if that ordering is ever broken
    /// (<see cref="TenantContextHttpExtensions.RequireTenantId"/>).
    /// </summary>
    protected string CurrentTenantId() => HttpContext.RequireTenantId();

    protected string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    /// <summary>
    /// Reads the caller's tenant role from the JWT <c>role</c> claim.
    /// Defaults to <c>member</c> when the claim is absent.
    /// </summary>
    protected string CurrentRole() =>
        User.FindFirst("role")?.Value ?? "member";
}
