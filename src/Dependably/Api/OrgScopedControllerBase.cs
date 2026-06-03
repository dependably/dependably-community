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
    /// Only valid after <c>OrgAccessGuard.AuthorizeCapAsync</c> has returned null.
    /// </summary>
    protected string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    protected string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;
}
