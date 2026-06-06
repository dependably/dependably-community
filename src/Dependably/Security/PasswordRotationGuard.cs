using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Dependably.Infrastructure;

namespace Dependably.Security;

/// <summary>
/// Global authorization filter that forces a user holding a temporary password to rotate it
/// before using the rest of the API. When the authenticated principal's account has
/// <c>must_change_password</c> set, every <c>/api/v1/</c> request is rejected with 403 and a
/// machine-readable <c>password_change_required</c> code, EXCEPT the change-password, me, and
/// logout routes the SPA needs to complete the rotation.
///
/// The flag is read live from the database (not carried as a JWT claim) so an operator-forced
/// rotation takes effect immediately and clearing the flag ends enforcement at once, rather
/// than waiting out the token lifetime. Runs after <see cref="RouteScopeFilter"/> so the realm
/// is validated first. Package-manager routes (outside <c>/api/v1/</c>) are unaffected.
/// </summary>
public sealed class PasswordRotationGuard : IAsyncAuthorizationFilter
{
    // Exact routes that must stay reachable so a flagged user can finish rotating — for both
    // the tenant realm (auth/users) and the system-admin realm (system/me).
    private static readonly string[] AllowedPaths =
    [
        "/api/v1/users/me/password",   // POST — tenant change password (clears the flag)
        "/api/v1/auth/me",             // GET  — SPA reads mustChangePassword
        "/api/v1/auth/logout",         // POST — let the user bail out
        "/api/v1/system/me/password",  // POST — system_admin self-rotation
        "/api/v1/system/me",           // GET  — apex SPA reads mustChangePassword
    ];

    private readonly UserService _users;
    private readonly SystemAdminRepository _admins;

    public PasswordRotationGuard(UserService users, SystemAdminRepository admins)
    {
        _users = users;
        _admins = admins;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var endpoint = context.HttpContext.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null) return;

        var path = context.HttpContext.Request.Path.Value ?? "";
        if (!path.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase)) return;

        if (AllowedPaths.Any(allowed => path.Equals(allowed, StringComparison.OrdinalIgnoreCase))) return;

        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true) return;

        var sub = user.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? user.FindFirst("sub")?.Value;
        if (sub is null) return;

        var ct = context.HttpContext.RequestAborted;
        // System-admin principals live in system_admins; everyone else in users.
        var mustChange = user.FindFirst("scope")?.Value == "system"
            ? await _admins.IsPasswordChangeRequiredAsync(sub, ct)
            : await _users.IsPasswordChangeRequiredAsync(sub, ct);

        if (mustChange)
        {
            // 403 (not 401 — the token is valid) with a code the SPA branches on.
            context.Result = new ObjectResult(new
            {
                detail = "You must change your password before continuing.",
                code = "password_change_required",
            })
            { StatusCode = StatusCodes.Status403Forbidden };
        }
    }
}
