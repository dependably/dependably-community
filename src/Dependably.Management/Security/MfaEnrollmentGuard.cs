using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Dependably.Security;

/// <summary>
/// Global authorization filter that requires users to enroll in MFA before accessing the API
/// when the per-tenant <c>require_mfa</c> setting or the instance-level <c>REQUIRE_MFA</c>
/// env var is enabled. Every <c>/api/v1/</c> request is rejected with 403 and a
/// machine-readable <c>mfa_enrollment_required</c> code until the user completes enrollment,
/// EXCEPT the routes the SPA needs to complete enrollment and the logout/me routes.
///
/// Enrollment is read live from the database (not the JWT claim) so it takes effect
/// immediately after the user finishes setup, rather than waiting out the token lifetime.
/// Runs after <see cref="PasswordRotationGuard"/> so rotation wins: a user who must both
/// rotate and enroll is sent to the password change form first, and the password endpoint
/// is on the MFA allowlist.
///
/// Exempt: opaque API tokens authenticated by the <c>ApiToken</c> scheme (PATs and service
/// tokens). MFA enrollment is enforced once, at login, when the JWT session is issued; a PAT
/// or service token already required that gated session (or an admin/owner's own capability
/// grant) to mint, so re-checking enrollment on every token-authenticated request would 403
/// CI/automation callers for a posture that governs interactive sessions.
/// </summary>
public sealed class MfaEnrollmentGuard : IAsyncAuthorizationFilter
{
    // Routes in the tenant realm that must remain reachable for a user who has not yet
    // enrolled in MFA, so they can complete enrollment (or bail out).
    private static readonly string[] TenantAllowedPaths =
    [
        "/api/v1/mfa/setup/begin",
        "/api/v1/mfa/setup/verify",
        "/api/v1/mfa/status",
        "/api/v1/auth/me",
        "/api/v1/auth/logout",
        "/api/v1/users/me/password",
        "/api/v1/users/me/language",
    ];

    // Routes in the system-admin realm that must remain reachable for an unenrolled operator.
    private static readonly string[] SystemAllowedPaths =
    [
        "/api/v1/system/mfa/setup/begin",
        "/api/v1/system/mfa/setup/verify",
        "/api/v1/system/mfa/status",
        "/api/v1/system/me",
        "/api/v1/system/me/password",
        "/api/v1/system/me/language",
        "/api/v1/auth/logout",
    ];

    private readonly UserService _users;
    private readonly SystemAdminRepository _admins;
    private readonly OrgRepository _orgs;
    private readonly IRequireMfaMode _requireMfa;

    public MfaEnrollmentGuard(
        UserService users,
        SystemAdminRepository admins,
        OrgRepository orgs,
        IRequireMfaMode requireMfa)
    {
        _users = users;
        _admins = admins;
        _orgs = orgs;
        _requireMfa = requireMfa;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        // AllowAnonymous endpoints (login, join, two-step) skip the guard entirely.
        var endpoint = context.HttpContext.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            return;
        }

        string path = context.HttpContext.Request.Path.Value ?? "";
        if (!path.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Determine the scope of the current principal and check the appropriate allowlist.
        var user = context.HttpContext.User;
        string? scope = user.FindFirst("scope")?.Value;
        string[] allowedPaths = scope == "system" ? SystemAllowedPaths : TenantAllowedPaths;
        if (allowedPaths.Any(allowed => path.Equals(allowed, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        if (user.Identity?.IsAuthenticated != true)
        {
            return;
        }

        // MFA enrollment is an interactive-user session concern — the enforcement point is
        // the login flow that issues a JWT. An opaque API token authenticated by the ApiToken
        // scheme required an already-MFA-gated session to mint in the first place, so it is
        // exempt here. Checked as a positive match on the ApiToken scheme (rather than the
        // absence of a JWT identity) so the exemption can never accidentally swallow a JWT
        // principal whose identity happens to carry an unexpected AuthenticationType.
        if (user.Identities.Any(i => i.AuthenticationType == TokenAuthenticationDefaults.Scheme))
        {
            return;
        }

        string? sub = user.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? user.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return;
        }

        var ct = context.HttpContext.RequestAborted;
        var (requireMfa, mfaEnabled) = await ResolveMfaStatusAsync(scope, sub, user, ct);

        if (requireMfa && !mfaEnabled)
        {
            // 403 (not 401 — the token is valid) with a code the SPA branches on.
            context.Result = new ObjectResult(new
            {
                detail = "MFA enrollment is required before you can continue.",
                code = "mfa_enrollment_required",
            })
            { StatusCode = StatusCodes.Status403Forbidden };
        }
    }

    // Resolves whether MFA is required and enrolled for the current principal. System admins
    // are gated by the instance-level override only (no per-tenant setting for system_admin
    // accounts); tenant users compose the instance override with the per-tenant require_mfa
    // flag. A tenant principal carrying no org_id claim reports (false, false) — never blocked,
    // matching the guard's original pass-through behaviour for that unexpected shape.
    private async Task<(bool RequireMfa, bool MfaEnabled)> ResolveMfaStatusAsync(
        string? scope, string sub, System.Security.Claims.ClaimsPrincipal user, CancellationToken ct)
    {
        if (scope == "system")
        {
            bool requireMfa = _requireMfa.IsEnabled;
            bool mfaEnabled = requireMfa && await _admins.IsMfaEnabledAsync(sub, ct);
            return (requireMfa, mfaEnabled);
        }

        string? orgId = user.FindFirst("org_id")?.Value;
        if (orgId is null)
        {
            return (false, false);
        }

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        bool tenantRequireMfa = _requireMfa.IsEnabled || (settings?.RequireMfa ?? false);
        bool tenantMfaEnabled = tenantRequireMfa && await _users.IsMfaEnabledAsync(sub, ct);
        return (tenantRequireMfa, tenantMfaEnabled);
    }
}
