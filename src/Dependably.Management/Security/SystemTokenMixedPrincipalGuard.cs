using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Dependably.Security;

/// <summary>
/// Global authorization filter refusing a request that authenticated under both the JwtBearer
/// scheme and the <see cref="SystemTokenDefaults.Scheme"/> scheme at once — the shape a session
/// cookie plus a <c>dpsys_…</c> Bearer header produces on one of the six <c>SystemController</c>
/// actions whose <c>[Authorize]</c> lists both schemes. The two credentials can only ever arrive
/// together this way: a JWT session is read from the <c>dependably_session</c> cookie
/// (<see cref="Dependably.Infrastructure.Startup.AuthStartupExtensions"/>'s
/// <c>OnJwtMessageReceivedAsync</c> sets <c>ctx.Token</c> from it), and only when that cookie is
/// absent does <c>JwtBearerHandler</c> fall back to its default of parsing
/// <c>Authorization: Bearer</c> itself. A single Bearer header therefore carries one credential —
/// a JWT or a <c>dpsys_…</c> token, never both — so the merged shape needs the cookie on one side
/// and the header on the other.
///
/// <para>
/// When both schemes individually succeed, ASP.NET Core's policy evaluator merges them into one
/// <see cref="System.Security.Claims.ClaimsPrincipal"/> carrying one
/// <see cref="System.Security.Claims.ClaimsIdentity"/> per scheme, and
/// <c>ClaimsPrincipal.FindFirst</c> returns whichever identity's matching claim comes first — so
/// a merged principal lets a JWT session's <c>sub</c> win over a token's, or vice versa, by
/// identity order. Worse, the <c>Identities.Any(i => AuthenticationType == …)</c> checks in
/// <see cref="SystemActor"/>, <see cref="MfaEnrollmentGuard"/>, and
/// <see cref="PasswordRotationGuard"/> see both schemes present and would apply the
/// interactive-session exemptions meant for a token-only principal to a request that is, in
/// truth, also carrying a full admin session. Running first in the filter pipeline (registered
/// ahead of <see cref="RouteScopeFilter"/>) means no downstream guard ever observes the merged
/// shape — they keep their existing single-scheme assumptions unchanged.
/// </para>
///
/// <para>
/// Triggers on "the SystemToken identity plus at least one other authenticated identity" rather
/// than matching a specific string for the JWT side: <c>JwtSecurityTokenHandler</c> stamps a
/// validated JWT's <see cref="System.Security.Claims.ClaimsIdentity.AuthenticationType"/> as the
/// legacy <c>"AuthenticationTypes.Federation"</c> constant, not the <c>"Bearer"</c> scheme name,
/// so a check anchored on <c>JwtBearerDefaults.AuthenticationScheme</c> would silently miss it.
/// The SystemToken identity's own <c>AuthenticationType</c> is reliable (this handler builds it
/// itself as <c>Scheme.Name</c>), so anchoring the other side of the check on "present and not
/// SystemToken" is what actually fires on the real merged shape.
/// </para>
/// </summary>
public sealed class SystemTokenMixedPrincipalGuard : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var identities = context.HttpContext.User.Identities;
        bool hasSystemToken = identities.Any(i =>
            i.IsAuthenticated && i.AuthenticationType == SystemTokenDefaults.Scheme);
        bool hasAnotherAuthenticatedIdentity = identities.Any(i =>
            i.IsAuthenticated && i.AuthenticationType != SystemTokenDefaults.Scheme);

        if (hasSystemToken && hasAnotherAuthenticatedIdentity)
        {
            context.Result = new UnauthorizedResult();
        }
    }
}
