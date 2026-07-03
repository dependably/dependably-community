using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Core authentication wiring shared by every host: the <c>ApiToken</c> authentication scheme
/// that the protocol controllers depend on, plus the capability authorization policy provider
/// and handler. This is the complete authentication surface a protocol-only (edge) host needs —
/// it pulls in no JwtBearer package types.
///
/// A full management host layers JwtBearer on top and takes over the default scheme; the ApiToken
/// scheme registered here is what <c>[Authorize(AuthenticationSchemes = "Bearer,ApiToken")]</c>
/// resolves the token half against.
/// </summary>
public static class CoreAuthStartupExtensions
{
    /// <summary>
    /// Registers the <c>ApiToken</c> authentication scheme (as the default scheme), authorization,
    /// and the capability policy provider + handler. Protocol endpoints opt in via
    /// <c>[Authorize(AuthenticationSchemes = "ApiToken")]</c> (or <c>"Bearer,ApiToken"</c> when a
    /// management host also adds JwtBearer); anonymous-pull endpoints add no <c>[Authorize]</c>
    /// and keep their <c>ResolveTokenAsync</c> flow so "no token + AnonymousPull=true" still works.
    /// </summary>
    public static void AddDependablyApiTokenAuth(this WebApplicationBuilder builder)
    {
        // API-token scheme for protocol endpoints. Registered as the default scheme so a
        // protocol-only host authenticates npm/pypi/nuget clients out of the box; a management
        // host overrides the default to JwtBearer in AddDependablyJwt after calling this.
        builder.Services.AddAuthentication(TokenAuthenticationDefaults.Scheme)
            .AddScheme<TokenAuthenticationOptions, TokenAuthenticationHandler>(
                TokenAuthenticationDefaults.Scheme, _ => { });

        builder.Services.AddAuthorization();

        // Capability enforcement: dynamic policy provider materialises a policy per
        // [RequireCapability("...")] attribute; the handler resolves the principal's role
        // claim through Capabilities.ForRole and checks Capabilities.Grants.
        builder.Services.AddSingleton<IAuthorizationPolicyProvider, CapabilityPolicyProvider>();
        builder.Services.AddSingleton<IAuthorizationHandler, CapabilityHandler>();
    }
}
