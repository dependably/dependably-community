using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Dependably.Security;

/// <summary>
/// Per-route capability enforcement. Applied as an attribute on actions or
/// controllers; ASP.NET Core's authorization pipeline resolves the policy via
/// <see cref="CapabilityPolicyProvider"/> and authorises with
/// <see cref="CapabilityHandler"/>. The capability granted by the request is
/// derived from the principal's <c>role</c> claim — JWTs issued by
/// <c>LoginService</c> carry it directly, so no DB lookup is required.
///
/// Defence-in-depth: existing <see cref="OrgAccessGuard"/> role gates remain on
/// admin actions. Capability checks restrict <em>which</em> admins can perform
/// <em>which</em> action; the org guard restricts <em>which</em> tenant they can
/// touch and that they are a member of it at all.
///
/// Applies to both principal kinds. JWT-session routes (admin/import/claims/audit-events)
/// reach it through ASP.NET authorization directly; API-token principals reach it through
/// <see cref="TokenAuthenticationDefaults.Scheme"/>, which projects a resolved token's
/// capabilities onto <c>cap</c> claims — so protocol controllers that authenticate by token
/// can and do carry the attribute (npm, pypi, nuget, maven and rpm gate publish this way).
/// The paths that cannot are the ones whose gate is not a single capability: OCI's read gate
/// accepts either of two, and every ecosystem's anonymous-pull branch has to decide before it
/// knows whether a principal exists. Those call
/// <see cref="TokenAuthExtensions.HasCapability"/> inline instead.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class RequireCapabilityAttribute : AuthorizeAttribute
{
    public const string PolicyPrefix = "cap:";

    public RequireCapabilityAttribute(string capability)
    {
        Capability = capability;
        Policy = PolicyPrefix + capability;
    }

    public string Capability { get; }
}

/// <summary>
/// Authorization requirement carrying the capability the route demands.
/// Materialised by <see cref="CapabilityPolicyProvider"/> from the policy name.
/// </summary>
public sealed class CapabilityRequirement : IAuthorizationRequirement
{
    public CapabilityRequirement(string capability) => Capability = capability;
    public string Capability { get; }
}

/// <summary>
/// Dynamic policy provider — emits a policy on demand for any name starting with
/// <see cref="RequireCapabilityAttribute.PolicyPrefix"/>. Falls back to the
/// default provider for everything else, so plain <c>[Authorize]</c> usages keep
/// working unchanged.
/// </summary>
public sealed class CapabilityPolicyProvider : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallback;

    public CapabilityPolicyProvider(IOptions<AuthorizationOptions> options)
        => _fallback = new DefaultAuthorizationPolicyProvider(options);

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(RequireCapabilityAttribute.PolicyPrefix, StringComparison.Ordinal))
        {
            string capability = policyName[RequireCapabilityAttribute.PolicyPrefix.Length..];
            var policy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddRequirements(new CapabilityRequirement(capability))
                .Build();
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }
        return _fallback.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();
}

/// <summary>
/// Authorization handler — resolves the principal's effective capability set and
/// consults <see cref="Capabilities.Grants"/>.
///
/// Resolution order:
/// <list type="number">
///   <item>If the principal carries explicit <c>cap</c> claims (set by
///         <see cref="TokenAuthenticationHandler"/> when an API token was issued with
///         a narrowed capabilities array), only those caps grant. Token issuance
///         already validated they're a subset of the user's role caps, so honouring
///         the narrowing is correct.</item>
///   <item>An API-token principal (authenticated by
///         <see cref="TokenAuthenticationDefaults.Scheme"/>) carrying zero <c>cap</c>
///         claims is denied outright — the token's <c>capabilities</c> column was
///         NULL/empty/malformed, and an empty set must never inherit the owner's role
///         capabilities. The token is what authenticates; its capability set is the
///         ceiling regardless of the owner's role.</item>
///   <item>Otherwise the role claim drives the cap set —
///         <see cref="Capabilities.ForPlatformAdmin"/> for <c>system_admin</c>, else
///         <see cref="Capabilities.ForRole"/>. Only JWT-session principals land here.</item>
/// </list>
/// </summary>
public sealed class CapabilityHandler : AuthorizationHandler<CapabilityRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, CapabilityRequirement requirement)
    {
        var explicitCaps = context.User.FindAll("cap")
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToHashSet(StringComparer.Ordinal);

        if (explicitCaps.Count > 0)
        {
            // Token-narrowed principal — only the explicit caps grant. Don't fall through
            // to the role claim, otherwise narrowing wouldn't actually narrow.
            if (Capabilities.Grants(explicitCaps, requirement.Capability))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }

        // An API-token principal reaches here only with zero explicit `cap` claims, which happens
        // solely when its `capabilities` column is NULL/empty/malformed. That empty set denies —
        // an API token must never fall through to the owner's role capabilities, which would
        // silently upgrade a should-be-denied legacy token to its owner's full role grant. The
        // role fallback below is legitimate only for JWT-session principals.
        if (context.User.Identities.Any(i => i.AuthenticationType == TokenAuthenticationDefaults.Scheme))
        {
            return Task.CompletedTask;
        }

        string? role = context.User.FindFirst("role")?.Value
                   ?? context.User.FindFirst(ClaimTypes.Role)?.Value;
        if (string.IsNullOrEmpty(role))
        {
            return Task.CompletedTask;
        }

        var granted = role == "system_admin"
            ? Capabilities.ForPlatformAdmin()
            : Capabilities.ForRole(role);

        if (Capabilities.Grants(granted, requirement.Capability))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
