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
/// Scope of this iteration: JWT-authenticated routes only (admin/import/claims/
/// audit-events). API-token-authenticated protocol routes (npm/pypi/nuget) gate
/// per-controller via <see cref="TokenAuthExtensions.HasCapability"/> — they
/// don't flow through ASP.NET authorization, so attribute-based policies cannot
/// reach them yet. Wiring the token-auth path through an
/// <c>AuthenticationHandler</c> is tracked as separate-PR work.
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
            var capability = policyName[RequireCapabilityAttribute.PolicyPrefix.Length..];
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
///   <item>Otherwise the role claim drives the cap set —
///         <see cref="Capabilities.ForPlatformAdmin"/> for <c>system_admin</c>, else
///         <see cref="Capabilities.ForRole"/>. JWT-authenticated admins land here.</item>
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
                context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var role = context.User.FindFirst("role")?.Value
                   ?? context.User.FindFirst(ClaimTypes.Role)?.Value;
        if (string.IsNullOrEmpty(role))
            return Task.CompletedTask;

        var granted = role == "system_admin"
            ? Capabilities.ForPlatformAdmin()
            : Capabilities.ForRole(role);

        if (Capabilities.Grants(granted, requirement.Capability))
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
