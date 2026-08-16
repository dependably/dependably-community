using System.Security.Claims;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the dynamic policy provider + capability handler. The attribute itself is
/// trivial wrapping over <see cref="AuthorizeAttribute.Policy"/> so we don't unit-test
/// it independently — the round-trip through provider + handler proves it works.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RequireCapabilityTests
{
    private static CapabilityPolicyProvider NewProvider() =>
        new(Options.Create(new AuthorizationOptions()));

    private static AuthorizationHandlerContext ContextFor(string capability, params Claim[] claims) =>
        ContextForScheme(capability, "test", claims);

    private static AuthorizationHandlerContext ContextForScheme(string capability, string authType, params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, authenticationType: authType);
        var principal = new ClaimsPrincipal(identity);
        var requirements = new IAuthorizationRequirement[] { new CapabilityRequirement(capability) };
        return new AuthorizationHandlerContext(requirements, principal, resource: null);
    }

    [Fact]
    public async Task PolicyProvider_EmitsCapabilityPolicyForCapPrefix()
    {
        var provider = NewProvider();
        var policy = await provider.GetPolicyAsync($"{RequireCapabilityAttribute.PolicyPrefix}{Capabilities.PublishNpm}");
        Assert.NotNull(policy);
        var req = Assert.Single(policy!.Requirements.OfType<CapabilityRequirement>());
        Assert.Equal(Capabilities.PublishNpm, req.Capability);
    }

    [Fact]
    public async Task PolicyProvider_FallsBackForOtherPolicyNames()
    {
        var provider = NewProvider();
        // Default provider has no "Foo" policy; we expect null (the default behaviour) rather
        // than a synthesised capability policy.
        var policy = await provider.GetPolicyAsync("Foo");
        Assert.Null(policy);
    }

    [Fact]
    public async Task Handler_OwnerRole_GrantsPublishCapability()
    {
        var handler = new CapabilityHandler();
        var ctx = ContextFor(Capabilities.PublishNpm, new Claim("role", "owner"));
        await handler.HandleAsync(ctx);
        Assert.True(ctx.HasSucceeded);
    }

    [Fact]
    public async Task Handler_MemberRole_DeniesPublishCapability()
    {
        var handler = new CapabilityHandler();
        var ctx = ContextFor(Capabilities.PublishNpm, new Claim("role", "member"));
        await handler.HandleAsync(ctx);
        // Authorization fails by absence of Succeed, not an explicit Fail call.
        Assert.False(ctx.HasSucceeded);
    }

    [Fact]
    public async Task Handler_AuditorRole_GrantsReadAuditOnly()
    {
        var handler = new CapabilityHandler();

        var canRead = ContextFor(Capabilities.ReadAudit, new Claim("role", "auditor"));
        await handler.HandleAsync(canRead);
        Assert.True(canRead.HasSucceeded);

        var cannotPublish = ContextFor(Capabilities.PublishNpm, new Claim("role", "auditor"));
        await handler.HandleAsync(cannotPublish);
        Assert.False(cannotPublish.HasSucceeded);
    }

    [Fact]
    public async Task Handler_SystemAdminRole_GetsPlatformCapabilities()
    {
        var handler = new CapabilityHandler();
        // platform admin has read:audit; the wildcard publish:* is a tenant capability and
        // should NOT be granted to the system_admin identity (writes go through assume_tenant).
        var canReadAudit = ContextFor(Capabilities.ReadAudit, new Claim("role", "system_admin"));
        await handler.HandleAsync(canReadAudit);
        Assert.True(canReadAudit.HasSucceeded);

        var cannotPublish = ContextFor(Capabilities.PublishNpm, new Claim("role", "system_admin"));
        await handler.HandleAsync(cannotPublish);
        Assert.False(cannotPublish.HasSucceeded);
    }

    [Fact]
    public async Task Handler_NoRoleClaim_Denies()
    {
        var handler = new CapabilityHandler();
        var ctx = ContextFor(Capabilities.ReadMetadata);   // no role claim
        await handler.HandleAsync(ctx);
        Assert.False(ctx.HasSucceeded);
    }

    [Fact]
    public async Task Handler_ExplicitCapClaims_GrantOnlyNarrowedCaps()
    {
        // Token-narrowed principal carries explicit "cap" claims. Only those caps grant;
        // the role claim must NOT be consulted, otherwise narrowing wouldn't actually narrow.
        var handler = new CapabilityHandler();

        var grants = ContextFor(
            Capabilities.ReadMetadata,
            new Claim("role", "owner"),                       // owner would normally grant everything
            new Claim("cap", Capabilities.ReadMetadata));
        await handler.HandleAsync(grants);
        Assert.True(grants.HasSucceeded);

        var denies = ContextFor(
            Capabilities.PublishNpm,
            new Claim("role", "owner"),                       // owner role would grant — but narrowed
            new Claim("cap", Capabilities.ReadMetadata));
        await handler.HandleAsync(denies);
        Assert.False(denies.HasSucceeded);
    }

    // ── API-token principals with zero cap claims must NOT inherit the owner's role ──────

    [Fact]
    public async Task Handler_ApiTokenNoCapClaims_DeniesRoleFallback()
    {
        // A user-owned API token whose `capabilities` column is legacy-NULL emits zero `cap`
        // claims but still carries the owner's `role` claim. It authenticates under the ApiToken
        // scheme, so the role fallback must NOT run — the empty capability set denies. Otherwise
        // the zero-capability token silently inherits its owner's full owner-role grant.
        var handler = new CapabilityHandler();
        var ctx = ContextForScheme(
            Capabilities.PublishNpm,
            TokenAuthenticationDefaults.Scheme,
            new Claim("role", "owner"));
        await handler.HandleAsync(ctx);
        Assert.False(ctx.HasSucceeded);
    }

    [Fact]
    public async Task Handler_ApiTokenWithCapClaim_Grants()
    {
        // Adversarial twin: an API token that DOES carry the required explicit capability still
        // authorizes — the fix denies only the zero-capability legacy case, not narrowed tokens.
        var handler = new CapabilityHandler();
        var ctx = ContextForScheme(
            Capabilities.PublishNpm,
            TokenAuthenticationDefaults.Scheme,
            new Claim("role", "member"),
            new Claim("cap", Capabilities.PublishNpm));
        await handler.HandleAsync(ctx);
        Assert.True(ctx.HasSucceeded);
    }

    [Fact]
    public async Task Handler_JwtSessionNoCapClaims_StillGrantsViaRole()
    {
        // Adversarial twin: a genuine JWT-session principal (non-ApiToken scheme) carrying a
        // `role` claim and no `cap` claims must still be granted via the role fallback — that
        // fallback is legitimate for sessions and must not regress when the ApiToken leg is closed.
        var handler = new CapabilityHandler();
        var ctx = ContextForScheme(
            Capabilities.PublishNpm,
            "AuthenticationTypes.Federation",                 // JwtBearer's default identity scheme
            new Claim("role", "owner"));
        await handler.HandleAsync(ctx);
        Assert.True(ctx.HasSucceeded);
    }
}
