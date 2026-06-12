using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Saml;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="RoleAttributeResolver"/> — the SAML role precedence chain.
/// Exercised through the claims-based <c>Resolve</c> overload and the public
/// <c>GetRoleValues</c> helper, so no live <c>Saml2AuthnResponse</c> is needed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RoleAttributeResolverTests
{
    private static Claim C(string type, string value) => new(type, value);

    // ---- Resolve: mapping-empty short-circuit ----

    [Fact]
    public void Resolve_NoMapping_ReturnsDefaultRole()
    {
        var cfg = new TenantSamlConfig { RoleMapping = null, DefaultRole = "admin" };
        Assert.Equal("admin", RoleAttributeResolver.Resolve(new[] { C("Role", "anything") }, cfg));
    }

    [Fact]
    public void Resolve_NoMapping_InvalidDefault_FallsBackToMember()
    {
        var cfg = new TenantSamlConfig { RoleMapping = "   ", DefaultRole = "superuser" };
        Assert.Equal("member", RoleAttributeResolver.Resolve(Array.Empty<Claim>(), cfg));
    }

    [Fact]
    public void Resolve_NoMapping_SystemAdminDefault_FallsBackToMember()
    {
        // system_admin is never a valid tenant role output.
        var cfg = new TenantSamlConfig { RoleMapping = null, DefaultRole = "system_admin" };
        Assert.Equal("member", RoleAttributeResolver.Resolve(Array.Empty<Claim>(), cfg));
    }

    // ---- Resolve: mapping match + precedence ----

    [Fact]
    public void Resolve_MappedValue_ReturnsMappedRole()
    {
        var cfg = new TenantSamlConfig
        {
            RoleMapping = """{"DevOps":"admin"}""",
            RoleAttribute = "groups",
        };
        Assert.Equal("admin", RoleAttributeResolver.Resolve(new[] { C("groups", "DevOps") }, cfg));
    }

    [Fact]
    public void Resolve_MultipleMatches_HighestPrecedenceWins()
    {
        // owner(0) > admin(1) > auditor(2) > member(3): owner must win regardless of claim order.
        var cfg = new TenantSamlConfig
        {
            RoleMapping = """{"g-member":"member","g-owner":"owner","g-admin":"admin"}""",
            RoleAttribute = "groups",
        };
        var claims = new[] { C("groups", "g-member"), C("groups", "g-admin"), C("groups", "g-owner") };
        Assert.Equal("owner", RoleAttributeResolver.Resolve(claims, cfg));
    }

    [Fact]
    public void Resolve_NoValueMatchesMapping_ReturnsDefault()
    {
        var cfg = new TenantSamlConfig
        {
            RoleMapping = """{"DevOps":"admin"}""",
            RoleAttribute = "groups",
            DefaultRole = "auditor",
        };
        Assert.Equal("auditor", RoleAttributeResolver.Resolve(new[] { C("groups", "Sales") }, cfg));
    }

    [Fact]
    public void Resolve_UsesBuiltInClaimTypes_WhenNoAttributeConfigured()
    {
        var cfg = new TenantSamlConfig { RoleMapping = """{"team-x":"member"}""" };
        var claims = new[] { C("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "team-x") };
        Assert.Equal("member", RoleAttributeResolver.Resolve(claims, cfg));
    }

    // ---- ParseMapping edge cases (via Resolve) ----

    [Fact]
    public void Resolve_MalformedJsonMapping_TreatedAsNoMapping()
    {
        var cfg = new TenantSamlConfig { RoleMapping = "{not-json", DefaultRole = "auditor" };
        // Bad JSON => empty mapping => default role.
        Assert.Equal("auditor", RoleAttributeResolver.Resolve(new[] { C("Role", "x") }, cfg));
    }

    [Fact]
    public void Resolve_MappingValueCaseInsensitive()
    {
        var cfg = new TenantSamlConfig { RoleMapping = """{"Admins":"ADMIN"}""", RoleAttribute = "groups" };
        Assert.Equal("admin", RoleAttributeResolver.Resolve(new[] { C("groups", "Admins") }, cfg));
    }

    [Fact]
    public void Resolve_MappingToSystemAdmin_IsStripped()
    {
        // A mapping entry targeting system_admin must be dropped, leaving an empty mapping
        // => default role is used.
        var cfg = new TenantSamlConfig
        {
            RoleMapping = """{"god":"system_admin"}""",
            RoleAttribute = "groups",
            DefaultRole = "member",
        };
        Assert.Equal("member", RoleAttributeResolver.Resolve(new[] { C("groups", "god") }, cfg));
    }

    [Fact]
    public void Resolve_MappingWithInvalidAndValidEntries_KeepsOnlyValid()
    {
        var cfg = new TenantSamlConfig
        {
            RoleMapping = """{"bad":"wizard","good":"owner"}""",
            RoleAttribute = "groups",
        };
        var claims = new[] { C("groups", "bad"), C("groups", "good") };
        Assert.Equal("owner", RoleAttributeResolver.Resolve(claims, cfg));
    }

    [Fact]
    public void Resolve_MappingJsonNull_TreatedAsNoMapping()
    {
        var cfg = new TenantSamlConfig { RoleMapping = "null", DefaultRole = "member" };
        Assert.Equal("member", RoleAttributeResolver.Resolve(Array.Empty<Claim>(), cfg));
    }

    // ---- GetRoleValues ----

    [Fact]
    public void GetRoleValues_ConfiguredAttribute_ReturnsAllMatchingValues()
    {
        var claims = new[]
        {
            C("groups", "a"),
            C("groups", "b"),
            C("other", "c"),
        };
        var values = RoleAttributeResolver.GetRoleValues(claims, "groups");
        Assert.Equal(new[] { "a", "b" }, values);
    }

    [Fact]
    public void GetRoleValues_ConfiguredAttribute_IsCaseInsensitive()
    {
        var claims = new[] { C("Groups", "a") };
        var values = RoleAttributeResolver.GetRoleValues(claims, "groups");
        Assert.Equal(new[] { "a" }, values);
    }

    [Fact]
    public void GetRoleValues_NoAttribute_FirstBuiltInTypeWithValuesWins()
    {
        // "Role" (built-in) is present; "groups" (later in list) also present but the
        // first type with any value short-circuits.
        var claims = new[]
        {
            C("Role", "r1"),
            C("groups", "g1"),
        };
        var values = RoleAttributeResolver.GetRoleValues(claims, null);
        Assert.Equal(new[] { "r1" }, values);
    }

    [Fact]
    public void GetRoleValues_NoAttribute_FallsThroughToLaterBuiltInType()
    {
        var claims = new[] { C("groups", "g1") };
        var values = RoleAttributeResolver.GetRoleValues(claims, null);
        Assert.Equal(new[] { "g1" }, values);
    }

    [Fact]
    public void GetRoleValues_NoMatch_ReturnsEmpty()
    {
        var claims = new[] { C("unrelated", "x") };
        Assert.Empty(RoleAttributeResolver.GetRoleValues(claims, null));
    }

    [Fact]
    public void GetRoleValues_BlankConfiguredAttribute_UsesBuiltInList()
    {
        var claims = new[] { C("Role", "r1") };
        var values = RoleAttributeResolver.GetRoleValues(claims, "   ");
        Assert.Equal(new[] { "r1" }, values);
    }
}
