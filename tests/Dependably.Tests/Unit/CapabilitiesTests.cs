using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class CapabilitiesTests
{
    [Fact]
    public void Member_GetsReaderCaps_NotPublish()
    {
        var caps = Capabilities.ForRole("member");
        Assert.True(Capabilities.Grants(caps, Capabilities.ReadMetadata));
        Assert.True(Capabilities.Grants(caps, Capabilities.ReadArtifact));
        Assert.False(Capabilities.Grants(caps, Capabilities.PublishNpm));
        Assert.False(Capabilities.Grants(caps, Capabilities.ClaimManage));
    }

    [Fact]
    public void Admin_GetsPublishWildcardAndClaimManage()
    {
        var caps = Capabilities.ForRole("admin");
        Assert.True(Capabilities.Grants(caps, Capabilities.PublishNpm));
        Assert.True(Capabilities.Grants(caps, Capabilities.PublishPypi));
        Assert.True(Capabilities.Grants(caps, Capabilities.ClaimManage));
        Assert.False(Capabilities.Grants(caps, Capabilities.TenantAdmin));
    }

    [Fact]
    public void Admin_GetsAuditReadAndTenantConfigure()
    {
        // Role→capability migration (PR-1): admin role must include read:audit and
        // tenant:configure so the management API can drop RoleRank without changing
        // who can read the audit log or write tenant settings. tenant:admin stays
        // owner-only — the only owner-distinguishing capability.
        var caps = Capabilities.ForRole("admin");
        Assert.True(Capabilities.Grants(caps, Capabilities.ReadAudit));
        Assert.True(Capabilities.Grants(caps, Capabilities.TenantConfigure));
        Assert.False(Capabilities.Grants(caps, Capabilities.TenantAdmin));
    }

    [Fact]
    public void Owner_GetsTenantConfigureInAdditionToTenantAdmin()
    {
        var caps = Capabilities.ForRole("owner");
        Assert.True(Capabilities.Grants(caps, Capabilities.TenantAdmin));
        Assert.True(Capabilities.Grants(caps, Capabilities.TenantConfigure));
    }

    [Fact]
    public void Member_DoesNotGetAuditOrTenantConfigure()
    {
        var caps = Capabilities.ForRole("member");
        Assert.False(Capabilities.Grants(caps, Capabilities.ReadAudit));
        Assert.False(Capabilities.Grants(caps, Capabilities.TenantConfigure));
    }

    [Fact]
    public void Owner_GetsTenantAdminAndAuditRead()
    {
        var caps = Capabilities.ForRole("owner");
        Assert.True(Capabilities.Grants(caps, Capabilities.TenantAdmin));
        Assert.True(Capabilities.Grants(caps, Capabilities.ReadAudit));
        Assert.True(Capabilities.Grants(caps, Capabilities.PublishNuget));
    }

    [Fact]
    public void Auditor_OnlyAuditAndOwnTokens()
    {
        var caps = Capabilities.ForRole("auditor");
        Assert.True(Capabilities.Grants(caps, Capabilities.ReadAudit));
        Assert.True(Capabilities.Grants(caps, Capabilities.ManageOwnTokens));
        Assert.False(Capabilities.Grants(caps, Capabilities.ReadMetadata));
        Assert.False(Capabilities.Grants(caps, Capabilities.PublishNpm));
    }

    [Fact]
    public void UnknownRole_EmptyCaps()
    {
        var caps = Capabilities.ForRole("ghost");
        Assert.Empty(caps);
        Assert.False(Capabilities.Grants(caps, Capabilities.ReadMetadata));
    }

    [Fact]
    public void Grants_WildcardWithinFamily()
    {
        var granted = new HashSet<string> { "publish:*" };
        Assert.True(Capabilities.Grants(granted, Capabilities.PublishNpm));
        Assert.True(Capabilities.Grants(granted, Capabilities.PublishPypi));
        // A family wildcard stays inside its family: it never reaches a sibling family's
        // leaf or wildcard. This is what keeps "can publish" from meaning "can also delete".
        Assert.False(Capabilities.Grants(granted, Capabilities.YankNpm));
        Assert.False(Capabilities.Grants(granted, Capabilities.ImportAll));
        Assert.False(Capabilities.Grants(granted, Capabilities.ReadArtifact));
    }

    /// <summary>
    /// The capability column is parsed all-or-nothing: one non-string element aborts the whole
    /// deserialize and the token is left granting nothing. Pinned because the UI mirrors this
    /// rule to decide what to display, and a UI that filtered the bad entries and rendered the
    /// rest would show a grant the credential does not hold — the exact confusion the display
    /// exists to remove.
    /// </summary>
    [Theory]
    [InlineData("[\"read:metadata\",1]")]
    [InlineData("[1,2,3]")]
    [InlineData("{\"foo\":1}")]
    [InlineData("not-json")]
    [InlineData("[]")]
    [InlineData("")]
    [InlineData(null)]
    public void CapabilitySet_MalformedOrMixedTypeValue_GrantsNothing(string? stored)
    {
        var token = new TokenRecord { Capabilities = stored };

        Assert.Empty(token.CapabilitySet);
        Assert.False(Capabilities.Grants(token.CapabilitySet, Capabilities.ReadMetadata));
        Assert.False(Capabilities.Grants(token.CapabilitySet, Capabilities.PublishOci));
    }

    /// <summary>A blank entry is dropped, and the surrounding grants survive.</summary>
    [Fact]
    public void CapabilitySet_BlankEntry_IsDroppedWithoutVoidingTheRest()
    {
        var token = new TokenRecord { Capabilities = "[\"read:metadata\",\"  \"]" };

        Assert.Equal(["read:metadata"], token.CapabilitySet);
    }

    [Fact]
    public void Grants_GlobalWildcardGrantsEverything()
    {
        var granted = new HashSet<string> { "*" };
        Assert.True(Capabilities.Grants(granted, Capabilities.PublishNpm));
        Assert.True(Capabilities.Grants(granted, Capabilities.TenantAdmin));
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadAudit));
    }

    [Fact]
    public void PlatformAdminCaps_GrantsPlatformWildcard()
    {
        var caps = Capabilities.ForPlatformAdmin();
        Assert.True(Capabilities.Grants(caps, Capabilities.PlatformAll));
        // Platform admin reads everything but does not get tenant write capabilities.
        Assert.False(Capabilities.Grants(caps, Capabilities.PublishNpm));
        Assert.False(Capabilities.Grants(caps, Capabilities.TenantAdmin));
    }

    [Fact]
    public void Grants_ReadAllWildcard_GrantsEveryReadLeaf()
    {
        var granted = new HashSet<string> { Capabilities.ReadAll };
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadMetadata));
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadArtifact));
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadPackages));
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadClaims));
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadAudit));
        Assert.True(Capabilities.Grants(granted, Capabilities.ReadTenant));
        // A different family is untouched by the read:* wildcard.
        Assert.False(Capabilities.Grants(granted, Capabilities.PublishNpm));
    }

    [Fact]
    public void AdminAndOwner_HoldReadAllLiteral_ForMinting()
    {
        // read:* is granted alongside (not instead of) the enumerated leaves, since admin/owner
        // already hold every individual leaf — minting it never widens effective access.
        Assert.True(Capabilities.Grants(Capabilities.ForRole("admin"), Capabilities.ReadAll));
        Assert.True(Capabilities.Grants(Capabilities.ForRole("owner"), Capabilities.ReadAll));
        Assert.True(Capabilities.Grants(Capabilities.ForPlatformAdmin(), Capabilities.ReadAll));
        // Member and auditor hold only a subset of the six read leaves, so they must not carry
        // the literal wildcard — that would be a real privilege escalation for them.
        Assert.False(Capabilities.Grants(Capabilities.ForRole("member"), Capabilities.ReadAll));
        Assert.False(Capabilities.Grants(Capabilities.ForRole("auditor"), Capabilities.ReadAll));
    }

    [Fact]
    public void Grants_RequestedCapabilityWithoutColon_ReturnsFalse()
    {
        // Hits the `colon < 0` fall-through: a malformed capability with no domain
        // segment cannot match any family wildcard, and is not present in the granted
        // set, so Grants returns false instead of attempting to build a family key.
        var granted = new HashSet<string> { Capabilities.PublishAll, Capabilities.ReadMetadata };
        Assert.False(Capabilities.Grants(granted, "malformed"));
        Assert.False(Capabilities.Grants(granted, ""));
    }
}
