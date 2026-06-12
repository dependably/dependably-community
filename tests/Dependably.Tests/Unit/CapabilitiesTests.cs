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
        Assert.False(Capabilities.Grants(granted, Capabilities.ImportNpm));
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
