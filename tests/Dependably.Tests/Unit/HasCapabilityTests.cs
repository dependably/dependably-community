using Dependably.Infrastructure;
using Dependably.Security;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="TokenAuthExtensions.HasCapability"/> reads the JSON <c>capabilities</c> column
/// as the only source of truth. NULL/malformed values deny everything — issuance always
/// stamps a canonical capability array via <c>Capabilities.TryNormalizeAndAuthorize</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HasCapabilityTests
{
    private static TokenRecord Token(string? capabilities = null) => new()
    {
        Id = "t1", OrgId = "o1", UserId = "u1", Capabilities = capabilities,
        CreatedAt = DateTimeOffset.UtcNow,
    };

    [Fact]
    public void Token_WithFineGrainedCapability_GrantsExactMatch()
    {
        var t = Token("""["publish:npm","read:metadata"]""");
        Assert.True(t.HasCapability(Capabilities.PublishNpm));
        Assert.True(t.HasCapability(Capabilities.ReadMetadata));
        Assert.False(t.HasCapability(Capabilities.PublishPypi));
        Assert.False(t.HasCapability(Capabilities.ClaimManage));
    }

    [Fact]
    public void Token_WithWildcardCapability_GrantsFamilyMembers()
    {
        var t = Token("""["publish:*"]""");
        Assert.True(t.HasCapability(Capabilities.PublishNpm));
        Assert.True(t.HasCapability(Capabilities.PublishPypi));
        Assert.True(t.HasCapability(Capabilities.PublishNuget));
        Assert.False(t.HasCapability(Capabilities.YankNpm));   // different family
    }

    [Fact]
    public void NullCapabilities_DeniesEverything()
    {
        // NULL capabilities = no permissions. Mint paths always populate the column, so
        // this row shape only occurs on corrupted rows or migration misses — deny is the
        // safe answer.
        var t = Token(capabilities: null);
        Assert.False(t.HasCapability(Capabilities.PublishNpm));
        Assert.False(t.HasCapability(Capabilities.ReadMetadata));
        Assert.False(t.HasCapability(Capabilities.ReadArtifact));
    }

    [Fact]
    public void MalformedCapabilitiesJson_DeniesEverything()
    {
        // Defensive: a malformed row must not throw mid-auth. The whole row becomes
        // "no capabilities" and every check denies.
        var t = Token("not json");
        Assert.False(t.HasCapability(Capabilities.PublishNpm));
        Assert.False(t.HasCapability(Capabilities.ReadMetadata));
    }

    [Fact]
    public void EmptyCapabilitiesJson_DeniesEverything()
    {
        var t = Token("[]");
        Assert.False(t.HasCapability(Capabilities.PublishNpm));
        Assert.False(t.HasCapability(Capabilities.ReadMetadata));
    }
}
