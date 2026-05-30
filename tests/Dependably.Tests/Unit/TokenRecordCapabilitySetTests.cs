using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class TokenRecordCapabilitySetTests
{
    [Fact]
    public void CapabilitySet_NullJson_ReturnsEmpty()
    {
        var token = new TokenRecord { Capabilities = null };
        Assert.Empty(token.CapabilitySet);
    }

    [Fact]
    public void CapabilitySet_WhitespaceJson_ReturnsEmpty()
    {
        var token = new TokenRecord { Capabilities = "   " };
        Assert.Empty(token.CapabilitySet);
    }

    [Fact]
    public void CapabilitySet_MalformedJson_ReturnsEmpty()
    {
        var token = new TokenRecord { Capabilities = "{not json[" };
        Assert.Empty(token.CapabilitySet);
    }

    [Fact]
    public void CapabilitySet_EmptyArray_ReturnsEmpty()
    {
        var token = new TokenRecord { Capabilities = "[]" };
        Assert.Empty(token.CapabilitySet);
    }

    [Fact]
    public void CapabilitySet_ValidArray_ReturnsParsedSet()
    {
        var token = new TokenRecord { Capabilities = "[\"publish:npm\",\"read:metadata\"]" };
        Assert.Contains("publish:npm", token.CapabilitySet);
        Assert.Contains("read:metadata", token.CapabilitySet);
        Assert.Equal(2, token.CapabilitySet.Count);
    }

    [Fact]
    public void CapabilitySet_FiltersWhitespaceEntries()
    {
        var token = new TokenRecord { Capabilities = "[\"publish:npm\",\"\",\"  \"]" };
        Assert.Single(token.CapabilitySet);
        Assert.Contains("publish:npm", token.CapabilitySet);
    }

    // Caching invariant from #97: repeated reads must return the same instance — proves
    // we parsed the JSON exactly once and cached the result on the TokenRecord.
    [Fact]
    public void CapabilitySet_CachedAcrossReads()
    {
        var token = new TokenRecord { Capabilities = "[\"publish:npm\"]" };
        var first = token.CapabilitySet;
        var second = token.CapabilitySet;
        Assert.Same(first, second);
    }

    // Setter must invalidate the cache so mutated rows don't carry stale auth data.
    [Fact]
    public void CapabilitySet_InvalidatedWhenCapabilitiesChange()
    {
        var token = new TokenRecord { Capabilities = "[\"publish:npm\"]" };
        var first = token.CapabilitySet;

        token.Capabilities = "[\"publish:pypi\"]";
        var second = token.CapabilitySet;

        Assert.NotSame(first, second);
        Assert.Contains("publish:pypi", second);
        Assert.DoesNotContain("publish:npm", second);
    }
}
