using System.Text.Json;
using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class CapabilityValidationTests
{
    private static readonly IReadOnlySet<string> OwnerGrants = Capabilities.ForRole("owner");
    private static readonly IReadOnlySet<string> AdminGrants = Capabilities.ForRole("admin");
    private static readonly IReadOnlySet<string> MemberGrants = Capabilities.ForRole("member");

    [Fact]
    public void Null_Rejected()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            null, OwnerGrants, out _, out _, out string? error, out string? field);
        Assert.False(ok);
        Assert.Equal("capabilities", field);
        Assert.Contains("required", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Empty_Rejected()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            Array.Empty<string>(), OwnerGrants, out _, out _, out string? error, out string? field);
        Assert.False(ok);
        Assert.Equal("capabilities", field);
        Assert.Contains("required", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Blank_Entry_Rejected()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "  " }, OwnerGrants, out _, out _, out _, out _);
        Assert.False(ok);
    }

    [Fact]
    public void Unknown_Capability_Rejected()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "publish:npm", "wat:dance" }, OwnerGrants,
            out _, out _, out string? error, out string? field);
        Assert.False(ok);
        Assert.Equal("capabilities", field);
        Assert.Contains("wat:dance", error);
    }

    [Fact]
    public void Duplicate_Rejected()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "publish:npm", "publish:npm" }, OwnerGrants,
            out _, out _, out string? error, out string? field);
        Assert.False(ok);
        Assert.Equal("capabilities", field);
        Assert.Contains("Duplicate", error);
    }

    [Fact]
    public void Member_Cannot_Mint_Publish()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "publish:npm" }, MemberGrants,
            out _, out _, out string? error, out string? field);
        Assert.False(ok);
        Assert.Equal("capabilities", field);
        Assert.Contains("exceed your role", error);
    }

    [Fact]
    public void Admin_Can_Mint_Publish_But_Not_TenantAdmin()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "publish:npm" }, AdminGrants,
            out _, out _, out _, out _);
        Assert.True(ok);

        bool ok2 = Capabilities.TryNormalizeAndAuthorize(
            new[] { "tenant:admin" }, AdminGrants,
            out _, out _, out _, out _);
        Assert.False(ok2);
    }

    [Fact]
    public void Canonical_Json_Is_Sorted()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "publish:npm", "read:metadata", "publish:pypi" }, OwnerGrants,
            out string? canonicalJson, out string[]? caps, out _, out _);
        Assert.True(ok);
        // Sorted ordinal: publish:npm, publish:pypi, read:metadata
        Assert.Equal(new[] { "publish:npm", "publish:pypi", "read:metadata" }, caps);
        Assert.Equal("""["publish:npm","publish:pypi","read:metadata"]""", canonicalJson);
    }

    [Fact]
    public void Canonical_Json_Matches_Structured_Array()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "read:audit", "tokens:manage_own" }, OwnerGrants,
            out string? canonicalJson, out string[]? caps, out _, out _);
        Assert.True(ok);
        string[]? roundTrip = JsonSerializer.Deserialize<string[]>(canonicalJson);
        Assert.Equal(caps, roundTrip);
    }

    [Fact]
    public void Global_Wildcard_Not_Requestable()
    {
        // Even owners cannot mint a global "*" token via the request boundary; that wildcard
        // is system-internal.
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "*" }, OwnerGrants,
            out _, out _, out string? error, out _);
        Assert.False(ok);
        Assert.Contains("Unknown", error);
    }

    [Fact]
    public void Platform_Wildcard_Not_Requestable()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            new[] { "platform:*" }, OwnerGrants,
            out _, out _, out string? error, out _);
        Assert.False(ok);
        Assert.Contains("Unknown", error);
    }
}
