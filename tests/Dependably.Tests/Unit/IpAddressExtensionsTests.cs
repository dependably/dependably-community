using System.Net;
using Dependably.Security;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class IpAddressExtensionsTests
{
    // ---------- Normalize(IPAddress?) ----------

    [Fact]
    public void Normalize_ReturnsNull_ForNullInput()
    {
        Assert.Null(IpAddressExtensions.Normalize(null));
    }

    [Fact]
    public void Normalize_ReturnsDottedQuad_ForPlainIPv4()
    {
        Assert.Equal("10.1.2.3", IpAddressExtensions.Normalize(IPAddress.Parse("10.1.2.3")));
    }

    [Fact]
    public void Normalize_CollapsesIPv4MappedIPv6_ToDottedQuad()
    {
        // ::ffff:10.1.2.3 — the dual-stack Kestrel form
        var mapped = IPAddress.Parse("::ffff:10.1.2.3");
        Assert.True(mapped.IsIPv4MappedToIPv6);
        Assert.Equal("10.1.2.3", IpAddressExtensions.Normalize(mapped));
    }

    [Fact]
    public void Normalize_LeavesGenuineIPv6_Untouched()
    {
        var v6 = IPAddress.Parse("2001:db8::1");
        Assert.False(v6.IsIPv4MappedToIPv6);
        Assert.Equal("2001:db8::1", IpAddressExtensions.Normalize(v6));
    }

    [Fact]
    public void Normalize_HandlesIPv6Loopback()
    {
        Assert.Equal("::1", IpAddressExtensions.Normalize(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void Normalize_HandlesIPv4Loopback()
    {
        Assert.Equal("127.0.0.1", IpAddressExtensions.Normalize(IPAddress.Loopback));
    }

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    public void Normalize_RoundTrips_VariousIPv4(string addr)
    {
        Assert.Equal(addr, IpAddressExtensions.Normalize(IPAddress.Parse(addr)));
    }

    // ---------- GetNormalizedRemoteIp(HttpContext?) ----------

    [Fact]
    public void GetNormalizedRemoteIp_ReturnsNull_ForNullContext()
    {
        HttpContext? ctx = null;
        Assert.Null(ctx.GetNormalizedRemoteIp());
    }

    [Fact]
    public void GetNormalizedRemoteIp_ReturnsNull_WhenRemoteIpAddressIsNull()
    {
        // DefaultHttpContext starts with a Connection but no RemoteIpAddress set.
        var ctx = new DefaultHttpContext();
        Assert.Null(ctx.Connection.RemoteIpAddress);
        Assert.Null(ctx.GetNormalizedRemoteIp());
    }

    [Fact]
    public void GetNormalizedRemoteIp_ReturnsDottedQuad_ForPlainIPv4()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("10.20.30.40");
        Assert.Equal("10.20.30.40", ctx.GetNormalizedRemoteIp());
    }

    [Fact]
    public void GetNormalizedRemoteIp_CollapsesIPv4MappedIPv6_ToDottedQuad()
    {
        // Simulates Kestrel's dual-stack representation of an incoming v4 connection.
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:172.16.0.5");
        Assert.Equal("172.16.0.5", ctx.GetNormalizedRemoteIp());
    }

    [Fact]
    public void GetNormalizedRemoteIp_LeavesGenuineIPv6_Untouched()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8::dead:beef");
        Assert.Equal("2001:db8::dead:beef", ctx.GetNormalizedRemoteIp());
    }

    // ---------- NormalizeForRateLimit(IPAddress?) — the #427 /64 partition ----------
    //
    // The rate-limit partition key must aggregate IPv6 to its routed /64 so that a single attacker
    // holding a /64 (the standard VPS/residential allocation) cannot mint 2^64 fresh budgets. IPv4
    // stays at its full /32, and audit source_ip (GetNormalizedRemoteIp above) keeps the full
    // address — these are deliberately different decisions.

    [Fact]
    public void NormalizeForRateLimit_ReturnsNull_ForNullInput()
    {
        Assert.Null(IpAddressExtensions.NormalizeForRateLimit(null));
    }

    [Fact]
    public void NormalizeForRateLimit_TwoAddressesInSameSlash64_ShareOnePartitionKey()
    {
        // Same /64 (2001:db8:1:2::/64), different low 64 bits — an attacker rebinding source
        // addresses inside their own allocation.
        string a = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:1:2::1"))!;
        string b = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:1:2:ffff:ffff:ffff:ffff"))!;

        Assert.Equal(a, b);
        // The key names the aggregate, not either host address, so it can't collide with a /128.
        Assert.Equal("2001:db8:1:2::/64", a);
    }

    [Fact]
    public void NormalizeForRateLimit_TwoDifferentSlash64s_DoNotShareAPartitionKey()
    {
        // Adjacent but distinct /64s (…:2:: vs …:3::) must remain separate budgets — no
        // over-collapsing that would let one tenant's traffic exhaust another's.
        string a = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:1:2::1"))!;
        string b = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:1:3::1"))!;

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void NormalizeForRateLimit_IPv4_StaysAtFullSlash32_NoAggregation()
    {
        // Two hosts in the same /24 must NOT collapse: IPv4 partitioning is unchanged.
        string a = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("203.0.113.7"))!;
        string b = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("203.0.113.8"))!;

        Assert.NotEqual(a, b);
        Assert.Equal("203.0.113.7", a);
    }

    [Fact]
    public void NormalizeForRateLimit_IPv4MappedIPv6_TreatedAsFullIPv4()
    {
        // Kestrel's dual-stack ::ffff:v4 form is a v4 host, not a v6 /64 — keep its full /32.
        string mapped = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("::ffff:198.51.100.9"))!;
        Assert.Equal("198.51.100.9", mapped);
    }

    [Fact]
    public void NormalizeForRateLimit_HonoursConfiguredPrefix()
    {
        // With a /48 override, two different /64s inside one /48 collapse together…
        string a = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:1:2::1"), 48)!;
        string b = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:1:9::1"), 48)!;
        Assert.Equal(a, b);
        Assert.Equal("2001:db8:1::/48", a);

        // …but a different /48 still does not.
        string c = IpAddressExtensions.NormalizeForRateLimit(IPAddress.Parse("2001:db8:2:2::1"), 48)!;
        Assert.NotEqual(a, c);
    }

    // ---------- GetRateLimitPartitionIp(HttpContext?) ----------

    [Fact]
    public void GetRateLimitPartitionIp_CollapsesIPv6_ButAuditIpKeepsFullAddress()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8:1:2::abcd");

        // Partition key aggregates to the /64…
        Assert.Equal("2001:db8:1:2::/64", ctx.GetRateLimitPartitionIp());
        // …while the audit path still records the exact source address (the adversarial twin).
        Assert.Equal("2001:db8:1:2::abcd", ctx.GetNormalizedRemoteIp());
    }

    [Fact]
    public void GetRateLimitPartitionIp_ReturnsNull_ForNullContext()
    {
        HttpContext? ctx = null;
        Assert.Null(ctx.GetRateLimitPartitionIp());
    }
}
