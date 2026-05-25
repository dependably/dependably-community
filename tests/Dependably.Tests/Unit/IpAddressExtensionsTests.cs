using System.Net;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Xunit;

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
}
