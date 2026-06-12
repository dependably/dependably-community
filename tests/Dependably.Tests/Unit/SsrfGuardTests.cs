using System.Net;
using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Security")]
public class SsrfGuardTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.100")]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]   // cloud metadata endpoint
    [InlineData("100.64.0.1")]        // CGNAT shared space
    [InlineData("::1")]               // IPv6 loopback
    [InlineData("fc00::1")]           // IPv6 unique-local
    [InlineData("fe80::1")]           // IPv6 link-local
    public void IsBlockedIp_PrivateOrInternal_ReturnsTrue(string ip)
    {
        Assert.True(SsrfGuard.IsBlockedIp(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("140.82.121.4")]
    [InlineData("2606:4700:4700::1111")]   // public IPv6 (Cloudflare)
    public void IsBlockedIp_Public_ReturnsFalse(string ip)
    {
        Assert.False(SsrfGuard.IsBlockedIp(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("::ffff:127.0.0.1")]      // IPv4-mapped loopback
    [InlineData("::ffff:169.254.169.254")] // IPv4-mapped metadata endpoint
    [InlineData("::ffff:10.0.0.1")]       // IPv4-mapped RFC1918
    public void IsBlockedIp_Ipv4MappedInternal_ReturnsTrue(string ip)
    {
        // A mapped internal address must not slip past the IPv4 ranges.
        Assert.True(SsrfGuard.IsBlockedIp(IPAddress.Parse(ip)));
    }
}
