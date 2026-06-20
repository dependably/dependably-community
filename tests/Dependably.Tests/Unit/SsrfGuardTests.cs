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
    // 0/8 "this host" range — Linux kernel routes these to loopback
    [InlineData("0.0.0.0")]
    [InlineData("0.0.0.1")]
    [InlineData("0.255.255.255")]
    // IPv6 unspecified — routes to loopback on Linux
    [InlineData("::")]
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
    [InlineData("::ffff:0.0.0.1")]        // IPv4-mapped "this host" range
    public void IsBlockedIp_Ipv4MappedInternal_ReturnsTrue(string ip)
    {
        // A mapped internal address must not slip past the IPv4 ranges.
        Assert.True(SsrfGuard.IsBlockedIp(IPAddress.Parse(ip)));
    }

    // IsBlockedIpExcludingPrivate — the always-blocked set must also cover 0/8 and ::

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("0.1.2.3")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    public void IsBlockedIpExcludingPrivate_AlwaysBlockedAddresses_ReturnsTrue(string ip)
    {
        Assert.True(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("10.0.0.1")]         // RFC 1918 — permitted when private-IP opt-in is active
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    public void IsBlockedIpExcludingPrivate_Rfc1918OrPublic_ReturnsFalse(string ip)
    {
        // RFC 1918 addresses are allowed through IsBlockedIpExcludingPrivate so that
        // on-premise deployments can point upstreams at a private SIEM collector.
        Assert.False(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    [Fact]
    public void IsBlockedIp_MixedBatch_BlockedAndAllowedAddressesBehaveCorrectly()
    {
        // Partial-failure scenario: a mixed set of addresses where some are blocked and
        // some are allowed — each address is evaluated independently and must return the
        // correct result without the presence of other addresses changing the outcome.
        var cases = new (string Ip, bool ShouldBlock)[]
        {
            ("8.8.8.8", false),
            ("0.0.0.0", true),
            ("1.1.1.1", false),
            ("::", true),
            ("2606:4700:4700::1111", false),
            ("::1", true),
            ("10.0.0.1", true),
            ("140.82.121.4", false),
        };

        var failures = cases
            .Where(c => SsrfGuard.IsBlockedIp(IPAddress.Parse(c.Ip)) != c.ShouldBlock)
            .Select(c => $"{c.Ip}: expected blocked={c.ShouldBlock}")
            .ToList();

        Assert.Empty(failures);
    }
}
