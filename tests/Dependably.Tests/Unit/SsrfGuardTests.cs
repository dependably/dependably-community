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

    // IPv6 transitional/embedding encodings — 6to4, Teredo, and NAT64 all carry an IPv4 address
    // inside an IPv6 literal. A blocked IPv4 target reachable only through one of these
    // encodings must still be caught.

    [Theory]
    [InlineData("2002:0a00:0001::")]     // 6to4 encoding 10.0.0.1 (RFC 1918)
    [InlineData("2002:7f00:0001::")]     // 6to4 encoding 127.0.0.1 (loopback)
    [InlineData("2002:a9fe:a9fe::")]     // 6to4 encoding 169.254.169.254 (cloud metadata)
    [InlineData("2001::80ff:fffe")]      // Teredo encoding 127.0.0.1 (XOR-obfuscated client)
    [InlineData("2001::53ef:fffe")]      // Teredo encoding 172.16.0.1 (RFC 1918)
    [InlineData("64:ff9b::a00:1")]       // NAT64 (RFC 6052) encoding 10.0.0.1
    [InlineData("64:ff9b::7f00:1")]      // NAT64 encoding 127.0.0.1
    public void IsBlockedIp_TransitionalEncodingOfBlockedTarget_ReturnsTrue(string ip)
    {
        Assert.True(SsrfGuard.IsBlockedIp(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("2002:0808:0808::")]     // 6to4 encoding 8.8.8.8 (public)
    [InlineData("2001::f7f7:f7f7")]      // Teredo encoding 8.8.8.8 (public)
    [InlineData("64:ff9b::808:808")]     // NAT64 encoding 8.8.8.8 (public)
    public void IsBlockedIp_TransitionalEncodingOfPublicTarget_ReturnsFalse(string ip)
    {
        Assert.False(SsrfGuard.IsBlockedIp(IPAddress.Parse(ip)));
    }

    [Fact]
    public void IsBlockedIp_TransitionalEncodings_MixedBatch_BlockedAndAllowedBehaveCorrectly()
    {
        // Partial-failure scenario across the three transitional encodings in one batch:
        // some carry a blocked target, some carry a public one, evaluated independently.
        var cases = new (string Ip, bool ShouldBlock)[]
        {
            ("2002:0a00:0001::", true),   // 6to4 → 10.0.0.1
            ("2002:0808:0808::", false),  // 6to4 → 8.8.8.8
            ("2001::80ff:fffe", true),    // Teredo → 127.0.0.1
            ("2001::f7f7:f7f7", false),   // Teredo → 8.8.8.8
            ("64:ff9b::a00:1", true),     // NAT64 → 10.0.0.1
            ("64:ff9b::808:808", false),  // NAT64 → 8.8.8.8
        };

        var failures = cases
            .Where(c => SsrfGuard.IsBlockedIp(IPAddress.Parse(c.Ip)) != c.ShouldBlock)
            .Select(c => $"{c.Ip}: expected blocked={c.ShouldBlock}")
            .ToList();

        Assert.Empty(failures);
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
