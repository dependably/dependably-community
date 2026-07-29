using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ConfigurationExtensionsTests
{
    private static IConfiguration Config(string? baseUrl) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["BASE_URL"] = baseUrl })
            .Build();

    [Fact]
    public void PublicBaseUrl_WithAndWithoutTrailingSlash_AreIdentical()
    {
        // The whole point: a trailing slash must not change the effective BASE_URL, so an
        // operator who pastes "https://repo.example.com/" gets the same behaviour as one who
        // does not. (A CORS origin or "{base}/join" link built from the slashed form would
        // otherwise silently break.)
        string? withSlash = Config("https://repo.example.com/").PublicBaseUrl();
        string? withoutSlash = Config("https://repo.example.com").PublicBaseUrl();

        Assert.Equal("https://repo.example.com", withoutSlash);
        Assert.Equal(withoutSlash, withSlash);
    }

    [Theory]
    [InlineData("https://repo.example.com/", "https://repo.example.com")]
    [InlineData("https://repo.example.com", "https://repo.example.com")]
    [InlineData("https://repo.example.com///", "https://repo.example.com")]
    [InlineData("http://localhost:8080/", "http://localhost:8080")]
    public void PublicBaseUrl_StripsTrailingSlashes(string configured, string expected)
        => Assert.Equal(expected, Config(configured).PublicBaseUrl());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PublicBaseUrl_ReturnsNull_WhenUnsetOrBlank(string? configured)
        => Assert.Null(Config(configured).PublicBaseUrl());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ParseTrustedProxies_UnsetOrBlank_ReturnsEmpty(string? value)
    {
        var (networks, proxies) = Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies(value);
        Assert.Empty(networks);
        Assert.Empty(proxies);
    }

    [Fact]
    public void ParseTrustedProxies_SplitsNetworksAndAddresses()
    {
        var (networks, proxies) = Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies(
            "10.0.0.0/8, 172.18.0.1 ,fd00::/8,::1");

        Assert.Equal(2, networks.Count);   // 10.0.0.0/8, fd00::/8
        Assert.Equal(2, proxies.Count);    // 172.18.0.1, ::1
        Assert.Contains(proxies, p => p.Equals(System.Net.IPAddress.Parse("172.18.0.1")));
        Assert.Contains(networks, n => n.Equals(System.Net.IPNetwork.Parse("10.0.0.0/8")));
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.0/999")]
    public void ParseTrustedProxies_Malformed_ThrowsAtStartup(string value)
        => Assert.ThrowsAny<FormatException>(() => Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies(value));

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    [InlineData("10.0.0.0/8,0.0.0.0/0")]
    public void ParseTrustedProxies_CatchAllRange_ThrowsAtStartup(string value)
    {
        // A /0 network trusts every possible peer as a forwarding proxy, so any client can
        // spoof X-Forwarded-For and forge the caller IP the /metrics, /version, and
        // management-docs allowlists authorize against. This must fail fast at startup rather
        // than silently accepting a config that trusts the entire internet.
        var ex = Assert.Throws<InvalidOperationException>(
            () => Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies(value));
        Assert.Contains("TRUSTED_PROXIES", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseTrustedProxies_NarrowRanges_AreNotRejected()
    {
        // A specific proxy subnet or VPC CIDR is a legitimate operator choice — only the
        // literal whole-address-space case (/0) is rejected.
        var (networks, _) = Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies("10.0.0.0/8,172.16.0.0/12");
        Assert.Equal(2, networks.Count);
    }

    [Theory]
    [InlineData("10.0.0.0/16", true)]     // whole-VPC-sized CIDR — every in-VPC host can forge its own source IP
    [InlineData("10.0.0.0/8", true)]
    [InlineData("10.0.0.0/22", false)]    // exactly at the threshold — not broader than it
    [InlineData("10.0.0.0/24", false)]    // a single conventional subnet — narrow
    [InlineData("10.0.0.0/28", false)]
    public void IsBroadTrustedProxyNetwork_Ipv4_MatchesPer22Threshold(string cidr, bool expectedBroad)
    {
        var network = System.Net.IPNetwork.Parse(cidr);
        Assert.Equal(expectedBroad, Dependably.Infrastructure.ConfigurationExtensions.IsBroadTrustedProxyNetwork(network));
    }

    [Theory]
    [InlineData("fd00::/8", true)]        // whole ULA range — far broader than a routed subnet
    [InlineData("2001:db8::/56", true)]   // a multi-subnet site allocation
    [InlineData("2001:db8::/64", false)]  // exactly one routed subnet — not broader than the threshold
    [InlineData("2001:db8::/112", false)]
    public void IsBroadTrustedProxyNetwork_Ipv6_MatchesPer64Threshold(string cidr, bool expectedBroad)
    {
        var network = System.Net.IPNetwork.Parse(cidr);
        Assert.Equal(expectedBroad, Dependably.Infrastructure.ConfigurationExtensions.IsBroadTrustedProxyNetwork(network));
    }

    // ── IPv4-mapped IPv6 networks: ForwardedHeadersMiddleware.CheckKnownAddress matches an
    // IPv4-mapped peer against an IPv4-mapped KnownIPNetworks entry, so ::ffff:a.b.c.d/N trusts
    // IPv4 peers exactly as the equivalent IPv4 network would (N-96). Judging the literal IPv6
    // prefix length against the IPv6 threshold would misjudge a wide one as narrow.

    [Theory]
    [InlineData("::ffff:10.0.0.0/104", true)]   // equivalent to IPv4 /8 — far broader than /22
    [InlineData("::ffff:10.0.0.0/118", false)]  // equivalent to IPv4 /22 — exactly at the threshold
    [InlineData("::ffff:10.0.0.0/120", false)]  // equivalent to IPv4 /24 — narrow
    public void IsBroadTrustedProxyNetwork_Ipv4MappedIpv6_JudgedByEquivalentIpv4Prefix(string cidr, bool expectedBroad)
    {
        var network = System.Net.IPNetwork.Parse(cidr);
        Assert.Equal(expectedBroad, Dependably.Infrastructure.ConfigurationExtensions.IsBroadTrustedProxyNetwork(network));
    }

    [Fact]
    public void ParseTrustedProxies_Ipv4MappedCatchAllRange_ThrowsAtStartup()
    {
        // ::ffff:0:0/96 is the mapped form of a zero-length (/0) IPv4 prefix — it declares every
        // IPv4 address a forwarding proxy, so it must be rejected on the same structural basis as
        // the literal /0 form rather than slipping through because its literal IPv6 prefix length
        // (96) is nonzero. Fail-closed and forward-looking: this is not a claim that the current
        // runtime's forwarded-header matching treats this specific mapped form as exploitable today.
        var ex = Assert.Throws<InvalidOperationException>(
            () => Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies("::ffff:0:0/96"));
        Assert.Contains("TRUSTED_PROXIES", ex.Message, StringComparison.Ordinal);
    }
}
