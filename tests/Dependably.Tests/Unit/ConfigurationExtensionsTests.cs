using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Xunit;

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
        var withSlash = Config("https://repo.example.com/").PublicBaseUrl();
        var withoutSlash = Config("https://repo.example.com").PublicBaseUrl();

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
}
