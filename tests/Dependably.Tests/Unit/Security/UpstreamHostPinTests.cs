using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Unit coverage for the shared upstream credential host-pin invariant used by the PyPI, Cargo,
/// and RPM proxy paths: a configured upstream's credential may only ride along to a fetch whose
/// host matches the configured upstream's own host.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamHostPinTests
{
    [Theory]
    [InlineData("https://private-upstream.test", "http://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test", "https://private-upstream.test:8443/packages/x")]
    [InlineData("https://private-upstream.test/api", "https://private-upstream.test/other/path")]
    public void IsSameHost_SameHostDifferentSchemePortOrPath_ReturnsTrue(string configured, string candidate)
    {
        Assert.True(UpstreamHostPin.IsSameHost(configured, candidate));
    }

    [Fact]
    public void IsSameHost_DifferentHost_ReturnsFalse()
    {
        Assert.False(UpstreamHostPin.IsSameHost(
            "https://private-upstream.test", "https://attacker-controlled-mirror.example/packages/x"));
    }

    [Fact]
    public void IsSameHost_CaseInsensitiveHostMatch_ReturnsTrue()
    {
        Assert.True(UpstreamHostPin.IsSameHost(
            "https://Private-Upstream.TEST", "https://private-upstream.test/packages/x"));
    }

    [Theory]
    [InlineData("not-a-url", "https://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test", "not-a-url")]
    [InlineData("", "https://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test", "")]
    public void IsSameHost_EitherSideUnparseable_ReturnsFalse(string configured, string candidate)
    {
        Assert.False(UpstreamHostPin.IsSameHost(configured, candidate));
    }
}
