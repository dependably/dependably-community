using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Unit coverage for the shared upstream credential pin used by the NuGet, PyPI, Cargo, RPM,
/// Terraform and OCI proxy paths: a configured upstream's credential may only ride along to a fetch
/// on the configured upstream's own origin — scheme, host and port.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamHostPinTests
{
    [Theory]
    [InlineData("https://private-upstream.test/api", "https://private-upstream.test/other/path")]
    [InlineData("https://private-upstream.test", "https://private-upstream.test:443/packages/x")]
    [InlineData("https://private-upstream.test:443", "https://private-upstream.test/packages/x")]
    [InlineData("http://private-upstream.test", "http://private-upstream.test:80/packages/x")]
    [InlineData("https://private-upstream.test:8443/v3", "https://private-upstream.test:8443/packages/x")]
    [InlineData("HTTPS://Private-Upstream.TEST", "https://private-upstream.test/packages/x")]
    public void IsSameOrigin_SameSchemeHostAndEffectivePort_ReturnsTrue(string configured, string candidate)
    {
        Assert.True(UpstreamHostPin.IsSameOrigin(configured, candidate));
    }

    [Theory]
    // Scheme downgrade on the same host: the credential would cross the wire in plaintext.
    [InlineData("https://private-upstream.test", "http://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test:8443", "http://private-upstream.test:8443/packages/x")]
    // No upgrade either: http://h is port 80, https://h is port 443 — a different service.
    [InlineData("http://private-upstream.test", "https://private-upstream.test/packages/x")]
    // An explicit different port on the same host is a different service.
    [InlineData("https://private-upstream.test", "https://private-upstream.test:8443/packages/x")]
    [InlineData("https://private-upstream.test:8443", "https://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test", "https://private-upstream.test:80/packages/x")]
    public void IsSameOrigin_SameHostDifferentSchemeOrPort_ReturnsFalse(string configured, string candidate)
    {
        Assert.False(UpstreamHostPin.IsSameOrigin(configured, candidate));
    }

    [Fact]
    public void IsSameOrigin_DifferentHost_ReturnsFalse()
    {
        Assert.False(UpstreamHostPin.IsSameOrigin(
            "https://private-upstream.test", "https://attacker-controlled-mirror.example/packages/x"));
    }

    [Theory]
    [InlineData("not-a-url", "https://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test", "not-a-url")]
    [InlineData("", "https://private-upstream.test/packages/x")]
    [InlineData("https://private-upstream.test", "")]
    [InlineData("https://private-upstream.test", "/packages/x")]
    public void IsSameOrigin_EitherSideUnparseable_ReturnsFalse(string configured, string candidate)
    {
        Assert.False(UpstreamHostPin.IsSameOrigin(configured, candidate));
    }
}
