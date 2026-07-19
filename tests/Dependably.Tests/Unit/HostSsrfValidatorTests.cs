using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Security")]
public class HostSsrfValidatorTests
{
    [Fact]
    public void IsHostBlocked_NullHost_ReturnsFalse()
    {
        // No value to validate — the caller's own required-field check owns this case.
        Assert.False(HostSsrfValidator.IsHostBlocked(null, SsrfGuard.IsBlockedIp));
    }

    [Fact]
    public void IsHostBlocked_WhitespaceHost_ReturnsFalse()
    {
        Assert.False(HostSsrfValidator.IsHostBlocked("   ", SsrfGuard.IsBlockedIp));
    }

    [Fact]
    public void IsHostBlocked_Hostname_ReturnsFalse_LeftToConnectTimeGate()
    {
        // Not resolved here — DNS can change between save and send, and a hostname that does
        // not resolve yet (an operator drafting a config, an intentionally-unreachable test
        // value) must not be rejected at save time. SsrfConnectCallback is the authoritative,
        // DNS-rebinding-aware gate at actual connect time.
        Assert.False(HostSsrfValidator.IsHostBlocked("smtp.example.com", SsrfGuard.IsBlockedIp));
    }

    [Theory]
    [InlineData("8.8.8.8", false)]        // public — allowed
    [InlineData("1.1.1.1", false)]        // public — allowed
    [InlineData("169.254.169.254", true)] // cloud metadata — blocked
    [InlineData("10.0.0.1", true)]        // RFC 1918 — blocked under the default (non-private-allowing) predicate
    [InlineData("127.0.0.1", true)]       // loopback — blocked
    public void IsHostBlocked_MixedIpLiterals_BlockedAndAllowedBehaveCorrectly(string host, bool expectedBlocked)
    {
        // Partial-failure scenario across a single validation surface: some literals are
        // blocked, some are allowed, evaluated independently in one theory rather than only
        // an all-blocked or all-allowed fixture.
        Assert.Equal(expectedBlocked, HostSsrfValidator.IsHostBlocked(host, SsrfGuard.IsBlockedIp));
    }

    [Fact]
    public void IsHostBlocked_PrivateRangeUnderExcludingPrivatePredicate_ReturnsFalse()
    {
        // WEBHOOK_ALLOW_PRIVATE=true swaps in IsBlockedIpExcludingPrivate — RFC 1918 must pass
        // while loopback/link-local/metadata stay blocked regardless (covered by the theory
        // above using the default predicate).
        Assert.False(HostSsrfValidator.IsHostBlocked("10.0.0.1", SsrfGuard.IsBlockedIpExcludingPrivate));
        Assert.True(HostSsrfValidator.IsHostBlocked("169.254.169.254", SsrfGuard.IsBlockedIpExcludingPrivate));
    }
}
