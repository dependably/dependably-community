using Dependably.Security;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The GlobalLimiter's two per-minute ceilings — the management per-principal limit and the
/// default-deny protocol limit — are env-configurable so a bounded internal client (e.g. a DAST
/// scan authenticating as one system principal) can be handed a very high limit for the scan
/// instead of a global disable switch. These tests pin that the resolvers read the env var and fall
/// back to the 300 default, which is what lets the CI `.app_boot` raise them for the ZAP jobs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RateLimitConfigResolutionTests
{
    private static IConfiguration Config(params (string Key, string Value)[] pairs) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(pairs.ToDictionary(p => p.Key, p => (string?)p.Value))
            .Build();

    [Fact]
    public void ResolveManagementPermitLimit_DefaultsTo300_WhenUnset()
    {
        Assert.Equal(
            RateLimitCeilings.DefaultManagementPermitLimit,
            RateLimitCeilings.ResolveManagementPermitLimit(Config()));
        Assert.Equal(300, RateLimitCeilings.DefaultManagementPermitLimit);
    }

    [Fact]
    public void ResolveManagementPermitLimit_ReadsEnvVar_HighValue()
    {
        // The exact knob the ZAP `.app_boot` sets so the authenticated scan is not throttled.
        Assert.Equal(100000, RateLimitCeilings.ResolveManagementPermitLimit(
            Config(("MANAGEMENT_RATE_LIMIT_PERMITS", "100000"))));
    }

    [Fact]
    public void ResolveManagementPermitLimit_ReadsEnvVar_ArbitraryValue()
    {
        Assert.Equal(42, RateLimitCeilings.ResolveManagementPermitLimit(
            Config(("MANAGEMENT_RATE_LIMIT_PERMITS", "42"))));
    }

    [Fact]
    public void ResolveManagementPermitLimit_FallsBackToDefault_OnNonNumeric()
    {
        Assert.Equal(300, RateLimitCeilings.ResolveManagementPermitLimit(
            Config(("MANAGEMENT_RATE_LIMIT_PERMITS", "not-a-number"))));
    }

    [Fact]
    public void ResolveProtocolDefaultPermitLimit_DefaultsTo300_WhenUnset()
    {
        Assert.Equal(
            RateLimitCeilings.DefaultProtocolPermitLimit,
            RateLimitCeilings.ResolveProtocolDefaultPermitLimit(Config()));
        Assert.Equal(300, RateLimitCeilings.DefaultProtocolPermitLimit);
    }

    [Fact]
    public void ResolveProtocolDefaultPermitLimit_ReadsEnvVar_HighValue()
    {
        // The new knob the ZAP `.app_boot` must set — the default-deny protocol ceiling that,
        // left at 300, throttled non-/api/v1 controller routes (e.g. /saml/metadata) during the
        // authenticated scan and perturbed it into a false positive.
        Assert.Equal(100000, RateLimitCeilings.ResolveProtocolDefaultPermitLimit(
            Config(("PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS", "100000"))));
    }

    [Fact]
    public void ResolveProtocolDefaultPermitLimit_FallsBackToDefault_OnNonNumeric()
    {
        Assert.Equal(300, RateLimitCeilings.ResolveProtocolDefaultPermitLimit(
            Config(("PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS", "garbage"))));
    }
}
