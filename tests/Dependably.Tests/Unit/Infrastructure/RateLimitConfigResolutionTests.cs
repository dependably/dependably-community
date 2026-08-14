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

    // ── Push ceilings ─────────────────────────────────────────────────────────
    // The push knobs are pinned here because no end-to-end run reaches them: the shared test
    // fixture and the CI `.test` template both raise PUSH_RATE_LIMIT_PERMITS to six figures so
    // unrelated jobs do not self-throttle. That is correct for those harnesses and it means the
    // shipped defaults are only ever exercised by real clients, so they are asserted directly.

    [Fact]
    public void ResolvePushPermitLimit_DefaultsTo20_WhenUnset()
    {
        Assert.Equal(
            RateLimitCeilings.DefaultPushPermitLimit,
            RateLimitCeilings.ResolvePushPermitLimit(Config()));
        Assert.Equal(20, RateLimitCeilings.DefaultPushPermitLimit);
    }

    [Fact]
    public void ResolvePushPermitLimit_ReadsEnvVar()
    {
        Assert.Equal(200, RateLimitCeilings.ResolvePushPermitLimit(
            Config(("PUSH_RATE_LIMIT_PERMITS", "200"))));
    }

    [Fact]
    public void ResolvePushPermitLimit_FallsBackToDefault_OnNonNumeric()
    {
        Assert.Equal(20, RateLimitCeilings.ResolvePushPermitLimit(
            Config(("PUSH_RATE_LIMIT_PERMITS", "not-a-number"))));
    }

    [Fact]
    public void ResolvePushQueueLimit_DefaultsToNonZero_WhenUnset()
    {
        // The default must not be 0. A zero queue rejects a routine multi-layer OCI push
        // outright (three push-policy requests per layer, several layers concurrent), and the
        // OCI clients do not honour Retry-After on a write, so the whole push fails.
        Assert.Equal(
            RateLimitCeilings.DefaultPushQueueLimit,
            RateLimitCeilings.ResolvePushQueueLimit(Config()));
        Assert.Equal(100, RateLimitCeilings.DefaultPushQueueLimit);
        Assert.True(RateLimitCeilings.DefaultPushQueueLimit > 0);
    }

    [Fact]
    public void ResolvePushQueueLimit_ReadsEnvVar_IncludingExplicitZero()
    {
        // An operator can still restore hard rejection explicitly; only the default changed.
        Assert.Equal(0, RateLimitCeilings.ResolvePushQueueLimit(
            Config(("PUSH_RATE_LIMIT_QUEUE", "0"))));
        Assert.Equal(500, RateLimitCeilings.ResolvePushQueueLimit(
            Config(("PUSH_RATE_LIMIT_QUEUE", "500"))));
    }

    [Fact]
    public void ResolvePushQueueLimit_FallsBackToDefault_OnNonNumeric()
    {
        Assert.Equal(100, RateLimitCeilings.ResolvePushQueueLimit(
            Config(("PUSH_RATE_LIMIT_QUEUE", "garbage"))));
    }
}
