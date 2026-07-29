using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// The operator switch that decides what the Redis-backed abuse-prevention limiters do when
/// Redis cannot answer. Two properties matter: the default must stay fail-open (turning it on
/// must not change an existing deployment's behaviour), and a value that is neither posture must
/// fail the boot rather than resolve to the permissive default — an operator who typed
/// <c>close</c> must not believe they are fail-closed while running fail-open.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RateLimitFailureModeTests
{
    private static IConfiguration Cfg(string? value) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [RateLimitFailureMode.ConfigKey] = value,
            })
            .Build();

    [Fact]
    public void Unset_DefaultsToFailOpen()
    {
        Assert.True(RateLimitFailureMode.ResolveFailOpen(new ConfigurationBuilder().Build()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("open")]
    [InlineData("OPEN")]
    [InlineData(" Open ")]
    public void OpenOrEmpty_ResolvesToFailOpen(string value)
    {
        Assert.True(RateLimitFailureMode.ResolveFailOpen(Cfg(value)));
    }

    [Theory]
    [InlineData("closed")]
    [InlineData("CLOSED")]
    [InlineData(" Closed ")]
    public void Closed_ResolvesToFailClosed(string value)
    {
        Assert.False(RateLimitFailureMode.ResolveFailOpen(Cfg(value)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("open")]
    [InlineData("closed")]
    public void Validate_AcceptsRecognizedPostures(string? value)
    {
        Assert.Null(Record.Exception(() => RateLimitFailureMode.Validate(Cfg(value))));
    }

    [Theory]
    [InlineData("close")]
    [InlineData("opened")]
    [InlineData("true")]
    [InlineData("deny")]
    public void Validate_ThrowsOnUnrecognizedPosture(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => RateLimitFailureMode.Validate(Cfg(value)));
        Assert.Contains(RateLimitFailureMode.ConfigKey, ex.Message, StringComparison.Ordinal);
    }

    // ── Startup wiring ───────────────────────────────────────────────────────

    private static WebApplicationBuilder NewBuilder(IDictionary<string, string?> config)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(config);
        return builder;
    }

    [Fact]
    public void Startup_RejectsUnrecognizedPosture_EvenWithoutRedisConfigured()
    {
        // The policy registration returns early when Redis is absent; validation runs before that
        // early return, so a typo is caught on the management root whether or not the setting has
        // anything to act on. It is not caught everywhere: the edge composition root registers
        // only the in-process limiters and never calls this method, so an edge node with a
        // misspelled posture boots clean and ignores the setting.
        var builder = NewBuilder(new Dictionary<string, string?>
        {
            [RateLimitFailureMode.ConfigKey] = "close",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => builder.AddDependablyRedisRateLimitPolicies());

        Assert.Contains(RateLimitFailureMode.ConfigKey, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Startup_AcceptsFailClosedPosture()
    {
        var builder = NewBuilder(new Dictionary<string, string?>
        {
            [RateLimitFailureMode.ConfigKey] = RateLimitFailureMode.Closed,
            ["REDIS_CONNECTION_STRING"] = "localhost:6379",
        });

        Assert.Null(Record.Exception(() => builder.AddDependablyRedisRateLimitPolicies()));
    }
}
