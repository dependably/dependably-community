using Dependably.Infrastructure.Redis;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// Pins that <see cref="RedisRateLimitPolicy"/> reads the same permit environment variables as
/// the in-process limiters (<c>AuthStartupExtensions.AddInProcessLimiters</c>) instead of its own
/// hardcoded window/permit pairs. Before the fix, <c>LOGIN_RATE_LIMIT_PERMITS</c>,
/// <c>INVITE_RATE_LIMIT_PERMITS</c>, and <c>TOKEN_CREATE_RATE_LIMIT_PERMITS</c> had no effect on
/// the Redis-backed policy an HA deployment actually uses — an operator's tuning silently did
/// nothing whenever Redis was configured.
///
/// Drives the real <see cref="RedisRateLimitPolicy"/> end to end — configuration in, lease out —
/// over a mocked <see cref="IDatabase"/> so the assertion exercises the Redis-backed path
/// (<see cref="RedisFixedWindowRateLimiter"/>), not the in-process limiter these env vars already
/// worked for. None of these cases throw, so — unlike the failure-mode sibling tests in this
/// directory — nothing here touches the process-wide <c>DependablyMeter</c>, and the class does
/// not need <c>[Collection("MeterSensitive")]</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RedisRateLimitPolicyPermitConfigTests
{
    /// <summary>
    /// Builds the policy from the given configuration, mints the partition for the named policy,
    /// and drives one <c>AcquireAsync</c> against a mocked Redis reply of
    /// <c>(count, ttl: 60)</c> — returning whether the lease was acquired.
    /// </summary>
    private static async Task<bool> AcquireAsync(
        string policyName, long scriptReplyCount, Dictionary<string, string?> configuredEnv)
    {
        var db = Substitute.For<IDatabase>();
        db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(new[]
            {
                RedisResult.Create(scriptReplyCount),
                RedisResult.Create(60L),
            }));

        var redis = Substitute.For<IRedisClient>();
        redis.GetDatabase().Returns(db);
        redis.ApplyPrefix(Arg.Any<string>()).Returns(ci => "dependably:" + ci.Arg<string>());

        var cfg = new ConfigurationBuilder().AddInMemoryCollection(configuredEnv).Build();

        var policy = new RedisRateLimitPolicy(
            redis, TimeProvider.System, cfg, NullLogger<RedisFixedWindowRateLimiter>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.SetEndpoint(new Endpoint(
            requestDelegate: null,
            new EndpointMetadataCollection(new EnableRateLimitingAttribute(policyName)),
            "test-" + policyName));

        var partition = policy.GetPartition(ctx);
        using var limiter = partition.Factory(partition.PartitionKey);
        using var lease = await limiter.AcquireAsync(1);
        return lease.IsAcquired;
    }

    [Fact]
    public async Task Login_NarrowedPermitEnvVar_RejectsBelowTheHardcodedDefault()
    {
        // The hardcoded default is 10/min, so a count of 3 would pass under it. Narrowing
        // LOGIN_RATE_LIMIT_PERMITS to 2 must reject the same count — proof the env var, not the
        // constant, is what the Redis-backed policy actually enforces.
        bool acquired = await AcquireAsync(
            "login",
            scriptReplyCount: 3,
            configuredEnv: new Dictionary<string, string?> { ["LOGIN_RATE_LIMIT_PERMITS"] = "2" });

        Assert.False(acquired);
    }

    [Fact]
    public async Task Login_Unconfigured_FallsBackToTheDocumentedDefaultOfTen()
    {
        bool acquired = await AcquireAsync(
            "login", scriptReplyCount: 10, configuredEnv: new Dictionary<string, string?>());

        Assert.True(acquired); // count(10) <= default permit limit(10)
    }

    [Fact]
    public async Task Invite_WidenedPermitEnvVar_AcquiresAboveTheHardcodedDefault()
    {
        // The hardcoded default is 20/hour, so a count of 30 would be rejected under it.
        // Widening INVITE_RATE_LIMIT_PERMITS to 50 must acquire the same count.
        bool acquired = await AcquireAsync(
            "invite",
            scriptReplyCount: 30,
            configuredEnv: new Dictionary<string, string?> { ["INVITE_RATE_LIMIT_PERMITS"] = "50" });

        Assert.True(acquired);
    }

    [Fact]
    public async Task TokenCreate_NarrowedPermitEnvVar_RejectsBelowTheHardcodedDefault()
    {
        // The hardcoded default is 60/hour, so a count of 40 would pass under it. Narrowing
        // TOKEN_CREATE_RATE_LIMIT_PERMITS to 5 must reject the same count.
        bool acquired = await AcquireAsync(
            "token-create",
            scriptReplyCount: 40,
            configuredEnv: new Dictionary<string, string?> { ["TOKEN_CREATE_RATE_LIMIT_PERMITS"] = "5" });

        Assert.False(acquired);
    }

    [Fact]
    public async Task UnparsablePermitEnvVar_FallsBackToTheHardcodedDefault()
    {
        // Same contract as the in-process limiters: an unparsable value is treated as unset
        // rather than crashing startup or resolving to zero.
        bool acquired = await AcquireAsync(
            "login",
            scriptReplyCount: 10,
            configuredEnv: new Dictionary<string, string?> { ["LOGIN_RATE_LIMIT_PERMITS"] = "not-a-number" });

        Assert.True(acquired); // count(10) <= default permit limit(10)
    }
}
