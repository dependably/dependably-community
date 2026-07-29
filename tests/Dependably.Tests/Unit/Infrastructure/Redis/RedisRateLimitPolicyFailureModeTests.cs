using Dependably.Infrastructure.Redis;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// Pins the wiring between the operator switch and the limiter it configures — the link that
/// unit-testing each end in isolation leaves unguarded. <c>RateLimitFailureModeTests</c> proves
/// the config parses, and <c>RedisFixedWindowRateLimiterTests</c> proves a limiter handed
/// <c>FailOpen=false</c> denies; neither notices if the policy stops threading the resolved
/// posture through, reads a stale key name, or inverts the boolean. These tests drive the real
/// <see cref="RedisRateLimitPolicy"/> from configuration to lease over an unreachable Redis, so
/// the whole path is covered: a deployment that configured <c>closed</c> must actually deny.
///
/// Emits to <c>dependably.rate_limit.backend_unavailable</c>, which
/// <c>RedisFixedWindowRateLimiterTests</c> asserts exact counts on — joining the serialized
/// collection keeps this class from racing that one. See MeterSensitiveCollection.
/// </summary>
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class RedisRateLimitPolicyFailureModeTests
{
    // Spelled out rather than referenced through RateLimitFailureMode.ConfigKey: the constant and
    // the operator-facing variable name have to stay the same string, and a test that reads the
    // constant would follow a rename silently while every deployed environment kept setting the
    // documented name. This is the assertion that the documented name is the one that is read.
    private const string EnvVarName = "RATE_LIMIT_REDIS_FAILURE_MODE";

    /// <summary>
    /// Builds the policy over an <see cref="IRedisClient"/> whose every script evaluation fails,
    /// then drives the partition factory the rate-limiting middleware would drive.
    /// </summary>
    private static async Task<bool> AcquireOverUnreachableRedisAsync(string? configuredMode)
    {
        var db = Substitute.For<IDatabase>();
        db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ =>
                throw new RedisConnectionException(ConnectionFailureType.SocketFailure, "down"));

        var redis = Substitute.For<IRedisClient>();
        redis.GetDatabase().Returns(db);
        redis.ApplyPrefix(Arg.Any<string>()).Returns(ci => "dependably:" + ci.Arg<string>());

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [EnvVarName] = configuredMode,
            })
            .Build();

        var policy = new RedisRateLimitPolicy(
            redis, TimeProvider.System, cfg, NullLogger<RedisFixedWindowRateLimiter>.Instance);

        var partition = policy.GetPartition(new DefaultHttpContext());
        using var limiter = partition.Factory(partition.PartitionKey);
        using var lease = await limiter.AcquireAsync(1);
        return lease.IsAcquired;
    }

    [Fact]
    public async Task ConfiguredClosed_UnreachableRedis_DeniesTheRequest()
    {
        Assert.False(await AcquireOverUnreachableRedisAsync("closed"));
    }

    [Fact]
    public async Task ConfiguredOpen_UnreachableRedis_GrantsTheRequest()
    {
        Assert.True(await AcquireOverUnreachableRedisAsync("open"));
    }

    [Fact]
    public async Task Unconfigured_UnreachableRedis_GrantsTheRequest()
    {
        // The default must stay fail-open: shipping this switch changes no existing deployment.
        Assert.True(await AcquireOverUnreachableRedisAsync(configuredMode: null));
    }
}
