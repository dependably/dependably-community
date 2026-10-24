using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Redis;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The full-host composition root (<see cref="Program.ConfigureBuilder"/>) must resolve with
/// <c>REDIS_CONNECTION_STRING</c> set. CI never sets it, so every other host-booting test runs the
/// standalone graph, and a dependency cycle that exists only in the HA graph ships unseen: the
/// metadata-invalidation coordinator needs the bus to publish, the Redis bus needs the receiver to
/// subscribe, and the receiver needs the coordinator to evict. Wired eagerly through the
/// interface-forwarding factory, that loop is invisible to <c>ValidateOnBuild</c> and recurses at
/// runtime until the container deadlocks on its own singleton lock — the host never listens and
/// ignores SIGTERM.
///
/// <para>The graph is built and resolved, never started, and the multiplexer is a fake: the cycle
/// lives in the object graph, not on the wire, so no broker is needed. Resolution runs under a time
/// budget because the failure mode is a hang, and a hang must fail the test rather than the CI job.
/// The standalone twin pins that the harness itself resolves, so a red Redis case is about Redis.</para>
///
/// <para>Both cases build with <c>ValidateScopes</c> as well as <c>ValidateOnBuild</c>, so a
/// singleton capturing a scoped service fails here rather than serving every request from one
/// root-scope instance in production, where scope validation is off.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class RedisHostCompositionTests : IDisposable
{
    // Generous for a resolve-only build of the whole graph; a cycle never finishes at all.
    private static readonly TimeSpan ResolveBudget = TimeSpan.FromSeconds(60);

    private readonly string _dataDir =
        Path.Combine(Path.GetTempPath(), "dependably-composition-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task FullHost_WithRedis_ResolvesEveryHostedServiceAndTheInvalidationGraph()
    {
        var subscriber = Substitute.For<ISubscriber>();
        var resolved = await ResolveWithinBudgetAsync(redisConnectionString: "redis.invalid:6379", subscriber);

        Assert.True(resolved.HostedServices.Count > 0);
        var bus = Assert.IsType<RedisMetadataInvalidationBus>(resolved.Bus);

        // One instance publishes and subscribes. The self-origin drop compares a received
        // message's origin with the subscriber's own, so a second bus instance behind the
        // interface would make every replica re-apply its own broadcasts.
        Assert.Contains(resolved.HostedServices, s => ReferenceEquals(s, bus));

        // Starting the subscription is where the bus reaches the receiver, and through it the
        // coordinator. It must resolve against the already-built bus rather than re-enter it.
        await subscriber.Received(1).SubscribeAsync(
            Arg.Any<RedisChannel>(), Arg.Any<Action<RedisChannel, RedisValue>>(), Arg.Any<CommandFlags>());
    }

    [Fact]
    public async Task FullHost_WithoutRedis_ResolvesEveryHostedServiceAndTheInvalidationGraph()
    {
        var resolved = await ResolveWithinBudgetAsync(redisConnectionString: "", subscriber: null);

        Assert.True(resolved.HostedServices.Count > 0);
        Assert.IsType<NullMetadataInvalidationBus>(resolved.Bus);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dataDir, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
            // Nothing was written.
        }
    }

    private async Task<Resolved> ResolveWithinBudgetAsync(string redisConnectionString, ISubscriber? subscriber)
    {
        var work = Task.Run(async () =>
        {
            var builder = WebApplication.CreateBuilder();
            TestHostEnv.PinAmbient(builder);
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Pinned in both directions so an ambient value in the developer's shell cannot
                // turn the standalone twin into an HA graph, or the reverse.
                ["REDIS_CONNECTION_STRING"] = redisConnectionString,
                ["DB_PATH"] = Path.Combine(_dataDir, "dependably.db"),
                ["LOCAL_STORAGE_PATH"] = Path.Combine(_dataDir, "blobs"),
            });

            // Build-time validation on, so a cycle wired through constructor call sites fails the
            // build with the container's own message. Scope validation on, so a singleton that
            // captures a scoped service (a captive dependency, which would then serve every
            // request from one instance resolved off the root scope) fails the build too.
            builder.Host.UseDefaultServiceProvider(o =>
            {
                o.ValidateOnBuild = true;
                o.ValidateScopes = true;
            });

            Program.ConfigureBuilder(builder);

            // The MFA key singletons read their key from instance_settings when first resolved,
            // and this graph is never started, so the schema is absent. Fixed-key instances keep
            // the per-scope LoginService resolution below off the database.
            byte[] mfaKey = new byte[32];
            builder.Services.RemoveAll<IMfaSecretProtector>();
            builder.Services.AddSingleton<IMfaSecretProtector>(new MfaSecretProtector(mfaKey));
            builder.Services.RemoveAll<IRecoveryCodeHasher>();
            builder.Services.AddSingleton<IRecoveryCodeHasher>(
                new RecoveryCodeHasher(mfaKey, acceptLegacyCodes: false, NullLogger<RecoveryCodeHasher>.Instance));

            if (subscriber is not null)
            {
                var mux = Substitute.For<IConnectionMultiplexer>();
                mux.GetSubscriber(Arg.Any<object?>()).Returns(subscriber);
                builder.Services.RemoveAll<IConnectionMultiplexer>();
                builder.Services.AddSingleton(mux);
            }

            await using var app = builder.Build();
            var services = app.Services;

            var hosted = services.GetServices<IHostedService>().ToList();
            var coordinator = services.GetRequiredService<MetadataInvalidationCoordinator>();
            services.GetRequiredService<MetadataInvalidationReceiver>();
            var bus = services.GetRequiredService<IMetadataInvalidationBus>();

            // The other primitives the HA branch swaps for Redis-backed ones.
            services.GetRequiredService<IDistributedLock>();
            services.GetRequiredService<ILockoutStore>();
            services.GetRequiredService<IDataProtectionProvider>();
            if (subscriber is not null)
            {
                services.GetRequiredService<IRedisHealthProbe>();
            }

            AssertResolvedPerRequestScope(services);

            if (bus is RedisMetadataInvalidationBus redisBus)
            {
                await redisBus.StartAsync(CancellationToken.None);
                await redisBus.StopAsync(CancellationToken.None);
            }

            Assert.NotNull(coordinator);
            return new Resolved(hosted, bus);
        });

        try
        {
            return await work.WaitAsync(ResolveBudget, TimeProvider.System);
        }
        catch (TimeoutException)
        {
            Assert.Fail(
                $"Resolving the full-host graph did not finish within {ResolveBudget.TotalSeconds:0}s "
                + $"(REDIS_CONNECTION_STRING='{redisConnectionString}'). A dependency cycle hidden behind "
                + "a factory registration recurses until the container deadlocks on its singleton lock.");
            throw;
        }
    }

    // The auth services that reach scoped collaborators (ProblemResults; UserManager and the
    // Identity user stores behind the MFA enrolment services) are themselves per-request: one
    // instance within a request scope, a fresh one in the next. A singleton registration would
    // hand both scopes the same instance, built once off the root scope.
    private static void AssertResolvedPerRequestScope(IServiceProvider services)
    {
        using var first = services.CreateScope();
        using var second = services.CreateScope();

        AssertScoped<OrgAccessGuard>(first.ServiceProvider, second.ServiceProvider);
        AssertScoped<LoginService>(first.ServiceProvider, second.ServiceProvider);
    }

    private static void AssertScoped<T>(IServiceProvider first, IServiceProvider second)
        where T : class
    {
        var instance = first.GetRequiredService<T>();
        Assert.Same(instance, first.GetRequiredService<T>());
        Assert.NotSame(instance, second.GetRequiredService<T>());
    }

    private sealed record Resolved(IReadOnlyList<IHostedService> HostedServices, IMetadataInvalidationBus Bus);
}
