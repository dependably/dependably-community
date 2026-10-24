using System.Net;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Dependably.Tests.Integration;

/// <summary>
/// Boots the full management host with <c>REDIS_CONNECTION_STRING</c> pointed at a real broker and
/// waits for <c>/health</c> to answer 200. Every other host-booting test runs the standalone graph,
/// so a fault that exists only when Redis is configured — a dependency cycle that deadlocks the
/// container while hosted services start, a Redis-backed component that throws on first use —
/// otherwise ships unseen. The host is started for real (every hosted service's
/// <c>StartAsync</c> runs, the Data Protection ring loads from Redis, the invalidation bus
/// subscribes); only the transport is in-process.
///
/// <para>The failure mode being guarded is a hang, so start-up and the health poll each run under a
/// budget: a deadlocked host must fail this test, not time out the CI job.</para>
/// </summary>
[Trait("Category", LiveRedis.Category)]
[Collection("LiveRedis")]
public sealed class RedisHostBootLiveTests : IDisposable
{
    // A cold full-host boot on a loaded runner, with headroom; a deadlock never finishes at all.
    private static readonly TimeSpan StartBudget = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan HealthBudget = TimeSpan.FromSeconds(30);

    private readonly string _dataDir =
        Path.Combine(Path.GetTempPath(), "dependably-redislive-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task HostWithRedis_Starts_AnswersHealth_AndSubscribesToTheInvalidationChannel()
    {
        string connection = LiveRedis.ConnectionString;
        string prefix = LiveRedis.UniquePrefix("host");

        // Build, pipeline configuration and start all run under the budget: a cycle can deadlock
        // the container at whichever of them first resolves the bus, not only in StartAsync.
        var boot = Task.Run(async () =>
        {
            var builder = WebApplication.CreateBuilder();
            TestHostEnv.PinAmbient(builder);
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["REDIS_CONNECTION_STRING"] = connection,
                ["REDIS_KEY_PREFIX"] = prefix,
                ["DB_PATH"] = Path.Combine(_dataDir, "dependably.db"),
                ["LOCAL_STORAGE_PATH"] = Path.Combine(_dataDir, "blobs"),
                // The jobs that reach the public internet on their first pass; the rest start as
                // in production.
                ["DISABLE_BACKGROUND_JOBS"] =
                    "vuln-scan,vuln-rescan,sbom-scan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep",
            });
            Program.ConfigureBuilder(builder);
            builder.WebHost.UseTestServer();

            var built = builder.Build();
            Program.ConfigureApp(built);
            await built.StartAsync(CancellationToken.None);
            return built;
        });

        WebApplication app;
        try
        {
            app = await boot.WaitAsync(StartBudget, TimeProvider.System);
        }
        catch (TimeoutException)
        {
            // The deadlocked host is abandoned rather than disposed: disposing it would block on
            // the same lock and hang the run this budget exists to protect.
            Assert.Fail(
                $"The host did not finish starting within {StartBudget.TotalSeconds:0}s with "
                + "REDIS_CONNECTION_STRING set. Something in the Redis-only graph is blocked; a "
                + "dependency cycle deadlocks the container on its singleton lock.");
            throw;
        }

        await using var disposeApp = app;
        try
        {
            using var client = app.GetTestClient();
            HttpStatusCode last = 0;
            bool healthy = await LiveRedis.UntilAsync(
                async () =>
                {
                    using var response = await client.GetAsync("/health");
                    last = response.StatusCode;
                    return last == HttpStatusCode.OK;
                },
                HealthBudget);
            Assert.True(healthy, $"/health answered {(int)last} rather than 200 within {HealthBudget.TotalSeconds:0}s.");

            Assert.IsType<RedisMetadataInvalidationBus>(app.Services.GetRequiredService<IMetadataInvalidationBus>());

            // The started host is subscribed on the broker itself, under its configured prefix.
            await using var raw = await ConnectionMultiplexer.ConnectAsync(connection);
            var subscribers = (RedisValue[])(await raw.GetDatabase().ExecuteAsync(
                "PUBSUB", "NUMSUB", prefix + RedisMetadataInvalidationBus.ChannelName))!;
            Assert.Equal(1, (int)subscribers[1]);
        }
        finally
        {
            await app.StopAsync(CancellationToken.None).WaitAsync(StartBudget, TimeProvider.System);
        }
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
}
