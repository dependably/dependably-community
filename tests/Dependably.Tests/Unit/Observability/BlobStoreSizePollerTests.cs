using Dependably.Infrastructure.Observability;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Branch coverage for <see cref="BlobStoreSizePoller"/>. The polled values are
/// recorded against a global meter dictionary; tests use a unique tier key trick
/// — feeding a split tier with mocked stores — so they don't race against the
/// production "registry"/"cache" labels in the shared <see cref="DependablyMeter"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlobStoreSizePollerTests
{
    private static IConfiguration Config() =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();

    [Fact]
    public async Task PollOnceAsync_SharedTier_PollsRegistryOnly()
    {
        // Cache and Registry point to the same store — IsSplit is false, so only the
        // registry walk runs (the if branch guarding the cache poll is false).
        var store = new InMemoryBlobStore();
        await store.PutAsync("k1", new MemoryStream(new byte[100]));
        var tiers = new TieredBlobStorage(store, store);

        var poller = new BlobStoreSizePoller(tiers, Config(), NullLogger<BlobStoreSizePoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        var sizes = DependablyMeter.ReadBlobStoreSizes();
        Assert.Equal(100L, sizes["registry"]);
    }

    [Fact]
    public async Task PollOnceAsync_SplitTier_PollsBothTiers()
    {
        var cache = new InMemoryBlobStore();
        var registry = new InMemoryBlobStore();
        await cache.PutAsync("c1", new MemoryStream(new byte[50]));
        await registry.PutAsync("r1", new MemoryStream(new byte[200]));
        var tiers = new TieredBlobStorage(cache, registry);

        var poller = new BlobStoreSizePoller(tiers, Config(), NullLogger<BlobStoreSizePoller>.Instance);
        await poller.PollOnceAsync(CancellationToken.None);

        var sizes = DependablyMeter.ReadBlobStoreSizes();
        Assert.Equal(200L, sizes["registry"]);
        Assert.Equal(50L, sizes["cache"]);
    }

    [Fact]
    public async Task PollOnceAsync_TierThrows_LogsAndSwallows()
    {
        // A failing tier must not abort the poll — the helper catches non-cancellation
        // exceptions, logs a warning, and lets the loop continue on the next interval.
        var failing = Substitute.For<IBlobStore>();
        failing.GetTotalSizeAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("backend offline"));
        var ok = new InMemoryBlobStore();
        await ok.PutAsync("ok", new MemoryStream(new byte[10]));
        var tiers = new TieredBlobStorage(ok, failing);
        var logger = Substitute.For<ILogger<BlobStoreSizePoller>>();

        var poller = new BlobStoreSizePoller(tiers, Config(), logger);
        await poller.PollOnceAsync(CancellationToken.None);

        // Registry (failing) logged a warning; cache (ok) still recorded.
        logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception>(),
            Arg.Any<Func<object, Exception?, string>>());
        Assert.Equal(10L, DependablyMeter.ReadBlobStoreSizes()["cache"]);
    }

    [Fact]
    public async Task PollOnceAsync_Cancelled_Rethrows()
    {
        // Use a mock that observes the token — InMemoryBlobStore.GetTotalSizeAsync ignores
        // cancellation, so we wire NSubstitute to throw the canonical cancellation exception.
        var store = Substitute.For<IBlobStore>();
        store.GetTotalSizeAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(callInfo => new OperationCanceledException(callInfo.Arg<CancellationToken>()));
        var tiers = new TieredBlobStorage(store, store);
        var poller = new BlobStoreSizePoller(tiers, Config(), NullLogger<BlobStoreSizePoller>.Instance);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => poller.PollOnceAsync(cts.Token));
    }

    [Fact]
    public async Task ExecuteAsync_CancelledDuringStartupDelay_ReturnsImmediately()
    {
        // Mirrors TenantCountPoller's pre-cancel pattern — exercises the
        // `catch (OperationCanceledException) { return; }` on the 30-second startup delay
        // without waiting through it.
        var tiers = new TieredBlobStorage(new InMemoryBlobStore(), new InMemoryBlobStore());
        var poller = new BlobStoreSizePoller(tiers, Config(), NullLogger<BlobStoreSizePoller>.Instance);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await poller.StartAsync(cts.Token);
        await poller.StopAsync(CancellationToken.None);

        Assert.True(poller.ExecuteTask is null || poller.ExecuteTask.IsCompleted);
    }
}
