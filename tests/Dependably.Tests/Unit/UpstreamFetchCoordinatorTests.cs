using Dependably.Storage;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class UpstreamFetchCoordinatorTests
{
    [Fact]
    public async Task ConcurrentCallers_SameKey_ShareOneFetch()
    {
        var coordinator = new UpstreamFetchCoordinator();
        var fetchCount = 0;
        var gate = new TaskCompletionSource();

        Func<Task<byte[]>> fetch = async () =>
        {
            Interlocked.Increment(ref fetchCount);
            await gate.Task;
            return [1, 2, 3];
        };

        var t1 = Task.Run(() => coordinator.FetchAsync("k", fetch));
        var t2 = Task.Run(() => coordinator.FetchAsync("k", fetch));
        var t3 = Task.Run(() => coordinator.FetchAsync("k", fetch));

        // Give scheduler a moment to register all three before unblocking the fetch.
        await Task.Delay(50);
        gate.SetResult();

        var results = await Task.WhenAll(t1, t2, t3);
        Assert.Equal(1, fetchCount);
        Assert.All(results, r => Assert.Equal(new byte[] { 1, 2, 3 }, r));
    }

    [Fact]
    public async Task DifferentKeys_FetchIndependently()
    {
        var coordinator = new UpstreamFetchCoordinator();
        var fetchCount = 0;

        Func<Task<byte[]>> fetch = () =>
        {
            Interlocked.Increment(ref fetchCount);
            return Task.FromResult(new byte[] { 1 });
        };

        await coordinator.FetchAsync("a", fetch);
        await coordinator.FetchAsync("b", fetch);
        Assert.Equal(2, fetchCount);
    }

    [Fact]
    public async Task FailedFetch_DoesNotPoisonNextRequest()
    {
        var coordinator = new UpstreamFetchCoordinator();
        var calls = 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.FetchAsync("k", () =>
            {
                calls++;
                throw new InvalidOperationException("boom");
            }));

        // Next caller should re-attempt, not get the cached failure.
        var bytes = await coordinator.FetchAsync("k", () =>
        {
            calls++;
            return Task.FromResult(new byte[] { 9 });
        });

        Assert.Equal(2, calls);
        Assert.Equal(new byte[] { 9 }, bytes);
    }

    [Fact]
    public async Task Completion_RemovesFromInFlight()
    {
        var coordinator = new UpstreamFetchCoordinator();
        await coordinator.FetchAsync("k", () => Task.FromResult(new byte[] { 1 }));
        Assert.Equal(0, coordinator.InFlightCount);
    }
}
