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
        var fetchStarted = new TaskCompletionSource();

        Func<Task<byte[]>> fetch = async () =>
        {
            Interlocked.Increment(ref fetchCount);
            fetchStarted.TrySetResult();
            await gate.Task;
            return [1, 2, 3];
        };

        // Start the first caller and wait until it has registered the in-flight entry and is
        // parked on the gate. FetchAsync runs its GetOrAdd synchronously before the first
        // await, so while the gate is held the entry cannot complete and be removed. This
        // makes the single-flight window deterministic instead of relying on wall-clock timing
        // to overlap three Task.Run callers — which fails under a loaded CI runner.
        var t1 = coordinator.FetchAsync("k", fetch);
        await fetchStarted.Task;

        // The remaining callers now observe the same in-flight entry and share its task.
        var t2 = coordinator.FetchAsync("k", fetch);
        var t3 = coordinator.FetchAsync("k", fetch);

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
