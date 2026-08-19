using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The scheduler behind both outbound notification queues. Every test here states a property one
/// tenant must not be able to take away from another: that another org's item is served while
/// this org's handler is still running, that one org's flood sheds only its own items, that an
/// org gets one turn per round rather than draining its whole backlog, and that no handler
/// outcome — a hang past the budget, a cancellation, a fault — can shrink the worker pool.
///
/// Every wait is gated on an explicit signal (a <see cref="TaskCompletionSource"/> the fake
/// handler blocks on, or a durable counter) rather than on elapsed time, so a pass means the
/// property held and not that the machine happened to be fast.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgFairDispatcherTests
{
    private static readonly TimeSpan GenerousBudget = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Real-time ceiling on every wait for the pool to do something. A bare <c>await</c> on a
    /// <see cref="TaskCompletionSource"/> turns a regression in the code these tests guard into a
    /// hung test host and a CI job that times out with no failing test name — a degraded signal
    /// reading as no signal, which is the same failure mode this type exists to prevent, inside
    /// its own test suite. Every wait here is on work a healthy pool does in milliseconds.
    /// </summary>
    // now-ok: real-time deadline bounding a wait on a genuinely asynchronous background worker
    private static Task Settles(Task signal) => signal.WaitAsync(TimeSpan.FromSeconds(10));

    private static OrgFairDispatcher<string> Build(
        int perOrgCapacity = 16,
        int workers = 2,
        TimeSpan? budget = null,
        TimeProvider? time = null) =>
        new(perOrgCapacity, workers, budget ?? GenerousBudget,
            time ?? TestTime.Frozen(), NullLogger.Instance, "test item");

    /// <summary>
    /// The core cross-tenant property. Org A's handler blocks indefinitely; org B's item is
    /// enqueued afterwards and must still be handled — with no clock advanced and no budget
    /// involved, purely because the two orgs are on separate lanes served by separate workers.
    /// A single shared queue with one reader cannot satisfy this: B's item sits behind A's until
    /// A's endpoint answers, which is A's choice to make.
    /// </summary>
    [Fact]
    public async Task ItemForOneOrg_BlockedIndefinitely_DoesNotHoldAnotherOrgsItem()
    {
        var dispatcher = Build(workers: 2);
        var orgABlocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var orgAStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var orgBHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync(async (item, ct) =>
        {
            if (item.StartsWith('a'))
            {
                orgAStarted.TrySetResult();
                await orgABlocked.Task;
            }
            else
            {
                orgBHandled.TrySetResult();
            }

            return true;
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "a1"));
        await Settles(orgAStarted.Task);
        Assert.True(dispatcher.TryEnqueue("orgB", "b1"));

        await Settles(orgBHandled.Task);
        Assert.False(orgABlocked.Task.IsCompleted, "org A's handler must still be running.");

        orgABlocked.TrySetResult();
        await cts.CancelAsync();
        await Settles(run);
    }

    /// <summary>
    /// The same property with the pool reduced to a single worker, where lanes alone cannot
    /// provide it: org A's handler never returns, so the only thing that can free the worker is
    /// the per-item budget. Org B's item must be handled once that budget elapses in virtual
    /// time — a bounded wait, not a starved one — and org A's handler must observe cancellation
    /// rather than the dispatcher abandoning it silently.
    /// </summary>
    [Fact]
    public async Task SingleWorker_ItemExceedingItsBudget_ReleasesTheWorkerForAnotherOrg()
    {
        var clock = TestTime.Frozen();
        var dispatcher = Build(workers: 1, budget: TimeSpan.FromSeconds(30), time: clock);

        var orgAStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var orgACancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var orgBHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync(async (item, ct) =>
        {
            if (item.StartsWith('a'))
            {
                orgAStarted.TrySetResult();
                var forever = new TaskCompletionSource();
                try
                {
                    await forever.Task.WaitAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    orgACancelled.TrySetResult();
                    throw;
                }
            }
            else
            {
                orgBHandled.TrySetResult();
            }

            return true;
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "a1"));
        await Settles(orgAStarted.Task);
        Assert.True(dispatcher.TryEnqueue("orgB", "b1"));
        Assert.False(orgBHandled.Task.IsCompleted, "the only worker is still held by org A.");

        // KEEPS its pump: virtual time IS this test's subject. org A's handler parks forever, so
        // the only thing that frees the worker is the per-item budget expiring on the injected
        // clock. There is no retry backoff anywhere in the dispatcher to skip — advancing the
        // clock is the behaviour under test, not a way around one.
        await ClockPump.UntilAsync(clock, () => orgBHandled.Task.IsCompleted, TimeSpan.FromSeconds(5));

        await Settles(orgACancelled.Task);
        await cts.CancelAsync();
        await Settles(run);
    }

    /// <summary>
    /// A handler that faults must not take its worker with it — a pool that shrinks by one
    /// poisoned item is the same starvation by another route. The item after the fault is still
    /// handled by the same single worker.
    /// </summary>
    [Fact]
    public async Task HandlerFault_DoesNotKillTheWorker()
    {
        var dispatcher = Build(workers: 1);
        var secondHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync((item, ct) =>
        {
            if (item == "boom")
            {
                throw new InvalidOperationException("handler fault");
            }

            secondHandled.TrySetResult();
            return Task.FromResult(true);
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "boom"));
        Assert.True(dispatcher.TryEnqueue("orgA", "next"));

        await Settles(secondHandled.Task);
        Assert.False(run.IsCompleted);

        await cts.CancelAsync();
        await Settles(run);
    }

    /// <summary>
    /// Same rule for cancellation: a handler that throws <see cref="OperationCanceledException"/>
    /// on a token that is not the pool's stopping token (an exhausted budget, or an inner call
    /// that observes cancellation) is a completed item, not a dead worker.
    /// </summary>
    [Fact]
    public async Task HandlerThrowingOperationCanceled_DoesNotKillTheWorker()
    {
        var dispatcher = Build(workers: 1);
        var secondHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync((item, ct) =>
        {
            if (item == "cancel")
            {
                throw new OperationCanceledException();
            }

            secondHandled.TrySetResult();
            return Task.FromResult(true);
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "cancel"));
        Assert.True(dispatcher.TryEnqueue("orgA", "next"));

        await Settles(secondHandled.Task);
        Assert.False(run.IsCompleted);

        await cts.CancelAsync();
        await Settles(run);
    }

    /// <summary>
    /// A fault raised while setting an item up — before the handler is ever called — must not cost
    /// the pool a worker either. Building the per-item deadline is the one thing that runs outside
    /// the handler, and it is the riskiest, because its duration comes from operator configuration:
    /// a value past the platform's maximum timer duration makes constructing the timer throw. A
    /// worker lost here is worse than a loud crash, because <see cref="Task.WhenAll(Task[])"/>
    /// leaves the fault unobserved while any sibling survives — the pool just quietly gets smaller
    /// and items vanish.
    /// </summary>
    [Fact]
    public async Task FaultConstructingTheItemDeadline_DoesNotKillTheWorker()
    {
        var dispatcher = Build(workers: 1, time: new ThrowOnFirstTimerTimeProvider());
        var handled = new List<string>();
        var secondHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync((item, ct) =>
        {
            handled.Add(item);
            if (item == "second")
            {
                secondHandled.TrySetResult();
            }

            return Task.FromResult(true);
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "first"));
        Assert.True(dispatcher.TryEnqueue("orgA", "second"));

        await Settles(secondHandled.Task);

        Assert.DoesNotContain("first", handled);
        Assert.False(run.IsCompleted);

        await cts.CancelAsync();
        await Settles(run);
    }

    /// <summary>
    /// The budget a dispatcher will accept is bounded, and an out-of-range configured value is
    /// refused at startup rather than carried into the workers. Left unbounded, a number past the
    /// platform's timer ceiling type-checks, parses, and then throws once per item forever.
    /// </summary>
    [Theory]
    [InlineData(null, 120)]
    [InlineData("", 120)]
    [InlineData("45", 45)]
    [InlineData("0", 120)]
    [InlineData("-5", 120)]
    [InlineData("not-a-number", 120)]
    [InlineData("2000000000", 120)]
    public void ResolveItemBudget_RefusesAnythingOutsideTheAcceptedRange(string? configured, int expectedSeconds)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["BUDGET"] = configured })
            .Build();

        var budget = OrgFairDispatcher.ResolveItemBudget(config, "BUDGET", 120, NullLogger.Instance);

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), budget);
        Assert.True(budget <= OrgFairDispatcher.MaxItemBudget);
    }

    /// <summary>
    /// And the dispatcher refuses one directly, so a future owner that resolves its budget some
    /// other way still cannot hand the pool a deadline it cannot build.
    /// </summary>
    [Fact]
    public void Constructor_RejectsABudgetBeyondTheAcceptedMaximum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new OrgFairDispatcher<string>(
            perOrgCapacity: 8,
            workerCount: 1,
            itemBudget: OrgFairDispatcher.MaxItemBudget + TimeSpan.FromSeconds(1),
            time: TestTime.Frozen(),
            logger: NullLogger.Instance,
            itemLabel: "test item"));
    }

    /// <summary>
    /// An item taken off a lane but not carried to a conclusion because the host is stopping goes
    /// back to the head of its lane, so the owner's drain still sees it. Dropping it instead loses
    /// one item per worker on every deploy — a multiplier the operator sets with the worker count.
    /// The budget arm must not share this behaviour, which the next test pins.
    /// </summary>
    [Fact]
    public async Task ItemInterruptedByShutdown_GoesBackToItsLaneForTheDrain()
    {
        var dispatcher = Build(workers: 1);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync(async (item, ct) =>
        {
            started.TrySetResult();
            var forever = new TaskCompletionSource();
            await forever.Task.WaitAsync(ct);
            return true;
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "in-flight"));
        await Settles(started.Task);

        await cts.CancelAsync();
        await Settles(run);

        Assert.True(dispatcher.TryTakeForDrain(out string? drained, out string orgId));
        Assert.Equal("in-flight", drained);
        Assert.Equal("orgA", orgId);
    }

    /// <summary>
    /// The other half of that rule: an item abandoned because it burned its own budget is NOT put
    /// back. Requeuing it would hand an endpoint that never answers a fresh budget period on every
    /// pass, which is an unbounded hold on a worker assembled out of bounded ones.
    /// </summary>
    [Fact]
    public async Task ItemAbandonedByItsOwnBudget_IsNotRequeued()
    {
        var clock = TestTime.Frozen();
        var dispatcher = Build(workers: 1, budget: TimeSpan.FromSeconds(30), time: clock);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync(async (item, ct) =>
        {
            var forever = new TaskCompletionSource();
            try
            {
                await forever.Task.WaitAsync(ct);
            }
            catch (OperationCanceledException)
            {
                cancelled.TrySetResult();
                throw;
            }

            return true;
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "over-budget"));
        // KEEPS its pump, for the same reason: the item is abandoned by its own budget expiring
        // on the injected clock, which is exactly what this test asserts.
        await ClockPump.UntilAsync(clock, () => cancelled.Task.IsCompleted, TimeSpan.FromSeconds(5));

        await cts.CancelAsync();
        await Settles(run);

        Assert.False(dispatcher.TryTakeForDrain(out _, out _));
        Assert.Equal(0, dispatcher.LaneCount);
    }

    /// <summary>A <see cref="TimeProvider"/> whose first timer construction throws, standing in for
    /// any fault raised while preparing an item's deadline.</summary>
    private sealed class ThrowOnFirstTimerTimeProvider : TimeProvider
    {
        private int _timers;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            Interlocked.Increment(ref _timers) == 1
                ? throw new InvalidOperationException("timer construction failed")
                : base.CreateTimer(callback, state, dueTime, period);
    }

    /// <summary>
    /// Capacity is charged per org. One org filling its lane sheds only its own items; another
    /// org's lane is untouched and still accepts work. On a single shared buffer the second org's
    /// item is refused for a backlog it had no part in creating.
    /// </summary>
    [Fact]
    public void PerOrgCapacity_OneOrgOverflowing_DoesNotShedAnotherOrgsItem()
    {
        var dispatcher = Build(perOrgCapacity: 2);

        Assert.True(dispatcher.TryEnqueue("orgA", "a1"));
        Assert.True(dispatcher.TryEnqueue("orgA", "a2"));
        Assert.False(dispatcher.TryEnqueue("orgA", "a3"));
        Assert.False(dispatcher.TryEnqueue("orgA", "a4"));

        Assert.True(dispatcher.TryEnqueue("orgB", "b1"));
        Assert.True(dispatcher.TryEnqueue("orgB", "b2"));
        Assert.False(dispatcher.TryEnqueue("orgB", "b3"));
    }

    /// <summary>
    /// Service is round-robin over orgs, not exhaustive per org: with one worker and a lane that
    /// already holds three items, the org that queued one item afterwards is served second, not
    /// fourth. This is what keeps another org's wait a function of the number of tenants rather
    /// than of how much work the loudest tenant queued.
    /// </summary>
    [Fact]
    public async Task Service_TakesOneItemPerOrgPerTurn()
    {
        var dispatcher = Build(workers: 1);
        var order = new List<string>();
        var allHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var cts = new CancellationTokenSource();
        var run = dispatcher.RunAsync(async (item, ct) =>
        {
            // The first item parks until every item is queued, so the ordering under test is the
            // scheduler's, not an artifact of who happened to be enqueued before service began.
            if (order.Count == 0)
            {
                order.Add(item);
                await release.Task;
                return true;
            }

            order.Add(item);
            if (order.Count == 4)
            {
                allHandled.TrySetResult();
            }

            return true;
        }, cts.Token);

        Assert.True(dispatcher.TryEnqueue("orgA", "a1"));
        Assert.True(dispatcher.TryEnqueue("orgA", "a2"));
        Assert.True(dispatcher.TryEnqueue("orgA", "a3"));
        Assert.True(dispatcher.TryEnqueue("orgB", "b1"));
        release.TrySetResult();

        await Settles(allHandled.Task);
        Assert.Equal(["a1", "b1", "a2", "a3"], order);

        await cts.CancelAsync();
        await Settles(run);
    }

    /// <summary>
    /// The drain takes items in the same per-org rotation, so a backlogged org cannot consume a
    /// bounded shutdown window at another org's expense.
    /// </summary>
    [Fact]
    public void Drain_RotatesAcrossOrgs()
    {
        var dispatcher = Build();

        dispatcher.TryEnqueue("orgA", "a1");
        dispatcher.TryEnqueue("orgA", "a2");
        dispatcher.TryEnqueue("orgB", "b1");

        var drained = new List<string>();
        while (dispatcher.TryTakeForDrain(out string? item, out _))
        {
            drained.Add(item);
        }

        Assert.Equal(["a1", "b1", "a2"], drained);
    }

    /// <summary>
    /// Lanes are reaped once they empty, so the lane map tracks orgs with work in flight rather
    /// than every org that has ever raised an event.
    /// </summary>
    [Fact]
    public void EmptiedLanes_AreReaped()
    {
        var dispatcher = Build();

        dispatcher.TryEnqueue("orgA", "a1");
        dispatcher.TryEnqueue("orgB", "b1");
        Assert.Equal(2, dispatcher.LaneCount);

        while (dispatcher.TryTakeForDrain(out _, out _))
        {
            // Drain everything.
        }

        Assert.Equal(0, dispatcher.LaneCount);

        // A reaped org enqueues again cleanly rather than resurrecting a retired lane.
        Assert.True(dispatcher.TryEnqueue("orgA", "a2"));
        Assert.Equal(1, dispatcher.LaneCount);
        Assert.True(dispatcher.TryTakeForDrain(out string? again, out string againOrg));
        Assert.Equal("a2", again);
        Assert.Equal("orgA", againOrg);
    }
}
