using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Dependably.Infrastructure;

/// <summary>
/// Configuration helpers shared by every <see cref="OrgFairDispatcher{TItem}"/> owner.
/// </summary>
internal static class OrgFairDispatcher
{
    /// <summary>
    /// Longest per-item budget a dispatcher accepts. An hour is far past any legitimate delivery
    /// retry budget, and the ceiling matters for a second reason: the budget becomes a timer, and
    /// a value beyond the platform's maximum timer duration makes constructing that timer throw.
    /// Bounding the configured value at the edge keeps a misconfiguration a startup warning
    /// instead of a fault raised once per item, deep inside a worker.
    /// </summary>
    internal static readonly TimeSpan MaxItemBudget = TimeSpan.FromHours(1);

    /// <summary>
    /// Reads a per-item budget expressed in whole seconds. An absent value takes the default
    /// silently; a value that is not a positive whole number of seconds within
    /// <see cref="MaxItemBudget"/> is refused with a warning naming what was rejected and what is
    /// being used instead, so the operator learns at boot rather than from a delivery outage.
    /// </summary>
    internal static TimeSpan ResolveItemBudget(
        IConfiguration config, string key, int defaultSeconds, ILogger logger)
    {
        string? raw = config[key];
        if (string.IsNullOrWhiteSpace(raw))
        {
            return TimeSpan.FromSeconds(defaultSeconds);
        }

        int maxSeconds = (int)MaxItemBudget.TotalSeconds;
        if (!int.TryParse(raw, out int seconds) || seconds <= 0 || seconds > maxSeconds)
        {
            logger.LogWarning(
                "{Key}={Value} is not a whole number of seconds between 1 and {MaxSeconds}; " +
                "using the default of {DefaultSeconds}s instead.",
                key, raw, maxSeconds, defaultSeconds);
            return TimeSpan.FromSeconds(defaultSeconds);
        }

        return TimeSpan.FromSeconds(seconds);
    }
}

/// <summary>
/// Per-org partitioned, round-robin work scheduler shared by the outbound notification queues
/// (<see cref="Webhooks.WebhookDispatchQueue"/>, <see cref="Alerts.AlertSlackQueue"/>). Both
/// deliver to tenant-supplied endpoints, so both need the same property: no tenant's endpoint
/// behaviour may determine when another tenant's notification is delivered.
///
/// A single process-wide queue with one reader cannot provide that. The org that owns the
/// envelope at the head of the queue holds the reader for as long as its endpoints take to
/// answer — every other org's notifications wait behind it, and once the shared buffer fills,
/// their events are dropped for a backlog they did not create. Both are cross-tenant effects
/// under one tenant's control.
///
/// Three mechanisms replace that, and the fairness bound comes from all three together:
/// <list type="number">
///   <item><b>Per-org lanes.</b> Each org has its own FIFO lane with its own capacity, so a
///   flood or a backlog in one org displaces only that org's own work. Overflow is charged to
///   the org that caused it.</item>
///   <item><b>Round-robin service.</b> A lane is served by at most one worker at a time and
///   yields after exactly one item, going back to the tail of the ready ring. An org with a
///   thousand queued items therefore takes one turn, not a thousand — the position of another
///   org's item is bounded by the number of <em>orgs</em> ahead of it, never by how much work
///   they queued.</item>
///   <item><b>A per-item budget.</b> Every item runs under a deadline, so a worker returns to
///   the ring within that bound no matter how the tenant's endpoint behaves. Without it, lanes
///   alone would still let W unresponsive orgs pin W workers indefinitely. Owners apply the same
///   budget to their shutdown drain through <see cref="RunOneAsync"/>, so the bound holds on the
///   stopping path too.</item>
/// </list>
/// With <c>W</c> workers and <c>K</c> orgs holding pending work, an item waits at most
/// <c>ceil(K / W)</c> budget periods before its lane is served — a bound in the number of
/// <em>tenants</em>, which no single tenant can inflate.
///
/// Nothing a handler does — completing, hanging past its budget, observing cancellation, or
/// faulting — removes a worker from the pool, and neither does a fault raised while setting an
/// item up. A worker lost that way shrinks the pool, which is the same starvation this type
/// exists to prevent arriving by another route, and it is silent: the pool's
/// <see cref="Task.WhenAll(Task[])"/> leaves the fault unobserved for as long as any worker
/// survives.
/// </summary>
internal sealed class OrgFairDispatcher<TItem>
{
    private readonly ConcurrentDictionary<string, Lane> _lanes = new(StringComparer.Ordinal);

    // Holds lanes with pending work, in service order. A lane is present at most once (the
    // Scheduled flag guarantees it), so this never exceeds the number of orgs with queued work.
    private readonly Channel<Lane> _ready = Channel.CreateUnbounded<Lane>(
        new UnboundedChannelOptions { SingleReader = false, SingleWriter = false });

    private readonly int _perOrgCapacity;
    private readonly int _workerCount;
    private readonly TimeSpan _itemBudget;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly string _itemLabel;

    /// <param name="perOrgCapacity">Queue depth per org. Overflow drops that org's own item.</param>
    /// <param name="workerCount">How many lanes are served concurrently.</param>
    /// <param name="itemBudget">
    /// Hard deadline on one item's handler run, at most <see cref="OrgFairDispatcher.MaxItemBudget"/>.
    /// Owners resolve it from configuration through <see cref="OrgFairDispatcher.ResolveItemBudget"/>,
    /// which refuses an out-of-range value before it reaches this constructor.
    /// </param>
    /// <param name="time">Injected clock driving the item budget.</param>
    /// <param name="logger">Owner's logger; used for budget-exhaustion and handler-fault warnings.</param>
    /// <param name="itemLabel">Human noun for one item ("webhook envelope"), used in log messages.</param>
    internal OrgFairDispatcher(
        int perOrgCapacity,
        int workerCount,
        TimeSpan itemBudget,
        TimeProvider time,
        ILogger logger,
        string itemLabel)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(perOrgCapacity);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(workerCount);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(itemBudget, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(itemBudget, OrgFairDispatcher.MaxItemBudget);

        _perOrgCapacity = perOrgCapacity;
        _workerCount = workerCount;
        _itemBudget = itemBudget;
        _time = time;
        _logger = logger;
        _itemLabel = itemLabel;
    }

    /// <summary>Number of orgs currently holding queued work. Lanes are reaped when they empty.</summary>
    internal int LaneCount => _lanes.Count;

    /// <summary>
    /// Non-blocking enqueue onto the org's own lane. Returns false when that org's lane is full;
    /// the caller records the drop. A full lane never affects any other org's lane.
    /// </summary>
    internal bool TryEnqueue(string orgId, TItem item)
    {
        // An item with no org attribution shares one lane rather than throwing on the producer's
        // thread: enqueue is called from request paths that must never fail on a notification.
        string key = string.IsNullOrEmpty(orgId) ? string.Empty : orgId;

        while (true)
        {
            var lane = _lanes.GetOrAdd(key, static id => new Lane(id));
            bool schedule;

            lock (lane.Sync)
            {
                if (lane.Retired)
                {
                    // Reaped between the lookup and the lock. The reaper removes the entry under
                    // this same lock, so the next lookup mints a fresh lane and this retries once.
                    continue;
                }

                if (lane.Pending.Count >= _perOrgCapacity)
                {
                    return false;
                }

                lane.Pending.AddLast(item);
                schedule = !lane.Scheduled;
                lane.Scheduled = true;
            }

            if (schedule)
            {
                _ready.Writer.TryWrite(lane);
            }

            return true;
        }
    }

    /// <summary>
    /// Runs the worker pool until <paramref name="ct"/> is cancelled. Completes normally on
    /// cancellation — callers drain afterwards, so cancellation is an expected end, not a fault.
    /// </summary>
    internal Task RunAsync(Func<TItem, CancellationToken, Task<bool>> handler, CancellationToken ct)
    {
        var workers = new Task[_workerCount];
        for (int i = 0; i < _workerCount; i++)
        {
            workers[i] = WorkerLoopAsync(handler, ct);
        }

        return Task.WhenAll(workers);
    }

    /// <summary>
    /// Takes the next item in round-robin order without running a worker loop, reporting the org
    /// it belongs to. Used by the owners' shutdown drain, which needs the same per-org rotation as
    /// normal service so a backlogged org cannot consume the whole drain window.
    /// </summary>
    internal bool TryTakeForDrain(out TItem item, out string orgId)
    {
        while (_ready.Reader.TryRead(out var lane))
        {
            bool taken;
            TItem candidate;
            bool requeue;

            lock (lane.Sync)
            {
                taken = TryDequeue(lane, out candidate);
                requeue = lane.Pending.Count > 0;
                if (!requeue)
                {
                    Retire(lane);
                }
            }

            if (requeue)
            {
                _ready.Writer.TryWrite(lane);
            }

            if (taken)
            {
                item = candidate;
                orgId = lane.OrgId;
                return true;
            }
        }

        item = default!;
        orgId = string.Empty;
        return false;
    }

    /// <summary>
    /// Runs one already-taken item under the same per-item budget and the same containment as the
    /// worker pool, and reports whether the handler carried it to a conclusion. The shutdown drain uses it
    /// so its items carry the fairness bound too: without it, the first org drained decides — from
    /// its own endpoint — how much of a bounded drain window every other org gets.
    /// </summary>
    internal Task<bool> RunOneAsync(
        Func<TItem, CancellationToken, Task<bool>> handler, TItem item, string orgId, CancellationToken ct) =>
        InvokeAsync(handler, item, orgId, ct);

    private async Task WorkerLoopAsync(Func<TItem, CancellationToken, Task<bool>> handler, CancellationToken ct)
    {
        try
        {
            await foreach (var lane in _ready.Reader.ReadAllAsync(ct))
            {
                if (ct.IsCancellationRequested)
                {
                    // ReadAllAsync hands over everything already buffered before it re-checks the
                    // token, so a lane can arrive after shutdown. Give it back for the drain
                    // instead of serving it with a dead token — that would return instantly,
                    // requeue, and spin for as long as the enumerator kept yielding.
                    _ready.Writer.TryWrite(lane);
                    break;
                }

                try
                {
                    await ServeOneAsync(lane, handler, ct);
                }
                catch (Exception ex)
                {
                    // ServeOneAsync contains handler outcomes itself, so reaching here means its
                    // own bookkeeping faulted. Log and take the next lane: a worker that exits
                    // here shrinks the pool permanently, and Task.WhenAll would not surface the
                    // fault while any other worker is still running.
                    _logger.LogWarning(ex,
                        "{ExceptionType} serving a {ItemLabel} lane for org {OrgId}; the worker continues.",
                        ex.GetType().Name, _itemLabel, lane.OrgId);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown. Whatever is still queued is handled by the owner's drain.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "{ExceptionType} in the {ItemLabel} dispatch worker loop; this worker has stopped.",
                ex.GetType().Name, _itemLabel);
        }
    }

    // Serves exactly one item from the lane, then returns the lane to the tail of the ready ring
    // (or reaps it when empty). Taking one item per turn is what makes service round-robin
    // across orgs rather than exhaustive per org.
    private async Task ServeOneAsync(Lane lane, Func<TItem, CancellationToken, Task<bool>> handler, CancellationToken ct)
    {
        bool taken;
        TItem item;
        lock (lane.Sync)
        {
            taken = TryDequeue(lane, out item);
        }

        bool returnItemToLane = false;
        try
        {
            if (taken)
            {
                bool completed = await InvokeAsync(handler, item, lane.OrgId, ct);

                // An item cut short by shutdown was never carried to a conclusion, and the reason
                // is the host stopping rather than anything about this org — put it back at the
                // head of its lane so the owner's drain still runs it. Redelivery of a part of it
                // that did land is the accepted cost: these deliveries are at-least-once already,
                // since an attempt that times out is retried on exactly the same terms. An item
                // cut short by its OWN budget is deliberately NOT put back: requeuing that would
                // let an endpoint which never answers hold a worker for a budget period per pass,
                // indefinitely.
                returnItemToLane = !completed && ct.IsCancellationRequested;
            }
        }
        finally
        {
            bool requeueLane;
            lock (lane.Sync)
            {
                if (returnItemToLane)
                {
                    lane.Pending.AddFirst(item!);
                }

                requeueLane = lane.Pending.Count > 0;
                if (!requeueLane)
                {
                    Retire(lane);
                }
            }

            if (requeueLane)
            {
                _ready.Writer.TryWrite(lane);
            }
        }
    }

    // Runs one handler under the fair-share deadline and reports whether it finished. Nothing
    // propagates — not a handler fault, not cancellation, and not a failure to build the deadline
    // itself, which is why both token sources are created inside the try rather than as using
    // declarations above it: a throw there is what silently costs the pool a worker.
    private async Task<bool> InvokeAsync(
        Func<TItem, CancellationToken, Task<bool>> handler, TItem item, string orgId, CancellationToken ct)
    {
        CancellationTokenSource? budget = null;
        CancellationTokenSource? linked = null;

        try
        {
            budget = new CancellationTokenSource(_itemBudget, _time);
            linked = CancellationTokenSource.CreateLinkedTokenSource(ct, budget.Token);

            // The handler reports whether it carried the item to a conclusion. It cannot be
            // inferred from a normal return: both owners deliberately swallow cancellation
            // internally (a delivery abandoned mid-shutdown is not an error), so a handler that
            // gave up looks exactly like one that finished.
            return await handler(item, linked.Token);
        }
        catch (OperationCanceledException)
        {
            if (budget is { IsCancellationRequested: true } && !ct.IsCancellationRequested)
            {
                _logger.LogWarning(
                    "Delivery of a {ItemLabel} for org {OrgId} exceeded its {Budget}s fair-share budget " +
                    "and was abandoned so other orgs are not held behind it.",
                    _itemLabel, orgId, _itemBudget.TotalSeconds);
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} delivering a {ItemLabel} for org {OrgId}; the worker continues with the next item.",
                ex.GetType().Name, _itemLabel, orgId);
            return false;
        }
        finally
        {
            linked?.Dispose();
            budget?.Dispose();
        }
    }

    // Caller must hold lane.Sync.
    private static bool TryDequeue(Lane lane, out TItem item)
    {
        var head = lane.Pending.First;
        if (head is null)
        {
            item = default!;
            return false;
        }

        item = head.Value;
        lane.Pending.RemoveFirst();
        return true;
    }

    // Caller must hold lane.Sync. Removing under the lock is what bounds TryEnqueue's retry to
    // one iteration: a producer that sees Retired is guaranteed the entry is already gone.
    private void Retire(Lane lane)
    {
        lane.Scheduled = false;
        lane.Retired = true;
        _lanes.TryRemove(new KeyValuePair<string, Lane>(lane.OrgId, lane));
    }

    private sealed class Lane
    {
        internal Lane(string orgId) => OrgId = orgId;

        internal string OrgId { get; }

        internal object Sync { get; } = new();

        /// <summary>Guarded by <see cref="Sync"/>. A list rather than a queue so an item
        /// interrupted by shutdown goes back to the head it came from.</summary>
        internal LinkedList<TItem> Pending { get; } = new();

        /// <summary>Guarded by <see cref="Sync"/>. True while the lane sits in the ready ring or is being served.</summary>
        internal bool Scheduled { get; set; }

        /// <summary>Guarded by <see cref="Sync"/>. True once reaped; producers holding a stale reference retry.</summary>
        internal bool Retired { get; set; }
    }
}
