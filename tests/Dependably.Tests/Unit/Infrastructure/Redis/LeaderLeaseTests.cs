using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// Lease-renewal contract for leader-coordinated background jobs.
///
/// A leader lock is acquired with a finite TTL. Without renewal, a pass that runs longer than the
/// TTL keeps working while the lock lapses, and the next replica to tick acquires the same lock
/// and starts a concurrent second pass over destructive work. These tests pin both halves of the
/// fix: the lease keeps the lock held for as long as the pass runs, and the lease is *lost* — the
/// pass cancelled — as soon as renewal can no longer be confirmed.
///
/// Timing is driven by <see cref="FakeTimeProvider"/>; the clock is advanced in steps smaller than
/// the TTL and each renewal is awaited via <see cref="WaitUntilAsync"/> before the next step, so no
/// assertion depends on wall-clock scheduling latency.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LeaderLeaseTests
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);

    // LeaderLease renews three times per TTL window, so a renewal is due every 20s at this TTL.
    private static readonly TimeSpan RenewStep = TimeSpan.FromSeconds(20);

    // Real-time safety bound for the "has the heartbeat run yet" polls below. A healthy renewal is
    // observed in microseconds; this only stops a broken one from hanging the runner.
    private static readonly TimeSpan PollTimeout = TimeSpan.FromSeconds(10);

    private const string LockName = "job:test";

    // Polls a condition to a bounded real-time deadline. The condition is driven by a background
    // heartbeat task whose continuation is scheduled on the thread pool, so it cannot be observed
    // synchronously after advancing the fake clock.
    private static async Task WaitUntilAsync(Func<bool> condition, string because)
    {
        var deadline = Task.Delay(PollTimeout);
        while (!condition())
        {
            Assert.False(deadline.IsCompleted, $"timed out after {PollTimeout.TotalSeconds:0}s waiting for {because}");
            await Task.Delay(5);
        }
    }

    // Advances the clock one renewal interval at a time, waiting for each renewal attempt to land,
    // until the lease has been carried well past its original TTL.
    private static async Task AdvancePastTtlAsync(FakeTimeProvider clock, LeasedTestLock locks, int steps)
    {
        for (int step = 1; step <= steps; step++)
        {
            clock.Advance(RenewStep);
            int expected = step;
            await WaitUntilAsync(() => locks.ExtendAttempts >= expected, $"renewal attempt {expected}");
        }
    }

    /// <summary>
    /// The core regression: a lease held past its TTL with renewal active still refuses a second
    /// acquirer. Without the renewal heartbeat the key expires at <see cref="Ttl"/> and the second
    /// replica — the one that would start a concurrent destructive pass — wins the lock.
    /// </summary>
    [Fact]
    public async Task Renewal_HoldsLockPastTtl_SecondAcquirerRefused()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        Assert.NotNull(handle);

        await using var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        // 6 x 20s = 120s of held time, twice the TTL.
        await AdvancePastTtlAsync(clock, locks, steps: 6);

        Assert.True(locks.ExtendSuccesses >= 6, $"expected the lease to be renewed each interval; got {locks.ExtendSuccesses}");
        Assert.False(lease.LeaseLost);
        Assert.False(lease.Token.IsCancellationRequested);
        Assert.Null(await locks.TryAcquireAsync(LockName, Ttl));
    }

    /// <summary>
    /// The unrenewed twin of the test above, pinning that the fake models real expiry: with no
    /// lease running, the same lock lapses at its TTL and a second acquirer takes it.
    /// </summary>
    [Fact]
    public async Task NoRenewal_LockLapsesAtTtl_SecondAcquirerWins()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        Assert.NotNull(handle);

        clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.NotNull(await locks.TryAcquireAsync(LockName, Ttl));
    }

    /// <summary>
    /// Disposing the lease releases the lock, so the next scheduled tick on any replica can take it.
    /// </summary>
    [Fact]
    public async Task Dispose_StopsHeartbeatAndReleasesLock()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        await AdvancePastTtlAsync(clock, locks, steps: 2);
        await lease.DisposeAsync();

        Assert.False(locks.IsHeld(LockName));
        Assert.NotNull(await locks.TryAcquireAsync(LockName, Ttl));

        // The heartbeat is stopped: further clock advances produce no more renewal traffic.
        int attemptsAtDispose = locks.ExtendAttempts;
        clock.Advance(RenewStep * 3);
        await Task.Delay(50);
        Assert.Equal(attemptsAtDispose, locks.ExtendAttempts);
    }

    /// <summary>
    /// A definitive "you no longer hold this lock" answer loses the lease immediately: the token is
    /// cancelled so the guarded pass aborts instead of continuing to operate unleased.
    /// </summary>
    [Fact]
    public async Task RenewalRefused_LeaseLost_TokenCancelled()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock) { ExtendBehavior = _ => ExtendOutcome.Refuse };
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        await using var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        clock.Advance(RenewStep);
        await WaitUntilAsync(() => lease.Token.IsCancellationRequested, "the lease to be lost and the pass cancelled");

        Assert.True(lease.LeaseLost);
    }

    /// <summary>
    /// Mixed partial-failure: some renewal attempts fail (the lock backend is briefly unreachable)
    /// and some succeed. A transient backend failure is not a lease decision, so the lease survives
    /// it, keeps the lock held past its original TTL, and never cancels the pass.
    /// </summary>
    [Fact]
    public async Task RenewalThrowsThenSucceeds_LeaseSurvives_LockStillHeld()
    {
        var clock = TestTime.Frozen();
        // Attempts 1 and 3 fail on the backend; 2, 4, 5, 6 renew normally.
        var locks = new LeasedTestLock(clock)
        {
            ExtendBehavior = attempt => attempt is 1 or 3 ? ExtendOutcome.Throw : ExtendOutcome.Renew,
        };
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        await using var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        await AdvancePastTtlAsync(clock, locks, steps: 6);

        Assert.False(lease.LeaseLost, "a transient lock-backend failure must not cost the lease while the window still has room");
        Assert.False(lease.Token.IsCancellationRequested);
        Assert.True(locks.ExtendSuccesses >= 4);
        Assert.Null(await locks.TryAcquireAsync(LockName, Ttl));
    }

    /// <summary>
    /// Fail-closed, with margin: when renewal keeps failing on the backend, the lease is
    /// unconfirmable and is given up one renewal interval *before* the lock would expire — not at
    /// the expiry instant. The recorded deadline is stamped after a renewal round-trip returns, so
    /// it already sits at or past the backend's real expiry; giving up only once it has fully
    /// elapsed leaves a window in which this instance still believes it holds a released lock,
    /// with the guarded work's cancellation latency on top. The margin is the whole point of this
    /// test: it asserts the loss lands strictly before the TTL elapses.
    /// </summary>
    [Fact]
    public async Task RenewalKeepsThrowing_LeaseLostBeforeTtlElapses()
    {
        var clock = TestTime.Frozen();
        var acquiredAt = clock.GetUtcNow();
        var locks = new LeasedTestLock(clock) { ExtendBehavior = _ => ExtendOutcome.Throw };
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        await using var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        // Two failed attempts (t+20s, t+40s) consume the window up to the give-up point at
        // t+40s = TTL minus one renewal interval.
        for (int step = 1; step <= 2; step++)
        {
            clock.Advance(RenewStep);
            int expected = step;
            await WaitUntilAsync(() => locks.ExtendAttempts >= expected, $"failed renewal attempt {expected}");
        }

        await WaitUntilAsync(() => lease.LeaseLost, "the unconfirmable lease to be declared lost");
        Assert.True(lease.Token.IsCancellationRequested);

        // The abort must land while the lock is still genuinely held, not after it lapsed.
        Assert.True(clock.GetUtcNow() < acquiredAt + Ttl,
            "the lease must be given up before its TTL elapses, leaving the guarded work time to stop");
        Assert.True(locks.IsHeld(LockName), "the lock is still held by this instance when the abort fires");
    }

    /// <summary>
    /// A cancellation callback registered on the lease token must not be able to strand the lock.
    /// <see cref="CancellationTokenSource.Cancel()"/> collects exceptions thrown by registered
    /// callbacks and rethrows them aggregated, and the guarded work hands this token straight to
    /// ADO.NET, HttpClient and the storage SDKs — all of which register callbacks. Left uncaught,
    /// that fault surfaces at disposal, skips the lock release (holding it for a full TTL) and
    /// escapes the <c>finally</c> block every call site disposes from, which from a
    /// BackgroundService takes the replica down — the exact outcome the lease exists to prevent.
    /// </summary>
    [Fact]
    public async Task CancellationCallbackThrows_LeaseStillReleasesLock_AndDisposeDoesNotThrow()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock) { ExtendBehavior = _ => ExtendOutcome.Refuse };
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        using (lease.Token.Register(() => throw new InvalidOperationException("cancellation callback failure")))
        {
            clock.Advance(RenewStep);
            await WaitUntilAsync(() => lease.LeaseLost, "the lease to be declared lost");

            var ex = await Record.ExceptionAsync(() => lease.DisposeAsync().AsTask());

            Assert.Null(ex);
        }

        Assert.False(locks.IsHeld(LockName), "the lock must be released even when a cancellation callback threw");
        Assert.NotNull(await locks.TryAcquireAsync(LockName, Ttl));
    }

    /// <summary>
    /// Host shutdown cancels the lease token through the linked caller token, but that is not a
    /// lost lease — callers use <see cref="LeaderLease.LeaseLost"/> to tell the two apart.
    /// </summary>
    [Fact]
    public async Task CallerCancellation_CancelsToken_ButLeaseNotLost()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        using var cts = new CancellationTokenSource();
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        await using var lease = LeaderLease.Start(handle!, Ttl, clock, NullLogger.Instance, cts.Token);

        await cts.CancelAsync();

        Assert.True(lease.Token.IsCancellationRequested);
        Assert.False(lease.LeaseLost);
    }

    // ── Margin floor + TTL validation (#475) ────────────────────────────────────────

    /// <summary>
    /// A TTL short enough that <c>TTL / RenewalsPerTtl</c> would fall under the ~5s
    /// StackExchange.Redis command-timeout floor must still get a margin at least that wide — the
    /// structural fix for the renewal margin being safe only by TTL coincidence. 12s clears the
    /// Start-time minimum-TTL guard (so this test exercises the margin floor specifically, not
    /// TTL rejection) but its raw TTL/3 interval (4s) sits under the 5s floor.
    /// </summary>
    [Fact]
    public async Task ShortTtl_MarginFlooredAtMinRenewMargin_NotThinnerRawInterval()
    {
        var ttl = TimeSpan.FromSeconds(12);
        var rawInterval = TimeSpan.FromSeconds(4); // 12s / RenewalsPerTtl(3) — below the 5s floor.

        var clock = TestTime.Frozen();
        var acquiredAt = clock.GetUtcNow();
        var locks = new LeasedTestLock(clock) { ExtendBehavior = _ => ExtendOutcome.Throw };
        var handle = await locks.TryAcquireAsync(LockName, ttl);
        await using var lease = LeaderLease.Start(handle!, ttl, clock, NullLogger.Instance, CancellationToken.None);

        // With the margin floored at 5s, the give-up point is t+7s (12s - 5s): two failed attempts
        // land at t+4s and t+7s, and the second one exhausts the window immediately — no further
        // delay. Without the floor (margin = raw 4s interval), the give-up point would instead be
        // t+8s and the lease would still be held at t+7s.
        clock.Advance(rawInterval);
        await WaitUntilAsync(() => locks.ExtendAttempts >= 1, "the first failed renewal attempt");

        clock.Advance(TimeSpan.FromSeconds(3));
        await WaitUntilAsync(() => lease.LeaseLost,
            "the lease to be given up at the floored margin (t+7s) rather than the thinner raw interval (t+8s)");

        Assert.True(clock.GetUtcNow() < acquiredAt + ttl,
            "the lease must still be given up before its TTL elapses");
    }

    /// <summary>
    /// Below the minimum safe TTL, a floored margin would consume most or all of the renewal
    /// window — and unlike the margin, the backend lock is already acquired with this TTL before
    /// <see cref="LeaderLease.Start"/> ever runs, so there is no safe way to correct it after the
    /// fact. <see cref="LeaderLease.Start"/> rejects it outright instead of running an
    /// always-losing lease.
    /// </summary>
    [Fact]
    public async Task Start_TtlBelowMinSafeTtl_Throws()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        var shortTtl = TimeSpan.FromSeconds(5);
        var handle = await locks.TryAcquireAsync(LockName, shortTtl);

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            LeaderLease.Start(handle!, shortTtl, clock, NullLogger.Instance, CancellationToken.None));

        Assert.Contains("TTL", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The boundary itself (10s — twice the 5s command-timeout floor) is accepted: a service
    /// configured right at the safe minimum still starts a working lease.
    /// </summary>
    [Fact]
    public async Task Start_TtlAtMinSafeTtl_Succeeds()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        var minSafeTtl = TimeSpan.FromSeconds(10);
        var handle = await locks.TryAcquireAsync(LockName, minSafeTtl);

        await using var lease = LeaderLease.Start(handle!, minSafeTtl, clock, NullLogger.Instance, CancellationToken.None);

        Assert.False(lease.LeaseLost);
    }

    /// <summary>
    /// <see cref="LeaderLease.RenewUntilStoppedAsync"/> used to return silently — heartbeat task
    /// ending normally, <see cref="LeaderLease.LeaseLost"/> never becoming true, ever — on ANY
    /// <see cref="OperationCanceledException"/> from <c>ExtendAsync</c>, on the assumption that only
    /// the lease's own disposal token could produce one. That is a fail-*open* path in a module
    /// whose thesis is "unconfirmed is lost, never held": a real backend could plausibly surface an
    /// OperationCanceledException for a reason other than the caller disposing the lease (e.g. a
    /// client-library internal timeout), and the heartbeat would vanish without a trace. Guarding
    /// the catch on the lease's own token means an unrelated OperationCanceledException instead
    /// falls to the same "renewal attempt failed" handling as any other exception — logged and
    /// retried inside the remaining window — so a persistent unrelated failure still gives up the
    /// lease once the window elapses, exactly like the ordinary lock-backend-unreachable case
    /// pinned by <see cref="RenewalKeepsThrowing_LeaseLostBeforeTtlElapses"/>, rather than never
    /// losing the lease at all.
    /// </summary>
    [Fact]
    public async Task ExtendThrowsUnrelatedCancellation_LeaseEventuallyFailsClosed_NeverSilentlyStopped()
    {
        var clock = TestTime.Frozen();
        var handle = new ExtendThrowsUnrelatedOceHandle();

        await using var lease = LeaderLease.Start(handle, Ttl, clock, NullLogger.Instance, CancellationToken.None);

        // Two failed attempts (t+20s, t+40s) consume the window up to the give-up point at
        // t+40s = TTL minus one renewal interval — same shape as a persistent backend-unreachable
        // failure. Under the pre-fix code the very first attempt returns silently and the heartbeat
        // never runs again, so LeaseLost would never become true even after both advances.
        clock.Advance(RenewStep);
        await WaitUntilAsync(() => handle.Attempts >= 1, "the first attempt against the unrelated-cancellation handle");
        clock.Advance(RenewStep);
        await WaitUntilAsync(() => lease.LeaseLost,
            "an OperationCanceledException unrelated to the lease's own disposal token to still fail the lease closed once the window elapses");

        Assert.True(lease.Token.IsCancellationRequested);
    }

    /// <summary>Lock handle whose <see cref="ExtendAsync"/> always throws an OperationCanceledException
    /// unconnected to the token it is passed — modelling an unexpected cancellation source distinct
    /// from the lease's own <c>_stopHeartbeat</c> token.</summary>
    private sealed class ExtendThrowsUnrelatedOceHandle : ILockHandle
    {
        private int _attempts;

        public string Name => LockName;
        public DateTimeOffset AcquiredAt => default;
        public int Attempts => Volatile.Read(ref _attempts);

        public Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _attempts);
            throw new OperationCanceledException("simulated cancellation unrelated to the caller token");
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    // ── InProcessDistributedLock lease semantics (standalone mode) ─────────────────

    /// <summary>
    /// The in-process lock backs standalone deployments, and its handle must honour the same lease
    /// contract the Redis handle does: an extended lease survives past its original TTL and keeps
    /// contenders out.
    /// </summary>
    [Fact]
    public async Task InProcessLock_Extended_HoldsPastTtl()
    {
        var clock = TestTime.Frozen();
        var locks = new InProcessDistributedLock(clock);
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        Assert.NotNull(handle);

        for (int step = 0; step < 4; step++)
        {
            clock.Advance(RenewStep);
            Assert.True(await handle!.ExtendAsync(Ttl), "an extend by the current holder must succeed");
        }

        // 80s elapsed — past the original 60s TTL.
        Assert.Null(await locks.TryAcquireAsync(LockName, Ttl));

        await handle!.DisposeAsync();
        Assert.NotNull(await locks.TryAcquireAsync(LockName, Ttl));
    }

    /// <summary>
    /// The unrenewed twin: an in-process lease that is not extended lapses at its TTL, a second
    /// acquirer wins, and the lapsed holder's extend is refused rather than reporting success.
    /// </summary>
    [Fact]
    public async Task InProcessLock_NotExtended_LapsesAtTtl()
    {
        var clock = TestTime.Frozen();
        var locks = new InProcessDistributedLock(clock);
        var handle = await locks.TryAcquireAsync(LockName, Ttl);
        Assert.NotNull(handle);

        clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.NotNull(await locks.TryAcquireAsync(LockName, Ttl));
        Assert.False(await handle!.ExtendAsync(Ttl), "a lapsed holder must not report a successful renewal");
    }
}
