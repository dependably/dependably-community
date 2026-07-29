namespace Dependably.Infrastructure.Redis;

/// <summary>
/// Keeps a held <see cref="ILockHandle"/> alive for the duration of a long-running pass and
/// aborts that pass the moment the lease can no longer be confirmed.
///
/// <para>A leader lock is acquired with a finite TTL. Without renewal, a pass that outlives its
/// TTL keeps running while the lock lapses, so the next replica to tick acquires the same lock
/// and starts a concurrent second pass over the same destructive work (blob reconciliation,
/// tenant hard delete, retention deletes). The lease closes that window from both ends: a
/// heartbeat extends the TTL <see cref="RenewalsPerTtl"/> times per window so the lock never
/// lapses under a running holder, and <see cref="Token"/> is cancelled as soon as renewal fails,
/// so a holder that has genuinely lost the lock stops working instead of operating unleased.</para>
///
/// <para>Renewal failures are graded. A definitive "you no longer hold this lock" (an
/// <see cref="ILockHandle.ExtendAsync"/> returning false — the key expired or was taken) loses
/// the lease immediately. A lock-backend exception (a Redis connection blip or failover) is
/// retried inside the remaining lease window, and becomes a lost lease one renewal interval
/// *before* the lock would expire — an unconfirmed lease is treated as lost, never as held, and
/// the margin covers both the recorded deadline being later than the backend's real expiry and
/// the time the guarded work needs to observe its cancellation.</para>
///
/// <para>The caller owns the abort: it must pass <see cref="Token"/> into the work and honor
/// cancellation. <see cref="LeaseLost"/> distinguishes a lease abort from ordinary host
/// shutdown so the two are logged, and handled, differently.</para>
///
/// <para>Disposing the lease stops the heartbeat and then disposes the underlying handle, so
/// the lock is released exactly once, by the lease.</para>
/// </summary>
public sealed class LeaderLease : IAsyncDisposable
{
    /// <summary>
    /// Renewal attempts per TTL window. Three gives a spare attempt inside a window, so a single
    /// transient lock-backend failure never costs the lease.
    /// </summary>
    private const int RenewalsPerTtl = 3;

    /// <summary>Floor on the renewal interval, so a very short TTL cannot produce a hot loop.</summary>
    private static readonly TimeSpan MinRenewInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Floor on the renewal margin — the safety buffer given up ahead of the recorded expiry (see
    /// <see cref="_renewMargin"/>). The margin exists to absorb a blocked
    /// <see cref="ILockHandle.ExtendAsync"/> call; StackExchange.Redis's command timeout is the
    /// worst case for how long that can block (~5s), so a margin under that could still have the
    /// lease believing it holds a lock the backend has already expired mid-extend. The margin is
    /// normally <c>TTL / RenewalsPerTtl</c>, which only clears this floor because every call site
    /// today uses a 5-minute TTL; a shorter <see cref="ScheduledBackgroundService.LeaderLockTtl"/>
    /// override would otherwise thin the margin below command-timeout safety with nothing to stop
    /// it. <see cref="MinRenewInterval"/> floors the renewal cadence; this floors the margin itself.
    /// </summary>
    private static readonly TimeSpan MinRenewMargin = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Minimum TTL <see cref="Start"/> accepts. Below <see cref="MinRenewMargin"/> floored at twice
    /// itself, the floor would consume most or all of the renewal window, leaving the guarded work
    /// no realistic chance to land a renewal before the lease gives itself up — and unlike the
    /// margin, a TTL this short cannot be silently corrected after the fact: the backend lock was
    /// already acquired with it before <see cref="Start"/> ever runs. A TTL below this floor is
    /// rejected outright rather than run as a lease that is effectively always mid-loss.
    /// </summary>
    private static readonly TimeSpan MinSafeTtl = TimeSpan.FromTicks(MinRenewMargin.Ticks * 2);

    private readonly ILockHandle _handle;
    private readonly TimeSpan _ttl;
    private readonly TimeSpan _renewInterval;
    private readonly TimeSpan _renewMargin;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _abort;
    private readonly CancellationTokenSource _stopHeartbeat = new();
    private readonly Task _heartbeat;

    private DateTimeOffset _expiresAt;
    private int _leaseLost;
    private bool _disposed;

    /// <summary>
    /// Starts a renewal heartbeat over an already-acquired <paramref name="handle"/>.
    /// </summary>
    /// <param name="handle">The acquired lock handle. The lease takes ownership and disposes it.</param>
    /// <param name="ttl">The TTL the handle was acquired with; each renewal extends by this much.</param>
    /// <param name="time">Injected clock driving both the renewal interval and the expiry deadline.</param>
    /// <param name="logger">Logger for renewal-failure and lease-loss reporting.</param>
    /// <param name="ct">Caller token; <see cref="Token"/> is linked to it.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="ttl"/> is below <see cref="MinSafeTtl"/>. The backend lock is acquired with
    /// <paramref name="ttl"/> before this is called, so there is no safe way to correct an
    /// undersized TTL after the fact — the caller must acquire with a longer TTL instead.
    /// </exception>
    public static LeaderLease Start(
        ILockHandle handle, TimeSpan ttl, TimeProvider time, ILogger logger, CancellationToken ct) =>
        new(handle, ttl, time, logger, ct);

    private LeaderLease(ILockHandle handle, TimeSpan ttl, TimeProvider time, ILogger logger, CancellationToken ct)
    {
        if (ttl < MinSafeTtl)
        {
            throw new ArgumentOutOfRangeException(nameof(ttl), ttl,
                $"Leader lock TTL must be at least {MinSafeTtl} (got {ttl}). A shorter TTL leaves "
                + $"no safe renewal margin above the ~5s StackExchange.Redis command timeout, and "
                + "the backend lock is already acquired with this TTL before the lease can correct "
                + "it. Increase the TTL passed to both the paired TryAcquireAsync call and "
                + "LeaderLease.Start — the 5-minute default used by every built-in call site "
                + "(ScheduledBackgroundService.LeaderLockTtl and its overrides) is comfortably "
                + "above this floor.");
        }

        _handle = handle;
        _ttl = ttl;
        _time = time;
        _logger = logger;
        _abort = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var interval = ttl / RenewalsPerTtl;
        _renewInterval = interval < MinRenewInterval ? MinRenewInterval : interval;
        // Safety margin ahead of the real expiry. The recorded deadline is set *after* a renewal
        // round-trip returns, so it is always at or later than the instant the backend key
        // actually expires; giving up only once it has fully elapsed would leave a window where
        // this instance still believes it holds a lock the backend has already released — and the
        // guarded work needs time to observe its cancellation on top of that. Give up one renewal
        // interval early instead — a third of the TTL — floored at MinRenewMargin so a short TTL
        // cannot thin this below the worst-case blocked ExtendAsync call.
        _renewMargin = interval < MinRenewMargin ? MinRenewMargin : interval;
        _expiresAt = time.GetUtcNow() + ttl;
        _heartbeat = HeartbeatAsync(_stopHeartbeat.Token);
    }

    /// <summary>
    /// Cancelled when the lease is lost, or when the caller's own token is cancelled. The work
    /// this lease guards runs under this token.
    /// </summary>
    public CancellationToken Token => _abort.Token;

    /// <summary>Name of the lock this lease is renewing.</summary>
    public string Name => _handle.Name;

    /// <summary>
    /// True once the lock is confirmed lost (or unconfirmable for a whole TTL window). Lets the
    /// caller tell a lease abort apart from a host-shutdown cancellation.
    /// </summary>
    public bool LeaseLost => Volatile.Read(ref _leaseLost) == 1;

    // Wraps the renewal loop so the heartbeat task can never fault. A faulted heartbeat would be
    // observed only at disposal, which every call site invokes from a finally block — the fault
    // would escape there, skip the lock release, and (from a BackgroundService) take the replica
    // down. An unexpected failure also means renewal has stopped, so it fails the lease closed.
    private async Task HeartbeatAsync(CancellationToken ct)
    {
        try
        {
            await RenewUntilStoppedAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The lease is being disposed; the pass owns its own shutdown from here.
        }
        catch (Exception ex)
        {
            // Reached either for a genuine unexpected exception, or for an OperationCanceledException
            // that did not originate from _stopHeartbeat (the only token this heartbeat honours) —
            // RenewUntilStoppedAsync's own catches carry the matching `when` guard for the same
            // reason. Either way, renewal did not confirm the lease is still held: fail closed
            // rather than let an unrecognized cancellation silently stop the heartbeat unconfirmed.
            _logger.LogError(ex,
                "Leader lock {LockName} renewal heartbeat stopped unexpectedly; treating the lease as lost.",
                _handle.Name);
            LoseLease("the renewal heartbeat stopped unexpectedly");
        }
    }

    private async Task RenewUntilStoppedAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            // Give up a margin ahead of the recorded expiry rather than at it — see _renewMargin.
            var remaining = _expiresAt - _renewMargin - _time.GetUtcNow();
            if (remaining <= TimeSpan.Zero)
            {
                LoseLease("the renewal window elapsed with no confirmed renewal");
                return;
            }

            try
            {
                await Task.Delay(remaining < _renewInterval ? remaining : _renewInterval, _time, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }

            bool extended;
            try
            {
                extended = await _handle.ExtendAsync(_ttl, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // The lock backend is unreachable, which is not the same signal as "someone else
                // holds this lock". Retry inside what is left of the current window; the
                // remaining-time check at the top of the loop is what fails the lease closed —
                // one renewal interval before the lock actually expires — if the window runs out.
                _logger.LogWarning(ex,
                    "Leader lock {LockName} renewal attempt failed; retrying inside the remaining lease window.",
                    _handle.Name);
                continue;
            }

            if (!extended)
            {
                LoseLease("the lock is no longer held by this instance");
                return;
            }

            _expiresAt = _time.GetUtcNow() + _ttl;
        }
    }

    private void LoseLease(string reason)
    {
        if (Interlocked.Exchange(ref _leaseLost, 1) == 1)
        {
            return;
        }

        _logger.LogWarning(
            "Leader lock {LockName} lease lost — {Reason}. Aborting the in-flight pass; another instance may already hold the lock.",
            _handle.Name, reason);

        try
        {
            _abort.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The lease was disposed concurrently; the pass is already finishing.
        }
        catch (Exception ex)
        {
            // Cancel collects exceptions thrown by registered cancellation callbacks and rethrows
            // them aggregated. The token is cancelled and every other callback has still run by
            // then, so the lease-lost signal is complete — a misbehaving callback must not stop
            // the heartbeat from reporting the loss it just recorded.
            _logger.LogWarning(ex,
                "Leader lock {LockName} lease-loss cancellation callback failed; the pass is still cancelled.",
                _handle.Name);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Every step is best-effort and ordered so the lock is always released: disposal runs
        // from a finally block at each call site, and an escaping exception there would both
        // strand the lock for a full TTL and, from a BackgroundService, fault the host.
        try
        {
            await _stopHeartbeat.CancelAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Leader lock {LockName} heartbeat stop failed.", _handle.Name);
        }

        try
        {
            await _heartbeat;
        }
        catch (OperationCanceledException)
        {
            // Expected when the heartbeat is stopped mid-delay.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Leader lock {LockName} renewal heartbeat ended faulted.", _handle.Name);
        }

        try
        {
            await _handle.DisposeAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Leader lock {LockName} release failed; the lock lapses at its TTL instead.",
                _handle.Name);
        }

        _stopHeartbeat.Dispose();
        _abort.Dispose();
    }
}
