namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Passively derives an edge node's reachability to its master from the outcome of upstream
/// fetches. Updated at the <c>UpstreamClient</c> fetch boundary — a successful upstream pull
/// (artifact or metadata) stamps <see cref="LastSuccessAtTicks"/>, a failed one stamps
/// <see cref="LastFailureAtTicks"/>; the coarse <see cref="State"/> reflects whichever happened
/// most recently. There is no active probing: the endpoint reads these already-known outcomes,
/// it never reaches out to the master itself.
///
/// <para>Timestamps are <see cref="TimeProvider"/>-stamped UTC ticks held in <c>long</c> fields
/// mutated with <see cref="Interlocked"/>, so concurrent fetch completions never corrupt a
/// value and the read path is lock-free. A single monotonically-increasing sequence orders
/// success-vs-failure without a lock: whichever recorded the higher sequence number is "most
/// recent", so the coarse state derivation stays correct even when two fetches complete
/// near-simultaneously.</para>
///
/// <para>Registered as a singleton in all deployment modes; the tracking calls are near-free
/// (two <see cref="Interlocked"/> writes), and the derived status is only ever exposed through
/// the edge-only <c>/edge/status</c> endpoint. Cache hit/miss counts are NOT held here — they
/// already live in <see cref="SnapshotCounters"/>, which the status endpoint reads directly.</para>
/// </summary>
public sealed class EdgeStatusTracker
{
    private readonly TimeProvider _time;

    // Ticks (UTC) of the last recorded success / failure; 0 means "never". A single
    // monotonic sequence disambiguates which of the two is the most recent outcome without
    // a lock — the higher sequence wins.
    private long _lastSuccessAtTicks;
    private long _lastFailureAtTicks;
    private long _lastSuccessSeq;
    private long _lastFailureSeq;
    private long _sequence;

    public EdgeStatusTracker(TimeProvider time) => _time = time;

    /// <summary>UTC ticks of the last successful upstream fetch; 0 when none has succeeded.</summary>
    public long LastSuccessAtTicks => Interlocked.Read(ref _lastSuccessAtTicks);

    /// <summary>UTC ticks of the last failed upstream fetch; 0 when none has failed.</summary>
    public long LastFailureAtTicks => Interlocked.Read(ref _lastFailureAtTicks);

    /// <summary>
    /// Records a successful upstream fetch, stamping "now" and marking it the most recent
    /// outcome. Near-free; safe to call from any fetch path in any mode.
    /// </summary>
    public void RecordSuccess()
    {
        long seq = Interlocked.Increment(ref _sequence);
        Interlocked.Exchange(ref _lastSuccessAtTicks, _time.GetUtcNow().UtcTicks);
        Interlocked.Exchange(ref _lastSuccessSeq, seq);
    }

    /// <summary>
    /// Records a failed upstream fetch, stamping "now" and marking it the most recent outcome.
    /// A "failure" is any upstream fetch that did not yield a usable response (network error,
    /// timeout, exhausted transient retries, 5xx, checksum mismatch). Client-driven cancellation
    /// is not a master-reachability signal and should not be recorded as a failure.
    /// </summary>
    public void RecordFailure()
    {
        long seq = Interlocked.Increment(ref _sequence);
        Interlocked.Exchange(ref _lastFailureAtTicks, _time.GetUtcNow().UtcTicks);
        Interlocked.Exchange(ref _lastFailureSeq, seq);
    }

    /// <summary>
    /// Coarse master-reachability state derived from the most recent outcome:
    ///   - <c>unknown</c> before any fetch has been attempted,
    ///   - <c>ok</c> when the most recent recorded outcome was a success,
    ///   - <c>degraded</c> when the most recent recorded outcome was a failure.
    /// </summary>
    public EdgeReachabilityState State
    {
        get
        {
            long successSeq = Interlocked.Read(ref _lastSuccessSeq);
            long failureSeq = Interlocked.Read(ref _lastFailureSeq);
            return successSeq == 0 && failureSeq == 0
                ? EdgeReachabilityState.Unknown
                : successSeq >= failureSeq
                    ? EdgeReachabilityState.Ok
                    : EdgeReachabilityState.Degraded;
        }
    }
}

/// <summary>Coarse master-reachability states surfaced by <see cref="EdgeStatusTracker.State"/>.</summary>
public enum EdgeReachabilityState
{
    /// <summary>No upstream fetch has been attempted yet.</summary>
    Unknown,

    /// <summary>The most recent upstream fetch succeeded.</summary>
    Ok,

    /// <summary>The most recent upstream fetch failed.</summary>
    Degraded,
}
