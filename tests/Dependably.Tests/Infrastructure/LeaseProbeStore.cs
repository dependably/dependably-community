using System.Data.Common;
using Dependably.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Metadata-store decorator that turns one connection open into a "the pass is taking longer than
/// its lock TTL" probe, for jobs that hold a leader lock across a pass.
///
/// <para>On the Nth <see cref="OpenAsync"/> — chosen so it lands inside the pass, after the lock
/// has been acquired — it advances the fake clock past the lock TTL one renewal interval at a
/// time, waiting for each renewal attempt to land before the next step, then records whether a
/// second replica could acquire the same lock at that moment. Stepping and waiting is what keeps
/// the probe independent of thread-pool scheduling: the renewal heartbeat's continuation runs off
/// the clock-advancing thread, so a single large advance would race the lock's expiry.</para>
///
/// <para>The verdict is <em>recorded</em>, not asserted in place: these passes guard their
/// per-item work with catch-all handlers that would swallow an assertion failure thrown here and
/// turn a real regression into a green run. Tests assert on
/// <see cref="SecondAcquirerRefusedMidPass"/> after the pass returns.</para>
/// </summary>
public sealed class LeaseProbeStore : IMetadataStore
{
    // Renewals per TTL window, matching LeaderLease.
    private const int RenewalsPerTtl = 3;

    // Real-time safety bound for the renewal wait; a healthy heartbeat satisfies it immediately.
    private static readonly TimeSpan PollTimeout = TimeSpan.FromSeconds(10);

    private readonly IMetadataStore _inner;
    private readonly FakeTimeProvider _clock;
    private readonly LeasedTestLock _locks;
    private readonly string _lockName;
    private readonly TimeSpan _lockTtl;
    private readonly int _probeOnOpen;
    private readonly int _renewalSteps;
    private int _opens;

    /// <param name="inner">The real store every open is delegated to.</param>
    /// <param name="clock">The fake clock the job's lease renews on.</param>
    /// <param name="locks">The lock the job acquired its lease from.</param>
    /// <param name="lockName">Name of that lock, for the second-acquirer probe.</param>
    /// <param name="lockTtl">TTL the job acquires with; the probe advances past it.</param>
    /// <param name="probeOnOpen">1-based open number to probe on — pick one inside the pass.</param>
    /// <param name="renewalSteps">Renewal intervals to advance; the default carries the clock past the TTL.</param>
    public LeaseProbeStore(
        IMetadataStore inner,
        FakeTimeProvider clock,
        LeasedTestLock locks,
        string lockName,
        TimeSpan lockTtl,
        int probeOnOpen,
        int renewalSteps = RenewalsPerTtl + 1)
    {
        _inner = inner;
        _clock = clock;
        _locks = locks;
        _lockName = lockName;
        _lockTtl = lockTtl;
        _probeOnOpen = probeOnOpen;
        _renewalSteps = renewalSteps;
    }

    public DbProvider Provider => _inner.Provider;

    /// <summary>
    /// Null until the probe runs; then true when the lock was still held against a second
    /// acquirer at a point past its original TTL — i.e. the running pass renewed its lease.
    /// </summary>
    public bool? SecondAcquirerRefusedMidPass { get; private set; }

    /// <summary>Renewal intervals the probe advanced through.</summary>
    public int RenewalStepsAdvanced { get; private set; }

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        _opens++;
        if (_opens == _probeOnOpen)
        {
            var renewStep = _lockTtl / RenewalsPerTtl;
            for (int step = 1; step <= _renewalSteps; step++)
            {
                _clock.Advance(renewStep);
                var deadline = Task.Delay(PollTimeout, ct);
                while (_locks.ExtendAttempts < step && !deadline.IsCompleted)
                {
                    await Task.Delay(5, ct);
                }

                RenewalStepsAdvanced = step;
            }

            SecondAcquirerRefusedMidPass = await _locks.TryAcquireAsync(_lockName, _lockTtl, ct) is null;
        }

        return await _inner.OpenAsync(ct);
    }
}
