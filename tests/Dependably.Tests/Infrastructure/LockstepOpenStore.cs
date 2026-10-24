using System.Data.Common;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test seam that makes two concurrent callers advance through <see cref="OpenAsync"/> in
/// lockstep: a participant's <c>n</c>th open waits until its partner has reached its own
/// <c>n</c>th open, or has finished. Code that opens one connection per statement therefore runs
/// each statement of one caller alongside the matching statement of the other, which turns a
/// check-then-act race (both callers read, then both write) from a timing accident into the
/// guaranteed interleaving. Code that does its check and write on a single serialized connection
/// is unaffected beyond the rendezvous at that open.
///
/// Run each participant through <see cref="RunAsAsync{T}"/>; opens from any other flow pass
/// straight through. A participant that finishes releases its partner's remaining waits, so a
/// caller that opens fewer connections than the other cannot deadlock the pair.
/// </summary>
public sealed class LockstepOpenStore(IMetadataStore inner) : IMetadataStore
{
    // Upper bound on a single rendezvous. Reaching it means the pair deadlocked, which should fail
    // the test loudly rather than hang the run.
    private static readonly TimeSpan RendezvousTimeout = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    private readonly int[] _opens = new int[2];
    private readonly bool[] _done = new bool[2];
    private readonly AsyncLocal<int?> _participant = new();
    private TaskCompletionSource _changed = NewSignal();

    public DbProvider Provider => inner.Provider;

    /// <summary>Runs <paramref name="body"/> as participant 0 or 1 on its own thread-pool flow.</summary>
    public Task<T> RunAsAsync<T>(int participant, Func<Task<T>> body)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(participant);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(participant, 1);
        return Task.Run(async () =>
        {
            _participant.Value = participant;
            try
            {
                return await body();
            }
            finally
            {
                lock (_gate)
                {
                    _done[participant] = true;
                    SignalLocked();
                }
            }
        });
    }

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        if (_participant.Value is int me)
        {
            int partner = 1 - me;
            int mine;
            lock (_gate)
            {
                mine = ++_opens[me];
                SignalLocked();
            }

            while (true)
            {
                Task changed;
                lock (_gate)
                {
                    if (_opens[partner] >= mine || _done[partner])
                    {
                        break;
                    }

                    changed = _changed.Task;
                }

                // now-ok: a deadlock guard on a rendezvous between two real threads; the wait is
                // released by the partner's progress, never by the clock.
                await changed.WaitAsync(RendezvousTimeout, ct);
            }
        }

        return await inner.OpenAsync(ct);
    }

    private void SignalLocked()
    {
        var previous = _changed;
        _changed = NewSignal();
        previous.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
