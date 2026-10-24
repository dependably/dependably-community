using System.Threading.Channels;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A <see cref="FakeTimeProvider"/> that reports each timer the code under test arms on it, with
/// the timer's due time, so a test advances virtual time only when something is waiting for it.
///
/// A fake clock fires only the timers that exist when it is advanced. A test that advances and
/// then polls for the effect loses the advance whenever the loop under test has not yet reached
/// its next <c>Task.Delay</c> — and a loop that re-reads the clock after a slow step can then see
/// a deadline that has already passed. Waiting for the arming signal first removes both: the
/// advance always lands on a live timer, and the loop has finished reading the clock by the time
/// it arms the timer.
/// </summary>
public sealed class TimerSignallingClock(DateTimeOffset start) : FakeTimeProvider(start)
{
    private readonly Channel<TimeSpan> _armed = Channel.CreateUnbounded<TimeSpan>();

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = base.CreateTimer(callback, state, dueTime, period);
        _armed.Writer.TryWrite(dueTime);
        return timer;
    }

    /// <summary>
    /// Completes with the due time of the next timer armed on this clock. Timers armed before the
    /// call are queued, so one armed while the test was busy is not missed.
    /// </summary>
    public Task<TimeSpan> NextTimerArmedAsync() => _armed.Reader.ReadAsync().AsTask();
}
