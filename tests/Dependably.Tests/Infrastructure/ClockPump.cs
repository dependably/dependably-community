using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Drives a <see cref="FakeTimeProvider"/> forward while waiting for a background consumer
/// (a queue's read loop, a delivery retry chain) to reach an observable state.
///
/// Two independent bounds apply, and keeping them separate is the whole point of this helper.
/// <paramref name="maxAdvances"/> bounds how much <em>virtual</em> time is burned, so a runaway
/// retry loop cannot spin the fake clock forever. The timeout bounds how much <em>real</em> time
/// the wait is given, so a consumer that has simply not been scheduled yet — the normal state of
/// affairs on a loaded CI runner — still gets a chance to observe the virtual time it was already
/// handed. Using the advance count as the timeout conflates the two and makes every caller flaky
/// under load: the budget burns in under a second of wall time whether or not the consumer ever
/// ran.
/// </summary>
public static class ClockPump
{
    /// <summary>
    /// Real-time ceiling on a pump. Generous by design — these waits normally settle in
    /// milliseconds, so the only thing a long ceiling costs is how quickly a genuinely broken
    /// test reports, while a short one buys back flakiness under load.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Real time yielded between polls. Pure pacing — it no longer bounds the wait.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(5);

    public static Task UntilAsync(
        FakeTimeProvider clock,
        Func<bool> condition,
        TimeSpan step,
        int maxAdvances = 200,
        TimeSpan? timeout = null) =>
        UntilAsync(clock, () => Task.FromResult(condition()), step, maxAdvances, timeout);

    public static async Task UntilAsync(
        FakeTimeProvider clock,
        Func<Task<bool>> condition,
        TimeSpan step,
        int maxAdvances = 200,
        TimeSpan? timeout = null)
    {
        // now-ok: real-time deadline bounding a wait on a genuinely asynchronous background
        // consumer. The injected clock is the thing under test's control here, not the test's.
        var deadline = DateTimeOffset.UtcNow + (timeout ?? DefaultTimeout);
        int advances = 0;

        while (!await condition())
        {
            // now-ok: see above — same deadline read.
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    $"Condition never satisfied while pumping the fake clock " +
                    $"({advances} advance(s) of {step} applied, real-time budget exhausted).");
            }

            if (advances < maxAdvances)
            {
                clock.Advance(step);
                advances++;
            }

            await Task.Delay(PollInterval);
        }
    }
}
