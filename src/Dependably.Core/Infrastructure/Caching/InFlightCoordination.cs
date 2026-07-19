using System.Collections.Concurrent;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Shared single-flight in-flight-dictionary eviction helper for every
/// <c>ConcurrentDictionary&lt;string, Lazy&lt;Task&lt;TResult&gt;&gt;&gt;</c> coordinator in the
/// proxy paths (Go <c>@latest</c>, apk index, RPM repomd).
///
/// <see cref="ScheduleRemoval{TResult}"/> attaches a continuation that removes exactly the
/// <c>(key, lazy)</c> pair the caller registered once the shared work item genuinely completes —
/// success or failure — never when an individual caller's own <c>WaitAsync(ct)</c> merely detaches
/// early. A caller cancelling mid-fetch must not evict a live in-flight entry while the shared
/// work item is still running for the remaining waiters, and the pair-targeted removal never
/// touches a newer generation that replaced this entry. Every concurrent caller may attach its
/// own continuation to the same Task; <c>TryRemove</c> is idempotent — only the first
/// continuation to run has any effect. An unconditional <c>TryRemove(key, out _)</c> in each
/// caller's <c>finally</c> is the ABA bug this guards against: it removes whatever Lazy currently
/// occupies the key, including a newer generation started by a concurrent caller after this one
/// detached early.
/// </summary>
public static class InFlightCoordination
{
    public static void ScheduleRemoval<TResult>(
        ConcurrentDictionary<string, Lazy<Task<TResult>>> dict, string key, Lazy<Task<TResult>> lazy)
    {
        lazy.Value.ContinueWith(
            _ => dict.TryRemove(new KeyValuePair<string, Lazy<Task<TResult>>>(key, lazy)),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}
