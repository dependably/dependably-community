using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A real <see cref="MemoryCache"/> that reports each entry's eviction to the test after the code
/// under test has seen it. <c>MemoryCache</c> runs post-eviction callbacks on the thread pool, in
/// registration order, so an observer appended when the entry is committed runs after every
/// callback the code under test registered. Awaiting <see cref="WhenEvictedAsync"/> therefore
/// means those callbacks have finished, which lets a test assert on their effect without sleeping
/// or polling.
/// </summary>
internal sealed class EvictionObservingCache : IMemoryCache
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    private readonly List<(object Key, EvictionReason Reason)> _evictions = new();
    private readonly List<(Func<bool> Condition, TaskCompletionSource Done)> _waiters = new();
    private int _committed;

    /// <param name="time">Drives the cache's own expiry, so a short TTL cannot lapse mid-test.</param>
    public EvictionObservingCache(TimeProvider time)
    {
        Inner = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 8 * 1024 * 1024,
            Clock = new TimeProviderClock(time),
        });
    }

    /// <summary>The underlying cache, for <see cref="MemoryCache.Compact"/>.</summary>
    public MemoryCache Inner { get; }

    /// <summary>Completes once an entry under <paramref name="key"/> was evicted for <paramref name="reason"/>.</summary>
    public Task WhenEvictedAsync(object key, EvictionReason reason) =>
        WhenAsync(() => _evictions.Contains((key, reason)));

    /// <summary>Completes once every entry committed so far has been evicted.</summary>
    public Task WhenAllEvictedAsync() => WhenAsync(() => _evictions.Count == _committed);

    private Task WhenAsync(Func<bool> condition)
    {
        lock (_gate)
        {
            if (condition())
            {
                return Task.CompletedTask;
            }

            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _waiters.Add((condition, done));
            return done.Task.WaitAsync(Timeout);
        }
    }

    private void Observe(object key, EvictionReason reason)
    {
        lock (_gate)
        {
            _evictions.Add((key, reason));
            foreach (var waiter in _waiters.Where(w => w.Condition()).ToList())
            {
                _waiters.Remove(waiter);
                waiter.Done.SetResult();
            }
        }
    }

    public ICacheEntry CreateEntry(object key) => new ObservedEntry(Inner.CreateEntry(key), this);

    public void Remove(object key) => Inner.Remove(key);

    public bool TryGetValue(object key, out object? value) => Inner.TryGetValue(key, out value);

    public void Dispose() => Inner.Dispose();

    private sealed class ObservedEntry(ICacheEntry inner, EvictionObservingCache owner) : ICacheEntry
    {
        public object Key => inner.Key;

        public object? Value
        {
            get => inner.Value;
            set => inner.Value = value;
        }

        public DateTimeOffset? AbsoluteExpiration
        {
            get => inner.AbsoluteExpiration;
            set => inner.AbsoluteExpiration = value;
        }

        public TimeSpan? AbsoluteExpirationRelativeToNow
        {
            get => inner.AbsoluteExpirationRelativeToNow;
            set => inner.AbsoluteExpirationRelativeToNow = value;
        }

        public TimeSpan? SlidingExpiration
        {
            get => inner.SlidingExpiration;
            set => inner.SlidingExpiration = value;
        }

        public IList<IChangeToken> ExpirationTokens => inner.ExpirationTokens;

        public IList<PostEvictionCallbackRegistration> PostEvictionCallbacks => inner.PostEvictionCallbacks;

        public CacheItemPriority Priority
        {
            get => inner.Priority;
            set => inner.Priority = value;
        }

        public long? Size
        {
            get => inner.Size;
            set => inner.Size = value;
        }

        // Committing the entry: append the observer last, so it runs after the code under test's
        // own callbacks, then hand the entry to the cache.
        public void Dispose()
        {
            inner.RegisterPostEvictionCallback(
                static (key, _, reason, state) => ((EvictionObservingCache)state!).Observe(key, reason),
                owner);
            lock (owner._gate)
            {
                owner._committed++;
            }

            inner.Dispose();
        }
    }

    private sealed class TimeProviderClock(TimeProvider time) : Microsoft.Extensions.Internal.ISystemClock
    {
        public DateTimeOffset UtcNow => time.GetUtcNow();
    }
}
