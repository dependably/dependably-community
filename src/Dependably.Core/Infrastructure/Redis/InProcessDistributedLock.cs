using System.Collections.Concurrent;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// In-process distributed lock fallback for standalone mode.
/// Backed by <see cref="SemaphoreSlim"/> per named lock.
/// Not safe across multiple replicas — standalone mode only.
/// </summary>
public sealed class InProcessDistributedLock : IDistributedLock
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly TimeProvider _time;

    public InProcessDistributedLock(TimeProvider time) => _time = time;

    public async Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
    {
        var sem = _locks.GetOrAdd(name, _ => new SemaphoreSlim(1, 1));
        bool acquired = await sem.WaitAsync(0, ct);
        return !acquired ? null : (ILockHandle)new LockHandle(name, sem, ttl, _time);
    }

    public async Task<ILockHandle> AcquireAsync(
        string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default)
    {
        var sem = _locks.GetOrAdd(name, _ => new SemaphoreSlim(1, 1));
        bool acquired = await sem.WaitAsync(wait, ct);
        return !acquired
            ? throw new TimeoutException($"Could not acquire in-process lock '{name}' within {wait}.")
            : (ILockHandle)new LockHandle(name, sem, ttl, _time);
    }

    private sealed class LockHandle : ILockHandle
    {
        private readonly SemaphoreSlim _sem;
        private readonly ITimer _expiry;
        private readonly object _gate = new();
        private bool _released;

        public string Name { get; }
        public DateTimeOffset AcquiredAt { get; }

        public LockHandle(string name, SemaphoreSlim sem, TimeSpan ttl, TimeProvider time)
        {
            Name = name;
            _sem = sem;
            AcquiredAt = time.GetUtcNow();
            // Auto-release after TTL if not explicitly disposed, on the injected clock so the
            // lease behaves the same way the Redis PX expiry does — a holder that stops renewing
            // loses the lock at its TTL.
            _expiry = time.CreateTimer(_ => Release(), null, ttl, Timeout.InfiniteTimeSpan);
        }

        public Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default)
        {
            lock (_gate)
            {
                if (_released)
                {
                    return Task.FromResult(false);
                }

                // Push the auto-release out, mirroring the Redis PEXPIRE renewal: a renewed lease
                // survives past its original TTL and keeps contending acquirers out.
                _expiry.Change(additional, Timeout.InfiniteTimeSpan);
                return Task.FromResult(true);
            }
        }

        public async ValueTask DisposeAsync()
        {
            Release();
            await _expiry.DisposeAsync();
        }

        private void Release()
        {
            lock (_gate)
            {
                if (_released)
                {
                    return;
                }

                _released = true;
            }

            try { _sem.Release(); } catch (SemaphoreFullException) { /* already released */ }
        }
    }
}
