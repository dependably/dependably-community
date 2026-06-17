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
        return !acquired ? null : (ILockHandle)new LockHandle(name, sem, ttl, _time.GetUtcNow());
    }

    public async Task<ILockHandle> AcquireAsync(
        string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default)
    {
        var sem = _locks.GetOrAdd(name, _ => new SemaphoreSlim(1, 1));
        bool acquired = await sem.WaitAsync(wait, ct);
        return !acquired
            ? throw new TimeoutException($"Could not acquire in-process lock '{name}' within {wait}.")
            : (ILockHandle)new LockHandle(name, sem, ttl, _time.GetUtcNow());
    }

    private sealed class LockHandle : ILockHandle
    {
        private readonly SemaphoreSlim _sem;
        private bool _released;

        public string Name { get; }
        public DateTimeOffset AcquiredAt { get; }

        public LockHandle(string name, SemaphoreSlim sem, TimeSpan ttl, DateTimeOffset acquiredAt)
        {
            Name = name;
            _sem = sem;
            AcquiredAt = acquiredAt;
            // Auto-release after TTL if not explicitly disposed.
            _ = Task.Delay(ttl).ContinueWith(_ => Release());
        }

        public Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default)
            => Task.FromResult(!_released); // In-process: always "succeeds" while held.

        public ValueTask DisposeAsync()
        {
            Release();
            return ValueTask.CompletedTask;
        }

        private void Release()
        {
            if (_released)
            {
                return;
            }

            _released = true;
            try { _sem.Release(); } catch { /* already released */ }
        }
    }
}
