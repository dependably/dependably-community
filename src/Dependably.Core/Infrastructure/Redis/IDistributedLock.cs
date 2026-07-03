namespace Dependably.Infrastructure.Redis;

public interface IDistributedLock
{
    /// <summary>
    /// Tries to acquire the named lock with the given TTL.
    /// Returns a handle on success, null if the lock is already held.
    /// </summary>
    Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>
    /// Acquires the named lock, polling with <paramref name="retryInterval"/> until <paramref name="wait"/> elapses.
    /// Throws <see cref="TimeoutException"/> if the lock cannot be acquired in time.
    /// </summary>
    Task<ILockHandle> AcquireAsync(string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default);
}

public interface ILockHandle : IAsyncDisposable
{
    string Name { get; }
    DateTimeOffset AcquiredAt { get; }

    /// <summary>
    /// Extends the lock TTL by <paramref name="additional"/> if the caller still owns the lock.
    /// Returns false if the lock has been stolen or expired.
    /// </summary>
    Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default);
}
