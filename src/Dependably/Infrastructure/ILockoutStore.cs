namespace Dependably.Infrastructure;

/// <summary>
/// Abstraction over where lockout state lives.
/// Standalone: SQLite (login_attempts table). HA: Redis.
/// </summary>
public interface ILockoutStore
{
    /// <summary>Returns current failed count and lockout expiry (or null if not locked).</summary>
    Task<(int FailedCount, DateTimeOffset? LockedUntil)> GetAsync(string emailHash, CancellationToken ct);

    /// <summary>Records a failed attempt, locking the account if the threshold is reached.</summary>
    Task RecordFailureAsync(string emailHash, int newCount, DateTimeOffset? lockedUntil, CancellationToken ct);

    /// <summary>Clears the lockout state on successful login.</summary>
    Task ClearAsync(string emailHash, CancellationToken ct);
}
