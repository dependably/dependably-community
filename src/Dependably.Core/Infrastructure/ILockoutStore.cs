namespace Dependably.Infrastructure;

/// <summary>
/// Abstraction over where lockout state lives.
/// Standalone: SQLite (login_attempts table). HA: Redis.
///
/// Failure contract: implementations let backend errors propagate — they never swallow a read
/// or write and report success. No caller catches them either, so an unavailable lockout store
/// surfaces as a 500. The invariant that holds across every call site is that none of them runs
/// after a session is issued, so no JWT is ever minted on a request whose lockout state could not
/// be read or written. Catching here — or in <c>LoginService</c> — would convert an outage into
/// silent unlimited password guessing, which is the one direction this path must not fail in.
///
/// What the 500 means differs by caller, and only the login paths abort cleanly:
/// <list type="bullet">
/// <item><description><c>LoginService</c> (both realms, both factors) calls into this store
/// before the credential check and before session issuance, so a failure aborts the attempt with
/// nothing committed.</description></item>
/// <item><description><c>AuthController.ResetPassword</c> calls <see cref="ClearAsync"/> after
/// the new password is committed and the single-use reset token is consumed. A failure there
/// returns 500 for a reset that actually succeeded: the password is changed, the link is spent
/// (a retry gets 410 Gone), and the stale failed-attempt counter survives until its own
/// expiry — so a user who was locked out stays locked out until the window elapses. No session is
/// issued on that endpoint at all, so the JWT invariant is unaffected.</description></item>
/// </list>
/// </summary>
public interface ILockoutStore
{
    /// <summary>Returns current failed count and lockout expiry (or null if not locked).</summary>
    Task<(int FailedCount, DateTimeOffset? LockedUntil)> GetAsync(string emailHash, CancellationToken ct);

    /// <summary>
    /// Atomically increments the failure counter and, in the same operation, locks the account
    /// once <paramref name="maxFailedAttempts"/> is reached. The increment is computed by the
    /// store itself rather than by the caller: two concurrent callers racing a read-then-write
    /// increment computed in application code can both observe the same pre-failure count and
    /// both write back the same post-failure value, silently losing one of the two failures. An
    /// implementation must guarantee that N concurrent calls for the same <paramref name="emailHash"/>
    /// always advance the counter by exactly N, and returns the authoritative post-increment count
    /// so the caller's lockout decision reflects the real value rather than one it computed from a
    /// stale read.
    /// </summary>
    Task<(int NewCount, DateTimeOffset? LockedUntil)> RecordFailureAsync(
        string emailHash, int maxFailedAttempts, TimeSpan lockoutDuration, CancellationToken ct);

    /// <summary>Clears the lockout state on successful login.</summary>
    Task ClearAsync(string emailHash, CancellationToken ct);
}
