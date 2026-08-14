using Dapper;

namespace Dependably.Infrastructure;

/// <summary>SQLite-backed lockout store — used in standalone mode.</summary>
public sealed class SqliteLockoutStore : ILockoutStore
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public SqliteLockoutStore(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    public async Task<(int FailedCount, DateTimeOffset? LockedUntil)> GetAsync(
        string emailHash, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (FailedCount, LockedUntil) = await conn.QuerySingleOrDefaultAsync<(int FailedCount, string? LockedUntil)>(
            "SELECT failed_count, locked_until FROM login_attempts WHERE email_hash = @hash",
            new { hash = emailHash });

        DateTimeOffset? lockedUntil = LockedUntil is not null
            ? DateTimeOffset.Parse(LockedUntil)
            : null;

        return (FailedCount, lockedUntil);
    }

    public async Task<(int NewCount, DateTimeOffset? LockedUntil)> RecordFailureAsync(
        string emailHash, int maxFailedAttempts, TimeSpan lockoutDuration, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = _time.GetUtcNow().ToUtcIso();
        string lockedIfTripped = _time.GetUtcNow().Add(lockoutDuration).ToUtcIso();

        // A single UPSERT so the increment and the threshold-and-lock decision commit as one
        // atomic statement: two concurrent failures for the same email_hash each see their own
        // distinct post-increment failed_count (the row serializes on write), so neither can
        // overwrite the other's increment the way a caller-computed absolute SET could.
        var (FailedCount, LockedUntil) = await conn.QuerySingleAsync<(int FailedCount, string? LockedUntil)>(
            """
            INSERT INTO login_attempts (email_hash, failed_count, locked_until, last_attempt)
            VALUES (@hash, 1, CASE WHEN 1 >= @maxAttempts THEN @lockedIfTripped ELSE NULL END, @now)
            ON CONFLICT(email_hash) DO UPDATE SET
                failed_count = login_attempts.failed_count + 1,
                locked_until = CASE WHEN login_attempts.failed_count + 1 >= @maxAttempts
                                    THEN @lockedIfTripped ELSE NULL END,
                last_attempt = @now
            RETURNING failed_count, locked_until
            """,
            new { hash = emailHash, maxAttempts = maxFailedAttempts, lockedIfTripped, now });

        DateTimeOffset? lockedUntil = LockedUntil is not null
            ? DateTimeOffset.Parse(LockedUntil)
            : null;

        return (FailedCount, lockedUntil);
    }

    public async Task ClearAsync(string emailHash, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = _time.GetUtcNow().ToUtcIso();
        await conn.ExecuteAsync(
            """
            INSERT INTO login_attempts (email_hash, failed_count, locked_until) VALUES (@hash, 0, NULL)
            ON CONFLICT(email_hash) DO UPDATE SET failed_count = 0, locked_until = NULL, last_attempt = @now
            """,
            new { hash = emailHash, now });
    }
}
