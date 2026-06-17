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

    public async Task RecordFailureAsync(
        string emailHash, int newCount, DateTimeOffset? lockedUntil, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? locked = lockedUntil?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(
            """
            INSERT INTO login_attempts (email_hash, failed_count, locked_until)
            VALUES (@hash, @count, @locked)
            ON CONFLICT(email_hash) DO UPDATE SET
                failed_count = @count,
                locked_until = @locked,
                last_attempt = @now
            """,
            new { hash = emailHash, count = newCount, locked, now });
    }

    public async Task ClearAsync(string emailHash, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(
            """
            INSERT INTO login_attempts (email_hash, failed_count, locked_until) VALUES (@hash, 0, NULL)
            ON CONFLICT(email_hash) DO UPDATE SET failed_count = 0, locked_until = NULL, last_attempt = @now
            """,
            new { hash = emailHash, now });
    }
}
