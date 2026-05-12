using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Stores and checks revoked JWT IDs (jti claims).
/// Used to support pre-expiry session invalidation on logout.
/// </summary>
public sealed class JwtRevocationRepository
{
    private readonly IMetadataStore _db;

    public JwtRevocationRepository(IMetadataStore db) => _db = db;

    public async Task RevokeAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO jwt_revocations (jti, expires_at)
            VALUES (@jti, @expiresAt)
            ON CONFLICT DO NOTHING
            """,
            new { jti, expiresAt = expiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ") });
    }

    public async Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM jwt_revocations WHERE jti = @jti AND expires_at > @now",
            new { jti, now });
        return count > 0;
    }

    /// <summary>Removes expired revocation entries (called by RetentionService GC pass).</summary>
    public async Task PruneExpiredAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync("DELETE FROM jwt_revocations WHERE expires_at <= @now", new { now });
    }
}
