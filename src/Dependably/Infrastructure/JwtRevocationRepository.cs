using Dapper;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure;

/// <summary>
/// Stores and checks revoked JWT IDs (jti claims).
/// Used to support pre-expiry session invalidation on logout.
///
/// Index: <c>jti</c> is the table's PRIMARY KEY, which SQLite and Postgres back with a
/// unique index automatically — the lookup in <see cref="IsRevokedAsync"/> is therefore
/// already an index search (verified by <c>JwtRevocationIndexPlanTests</c>). No separate
/// <c>idx_jwt_revocations_jti</c> is needed.
///
/// Negative-result cache: every JWT-authenticated request hits <see cref="IsRevokedAsync"/>;
/// in steady state the answer is "false". We cache that for <see cref="NegativeCacheTtl"/>
/// so warm JWT validation skips the DB round-trip. <see cref="RevokeAsync"/> evicts the
/// entry so logout takes effect within one TTL.
/// </summary>
public sealed class JwtRevocationRepository
{
    private static readonly TimeSpan NegativeCacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;

    public JwtRevocationRepository(IMetadataStore db, IMemoryCache? cache = null)
    {
        _db = db;
        _cache = cache;
    }

    private static string CacheKey(string jti) => $"jwt-revocation:{jti}";

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
        _cache?.Remove(CacheKey(jti));
    }

    public async Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey(jti), out bool cached))
        {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM jwt_revocations WHERE jti = @jti AND expires_at > @now",
            new { jti, now });
        bool revoked = count > 0;

        // Only cache the negative answer. A positive (revoked) result is rare and
        // persistent — no need to cache it; let the DB carry the truth.
        if (!revoked)
        {
            _cache?.Set(CacheKey(jti), false, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = NegativeCacheTtl,
                Size = 1,
            });
        }

        return revoked;
    }

    /// <summary>Removes expired revocation entries (called by RetentionService GC pass).</summary>
    public async Task PruneExpiredAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync("DELETE FROM jwt_revocations WHERE expires_at <= @now", new { now });
    }
}
