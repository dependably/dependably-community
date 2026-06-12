using Dapper;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure;

/// <summary>
/// Reads <c>users.token_version</c> for the JwtBearer <c>OnTokenValidated</c> check: tenant
/// session JWTs snapshot the version at issuance (the <c>tver</c> claim) and are rejected once
/// the stored version moves on — the password-change session-invalidation mechanism.
///
/// Caching mirrors <see cref="JwtRevocationRepository"/>: every JWT-authenticated request hits
/// this lookup, and in steady state the version is unchanged, so the value is cached for
/// <see cref="CacheTtl"/>. A password change bumps the version and calls
/// <see cref="Invalidate"/>, so on the bumping node stale sessions die immediately; other nodes
/// converge within one TTL.
/// </summary>
public sealed class UserTokenVersionStore
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;

    public UserTokenVersionStore(IMetadataStore db, IMemoryCache? cache = null)
    {
        _db = db;
        _cache = cache;
    }

    private static string CacheKey(string userId) => $"user-token-version:{userId}";

    /// <summary>
    /// Returns the user's current token version, or null when the user row no longer exists
    /// (the caller fails the session — a tenant JWT must reference a live user).
    /// </summary>
    public async Task<long?> GetCurrentVersionAsync(string userId, CancellationToken ct = default)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey(userId), out long cached))
        {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        long? version = await conn.ExecuteScalarAsync<long?>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });

        // Only cache the found case. A missing row fails the session anyway, and not caching
        // it keeps a just-created user from being spuriously rejected for a TTL.
        if (version is not null)
        {
            _cache?.Set(CacheKey(userId), version.Value, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheTtl,
                Size = 1,
            });
        }

        return version;
    }

    /// <summary>Evicts the cached version so the next request re-reads the bumped value.</summary>
    public void Invalidate(string userId) => _cache?.Remove(CacheKey(userId));
}
