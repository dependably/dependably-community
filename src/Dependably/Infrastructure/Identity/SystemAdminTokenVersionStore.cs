using Dapper;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Reads <c>system_admins.token_version</c> for the JwtBearer <c>OnTokenValidated</c> check.
/// System-scope session JWTs snapshot the version at issuance (the <c>tver</c> claim) and are
/// rejected once the stored version moves on — the same password-change session-invalidation
/// mechanism that <see cref="UserTokenVersionStore"/> provides for tenant users.
///
/// Caching mirrors <see cref="UserTokenVersionStore"/>: the version is stable between password
/// changes, so hits are cached for 60 seconds. A password change bumps the version and calls
/// <see cref="Invalidate"/>, so the bumping node invalidates immediately; other nodes converge
/// within one TTL.
/// </summary>
internal sealed class SystemAdminTokenVersionStore
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;

    public SystemAdminTokenVersionStore(IMetadataStore db, IMemoryCache? cache = null)
    {
        _db = db;
        _cache = cache;
    }

    private static string CacheKey(string adminId) => $"sysadmin-token-version:{adminId}";

    /// <summary>
    /// Returns the system_admin's current token version, or null when the row no longer
    /// exists. A null result causes the caller to fail the session.
    /// </summary>
    public async Task<long?> GetCurrentVersionAsync(string adminId, CancellationToken ct = default)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey(adminId), out long cached))
        {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        long? version = await conn.ExecuteScalarAsync<long?>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });

        if (version is not null)
        {
            _cache?.Set(CacheKey(adminId), version.Value, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheTtl,
                Size = 1,
            });
        }

        return version;
    }

    /// <summary>Evicts the cached version so the next request re-reads the bumped value.</summary>
    public void Invalidate(string adminId) => _cache?.Remove(CacheKey(adminId));
}
