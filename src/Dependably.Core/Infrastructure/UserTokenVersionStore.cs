using System.Collections.Concurrent;
using Dapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

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
///
/// Fill and invalidation race: a lookup that reads the DB just before a concurrent version bump
/// commits would otherwise cache the pre-bump value <em>after</em> <see cref="Invalidate"/> has
/// already evicted the key, resurrecting the killed session for a full TTL. Each fill captures a
/// per-user generation token before its read and binds the cache entry to that token as an
/// expiration trigger; <see cref="Invalidate"/> cancels the current token, so a fill that raced
/// the bump binds an already-cancelled token and its write is dropped (or immediately evicted).
/// </summary>
public sealed class UserTokenVersionStore
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;

    // Per-user generation token. A fill captures the token before its DB read and binds the cache
    // entry to it; Invalidate cancels-and-replaces the token so any in-flight fill that read the
    // stale version is prevented from persisting (or is immediately evicted).
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _fillGuards =
        new(StringComparer.Ordinal);

    public UserTokenVersionStore(IMetadataStore db, IMemoryCache? cache = null)
    {
        _db = db;
        _cache = cache;
    }

    private static string CacheKey(string userId) => $"user-token-version:{userId}";

    private CancellationTokenSource GuardFor(string userId) =>
        _fillGuards.GetOrAdd(userId, static _ => new CancellationTokenSource());

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _fillGuards.Count;

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

        // Snapshot the generation source BEFORE the read. A concurrent Invalidate cancels this
        // source (and installs a fresh one), so a fill that raced a version bump binds an
        // already-cancelled expiration token and never persists the stale value. Capturing the
        // CancellationToken struct (not the source) keeps this safe even if the source is later
        // cancelled or collected.
        var guardSource = _cache is null ? null : GuardFor(userId);

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK from the validated JWT's subject claim — the session's own
        // user. Reading another tenant's row would require forging a signed token.
        long? version = await conn.ExecuteScalarAsync<long?>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });

        // Only cache the found case. A missing row fails the session anyway, and not caching
        // it keeps a just-created user from being spuriously rejected for a TTL.
        if (version is not null && _cache is not null)
        {
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheTtl,
                Size = 1,
            };
            // If the guard was cancelled by a concurrent Invalidate the entry is expired on
            // insert; if cancellation lands after the insert the registered callback evicts it.
            options.AddExpirationToken(new CancellationChangeToken(guardSource!.Token));
            // Tie the generation's lifetime to this entry so a naturally-expiring user session
            // (which never calls Invalidate) does not leave its guard in the map forever.
            CacheFillGuard.TieToEntryLifetime(options, _fillGuards, userId, guardSource);
            _cache.Set(CacheKey(userId), version.Value, options);
        }
        else if (guardSource is not null)
        {
            // A missing user row is never cached, so the generation minted before the read is never
            // tied to a cache entry. Retire the just-minted instance here so a deleted user's id
            // does not leave its guard in the map forever.
            CacheFillGuard.RetireUnbound(_fillGuards, userId, guardSource);
        }

        return version;
    }

    /// <summary>
    /// Evicts the cached version so the next request re-reads the bumped value, and cancels the
    /// current generation token so an in-flight fill that read the pre-bump value cannot cache it.
    /// </summary>
    public void Invalidate(string userId)
    {
        if (_cache is null)
        {
            return;
        }

        _cache.Remove(CacheKey(userId));

        // Retire the current generation: remove it so the next fill mints a fresh (cacheable)
        // token, then cancel it so any in-flight fill bound to it is dropped or evicted. The
        // source is left undisposed on purpose — an in-flight fill may still read its Token
        // struct, and cancelled-then-collected is cheaper than guarding a dispose race.
        if (_fillGuards.TryRemove(userId, out var retired))
        {
            retired.Cancel();
        }
    }
}
