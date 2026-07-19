using System.Collections.Concurrent;
using Dapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

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
///
/// Fill and invalidation race: a lookup that reads the DB just before a concurrent version bump
/// commits would otherwise cache the pre-bump value <em>after</em> <see cref="Invalidate"/> has
/// already evicted the key, resurrecting the killed system-admin session for a full TTL. Each
/// fill captures a per-admin generation token before its read and binds the cache entry to that
/// token as an expiration trigger; <see cref="Invalidate"/> cancels the current token, so a fill
/// that raced the bump binds an already-cancelled token and its write is dropped (or immediately
/// evicted).
/// </summary>
public sealed class SystemAdminTokenVersionStore
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;

    // Per-admin generation token. A fill captures the token before its DB read and binds the
    // cache entry to it; Invalidate cancels-and-replaces the token so any in-flight fill that
    // read the stale version is prevented from persisting (or is immediately evicted).
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _fillGuards =
        new(StringComparer.Ordinal);

    public SystemAdminTokenVersionStore(IMetadataStore db, IMemoryCache? cache = null)
    {
        _db = db;
        _cache = cache;
    }

    private static string CacheKey(string adminId) => $"sysadmin-token-version:{adminId}";

    private CancellationTokenSource GuardFor(string adminId) =>
        _fillGuards.GetOrAdd(adminId, static _ => new CancellationTokenSource());

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _fillGuards.Count;

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

        // Snapshot the generation source BEFORE the read. A concurrent Invalidate cancels this
        // source (and installs a fresh one), so a fill that raced a version bump binds an
        // already-cancelled expiration token and never persists the stale value. Capturing the
        // CancellationToken struct (not the source) keeps this safe even if the source is later
        // cancelled or collected.
        var guardSource = _cache is null ? null : GuardFor(adminId);

        await using var conn = await _db.OpenAsync(ct);
        long? version = await conn.ExecuteScalarAsync<long?>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });

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
            // Tie the generation's lifetime to this entry so a naturally-expiring admin session
            // (which never calls Invalidate) does not leave its guard in the map forever.
            CacheFillGuard.TieToEntryLifetime(options, _fillGuards, adminId, guardSource);
            _cache.Set(CacheKey(adminId), version.Value, options);
        }
        else if (guardSource is not null)
        {
            // A missing system_admin row is never cached, so the generation minted before the read
            // is never tied to a cache entry. Retire the just-minted instance here so a removed
            // admin's id does not leave its guard in the map forever.
            CacheFillGuard.RetireUnbound(_fillGuards, adminId, guardSource);
        }

        return version;
    }

    /// <summary>
    /// Evicts the cached version so the next request re-reads the bumped value, and cancels the
    /// current generation token so an in-flight fill that read the pre-bump value cannot cache it.
    /// </summary>
    public void Invalidate(string adminId)
    {
        if (_cache is null)
        {
            return;
        }

        _cache.Remove(CacheKey(adminId));

        // Retire the current generation: remove it so the next fill mints a fresh (cacheable)
        // token, then cancel it so any in-flight fill bound to it is dropped or evicted. The
        // source is left undisposed on purpose — an in-flight fill may still read its Token
        // struct, and cancelled-then-collected is cheaper than guarding a dispose race.
        if (_fillGuards.TryRemove(adminId, out var retired))
        {
            retired.Cancel();
        }
    }
}
