using System.Collections.Concurrent;
using Dapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

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
///
/// Fill and revocation race: an <see cref="IsRevokedAsync"/> whose DB read runs just before a
/// concurrent <see cref="RevokeAsync"/> commits its INSERT would otherwise cache a stale
/// "not revoked" answer <em>after</em> <see cref="RevokeAsync"/> has already evicted the key,
/// resurrecting the logged-out token for a full TTL. Each fill captures a per-jti generation
/// token before its read and binds the negative cache entry to that token as an expiration
/// trigger; <see cref="RevokeAsync"/> cancels the current token, so a fill that raced the
/// revocation binds an already-cancelled token and its write is dropped (or immediately evicted).
/// </summary>
public sealed class JwtRevocationRepository
{
    private static readonly TimeSpan NegativeCacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;
    private readonly TimeProvider _time;

    // Per-jti generation token. A fill captures the token before its DB read and binds the
    // negative cache entry to it; RevokeAsync cancels-and-replaces the token so any in-flight
    // fill that read the pre-revocation state cannot persist its stale "not revoked" answer.
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _fillGuards =
        new(StringComparer.Ordinal);

    public JwtRevocationRepository(IMetadataStore db, IMemoryCache? cache = null, TimeProvider? time = null)
    {
        _db = db;
        _cache = cache;
        _time = time ?? TimeProvider.System;
    }

    private static string CacheKey(string jti) => $"jwt-revocation:{jti}";

    private CancellationTokenSource GuardFor(string jti) =>
        _fillGuards.GetOrAdd(jti, static _ => new CancellationTokenSource());

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _fillGuards.Count;

    public async Task RevokeAsync(string jti, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO jwt_revocations (jti, expires_at)
            VALUES (@jti, @expiresAt)
            ON CONFLICT DO NOTHING
            """,
            new { jti, expiresAt = expiresAt.ToUtcIso() });
        _cache?.Remove(CacheKey(jti));

        // Retire the current generation: remove it so the next fill mints a fresh (cacheable)
        // token, then cancel it so any in-flight fill bound to it is dropped or evicted. The
        // source is left undisposed on purpose — an in-flight fill may still read its Token
        // struct, and cancelled-then-collected is cheaper than guarding a dispose race.
        if (_fillGuards.TryRemove(jti, out var retired))
        {
            retired.Cancel();
        }
    }

    public async Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey(jti), out bool cached))
        {
            return cached;
        }

        // Snapshot the generation source BEFORE the read. A concurrent RevokeAsync cancels this
        // source (and installs a fresh one), so a fill that raced the INSERT binds an
        // already-cancelled expiration token and never persists the stale answer. Capturing the
        // CancellationToken struct (not the source) keeps this safe even if the source is later
        // cancelled or collected.
        var guardSource = _cache is null ? null : GuardFor(jti);

        await using var conn = await _db.OpenAsync(ct);
        string now = _time.GetUtcNow().ToUtcIso();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM jwt_revocations WHERE jti = @jti AND expires_at > @now",
            new { jti, now });
        bool revoked = count > 0;

        // Only cache the negative answer. A positive (revoked) result is rare and
        // persistent — no need to cache it; let the DB carry the truth.
        if (!revoked && _cache is not null)
        {
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = NegativeCacheTtl,
                Size = 1,
            };
            // If the guard was cancelled by a concurrent RevokeAsync the entry is expired on
            // insert; if cancellation lands after the insert the registered callback evicts it.
            options.AddExpirationToken(new CancellationChangeToken(guardSource!.Token));
            // Tie the generation's lifetime to this entry so a naturally-expiring jti (which never
            // calls RevokeAsync) does not leave its guard in the map forever.
            CacheFillGuard.TieToEntryLifetime(options, _fillGuards, jti, guardSource);
            _cache.Set(CacheKey(jti), false, options);
        }
        else if (guardSource is not null)
        {
            // Revoked (positive) results are never cached, so the generation minted before the read
            // is never tied to a cache entry. IsRevokedAsync runs on every JWT request, so a
            // repeatedly-presented logged-out token would otherwise leak one guard per distinct
            // revoked jti forever — retire the just-minted instance here.
            CacheFillGuard.RetireUnbound(_fillGuards, jti, guardSource);
        }

        return revoked;
    }

    /// <summary>Removes expired revocation entries (called by RetentionService GC pass).</summary>
    public async Task PruneExpiredAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = _time.GetUtcNow().ToUtcIso();
        await conn.ExecuteAsync("DELETE FROM jwt_revocations WHERE expires_at <= @now", new { now });
    }
}
