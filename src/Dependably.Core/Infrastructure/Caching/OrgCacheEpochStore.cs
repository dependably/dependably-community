using System.Collections.Concurrent;
using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Per-org policy-invalidation epoch for the rendered-metadata caches. A proxy-settings policy
/// change (block/verify gates, release-age and score thresholds) can flip the advertised state of
/// every version across every package a tenant has published or proxied — evicting one formatted
/// cache key at a time the way the publish/unpublish handlers do is infeasible because there is
/// no enumerable list of affected keys. Instead, every rendered cache entry for an org is bound
/// (via <see cref="GetToken"/>) to that org's current epoch as an
/// <see cref="Microsoft.Extensions.Caching.Memory.IMemoryCache"/> expiration trigger;
/// <see cref="Invalidate"/> cancels the epoch, expiring every bound entry for that org in one call
/// regardless of ecosystem or package name.
///
/// Mirrors <see cref="UserTokenVersionStore"/>'s per-key generation guard: a
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> of <see cref="CancellationTokenSource"/>,
/// retired-and-replaced on invalidation so entries already bound to the retired token expire
/// while new writes bind the fresh one.
/// </summary>
public sealed class OrgCacheEpochStore
{
    // Per-org generation token. GetToken hands out a change token bound to the org's current
    // source; Invalidate retires (removes-and-cancels) the source so every entry already bound to
    // it expires, and a subsequent GetToken mints a fresh (live) source for new writes.
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _epochs =
        new(StringComparer.Ordinal);

    private CancellationTokenSource GuardFor(string orgId) =>
        _epochs.GetOrAdd(orgId, static _ => new CancellationTokenSource());

    /// <summary>
    /// Returns an expiration token bound to <paramref name="orgId"/>'s current epoch. Add this to
    /// a <see cref="Microsoft.Extensions.Caching.Memory.MemoryCacheEntryOptions"/> so the entry
    /// expires the moment <see cref="Invalidate"/> is next called for this org.
    /// </summary>
    public IChangeToken GetToken(string orgId) => new CancellationChangeToken(GuardFor(orgId).Token);

    /// <summary>
    /// Cancels the org's current epoch — expiring every rendered-cache entry bound to it — and
    /// installs a fresh epoch for subsequent writes.
    /// </summary>
    public void Invalidate(string orgId)
    {
        // Remove-then-cancel (not cancel-in-place): a fresh GuardFor call racing this Invalidate
        // must never observe and bind to the token being retired. The source is left undisposed
        // on purpose — an in-flight Set may still read its Token struct, and cancelled-then-
        // collected is cheaper than guarding a dispose race.
        if (_epochs.TryRemove(orgId, out var retired))
        {
            retired.Cancel();
        }
    }
}
