using System.Collections.Concurrent;
using Dapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolver for <c>DEPLOYMENT_MODE=multi</c> deployments. Reads <c>Request.Host</c> (already
/// rewritten from <c>X-Forwarded-Host</c> by <c>ForwardedHeadersMiddleware</c> when the request
/// arrives from a trusted proxy), strips the apex suffix, and looks up the tenant by slug.
///
/// Apex hits (host == apex) → <see cref="TenantContext.Apex"/>.
/// Subdomain hits with a known, non-reserved slug → <see cref="TenantContext.ForTenant"/>.
/// Anything else → <see cref="TenantContext.Uninitialized"/> (translated to 404 by the middleware).
/// </summary>
/// <summary>
/// Eviction hook for the subdomain tenant cache. Implemented by
/// <see cref="SubdomainTenantResolver"/> and consumed by tenant-lifecycle endpoints in
/// <c>SystemController</c> (soft-delete / restore / status / hard-delete) so the subdomain
/// reflects the new state immediately. Optional so single-tenant deployments — where the
/// concrete resolver isn't registered — compile against the same controller.
/// </summary>
public interface ITenantSlugCacheInvalidator
{
    void InvalidateSlug(string slug);
}

public sealed class SubdomainTenantResolver : ITenantResolver, ITenantSlugCacheInvalidator
{
    // 5-second sliding TTL on slug → (tenant id, slug) lookups. Short enough that
    // restoring a soft-deleted tenant or creating a new one becomes visible within a
    // single CI batch's lifespan; long enough to amortise the DB lookup across the burst
    // of requests a single `npm install` / `pip install` produces against one subdomain.
    private static readonly TimeSpan TenantCacheTtl = TimeSpan.FromSeconds(5);

    private readonly IMetadataStore _db;
    private readonly string _apexHost;
    private readonly IReadOnlySet<string> _extraReserved;
    private readonly IMemoryCache? _cache;

    // Per-slug generation token. A fill captures the token before its DB read and binds the
    // cache entry to it; InvalidateSlug cancels-and-replaces the token so an in-flight fill that
    // read the pre-lifecycle-change row cannot persist it past the eviction.
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _fillGuards =
        new(StringComparer.Ordinal);

    public SubdomainTenantResolver(IMetadataStore db, IConfiguration config, IMemoryCache? cache = null)
    {
        _db = db;
        _cache = cache;

        // Apex hostname is derived exclusively from BASE_URL (host portion only).
        string? apex = BaseUrlHostHelper.ExtractHost(config["BASE_URL"]);

        _apexHost = (apex ?? "")
            .TrimEnd('.');

        _extraReserved = ReservedSlugs.ParseExtra(config["RESERVED_SUBDOMAINS"]);
    }

    private static string CacheKey(string slug) => "tenant-resolve:" + slug;

    private CancellationTokenSource GuardFor(string slug) =>
        _fillGuards.GetOrAdd(slug, static _ => new CancellationTokenSource());

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _fillGuards.Count;

    /// <summary>
    /// Evicts the cached resolution for <paramref name="slug"/> and cancels the current
    /// generation token so an in-flight fill that read the pre-lifecycle-change row cannot cache
    /// it. Called by tenant-lifecycle endpoints (soft-delete, restore, status flip, hard-delete)
    /// so the subdomain reflects the new state immediately instead of waiting up to
    /// <see cref="TenantCacheTtl"/>.
    /// </summary>
    public void InvalidateSlug(string slug)
    {
        if (_cache is null)
        {
            return;
        }

        _cache.Remove(CacheKey(slug));
        if (_fillGuards.TryRemove(slug, out var retired))
        {
            retired.Cancel();
        }
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_apexHost))
        {
            return TenantContext.Uninitialized;
        }

        // Request.Host is authoritative here: ForwardedHeadersMiddleware (registered before this
        // middleware in the pipeline) rewrites Request.Host from X-Forwarded-Host only when the
        // immediate peer IP appears in the TRUSTED_PROXIES allowlist. Raw X-Forwarded-Host is
        // intentionally not read — reading it directly would let any client spoof the tenant
        // context regardless of TRUSTED_PROXIES.
        string rawHost = context.Request.Host.Value ?? string.Empty;
        if (string.IsNullOrEmpty(rawHost))
        {
            return TenantContext.Uninitialized;
        }

        // Strip port and trailing dot, lowercase.
        string host = rawHost.ToLowerInvariant().TrimEnd('.');
        int colonIdx = host.IndexOf(':');
        if (colonIdx >= 0)
        {
            host = host[..colonIdx];
        }

        if (host == _apexHost)
        {
            return TenantContext.Apex;
        }

        string suffix = "." + _apexHost;
        if (!host.EndsWith(suffix, StringComparison.Ordinal))
        {
            return TenantContext.Uninitialized;
        }

        string rawSlug = host[..^suffix.Length];

        // Reject sub-subdomains (e.g. foo.bar.apex) — only single-label slugs are tenants.
        if (rawSlug.Contains('.', StringComparison.Ordinal))
        {
            return TenantContext.Uninitialized;
        }

        string? slug = ReservedSlugs.Normalize(rawSlug, _extraReserved);
        if (slug is null)
        {
            return TenantContext.Uninitialized;
        }

        // Cache: slug → resolved tenant context. Short TTL keeps the resolver hot for
        // CI fan-out without leaving tenant lifecycle changes invisible. Negative results
        // (slug present in URL but not in DB) get the same TTL so a missing tenant doesn't
        // cause a DB lookup per request either.
        string cacheKey = CacheKey(slug);
        if (_cache is not null && _cache.TryGetValue(cacheKey, out TenantContext? cached) && cached is not null)
        {
            return cached;
        }

        // Snapshot the generation source BEFORE the read. A concurrent InvalidateSlug cancels this
        // source (and installs a fresh one), so a fill that raced a lifecycle change binds an
        // already-cancelled expiration token and never persists the stale context.
        var guardSource = _cache is null ? null : GuardFor(slug);

        await using var conn = await _db.OpenAsync(ct);
        // Soft-deleted tenants are immediately inaccessible — the subdomain returns 404 until
        // system_admin restores within the grace window.
        var (Id, Slug) = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug)>(
            "SELECT id, slug FROM orgs WHERE slug = @slug AND deleted_at IS NULL LIMIT 1",
            new { slug });

        var result = Id is null
            ? TenantContext.Uninitialized
            : TenantContext.ForTenant(Id, Slug);

        if (_cache is not null)
        {
            var options = new MemoryCacheEntryOptions
            {
                SlidingExpiration = TenantCacheTtl,
                // Absolute cap so a long-running hot subdomain still pays the DB lookup
                // periodically and picks up out-of-band changes (e.g. lifecycle status flips).
                AbsoluteExpirationRelativeToNow = TenantCacheTtl,
                Size = 1,
            };
            // If the guard was cancelled by a concurrent InvalidateSlug the entry is expired on
            // insert; if cancellation lands after the insert the callback evicts it.
            options.AddExpirationToken(new CancellationChangeToken(guardSource!.Token));
            // Tie the generation's lifetime to this entry. This path is reachable pre-auth: a
            // never-existent slug caches Uninitialized and mints a guard InvalidateSlug never
            // clears, so without this an unauthenticated client could grow the map without bound.
            CacheFillGuard.TieToEntryLifetime(options, _fillGuards, slug, guardSource!);
            _cache.Set(cacheKey, result, options);
        }

        return result;
    }
}
