using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-org trust anchor abstraction. Provides a hot cache over
/// <see cref="TrustAnchorRepository"/> with a shared org-scoped invalidation hook.
/// Per-ecosystem typed accessors are added by each ecosystem migration; the generic
/// <see cref="ListAsync"/> and <see cref="IsConfiguredForAsync"/> surfaces are the
/// foundation-level interface.
/// </summary>
public interface IPerOrgTrustAnchorStore
{
    /// <summary>
    /// Returns true when at least one trust anchor is configured for the given
    /// (org, ecosystem) pair. Fail-closed: an org with no anchors cannot enable
    /// signature verification for that ecosystem.
    /// </summary>
    Task<bool> IsConfiguredForAsync(string orgId, string ecosystem, CancellationToken ct = default);

    /// <summary>
    /// Returns all trust anchor rows for the given (org, ecosystem), including the
    /// raw <c>material</c> text. Used by per-ecosystem verifiers at request time.
    /// </summary>
    Task<IReadOnlyList<TrustAnchorMaterial>> ListAsync(
        string orgId, string ecosystem, CancellationToken ct = default);

    /// <summary>
    /// Builds a <see cref="PgpPublicKeyRingBundle"/> from the org's RPM PGP trust anchors
    /// (<c>ecosystem='rpm', anchor_kind='pgp'</c>). Returns null when no anchors are configured
    /// or when all anchors fail to parse. Cached through the same hot cache as
    /// <see cref="ListAsync"/>; invalidated by <see cref="InvalidateTrustAnchorCache"/>.
    /// </summary>
    Task<PgpPublicKeyRingBundle?> GetRpmKeyRingAsync(string orgId, CancellationToken ct = default);

    /// <summary>
    /// Builds a <see cref="PgpPublicKeyRingBundle"/> from the org's Maven PGP trust anchors
    /// (<c>ecosystem='maven', anchor_kind='pgp'</c>). Returns null when no anchors are configured
    /// or when all anchors fail to parse. Cached through the same hot cache as
    /// <see cref="ListAsync"/>; invalidated by <see cref="InvalidateTrustAnchorCache"/>.
    /// </summary>
    Task<PgpPublicKeyRingBundle?> GetMavenKeyRingAsync(string orgId, CancellationToken ct = default);

    /// <summary>
    /// Builds a keyid-to-SPKI-bytes map from the org's npm SPKI trust anchors
    /// (<c>ecosystem='npm', anchor_kind='spki'</c>). Returns an empty dictionary when no
    /// anchors are configured or all anchors fail to parse. Cached through the same hot cache
    /// as <see cref="ListAsync"/>; invalidated by <see cref="InvalidateTrustAnchorCache"/>.
    /// </summary>
    Task<IReadOnlyDictionary<string, byte[]>> GetNpmKeysAsync(
        string orgId, CancellationToken ct = default);

    /// <summary>
    /// Builds an <see cref="X509Certificate2Collection"/> from the org's NuGet X.509 trust
    /// anchors (<c>ecosystem='nuget', anchor_kind='x509'</c>). Returns an empty collection
    /// when no anchors are configured or all anchors fail to parse. Cached through the same
    /// hot cache as <see cref="ListAsync"/>; invalidated by
    /// <see cref="InvalidateTrustAnchorCache"/>.
    /// </summary>
    Task<X509Certificate2Collection> GetNuGetAnchorsAsync(
        string orgId, CancellationToken ct = default);

    /// <summary>
    /// Builds a <see cref="Dependably.Protocol.Provenance.PyPiTrustMaterial"/> from the org's
    /// PyPI trust anchors (<c>ecosystem='pypi'</c>, three anchor kinds: <c>sigstore_root</c>,
    /// <c>trusted_publisher</c>, <c>rekor_key</c>). Returns
    /// <see cref="Dependably.Protocol.Provenance.PyPiTrustMaterial.Empty"/> when no anchors
    /// are configured or all fail to parse. Cached through the same hot cache as
    /// <see cref="ListAsync"/>; invalidated by <see cref="InvalidateTrustAnchorCache"/>.
    /// </summary>
    Task<Dependably.Protocol.Provenance.PyPiTrustMaterial> GetPyPiTrustAsync(
        string orgId, CancellationToken ct = default);

    /// <summary>
    /// Evicts the cached anchor list for <paramref name="orgId"/> so the next request
    /// re-reads from the database. Call after every add/delete mutation.
    /// </summary>
    void InvalidateTrustAnchorCache(string orgId);
}

/// <summary>
/// Production implementation of <see cref="IPerOrgTrustAnchorStore"/>. Wraps
/// <see cref="TrustAnchorRepository"/> with a per-org IMemoryCache keyed on
/// <c>trust-anchor:{orgId}</c>. Cache TTL is short (1 second sliding) so an
/// operator add/delete takes effect within one second on the verify path without
/// relying solely on explicit invalidation. Explicit invalidation is always called
/// after a mutation so the hot path stays accurate.
/// </summary>
public sealed class PerOrgTrustAnchorStore : IPerOrgTrustAnchorStore
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(1);

    private readonly TrustAnchorRepository _repo;
    private readonly IMemoryCache? _cache;
    private readonly ILogger<PerOrgTrustAnchorStore> _logger;

    public PerOrgTrustAnchorStore(
        TrustAnchorRepository repo,
        ILogger<PerOrgTrustAnchorStore> logger,
        IMemoryCache? cache = null)
    {
        _repo = repo;
        _logger = logger;
        _cache = cache;
    }

    private static string CacheKey(string orgId) => "trust-anchor:" + orgId;

    public void InvalidateTrustAnchorCache(string orgId)
        => _cache?.Remove(CacheKey(orgId));

    public async Task<bool> IsConfiguredForAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        var anchors = await GetCachedForOrgAsync(orgId, ct);
        return anchors.Any(a => string.Equals(a.Ecosystem, ecosystem, StringComparison.Ordinal));
    }

    public async Task<IReadOnlyList<TrustAnchorMaterial>> ListAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        var anchors = await GetCachedForOrgAsync(orgId, ct);
        return anchors
            .Where(a => string.Equals(a.Ecosystem, ecosystem, StringComparison.Ordinal))
            .Select(a => a.Material)
            .ToList();
    }

    public async Task<PgpPublicKeyRingBundle?> GetRpmKeyRingAsync(
        string orgId, CancellationToken ct = default)
        => await GetPgpKeyRingAsync(orgId, "rpm", ct);

    public async Task<PgpPublicKeyRingBundle?> GetMavenKeyRingAsync(
        string orgId, CancellationToken ct = default)
        => await GetPgpKeyRingAsync(orgId, "maven", ct);

    // Shared PGP key-ring builder: loads per-org anchors for the given ecosystem and
    // assembles them into a single PgpPublicKeyRingBundle via PgpKeyRingBuilder.
    private async Task<PgpPublicKeyRingBundle?> GetPgpKeyRingAsync(
        string orgId, string ecosystem, CancellationToken ct)
    {
        var anchors = await ListAsync(orgId, ecosystem, ct);
        return anchors.Count == 0
            ? null
            : Protocol.Provenance.PgpKeyRingBuilder.BuildFromAnchors(anchors, _logger, ecosystem);
    }

    public async Task<IReadOnlyDictionary<string, byte[]>> GetNpmKeysAsync(
        string orgId, CancellationToken ct = default)
    {
        var anchors = await ListAsync(orgId, "npm", ct);
        return Protocol.Provenance.NpmSignatureKeyStore.BuildSpkiMap(anchors, _logger);
    }

    public async Task<X509Certificate2Collection> GetNuGetAnchorsAsync(
        string orgId, CancellationToken ct = default)
    {
        var anchors = await ListAsync(orgId, "nuget", ct);
        return Protocol.Provenance.NuGetSignatureTrustStore.ParseAnchors(anchors, _logger);
    }

    public async Task<Protocol.Provenance.PyPiTrustMaterial> GetPyPiTrustAsync(
        string orgId, CancellationToken ct = default)
    {
        var anchors = await ListAsync(orgId, "pypi", ct);
        return anchors.Count == 0
            ? Protocol.Provenance.PyPiTrustMaterial.Empty
            : Protocol.Provenance.PyPiSigstoreTrustStore.BuildFromAnchors(anchors, _logger);
    }

    // Loads all (orgId, *) anchors and caches them as one slot per org. Ecosystem filtering
    // happens in-process so a single cache read covers all five ecosystems without one slot
    // per ecosystem. The cache is a flat List<CachedAnchor> that carries the ecosystem
    // discriminator so callers can filter cheaply without a second DB round-trip.
    private async Task<IReadOnlyList<CachedAnchor>> GetCachedForOrgAsync(
        string orgId, CancellationToken ct)
    {
        string key = CacheKey(orgId);
        if (_cache is not null && _cache.TryGetValue(key, out IReadOnlyList<CachedAnchor>? cached))
        {
            return cached!;
        }

        // Load material for each supported ecosystem and flatten into a single list.
        var result = new List<CachedAnchor>();
        foreach (string eco in TrustAnchorRepository.SupportedEcosystems)
        {
            var rows = await _repo.ListForEcosystemAsync(orgId, eco, ct);
            foreach (var r in rows)
            {
                result.Add(new CachedAnchor(eco, r));
            }
        }

        IReadOnlyList<CachedAnchor> list = result;
        _cache?.Set(key, list, new MemoryCacheEntryOptions
        {
            SlidingExpiration = CacheTtl,
            AbsoluteExpirationRelativeToNow = CacheTtl,
            Size = 1,
        });
        return list;
    }

    private sealed record CachedAnchor(string Ecosystem, TrustAnchorMaterial Material);
}
