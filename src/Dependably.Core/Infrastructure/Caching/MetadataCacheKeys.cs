using Dependably.Protocol;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Marks a rendered-cache key as belonging to one org's tenant-scoped policy state. Implemented
/// by every key whose rendered bytes reflect the org's proxy-settings gate (block/verify
/// policies, release-age and score thresholds), so <see cref="MetadataResponseCache{TKey,TValue}"/>
/// can bind its cache entries to that org's <see cref="OrgCacheEpochStore"/> epoch and expire them
/// all at once when the policy changes.
/// </summary>
public interface IOrgScopedCacheKey
{
    string OrgId { get; }
}

/// <summary>
/// Marks a rendered-cache key whose document embeds absolute URLs built from the request's
/// public base (<c>IPublicUrlBuilder.BaseUrl</c>: scheme and <c>Host</c>, port included). The
/// host filter admits more than one authority for the same tenant (the apex, the loopback names,
/// any port, every <c>HOST_ROUTING</c> host), so a document rendered for one authority must never
/// answer a request through another: its tarball and registration URLs would send that client to
/// the first requester's host until the entry expired.
///
/// <para>The key formatter leaves <see cref="PublicBase"/> out: the string it produces names the
/// document's family, every base's variant of one package, and is what eviction addresses.
/// <see cref="MetadataResponseCache{TKey,TValue}"/> stores each variant under
/// <see cref="MetadataCacheKeys.PublicBaseVariant"/>, which adds the family's invalidation
/// generation and the base, so evicting the family retires every variant without enumerating the
/// hosts it was rendered for. A <see langword="null"/> base is the family itself, which is what an
/// eviction site passes.</para>
/// </summary>
public interface IPublicBaseVariantKey
{
    string? PublicBase { get; }
}

/// <summary>
/// Canonical cache-key formatters for each ecosystem's metadata responses. Each
/// <c>RenderedResponseCache</c>/<c>MetadataResponseCache</c> singleton is constructed with the
/// matching formatter, so every get/set/evict for a logical entry produces the identical string —
/// the read path and the eviction path can never disagree on a key. Owning name normalization
/// here (rather than at each call site) structurally prevents the cache-key-divergence class of
/// bug: callers pass raw components and cannot supply an inconsistently-normalized name.
/// </summary>
public static class MetadataCacheKeys
{
    /// <summary>
    /// The complete set of locally-rendered RPM repodata document types. Named here, beside the
    /// key formatter, so the render path and every invalidation site enumerate one list — adding
    /// a fourth document type cannot leave an un-evicted cache entry behind.
    /// </summary>
    public static readonly IReadOnlyList<string> RpmRepodataDocTypes = new[] { "primary", "filelists", "other" };

    /// <summary>
    /// PyPI simple-index key. Normalizes the package name to its PEP 503 form so the
    /// <c>my-package</c> / <c>my_package</c> spellings resolve to one entry. Four variants per
    /// name: JSON × proxy. The <c>:json</c> suffix distinguishes the PEP 691 JSON representation
    /// from the PEP 503 HTML one — the same URL serves both, negotiated per request from the
    /// Accept header, so a shared key would let a client receive the other representation's bytes
    /// under its own content type. The <c>:proxy</c> suffix distinguishes entries built by
    /// <c>ServeProxySimpleIndexAsync</c> (upstream-merged) from entries built by
    /// <c>ServeLocalSimpleIndexAsync</c> (local-only), mirroring the npm and NuGet keys: the two
    /// paths are mutually exclusive per request but a claim-state change (a name becoming
    /// local-only, or proxy passthrough being toggled) shifts subsequent requests between them,
    /// and the two paths also store at different TTLs. Mutation sites evict all four variants.
    /// </summary>
    public static string PyPiSimpleIndex(PyPiSimpleIndexKey key) =>
        $"metadata:{key.OrgId}:pypi:{PurlNormalizer.PyPiName(key.Name)}{(key.WantsJson ? ":json" : "")}{(key.IsProxy ? ":proxy" : "")}";

    /// <summary>
    /// npm packument key. The full (scoped) name is already canonical for npm. Two variants
    /// per name: the <c>:proxy</c> suffix distinguishes entries built by the passthrough
    /// (upstream-merged) path from entries built by the local-only path. The two paths are
    /// mutually exclusive per request, but a claim-state change (e.g. operator adds a mixed
    /// claim to a hosted name, or locks a mixed name down to local_only) shifts subsequent
    /// requests between them; sharing one key would serve the stale wrong-path body until
    /// its TTL expired. Distinct keys prevent that, mirroring the NuGet registration key.
    /// </summary>
    /// <remarks>The request's public base is a variant of this family, not part of it — see
    /// <see cref="IPublicBaseVariantKey"/>.</remarks>
    public static string NpmPackument(NpmPackumentKey key) =>
        $"metadata:{key.OrgId}:npm:{key.FullName}{(key.IsProxy ? ":proxy" : "")}";

    /// <summary>
    /// NuGet registration-index key. Four variants per package: SemVer 1/2 × local/proxy.
    /// The <c>:proxy</c> suffix distinguishes entries populated by <c>ServeProxyMergedRegistrationAsync</c>
    /// from entries populated by <c>ServeLocalRegistrationAsync</c>. The two paths are mutually
    /// exclusive per request (determined by <c>passthroughAllowed</c>), but a claim-state change
    /// (e.g. operator adds a mixed claim after a package was pushed) can shift subsequent requests
    /// from the local path to the proxy path. Sharing the same key would let a stale local-only
    /// cache entry be served as the merged upstream response. Distinct keys prevent that.
    /// </summary>
    /// <remarks>The request's public base is a variant of this family, not part of it — see
    /// <see cref="IPublicBaseVariantKey"/>.</remarks>
    public static string NuGetRegistration(NuGetRegistrationKey key) =>
        $"metadata:{key.OrgId}:nuget:{key.NormalizedId}:{(key.SemVer2 ? "sv2" : "sv1")}{(key.IsProxy ? ":proxy" : "")}";

    /// <summary>
    /// Storage key for one public-base variant of a rendered document: the family key, the
    /// family's invalidation generation, and the base the document was rendered with. The
    /// generation is what lets one eviction of the family retire every variant. <c>|</c> separates
    /// the parts because no npm package name, NuGet id, or URL authority contains it.
    /// </summary>
    public static string PublicBaseVariant(string family, long generation, string publicBase) =>
        $"{family}|g{generation}|{publicBase}";

    /// <summary>RPM merged-repodata key — org-scoped, one merged tuple per tenant.</summary>
    public static string RpmMergedRepodata(RpmMergedRepodataKey key) =>
        $"rpm:merged-repodata:{key.OrgId}";

    /// <summary>
    /// Maven <c>maven-metadata.xml</c> key — one rendered document per (tenant, groupId,
    /// artifactId) for the artifact-level document, plus one per (tenant, groupId, artifactId,
    /// version) for a SNAPSHOT's version-level document. <see cref="MavenMetadataKey.Version"/>
    /// is <see langword="null"/> for the artifact-level request; the two flavours must never
    /// share a cache entry — they are different documents (version list vs. snapshot build
    /// list) even though they're both named <c>maven-metadata.xml</c> at adjacent path depths.
    /// The <c>proxy</c>/<c>local</c> tag distinguishes a document rendered when proxying was
    /// allowed for the coordinate (upstream-merged) from one rendered local-only, mirroring the
    /// npm, PyPI and NuGet keys: a reservation or registry change moves subsequent requests
    /// between the two, and a shared key would let a document rendered under the earlier decision
    /// answer a request that decided otherwise. Mutation sites evict both variants of each flavour.
    ///
    /// Unlike those keys, the tag sits in a fixed position ahead of the coordinate rather than as
    /// a trailing <c>:proxy</c> suffix. Their trailing segments are names that cannot contain a
    /// colon; a Maven version is free text, so a suffix would let a local key for version
    /// <c>proxy</c> (or <c>x:proxy</c>) spell the same string as a proxy key. After the tag the
    /// coordinate is written as its repository path — groupId and artifactId never contain
    /// <c>/</c>, and a version is a single path segment — so the artifact-level and version-level
    /// forms are told apart by segment count, whatever the version text.
    /// </summary>
    public static string MavenMetadata(MavenMetadataKey key) =>
        $"metadata:{key.OrgId}:maven:{(key.IsProxy ? "proxy" : "local")}:{key.GroupId}/{key.ArtifactId}"
        + (key.Version is null ? "" : $"/{key.Version}");

    /// <summary>
    /// RPM local-repodata key — one rendered gzipped document per (tenant, document type).
    /// Covers primary, filelists, and other documents for the hosted-only (non-proxy) path.
    /// The type string is the lowercase document name stem: "primary", "filelists", or "other".
    /// </summary>
    public static string RpmLocalRepodata(RpmLocalRepodataKey key) =>
        $"rpm:local-repodata:{key.OrgId}:{key.DocType}";
}

/// <summary>
/// Identifies a PyPI simple index by tenant, (raw, un-normalized) package name, negotiated
/// representation (see <see cref="WantsJson"/>), and cache path (local-only vs proxy-merged —
/// see <see cref="IsProxy"/>).
/// </summary>
public readonly record struct PyPiSimpleIndexKey(string OrgId, string Name) : IOrgScopedCacheKey
{
    /// <summary>
    /// <see langword="true"/> for the PEP 691 JSON representation; <see langword="false"/> for
    /// the PEP 503 HTML one. Defaults to <see langword="false"/> so HTML callsites read as the
    /// unsuffixed key. Mutation sites evict all four variants.
    /// </summary>
    public bool WantsJson { get; init; } = false;

    /// <summary>
    /// <see langword="true"/> when the entry was built by the passthrough (upstream-merged)
    /// path; <see langword="false"/> when built by the local-only path. Mutation sites evict
    /// all four variants.
    /// </summary>
    public bool IsProxy { get; init; } = false;
}

/// <summary>
/// Identifies an npm packument by tenant, full (scoped) package name, and cache path
/// (local-only vs proxy-merged — see <see cref="IsProxy"/>).
/// </summary>
public readonly record struct NpmPackumentKey(string OrgId, string FullName) : IOrgScopedCacheKey, IPublicBaseVariantKey
{
    /// <summary>
    /// <see langword="true"/> when the entry was built by the passthrough (upstream-merged)
    /// path; <see langword="false"/> when built by the local-only path. Mutation sites
    /// evict both variants.
    /// </summary>
    public bool IsProxy { get; init; } = false;

    /// <summary>
    /// The public base (scheme and authority) the packument's tarball URLs were rendered with.
    /// Every serving path sets it; an eviction site leaves it <see langword="null"/>, which
    /// addresses every base's variant (see <see cref="IPublicBaseVariantKey"/>).
    /// </summary>
    public string? PublicBase { get; init; }
}

/// <summary>
/// Identifies a NuGet registration index by tenant, normalized id, SemVer variant, and cache path.
/// <see cref="IsProxy"/> distinguishes entries built by the upstream-merge path
/// (<see langword="true"/>) from entries built by the local-only path (<see langword="false"/>).
/// Defaults to <see langword="false"/> so existing non-proxy callsites require no change.
/// </summary>
public readonly record struct NuGetRegistrationKey(string OrgId, string NormalizedId, bool SemVer2)
    : IOrgScopedCacheKey, IPublicBaseVariantKey
{
    /// <summary>
    /// <see langword="true"/> when the entry was built by <c>ServeProxyMergedRegistrationAsync</c>;
    /// <see langword="false"/> when built by <c>ServeLocalRegistrationAsync</c>.
    /// </summary>
    public bool IsProxy { get; init; } = false;

    /// <summary>
    /// The public base (scheme and authority) the document's registration and package-content
    /// URLs were rendered with. Every serving path sets it; an eviction site leaves it
    /// <see langword="null"/>, which addresses every base's variant (see
    /// <see cref="IPublicBaseVariantKey"/>).
    /// </summary>
    public string? PublicBase { get; init; }
}

/// <summary>Identifies a tenant's merged RPM repodata tuple.</summary>
public readonly record struct RpmMergedRepodataKey(string OrgId) : IOrgScopedCacheKey;

/// <summary>
/// Identifies a Maven metadata document by tenant, groupId, and artifactId, plus an optional
/// <see cref="Version"/> distinguishing the version-level SNAPSHOT document
/// (<c>g/a/{version}/maven-metadata.xml</c>) from the artifact-level document
/// (<c>g/a/maven-metadata.xml</c>, <see langword="null"/> version), and the rendering decision
/// (see <see cref="IsProxy"/>).
/// </summary>
public readonly record struct MavenMetadataKey(string OrgId, string GroupId, string ArtifactId, string? Version = null)
    : IOrgScopedCacheKey
{
    /// <summary>
    /// <see langword="true"/> when the request decided proxying was allowed for the coordinate
    /// (an upstream registry is configured and no reservation covers the path), so the document
    /// may carry upstream versions; <see langword="false"/> when it decided local-only. Mutation
    /// sites evict both variants.
    /// </summary>
    public bool IsProxy { get; init; } = false;
}

/// <summary>
/// Identifies a single locally-rendered RPM repodata document (primary, filelists, or other)
/// by tenant and document type. The type string is the lowercase filename stem ("primary",
/// "filelists", or "other") — distinct from the merged-mode cache that holds the full tuple.
/// </summary>
public readonly record struct RpmLocalRepodataKey(string OrgId, string DocType) : IOrgScopedCacheKey;
