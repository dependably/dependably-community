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
    /// <c>my-package</c> / <c>my_package</c> spellings resolve to one entry. Two variants per
    /// name: the <c>:json</c> suffix distinguishes the PEP 691 JSON representation from the
    /// PEP 503 HTML one. The same URL serves both, negotiated per request from the Accept
    /// header, so a shared key would let a client receive the other representation's bytes
    /// under its own content type. Mutation sites evict both variants.
    /// </summary>
    public static string PyPiSimpleIndex(PyPiSimpleIndexKey key) =>
        $"metadata:{key.OrgId}:pypi:{PurlNormalizer.PyPiName(key.Name)}{(key.WantsJson ? ":json" : "")}";

    /// <summary>
    /// npm packument key. The full (scoped) name is already canonical for npm. Two variants
    /// per name: the <c>:proxy</c> suffix distinguishes entries built by the passthrough
    /// (upstream-merged) path from entries built by the local-only path. The two paths are
    /// mutually exclusive per request, but a claim-state change (e.g. operator adds a mixed
    /// claim to a hosted name, or locks a mixed name down to local_only) shifts subsequent
    /// requests between them; sharing one key would serve the stale wrong-path body until
    /// its TTL expired. Distinct keys prevent that, mirroring the NuGet registration key.
    /// </summary>
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
    public static string NuGetRegistration(NuGetRegistrationKey key) =>
        $"metadata:{key.OrgId}:nuget:{key.NormalizedId}:{(key.SemVer2 ? "sv2" : "sv1")}{(key.IsProxy ? ":proxy" : "")}";

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
    /// </summary>
    public static string MavenMetadata(MavenMetadataKey key) =>
        key.Version is null
            ? $"metadata:{key.OrgId}:maven:{key.GroupId}/{key.ArtifactId}"
            : $"metadata:{key.OrgId}:maven:{key.GroupId}/{key.ArtifactId}:{key.Version}";

    /// <summary>
    /// RPM local-repodata key — one rendered gzipped document per (tenant, document type).
    /// Covers primary, filelists, and other documents for the hosted-only (non-proxy) path.
    /// The type string is the lowercase document name stem: "primary", "filelists", or "other".
    /// </summary>
    public static string RpmLocalRepodata(RpmLocalRepodataKey key) =>
        $"rpm:local-repodata:{key.OrgId}:{key.DocType}";
}

/// <summary>
/// Identifies a PyPI simple index by tenant, (raw, un-normalized) package name, and negotiated
/// representation (see <see cref="WantsJson"/>).
/// </summary>
public readonly record struct PyPiSimpleIndexKey(string OrgId, string Name) : IOrgScopedCacheKey
{
    /// <summary>
    /// <see langword="true"/> for the PEP 691 JSON representation; <see langword="false"/> for
    /// the PEP 503 HTML one. Defaults to <see langword="false"/> so HTML callsites read as the
    /// unsuffixed key. Mutation sites evict both variants.
    /// </summary>
    public bool WantsJson { get; init; } = false;
}

/// <summary>
/// Identifies an npm packument by tenant, full (scoped) package name, and cache path
/// (local-only vs proxy-merged — see <see cref="IsProxy"/>).
/// </summary>
public readonly record struct NpmPackumentKey(string OrgId, string FullName) : IOrgScopedCacheKey
{
    /// <summary>
    /// <see langword="true"/> when the entry was built by the passthrough (upstream-merged)
    /// path; <see langword="false"/> when built by the local-only path. Mutation sites
    /// evict both variants.
    /// </summary>
    public bool IsProxy { get; init; } = false;
}

/// <summary>
/// Identifies a NuGet registration index by tenant, normalized id, SemVer variant, and cache path.
/// <see cref="IsProxy"/> distinguishes entries built by the upstream-merge path
/// (<see langword="true"/>) from entries built by the local-only path (<see langword="false"/>).
/// Defaults to <see langword="false"/> so existing non-proxy callsites require no change.
/// </summary>
public readonly record struct NuGetRegistrationKey(string OrgId, string NormalizedId, bool SemVer2) : IOrgScopedCacheKey
{
    /// <summary>
    /// <see langword="true"/> when the entry was built by <c>ServeProxyMergedRegistrationAsync</c>;
    /// <see langword="false"/> when built by <c>ServeLocalRegistrationAsync</c>.
    /// </summary>
    public bool IsProxy { get; init; } = false;
}

/// <summary>Identifies a tenant's merged RPM repodata tuple.</summary>
public readonly record struct RpmMergedRepodataKey(string OrgId);

/// <summary>
/// Identifies a Maven metadata document by tenant, groupId, and artifactId, plus an optional
/// <see cref="Version"/> distinguishing the version-level SNAPSHOT document
/// (<c>g/a/{version}/maven-metadata.xml</c>) from the artifact-level document
/// (<c>g/a/maven-metadata.xml</c>, <see langword="null"/> version).
/// </summary>
public readonly record struct MavenMetadataKey(string OrgId, string GroupId, string ArtifactId, string? Version = null)
    : IOrgScopedCacheKey;

/// <summary>
/// Identifies a single locally-rendered RPM repodata document (primary, filelists, or other)
/// by tenant and document type. The type string is the lowercase filename stem ("primary",
/// "filelists", or "other") — distinct from the merged-mode cache that holds the full tuple.
/// </summary>
public readonly record struct RpmLocalRepodataKey(string OrgId, string DocType);
