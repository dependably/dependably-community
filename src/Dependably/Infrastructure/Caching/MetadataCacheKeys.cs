using Dependably.Protocol;

namespace Dependably.Infrastructure.Caching;

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
    /// PyPI simple-index key. Normalizes the package name to its PEP 503 form so the
    /// <c>my-package</c> / <c>my_package</c> spellings resolve to one entry.
    /// </summary>
    public static string PyPiSimpleIndex(PyPiSimpleIndexKey key) =>
        $"metadata:{key.OrgId}:pypi:{PurlNormalizer.PyPiName(key.Name)}";

    /// <summary>npm packument key. The full (scoped) name is already canonical for npm.</summary>
    public static string NpmPackument(NpmPackumentKey key) =>
        $"metadata:{key.OrgId}:npm:{key.FullName}";

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
    /// Maven <c>maven-metadata.xml</c> key — one rendered version document per
    /// (tenant, groupId, artifactId). The coordinate components are already canonical.
    /// </summary>
    public static string MavenMetadata(MavenMetadataKey key) =>
        $"metadata:{key.OrgId}:maven:{key.GroupId}/{key.ArtifactId}";

    /// <summary>
    /// RPM local-repodata key — one rendered gzipped document per (tenant, document type).
    /// Covers primary, filelists, and other documents for the hosted-only (non-proxy) path.
    /// The type string is the lowercase document name stem: "primary", "filelists", or "other".
    /// </summary>
    public static string RpmLocalRepodata(RpmLocalRepodataKey key) =>
        $"rpm:local-repodata:{key.OrgId}:{key.DocType}";
}

/// <summary>Identifies a PyPI simple index by tenant and (raw, un-normalized) package name.</summary>
public readonly record struct PyPiSimpleIndexKey(string OrgId, string Name);

/// <summary>Identifies an npm packument by tenant and full (scoped) package name.</summary>
public readonly record struct NpmPackumentKey(string OrgId, string FullName);

/// <summary>
/// Identifies a NuGet registration index by tenant, normalized id, SemVer variant, and cache path.
/// <see cref="IsProxy"/> distinguishes entries built by the upstream-merge path
/// (<see langword="true"/>) from entries built by the local-only path (<see langword="false"/>).
/// Defaults to <see langword="false"/> so existing non-proxy callsites require no change.
/// </summary>
public readonly record struct NuGetRegistrationKey(string OrgId, string NormalizedId, bool SemVer2)
{
    /// <summary>
    /// <see langword="true"/> when the entry was built by <c>ServeProxyMergedRegistrationAsync</c>;
    /// <see langword="false"/> when built by <c>ServeLocalRegistrationAsync</c>.
    /// </summary>
    public bool IsProxy { get; init; } = false;
}

/// <summary>Identifies a tenant's merged RPM repodata tuple.</summary>
public readonly record struct RpmMergedRepodataKey(string OrgId);

/// <summary>Identifies a Maven metadata document by tenant, groupId, and artifactId.</summary>
public readonly record struct MavenMetadataKey(string OrgId, string GroupId, string ArtifactId);

/// <summary>
/// Identifies a single locally-rendered RPM repodata document (primary, filelists, or other)
/// by tenant and document type. The type string is the lowercase filename stem ("primary",
/// "filelists", or "other") — distinct from the merged-mode cache that holds the full tuple.
/// </summary>
public readonly record struct RpmLocalRepodataKey(string OrgId, string DocType);
