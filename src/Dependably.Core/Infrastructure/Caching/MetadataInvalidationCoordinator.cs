using Dependably.Infrastructure.Observability;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// The single place a rendered-metadata invalidation is expanded into cache keys and applied.
///
/// <para>Every mutation site (npm publish/unpublish/dist-tag, PyPI upload, NuGet push/unlist,
/// Maven publish, RPM publish, and the management-plane yank) calls
/// <see cref="Invalidate"/> with package coordinates. This class expands those coordinates into
/// the ecosystem's <em>complete</em> key-variant matrix, evicts each variant through the same
/// <see cref="MetadataCacheKeys"/> formatter the render path reads with, and then hands the
/// coordinates to <see cref="IMetadataInvalidationBus"/> so the other replicas do the same.</para>
///
/// <para>Owning the variant matrix here is the point. A partial invalidation is worse than none:
/// a set that is right for npm and misses PyPI's JSON representation, or NuGet's proxy pair,
/// leaves a silently stale surface that looks solved. Call sites pass coordinates and cannot
/// under-enumerate; <see cref="EvictLocal"/> is shared verbatim by the publish path and the
/// subscriber path, so a message received from a peer evicts exactly what a local mutation
/// evicts.</para>
/// </summary>
public sealed class MetadataInvalidationCoordinator
{
    private readonly RenderedResponseCache<NpmPackumentKey> _npm;
    private readonly RenderedResponseCache<PyPiSimpleIndexKey> _pypi;
    private readonly RenderedResponseCache<NuGetRegistrationKey> _nuget;
    private readonly RenderedResponseCache<MavenMetadataKey> _maven;
    private readonly RenderedResponseCache<RpmLocalRepodataKey> _rpmLocal;
    private readonly MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache> _rpmMerged;
    private readonly IMetadataInvalidationBus _bus;

    public MetadataInvalidationCoordinator(
        RenderedResponseCache<NpmPackumentKey> npm,
        RenderedResponseCache<PyPiSimpleIndexKey> pypi,
        RenderedResponseCache<NuGetRegistrationKey> nuget,
        RenderedResponseCache<MavenMetadataKey> maven,
        RenderedResponseCache<RpmLocalRepodataKey> rpmLocal,
        MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache> rpmMerged,
        IMetadataInvalidationBus bus)
    {
        _npm = npm;
        _pypi = pypi;
        _nuget = nuget;
        _maven = maven;
        _rpmLocal = rpmLocal;
        _rpmMerged = rpmMerged;
        _bus = bus;
    }

    /// <summary>
    /// Evicts every affected rendered-cache entry on this replica, then broadcasts the
    /// coordinates so peer replicas evict theirs. The broadcast is best-effort and never throws
    /// (see <see cref="IMetadataInvalidationBus"/>), so a broker outage degrades this call to the
    /// local-only behaviour it had before the channel existed: peers converge on TTL expiry.
    /// </summary>
    public void Invalidate(MetadataInvalidation invalidation)
    {
        EvictLocal(invalidation);
        _bus.Publish(invalidation);
    }

    /// <summary>
    /// Evicts this replica's entries for <paramref name="invalidation"/> without broadcasting —
    /// the subscriber's entry point. Re-broadcasting a received message would loop the channel
    /// forever, so applying and publishing are deliberately separate operations over one shared
    /// expansion.
    /// </summary>
    public void EvictLocal(MetadataInvalidation invalidation)
    {
        switch (invalidation.Ecosystem)
        {
            case MetadataInvalidationEcosystems.Npm:
                EvictNpm(invalidation);
                break;
            case MetadataInvalidationEcosystems.PyPi:
                EvictPyPi(invalidation);
                break;
            case MetadataInvalidationEcosystems.NuGet:
                EvictNuGet(invalidation);
                break;
            case MetadataInvalidationEcosystems.Maven:
                EvictMaven(invalidation);
                break;
            case MetadataInvalidationEcosystems.Rpm:
                EvictRpm(invalidation);
                break;
            default:
                // Unknown ecosystem: nothing to expand. Reached only for a peer message from a
                // newer build; dropping it leaves that surface on TTL expiry, which is the
                // documented degraded behaviour rather than a fault.
                break;
        }
    }

    // npm: two variants per name — the local-only document and the proxy-merged one. A
    // claim-state flip moves subsequent requests between the two paths, so a mutation must clear
    // both or the other path serves a pre-mutation body until its TTL expires. The rendered
    // packument is not content-negotiated (the full/abbreviated "corgi" Accept variants are keyed
    // separately inside the upstream-fetch cache, by URL + Accept), so these two are the whole set.
    private void EvictNpm(MetadataInvalidation inv)
    {
        if (inv.Name is not { Length: > 0 } name)
        {
            return;
        }

        _npm.Evict(new NpmPackumentKey(inv.OrgId, name));
        _npm.Evict(new NpmPackumentKey(inv.OrgId, name) { IsProxy = true });
    }

    // PyPI: two negotiated representations at one URL — PEP 503 HTML and PEP 691 JSON. The key
    // formatter applies PEP 503 name normalization, so the raw project name is passed through.
    private void EvictPyPi(MetadataInvalidation inv)
    {
        if (inv.Name is not { Length: > 0 } name)
        {
            return;
        }

        _pypi.Evict(new PyPiSimpleIndexKey(inv.OrgId, name));
        _pypi.Evict(new PyPiSimpleIndexKey(inv.OrgId, name) { WantsJson = true });
    }

    // NuGet: four variants — SemVer1/SemVer2 × local/proxy. The registration key holds the
    // lower-cased (normalized PURL) id, so normalize here rather than relying on every call site.
    private void EvictNuGet(MetadataInvalidation inv)
    {
        if (inv.Name is not { Length: > 0 } name)
        {
            return;
        }

        string normalized = name.ToLowerInvariant();
        _nuget.Evict(new NuGetRegistrationKey(inv.OrgId, normalized, SemVer2: false));
        _nuget.Evict(new NuGetRegistrationKey(inv.OrgId, normalized, SemVer2: true));
        _nuget.Evict(new NuGetRegistrationKey(inv.OrgId, normalized, SemVer2: false) { IsProxy = true });
        _nuget.Evict(new NuGetRegistrationKey(inv.OrgId, normalized, SemVer2: true) { IsProxy = true });
    }

    // Maven: the artifact-level maven-metadata.xml always, plus the version-level SNAPSHOT
    // document when the mutation named a version. The two are different documents at adjacent
    // path depths and never share an entry.
    private void EvictMaven(MetadataInvalidation inv)
    {
        if (inv.GroupId is not { Length: > 0 } groupId || inv.ArtifactId is not { Length: > 0 } artifactId)
        {
            return;
        }

        _maven.Evict(new MavenMetadataKey(inv.OrgId, groupId, artifactId));
        if (inv.Version is { Length: > 0 } version)
        {
            _maven.Evict(new MavenMetadataKey(inv.OrgId, groupId, artifactId, version));
        }
    }

    // RPM: tenant-wide rather than per-package — every local repodata document plus the merged
    // local+upstream tuple. One publish rewrites all of them.
    private void EvictRpm(MetadataInvalidation inv)
    {
        foreach (string docType in MetadataCacheKeys.RpmRepodataDocTypes)
        {
            _rpmLocal.Evict(new RpmLocalRepodataKey(inv.OrgId, docType));
        }

        _rpmMerged.Evict(new RpmMergedRepodataKey(inv.OrgId));
    }
}

/// <summary>
/// Applies invalidations received from peer replicas. Separated from the transport so the
/// receive-side accounting (metric, ignore-own-message, unknown-message tolerance) is one
/// testable unit independent of any broker.
/// </summary>
public sealed class MetadataInvalidationReceiver
{
    private readonly MetadataInvalidationCoordinator _coordinator;
    private readonly ILogger<MetadataInvalidationReceiver> _logger;

    public MetadataInvalidationReceiver(
        MetadataInvalidationCoordinator coordinator, ILogger<MetadataInvalidationReceiver> logger)
    {
        _coordinator = coordinator;
        _logger = logger;
    }

    /// <summary>
    /// Decodes and applies one received payload. <paramref name="selfOrigin"/> is the receiving
    /// replica's own process id — a message it published itself is dropped, because the publish
    /// path already evicted locally before broadcasting.
    /// Returns <see langword="true"/> when an eviction was applied.
    /// </summary>
    public bool Apply(string? payload, string selfOrigin)
    {
        if (!MetadataInvalidationCodec.TryDecode(payload, out var invalidation, out string origin))
        {
            // Malformed, or from a build whose schema this one does not read. Dropping it leaves
            // the affected entries on TTL expiry rather than faulting the subscriber.
            _logger.LogDebug("Discarded an undecodable metadata-invalidation message.");
            return false;
        }

        if (string.Equals(origin, selfOrigin, StringComparison.Ordinal))
        {
            return false;
        }

        _coordinator.EvictLocal(invalidation);
        DependablyMeter.MetadataInvalidationsReceived.Add(
            1, new KeyValuePair<string, object?>("ecosystem", invalidation.Ecosystem));
        return true;
    }
}
