using Dependably.Infrastructure;

namespace Dependably.Storage;

/// <summary>
/// Answers whether an org's proxied artefacts for one ecosystem are public upstream content — the
/// question that decides whether <see cref="BlobPresignService"/> may classify a proxied blob as
/// <see cref="BlobVisibility.Public"/>.
/// </summary>
public interface IProxiedContentVisibility
{
    /// <summary>
    /// True only when the org's proxied content for <paramref name="ecosystem"/> (the serve path's
    /// ecosystem name, as handed to the redirect seam) can be shown to be public. Anything the
    /// implementation cannot show is false.
    /// </summary>
    Task<bool> IsPublicAsync(string orgId, string ecosystem, CancellationToken ct = default);
}

/// <summary>
/// Decides proxied-content visibility from the org's upstream configuration: public only when every
/// upstream the org has configured for the ecosystem is credential-free
/// (<see cref="UpstreamRegistryRepository.AllUpstreamsCredentialFreeAsync"/>).
///
/// <para>
/// The decision is per (org, ecosystem), not per object, because nothing records which upstream
/// row supplied a tenant's copy: <c>cache_artifact.upstream_url</c> is the first fetching tenant's
/// URL on a row shared by every tenant, and <c>tenant_artifact_access</c> and <c>oci_blobs</c> hold
/// no upstream at all. Sharing is not a leak in the other direction: signed paths are
/// content-addressed, so when an org whose upstreams are all anonymous is served a blob under the
/// cached prefix, those exact bytes are what its anonymous upstream serves to anyone, whichever
/// other tenant also holds them through a credentialed upstream.
/// </para>
///
/// <para>
/// The answer is read per request and never cached across requests. A cached "public" is the
/// unsafe direction: an upstream with credentials added on one instance would not be seen by
/// another instance's cache, and an object fetched through it could be signed as public until the
/// entry expired. The read is one indexed lookup, made only for a proxied redirect candidate under
/// the CloudFront signer.
/// </para>
///
/// <para>
/// On an edge node every proxied object is private: the edge's upstream is its master, which
/// serves the org's own hosted artefacts as well as the master's proxy cache, so an edge's proxy
/// cache is never only public content.
/// </para>
/// </summary>
public sealed class UpstreamProxiedContentVisibility : IProxiedContentVisibility
{
    private readonly UpstreamRegistryRepository _upstreams;
    private readonly IEdgeMode _edge;

    public UpstreamProxiedContentVisibility(UpstreamRegistryRepository upstreams, IEdgeMode edge)
    {
        _upstreams = upstreams;
        _edge = edge;
    }

    public async Task<bool> IsPublicAsync(string orgId, string ecosystem, CancellationToken ct = default)
    {
        string? upstreamEcosystem = UpstreamEcosystem(ecosystem);
        return !_edge.IsEdge
            && upstreamEcosystem is not null
            && await _upstreams.AllUpstreamsCredentialFreeAsync(orgId, upstreamEcosystem, ct);
    }

    /// <summary>
    /// Maps a serve path's ecosystem name to its <c>upstream_registry.ecosystem</c> value, or null
    /// when the ecosystem has no configurable upstream. Go serves under <c>go</c> and configures its
    /// upstreams under <c>golang</c>; every other name is shared.
    /// </summary>
    internal static string? UpstreamEcosystem(string ecosystem)
    {
        string mapped = ecosystem == "go" ? "golang" : ecosystem;
        return UpstreamRegistryRepository.IsSupportedEcosystem(mapped) ? mapped : null;
    }
}
