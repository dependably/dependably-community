using Dapper;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure.OciScan;

/// <summary>Why a scanner read was not answered with bytes.</summary>
public enum OciScanReadOutcome
{
    /// <summary>The bytes are in <see cref="OciScanRead.Content"/>.</summary>
    Found,

    /// <summary>The digest is not part of the claimed image, or this org holds no such object.</summary>
    NotFound,

    /// <summary>The image references it, but neither the store nor the upstream could supply it now.</summary>
    Unavailable,
}

/// <summary>The answer to one scanner read.</summary>
public sealed record OciScanRead(OciScanReadOutcome Outcome, Stream? Content = null, string? MediaType = null, long? SizeBytes = null)
{
    public static readonly OciScanRead NotFound = new(OciScanReadOutcome.NotFound);
    public static readonly OciScanRead Unavailable = new(OciScanReadOutcome.Unavailable);
}

/// <summary>
/// Serves a scanner the manifests and blobs of the image it leased, and nothing else.
///
/// <para><b>Scope.</b> A digest is readable only when it is the job's root manifest, or is
/// reachable from it through <see cref="OciReferenceGraph"/>: index → child manifests → config and
/// layers. A manifest whose closure is unknown contributes nothing, so an image recorded before the
/// graph existed fails closed rather than opening up the org's whole store.</para>
///
/// <para><b>Not a download.</b> Bytes come from the caller's org's <c>oci_blobs</c> row and its tier
/// (cache for <c>proxy</c>, registry for <c>uploaded</c>). Nothing here writes activity, meters
/// egress or counts usage; the protocol read path in <c>OciController</c> does those, and the scan
/// API does not go through it.</para>
///
/// <para><b>Evicted bytes.</b> A proxied image whose bytes left the cache is fetched again from its
/// upstream by digest. A hosted image has no upstream, so missing bytes are reported as unavailable.</para>
/// </summary>
public sealed class OciScanImageReader
{
    /// <summary>Manifests visited while resolving one digest; an index nests one level, an image none.</summary>
    private const int MaxManifestsWalked = 1_024;

    private readonly IMetadataStore _db;
    private readonly OciReferenceGraph _graph;
    private readonly TieredBlobStorage _blobs;
    private readonly OciUpstreamResolver _upstream;
    private readonly ILogger<OciScanImageReader> _logger;

    public OciScanImageReader(
        IMetadataStore db, OciReferenceGraph graph, TieredBlobStorage blobs, OciUpstreamResolver upstream,
        ILogger<OciScanImageReader> logger)
    {
        _db = db;
        _graph = graph;
        _blobs = blobs;
        _upstream = upstream;
        _logger = logger;
    }

    /// <summary>Reads <paramref name="digest"/> for <paramref name="job"/>'s scanner.</summary>
    public async Task<OciScanRead> ReadAsync(OciScanJob job, string digest, bool manifest, CancellationToken ct = default)
    {
        if (!await IsInImageAsync(job.OrgId, job.Digest, digest, ct))
        {
            return OciScanRead.NotFound;
        }

        await using (var conn = await _db.OpenAsync(ct))
        {
            var (MediaType, SizeBytes, BlobKey, Origin) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin)>(
                """
                SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin
                FROM oci_blobs WHERE digest = @digest AND org_id = @orgId
                """,
                new { digest, orgId = job.OrgId });
            if (BlobKey is not null)
            {
                var tier = Origin == "proxy" ? _blobs.Cache : _blobs.Registry;
                var stream = await tier.GetAsync(BlobKey, ct);
                if (stream is not null)
                {
                    return new OciScanRead(OciScanReadOutcome.Found, stream,
                        MediaType ?? "application/octet-stream", SizeBytes);
                }
            }
        }

        return job.Owner.IsHosted
            ? OciScanRead.Unavailable
            : await FetchUpstreamAsync(job, digest, manifest, ct);
    }

    /// <summary>
    /// True when <paramref name="digest"/> is <paramref name="rootDigest"/> or reachable from it
    /// through manifests whose closure this org's graph knows.
    /// </summary>
    public async Task<bool> IsInImageAsync(string orgId, string rootDigest, string digest, CancellationToken ct = default)
    {
        if (string.Equals(digest, rootDigest, StringComparison.Ordinal))
        {
            return true;
        }

        var visited = new HashSet<string>(StringComparer.Ordinal) { rootDigest };
        var frontier = new Queue<string>();
        frontier.Enqueue(rootDigest);
        while (frontier.Count > 0 && visited.Count <= MaxManifestsWalked)
        {
            string manifest = frontier.Dequeue();
            if (!await _graph.IsClosureKnownAsync(orgId, manifest, ct))
            {
                continue;
            }

            foreach (string child in await _graph.GetReferencedAsync(orgId, manifest, ct))
            {
                if (string.Equals(child, digest, StringComparison.Ordinal))
                {
                    return true;
                }

                // A child with recorded edges is itself a manifest (an index's platform image);
                // layers and configs have none.
                if (visited.Add(child) && await _graph.IsClosureKnownAsync(orgId, child, ct))
                {
                    frontier.Enqueue(child);
                }
            }
        }

        return false;
    }

    private async Task<OciScanRead> FetchUpstreamAsync(OciScanJob job, string digest, bool manifest, CancellationToken ct)
    {
        try
        {
            if (manifest)
            {
                var fetched = await _upstream.FetchManifestAsync(job.OrgId, job.Repository, digest, isDigest: true, ct);
                return fetched is null
                    ? OciScanRead.Unavailable
                    : new OciScanRead(OciScanReadOutcome.Found, fetched.Content, fetched.MediaType, fetched.SizeBytes);
            }

            var blob = await _upstream.FetchBlobAsync(job.OrgId, job.Repository, digest, ct);
            return blob?.Blob is { } served
                ? new OciScanRead(OciScanReadOutcome.Found, served.Content, served.MediaType)
                : OciScanRead.Unavailable;
        }
        catch (Exception ex) when (ex is AirGappedException or OciPassthroughOffException)
        {
            // Upstream off by policy, not a failure: the bytes are unavailable to this scan.
            _logger.LogDebug(
                "{Digest} for the scan of {Repository} is not held locally and upstream fetching is off (org {OrgId}).",
                digest, job.Repository, job.OrgId);
            return OciScanRead.Unavailable;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Upstream re-fetch of {Digest} for the scan of {Repository} failed (org {OrgId}).",
                digest, job.Repository, job.OrgId);
            return OciScanRead.Unavailable;
        }
    }
}
