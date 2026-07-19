using Dependably.Infrastructure.Observability;

namespace Dependably.Infrastructure;

/// <summary>
/// Wires the proxy fetch path to the <c>cache_artifact</c> and
/// <c>tenant_artifact_access</c> tables. Called by each ecosystem's controller after a
/// successful upstream fetch or cache hit.
///
/// Every call upserts both: a global row identifying the artefact at the coordinate
/// (creating it on first sight and touching <c>last_accessed_at</c> thereafter) and a
/// per-tenant row tracking access count + first/last seen for that tenant. The latter is
/// what drives the vulnerability-response query.
///
/// Idempotent, and consequential: the row it returns is the artefact's identity on the cache
/// plane, and the proxy fetch path gates against that row before any byte reaches the client. A
/// failure here is therefore not cosmetic — <see cref="RecordAccessAsync"/> retries once and
/// returns null only when the plane is genuinely unavailable, which the proxy fetch path treats as
/// grounds to refuse the fetch.
/// </summary>
public sealed class CacheAccessRecorder
{
    private readonly CacheArtifactRepository _cache;
    private readonly TenantArtifactAccessRepository _access;
    private readonly ILogger<CacheAccessRecorder> _logger;
    private readonly TimeProvider _time;

    public CacheAccessRecorder(
        CacheArtifactRepository cache,
        TenantArtifactAccessRepository access,
        ILogger<CacheAccessRecorder> logger,
        TimeProvider time)
    {
        _cache = cache;
        _access = access;
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// Records that the given tenant accessed the cached artefact at the given coordinate.
    /// Creates the <c>cache_artifact</c> row if absent (using <c>ON CONFLICT DO NOTHING</c> +
    /// re-read so a concurrent first-fetch race always resolves to the single winner row),
    /// otherwise touches its <c>last_accessed_at</c>. Always upserts the per-tenant access row.
    /// Returns the <c>cache_artifact.id</c> on success, or <c>null</c> when recording fails.
    ///
    /// The write is attempted twice. The dominant failure is contention on the metadata store — the
    /// concurrent first-fetch race that <see cref="CacheArtifactRepository.InsertAsync"/> resolves by
    /// re-reading the winner row — and a second attempt turns most of those into an ordinary success.
    ///
    /// The retry is worth having because the cost of returning null is high. A cache-plane row is
    /// what makes a proxied artefact scannable and evictable, and it is the row the proxy fetch gates
    /// against: an artefact with no row is one the registry cannot vouch for.
    /// </summary>
    public async Task<string?> RecordAccessAsync(CacheAccess access, CancellationToken ct = default)
    {
        string? id = await RecordAccessImplAsync(access, ct);
        return id is not null || ct.IsCancellationRequested
            ? id
            : await RecordAccessImplAsync(access, ct);
    }

    private async Task<string?> RecordAccessImplAsync(CacheAccess access, CancellationToken ct)
    {
        var (orgId, ecosystem, name, version, filename,
             sha256, sizeBytes, blobKey, upstreamUrl) = access;
        try
        {
            var existing = await _cache.GetByCoordinateAsync(ecosystem, name, version, filename, ct);
            string artifactId;
            var now = _time.GetUtcNow();
            if (existing is null)
            {
                var inserted = await _cache.InsertAsync(new CacheArtifact
                {
                    Id = Guid.NewGuid().ToString("D"),
                    Ecosystem = ecosystem,
                    Name = name,
                    Version = version,
                    Filename = filename,
                    BlobKey = blobKey,
                    ContentHash = sha256,
                    SizeBytes = sizeBytes,
                    UpstreamUrl = upstreamUrl,
                    FirstCachedAt = now,
                    LastAccessedAt = now,
                }, ct);
                artifactId = inserted.Id;
            }
            else
            {
                artifactId = existing.Id;
                await _cache.TouchAccessAsync(existing.Id, now, ct);

                // First-fetch content-divergence detection: a freshly-fetched SHA-256 that
                // differs from the globally-cached row signals that two organisations resolved
                // different bytes for the same coordinate. The cache_artifact row is NOT
                // mutated — detection only; serve-path behaviour is unchanged.
                if (!string.IsNullOrEmpty(sha256)
                    && !string.IsNullOrEmpty(existing.ContentHash)
                    && !string.Equals(sha256, existing.ContentHash, StringComparison.OrdinalIgnoreCase))
                {
                    DependablyMeter.CacheContentDivergences.Add(
                        1,
                        new KeyValuePair<string, object?>("ecosystem", ecosystem));

                    _logger.LogWarning(
                        "Cache-plane content divergence detected: {Ecosystem}/{Name}@{Version} " +
                        "{Filename} — cached hash {CachedHash}, diverging hash {DivertingHash}, " +
                        "requesting org {OrgId}. The cached row is unchanged; the first-fetch " +
                        "content is authoritative on the shared cache plane.",
                        ecosystem, name, version, filename,
                        existing.ContentHash, sha256, orgId);
                }
            }

            await _access.UpsertAsync(orgId, artifactId, now, ct);
            return artifactId;
        }
        catch (Exception ex)
        {
            // Logged per attempt so a systemic failure is visible before it becomes a serving
            // problem: RecordAccessAsync retries once, and the caller decides what a second failure
            // means for the fetch.
            _logger.LogWarning(ex,
                "CacheAccessRecorder failed for {Ecosystem}/{Name}@{Version} {Filename} (org {OrgId}).",
                ecosystem, name, version, filename, orgId);
            return null;
        }
    }
}

/// <summary>
/// Bundle of every coordinate <see cref="CacheAccessRecorder.RecordAccessAsync"/> needs.
/// Records the tenant identity (<see cref="OrgId"/>) plus the artefact (<see cref="Ecosystem"/>,
/// <see cref="Name"/>, <see cref="Version"/>, <see cref="Filename"/>) plus the bytes-side
/// metadata that lands in <c>cache_artifact</c> (<see cref="Sha256"/>, <see cref="SizeBytes"/>,
/// <see cref="BlobKey"/>, <see cref="UpstreamUrl"/>). A record so call sites destructure
/// rather than positionally pass nine strings.
/// </summary>
public sealed record CacheAccess(
    string OrgId,
    string Ecosystem,
    string Name,
    string Version,
    string Filename,
    string Sha256,
    long SizeBytes,
    string BlobKey,
    string? UpstreamUrl);
