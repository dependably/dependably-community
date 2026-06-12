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
/// Designed to be idempotent and side-effect-light — failures here log and continue rather
/// than break the request, because the originating fetch already succeeded.
/// </summary>
public sealed class CacheAccessRecorder
{
    private readonly CacheArtifactRepository _cache;
    private readonly TenantArtifactAccessRepository _access;
    private readonly ILogger<CacheAccessRecorder> _logger;

    public CacheAccessRecorder(
        CacheArtifactRepository cache,
        TenantArtifactAccessRepository access,
        ILogger<CacheAccessRecorder> logger)
    {
        _cache = cache;
        _access = access;
        _logger = logger;
    }

    /// <summary>
    /// Records that the given tenant accessed the cached artefact at the given coordinate.
    /// Creates the <c>cache_artifact</c> row if absent, otherwise touches its
    /// <c>last_accessed_at</c>. Always upserts the per-tenant access row.
    /// </summary>
    public Task RecordAccessAsync(CacheAccess access, CancellationToken ct = default)
        => RecordAccessImplAsync(access, ct);

    private async Task RecordAccessImplAsync(CacheAccess access, CancellationToken ct)
    {
        var (orgId, ecosystem, name, version, filename,
             sha256, sizeBytes, blobKey, upstreamUrl) = access;
        try
        {
            var existing = await _cache.GetByCoordinateAsync(ecosystem, name, version, filename, ct);
            string artifactId;
            var now = DateTimeOffset.UtcNow;
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
            }

            await _access.UpsertAsync(orgId, artifactId, now, ct);
        }
        catch (Exception ex)
        {
            // The proxy fetch already returned bytes to the client; this recording is
            // best-effort. Log loud enough that ops notice if it starts failing systemically
            // (the vulnerability-response query depends on it) without breaking serving.
            _logger.LogWarning(ex,
                "CacheAccessRecorder failed for {Ecosystem}/{Name}@{Version} {Filename} (org {OrgId}).",
                ecosystem, name, version, filename, orgId);
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
