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
/// returns null only when the plane is genuinely unavailable, or when a first fetch could not
/// identify the bytes it is asking to admit; the proxy fetch path treats both as grounds to
/// refuse the fetch.
///
/// The per-tenant row is also where the artefact's bytes are bound to the tenant. The
/// <c>cache_artifact</c> row is global and keyed only by (ecosystem, name, version, filename)
/// while upstream registries are per-org, so one row stands for whichever bytes the first tenant
/// to reach the coordinate resolved from its own upstream. Writing this tenant's own
/// content_hash / blob_key / size_bytes onto <c>tenant_artifact_access</c> is what lets the
/// per-tenant serve projections hand each tenant the bytes it resolved itself, and it is written
/// only from a fetch this tenant actually performed — see <see cref="CacheAccessOrigin"/>.
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
    /// otherwise touches its <c>last_accessed_at</c>. Always upserts the per-tenant access row,
    /// carrying this tenant's content binding when the access is a fetch that produced one.
    /// Returns the <c>cache_artifact.id</c> on success, or <c>null</c> when recording fails or
    /// the access is refused.
    ///
    /// A <see cref="CacheAccessOrigin.FirstFetch"/> that carries no SHA-256 or no blob key is
    /// refused outright: it is asking to admit bytes it cannot identify, so no binding can be
    /// written for the tenant and the serve path would fall back to whatever the shared row
    /// holds — which is exactly the substitution the binding exists to prevent. A security gate
    /// does not degrade to "allow" because its input signal is missing. The check reads the
    /// arguments alone, so it is settled before the retry loop below rather than inside it.
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
        if (access.Origin == CacheAccessOrigin.FirstFetch
            && (string.IsNullOrEmpty(access.Sha256) || string.IsNullOrEmpty(access.BlobKey)))
        {
            DependablyMeter.CacheUnidentifiedFetchRefusals.Add(
                1,
                new KeyValuePair<string, object?>("ecosystem", access.Ecosystem));

            _logger.LogWarning(
                "Cache-plane first fetch refused as unidentified: {Ecosystem}/{Name}@{Version} " +
                "{Filename} (org {OrgId}) supplied no content hash or no blob key, so no tenant " +
                "content binding could be recorded. The fetch is refused rather than admitted " +
                "against whatever bytes the shared coordinate row already holds.",
                access.Ecosystem, access.Name, access.Version, access.Filename, access.OrgId);

            return null;
        }

        string? id = await RecordAccessImplAsync(access, ct);
        return id is not null || ct.IsCancellationRequested
            ? id
            : await RecordAccessImplAsync(access, ct);
    }

    private async Task<string?> RecordAccessImplAsync(CacheAccess access, CancellationToken ct)
    {
        var (orgId, ecosystem, name, version, filename,
             sha256, sizeBytes, blobKey, upstreamUrl, origin) = access;
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

                // A lost insert race resolves to the winner's row, whose bytes are the winner's,
                // not this call's — InsertAsync re-reads by coordinate after ON CONFLICT DO
                // NOTHING, so the row that comes back may hold content this tenant never fetched.
                // The divergence is reported for the same reason as the cache-hit branch below,
                // and it is harmless for the same reason: the binding written from this call's own
                // hash and blob key, never from the row's, is what this tenant is served.
                ReportDivergence(inserted.ContentHash, sha256, access);
            }
            else
            {
                artifactId = existing.Id;
                await _cache.TouchAccessAsync(existing.Id, now, ct);

                // Content divergence: a freshly-fetched SHA-256 that differs from the globally
                // cached row means two organisations resolved different bytes for the same
                // coordinate — most plausibly because one org's upstream is not the other's. The
                // cache_artifact row is NOT mutated, and this org is NOT refused: it is bound to
                // its own bytes below, so the shared row's content stops being what it is served.
                ReportDivergence(existing.ContentHash, sha256, access);
            }

            await _access.UpsertAsync(
                orgId, artifactId, now, BindingFor(origin, sha256, blobKey, sizeBytes), ct);
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

    // The tenant content binding this access establishes. Only a fetch this tenant performed is
    // evidence of what the tenant's own upstream served: a cache hit re-states facts already read
    // off the plane, so binding from one would let the coordinate's shared values overwrite the
    // tenant's own. Each field is bound independently and a missing one leaves the stored value
    // alone (the repository COALESCEs), so a path that knows the blob key but not the hash still
    // binds the half it knows.
    //
    // FirstFetchUnidentified never binds a hash, even a non-empty one. By definition that path did
    // not hash the bytes it staged, so any hash it carries was read off the shared coordinate row —
    // which is another tenant's when the coordinate diverges. Binding it would leave this tenant
    // holding its own blob_key beside a hash over somebody else's bytes, and CacheArtifactServeFacts
    // publishes that hash as the ETag: exactly the mixed provenance the binding exists to prevent.
    // The blob key is safe to bind alone because this origin is only permitted where the key is
    // tenant-scoped.
    //
    // A zero size is not bound either. It is what a path reports when it could not measure the
    // stream (a non-seekable blob store), not a measurement of zero, and binding it would shadow a
    // good size on the shared row with a value the HEAD Content-Length is served from.
    private static TenantContentBinding BindingFor(
        CacheAccessOrigin origin, string sha256, string blobKey, long sizeBytes) =>
        origin == CacheAccessOrigin.CacheHit
            ? TenantContentBinding.None
            : new TenantContentBinding(
                ContentHash: string.IsNullOrEmpty(sha256) || origin == CacheAccessOrigin.FirstFetchUnidentified
                    ? null
                    : sha256,
                BlobKey: string.IsNullOrEmpty(blobKey) ? null : blobKey,
                SizeBytes: string.IsNullOrEmpty(blobKey) || sizeBytes <= 0 ? null : sizeBytes);

    // Counts and logs a coordinate whose already-cached bytes differ from the ones this access
    // carries. Reporting only: the divergence is not an error for the requesting tenant, and
    // refusing here would let whichever tenant reaches a coordinate first deny it to every other.
    private void ReportDivergence(string cachedHash, string fetchedHash, CacheAccess access)
    {
        if (string.IsNullOrEmpty(fetchedHash)
            || string.IsNullOrEmpty(cachedHash)
            || string.Equals(fetchedHash, cachedHash, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        DependablyMeter.CacheContentDivergences.Add(
            1,
            new KeyValuePair<string, object?>("ecosystem", access.Ecosystem));

        _logger.LogWarning(
            "Cache-plane content divergence detected: {Ecosystem}/{Name}@{Version} " +
            "{Filename} — cached hash {CachedHash}, diverging hash {DivertingHash}, " +
            "requesting org {OrgId}. The cached row is unchanged and this org is bound to the " +
            "bytes it fetched itself, which is what it is served from here on.",
            access.Ecosystem, access.Name, access.Version, access.Filename,
            cachedHash, fetchedHash, access.OrgId);
    }
}

/// <summary>
/// What a <see cref="CacheAccess"/> is evidence of, and therefore whether it may write the
/// tenant's content binding on <c>tenant_artifact_access</c>.
/// </summary>
public enum CacheAccessOrigin
{
    /// <summary>
    /// The caller fetched these bytes on this request and computed their SHA-256. Both the hash
    /// and the blob key are required — an access that cannot identify the bytes it is admitting
    /// is refused rather than attached to whatever the shared coordinate row already holds.
    /// </summary>
    FirstFetch,

    /// <summary>
    /// The caller fetched these bytes on this request but does not compute their SHA-256 on this
    /// path. Permitted only where the blob key is tenant-scoped (Go modules, apk packages), so
    /// the bytes behind it can never be handed to another tenant even when the shared coordinate
    /// row names a different upstream's content.
    ///
    /// Binds the blob key and nothing else. Any hash such a call carries came off the shared
    /// coordinate row rather than from the bytes it staged, so binding it would pair this tenant's
    /// blob key with another tenant's hash.
    /// </summary>
    FirstFetchUnidentified,

    /// <summary>
    /// An access tick for bytes already admitted for this tenant. Carries no new evidence — its
    /// hash is typically read straight back off the plane — so it never writes the binding.
    /// </summary>
    CacheHit,
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
    string? UpstreamUrl,
    /// <summary>
    /// Whether this access is a fetch the tenant performed (and so may bind the tenant to these
    /// bytes) or a tick against bytes already admitted. Positional and required so a new call
    /// site cannot leave the binding decision to a default: the difference between the two is
    /// whether the tenant is served its own bytes or the coordinate's.
    /// </summary>
    CacheAccessOrigin Origin);
