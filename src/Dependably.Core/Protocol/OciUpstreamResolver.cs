using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.Extensions.Options;

namespace Dependably.Protocol;

/// <summary>
/// Fetches OCI manifests, blobs, and tag lists from configured upstream registries.
///
/// Prefix routing: the first <see cref="OciUpstreamRegistryOptions"/> whose
/// <c>Prefixes</c> list contains a prefix of the repository name wins.
/// Auth is delegated to <see cref="OciUpstreamAuthService"/>; a 401 from upstream triggers
/// one token eviction + retry.
///
/// Manifest TTL: tag → digest mappings are re-validated against upstream when
/// <c>oci_tags.last_revalidated</c> is older than <c>ManifestTagTtl</c>.
/// Digest references are immutable per the Distribution Spec — served from cache without
/// an upstream round-trip.
///
/// Blob fetching: the digest is known from the request, so the blob store key
/// (<see cref="BlobKeys.OciBlob"/>) is computed before downloading. The upstream response
/// is streamed through an <see cref="OciDigestVerifyStream"/> for live SHA-256 verification;
/// the verified bytes are written to <see cref="TieredBlobStorage.Cache"/>, then read back
/// for streaming to the caller.
/// </summary>
public sealed class OciUpstreamResolver
{
    // Split limit for OCI digest strings: algorithm and hex are exactly two parts ({algo}:{hex}).
    private const int DigestSplitParts = 2;

    // Auth retry pattern: one initial attempt and one retry after token invalidation.
    private const int UpstreamMaxAttempts = 2;
    private const int UpstreamFirstAttempt = 0;

    // All four manifest media types accepted by current Docker and OCI clients.
    private static readonly string[] ManifestAcceptTypes =
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];

    // Constant filename recorded on an OCI manifest's cache_artifact row. version is the
    // content-addressed digest, so a fixed filename is safe and collision-free within the
    // (ecosystem, name, version, filename) UNIQUE coordinate — this row always represents the
    // pullable manifest, never a layer or config blob (those stay in oci_blobs only, with no
    // cache_artifact row). Internal so SchemaInitializer's backfill migration can reuse it.
    internal const string ManifestCacheFilename = "manifest";

    private readonly IHttpClientFactory _http;
    private readonly OciUpstreamAuthService _auth;
    private readonly IOptions<OciOptions> _options;
    private readonly TieredBlobStorage _blobs;
    private readonly IMetadataStore _db;
    private readonly PackageRepository _packages;
    private readonly UpstreamRegistryRepository _upstreamRepo;
    private readonly IAirGapMode _airGap;
    private readonly OciImageLicenseRecorder _licenseRecorder;
    private readonly OciReferenceGraph _referenceGraph;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly ILogger<OciUpstreamResolver> _logger;
    private readonly TimeProvider _time;

    // Single-flight dedup for concurrent OCI blob fetches: keyed by (org id, content-addressed
    // blob key) so concurrent cache-misses for the same digest WITHIN ONE ORG collapse to one
    // upstream pull. The org is part of the key because the shared work item captures the
    // winner's org, upstream, and credentials: a key of bytes alone would hand a caller from
    // another tenant a payload pulled with credentials it never holds, from a registry it
    // cannot reach. The shared work item writes the verified blob to the cache store and
    // returns only metadata (key + media type) — NOT an open stream. Each waiter independently
    // calls _blobs.Cache.GetAsync after the Lazy resolves to open its OWN stream, avoiding
    // use-after-dispose when N callers race on the same digest. CancellationToken.None prevents
    // a single caller disconnect from faulting the shared Lazy and cancelling all other
    // waiters — the blob write is idempotent.
    private readonly ConcurrentDictionary<OciBlobInflightKey, Lazy<Task<OciBlobFetchMetadata?>>> _blobInflight = new();

    // Test-only observation seam (InternalsVisibleTo Dependably.Tests): counts callers that have
    // reached the _blobInflight registration point for a given (org, blob key), so a concurrency
    // test can deterministically wait for "all N callers have registered as winner/joiner"
    // instead of guessing at that moment with a timeout. Never read on any production path.
    private readonly ConcurrentDictionary<OciBlobInflightKey, int> _blobInflightArrivals = new();

    /// <summary>
    /// Number of <see cref="FetchBlobAsync"/> callers from <paramref name="orgId"/> that have
    /// registered against the shared in-flight entry for <paramref name="blobKey"/> (winner +
    /// joiners), for deterministic concurrency-test synchronization only.
    /// </summary>
    internal int BlobInflightArrivalCount(string orgId, string blobKey) =>
        _blobInflightArrivals.TryGetValue(new OciBlobInflightKey(orgId, blobKey), out int count) ? count : 0;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification =
            "Resolver aggregates 12 independent DI-resolved services (HTTP client factory, auth service, " +
            "options, tiered blob storage, metadata store, air-gap mode, license recorder, cache-plane " +
            "recorder + repository, logger, clock, secret protector). Bundling into a wrapper record " +
            "would obscure the DI graph.")]
    public OciUpstreamResolver(
        IHttpClientFactory http,
        OciUpstreamAuthService auth,
        IOptions<OciOptions> options,
        TieredBlobStorage blobs,
        IMetadataStore db,
        IAirGapMode airGap,
        OciImageLicenseRecorder licenseRecorder,
        CacheAccessRecorder cacheRecorder,
        CacheArtifactRepository cacheArtifacts,
        ILogger<OciUpstreamResolver> logger,
        TimeProvider time,
        Dependably.Infrastructure.Identity.EnvelopeProtector envelope)
    {
        _http = http;
        _auth = auth;
        _options = options;
        _blobs = blobs;
        _db = db;
        // Repository wrappers are stateless Dapper helpers over the shared IMetadataStore.
        // Built here rather than injected to avoid capturing Scoped services in this Singleton.
        _packages = new PackageRepository(db, time: time);
        _upstreamRepo = new UpstreamRegistryRepository(db, time, envelope);
        _referenceGraph = new OciReferenceGraph(db);
        _airGap = airGap;
        _licenseRecorder = licenseRecorder;
        // CacheAccessRecorder and CacheArtifactRepository are registered as singletons (stateless
        // Dapper helpers over the shared IMetadataStore), so — unlike the scoped services this
        // resolver avoids capturing — they are safe to inject directly here.
        _cacheRecorder = cacheRecorder;
        _cacheArtifacts = cacheArtifacts;
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// Finds the first upstream registry for <paramref name="orgId"/> whose prefix list matches
    /// <paramref name="repository"/>. An empty string prefix is the catch-all fallback. Returns
    /// null when no upstreams are configured for the org or none matches.
    /// </summary>
    public async Task<OciUpstreamRegistryOptions?> MatchUpstreamAsync(
        string orgId, string repository, CancellationToken ct)
    {
        var upstreams = await _upstreamRepo.BuildOciUpstreamsForOrgAsync(orgId, ct);
        foreach (var u in upstreams)
        {
            foreach (string prefix in u.Prefixes)
            {
                if (string.IsNullOrEmpty(prefix) ||
                    repository.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return u;
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Fetches only the header metadata (digest, size, media type) for a manifest from the
    /// upstream registry using a HEAD request — no body is downloaded. Used by the manifest
    /// HEAD handler on a cache-miss to avoid downloading the full manifest body only to
    /// discard it.
    ///
    /// Checks the local cache first (same TTL logic as <see cref="FetchManifestAsync"/>).
    /// Falls back to an upstream HEAD on a cache-miss. Returns <c>null</c> when no upstream
    /// matches, the upstream returns 404, or the upstream does not supply the required headers.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciManifestMetadata?> FetchManifestMetadataAsync(
        string orgId,
        string repository,
        string reference,
        bool isDigest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-manifest::{repository}/{reference}");
        }

        // Check the local cache before hitting upstream — a cached manifest already has
        // all the metadata we need without any network round-trip.
        var fromCache = isDigest
            ? await TryGetCachedManifestMetadataByDigestAsync(orgId, reference, ct)
            : await TryGetCachedTagManifestMetadataAsync(orgId, repository, reference, ct);

        if (fromCache is not null)
        {
            return fromCache;
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        return upstream is null ? null : await FetchManifestMetadataFromUpstreamAsync(orgId, upstream, repository, reference, ct);
    }

    private async Task<OciManifestMetadata?> TryGetCachedManifestMetadataByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        // Confirm the blob is still present in the store without opening a stream.
        bool exists = await _blobs.Cache.ExistsAsync(BlobKey, ct)
            || await _blobs.Registry.ExistsAsync(BlobKey, ct);
        return exists ? new OciManifestMetadata(digest, MediaType ?? "application/octet-stream", SizeBytes) : null;
    }

    private async Task<OciManifestMetadata?> TryGetCachedTagManifestMetadataAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });

        if (Digest is null)
        {
            return null;
        }

        var ttl = _options.Value.ManifestTagTtl;
        return LastRevalidated is not null &&
            DateTimeOffset.TryParse(LastRevalidated, null, System.Globalization.DateTimeStyles.RoundtripKind, out var revalidated) &&
            _time.GetUtcNow() - revalidated < ttl
            ? await TryGetCachedManifestMetadataByDigestAsync(orgId, Digest, ct)
            : null;
    }

    private async Task<OciManifestMetadata?> FetchManifestMetadataFromUpstreamAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string reference, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        var client = _http.CreateClient("OciUpstream");
        string logContext = $"OCI manifest HEAD {repository}:{reference} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Head, url, ManifestAcceptTypes, upstream, repository, "pull", logContext, ct);
        return resp is null ? null : ExtractManifestMetadataFromHeadResponse(resp, repository, reference, upstream.Host);
    }

    // Extracts OciManifestMetadata from a successful HEAD response.
    // Returns null when no usable digest can be determined from the response headers.
    private OciManifestMetadata? ExtractManifestMetadataFromHeadResponse(
        HttpResponseMessage resp, string repository, string reference, string upstreamHost)
    {
        // Prefer the upstream's Docker-Content-Digest header as the digest; fall back
        // to the reference itself when the reference is already a digest.
        string? upstreamDigest = resp.Headers.TryGetValues("Docker-Content-Digest", out var dcdVals)
            ? dcdVals.FirstOrDefault()
            : null;

        string digest = !string.IsNullOrEmpty(upstreamDigest)
            ? upstreamDigest
            : OciCoordinatesParser.IsValidDigest(reference) ? reference : string.Empty;

        if (string.IsNullOrEmpty(digest))
        {
            _logger.LogWarning(
                "OCI manifest HEAD {Repository}:{Reference} from {Host}: no Docker-Content-Digest header and reference is not a digest; cannot satisfy HEAD without body download.",
                repository, reference, upstreamHost);
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        long sizeBytes = resp.Content.Headers.ContentLength ?? 0;
        return new OciManifestMetadata(digest, mediaType, sizeBytes);
    }

    /// <summary>
    /// Returns the OCI manifest for <paramref name="repository"/>/<paramref name="reference"/>
    /// from cache (if fresh) or from the upstream registry.
    ///
    /// For digest references the cache is checked first (content-addressed → immutable).
    /// For tag references the cache is used only when <c>last_revalidated</c> is within
    /// <c>ManifestTagTtl</c>; otherwise the upstream is consulted and the local tag entry
    /// is refreshed.
    ///
    /// Returns null when no upstream matches or the upstream returns 404.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciManifestResult?> FetchManifestAsync(
        string orgId,
        string repository,
        string reference,
        bool isDigest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-manifest::{repository}/{reference}");
        }

        // For digest references, the cache is authoritative (content-addressed).
        if (isDigest)
        {
            var cached = await TryGetCachedManifestByDigestAsync(orgId, reference, ct);
            if (cached is not null)
            {
                return cached;
            }
        }
        else
        {
            // Tag reference: use cache only when within TTL.
            var cached = await TryGetCachedTagManifestAsync(orgId, repository, reference, ct);
            if (cached is not null)
            {
                return cached;
            }
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        return upstream is null ? null : await FetchAndCacheManifestAsync(upstream, orgId, repository, reference, ct);
    }

    /// <summary>
    /// Fetches only the header metadata for an OCI blob from upstream using a HEAD request —
    /// no body is downloaded. Returns a <see cref="OciBlobMetadata"/> record with the media
    /// type from the upstream response headers when the blob exists, or <c>null</c> when
    /// no upstream matches or the upstream returns 404.
    /// Used by the blob HEAD handler on a cache-miss to avoid downloading the full layer blob.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciBlobMetadata?> FetchBlobMetadataAsync(
        string orgId,
        string repository,
        string digest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-blob::{repository}/{digest}");
        }

        string[] parts = digest.Split(':', DigestSplitParts);
        if (parts.Length != 2)
        {
            return null;
        }

        // Answer a cache-hit HEAD only from an oci_blobs row scoped to THIS org. A bare
        // content-key existence probe against the shared, content-addressed cache store would
        // report 200/404 based on whether the digest exists for ANY tenant — a cross-tenant
        // existence oracle over org-agnostic storage. Scoping to (digest, org_id) confines the
        // answer to blobs the caller's own org has actually fetched; anything else falls through
        // to a real, org-scoped upstream HEAD.
        var cached = await TryGetCachedBlobMetadataByDigestAsync(orgId, digest, ct);
        if (cached is not null)
        {
            return cached;
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        if (upstream is null)
        {
            return null;
        }

        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        string logContext = $"OCI blob HEAD {digest} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Head, url, ["application/octet-stream"], upstream, repository, "pull", logContext, ct);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        return new OciBlobMetadata(mediaType);
    }

    // Returns blob HEAD metadata only when the org owns an oci_blobs row for the digest AND the
    // backing bytes are still present in the store. A dangling row (blob evicted) returns null so
    // the caller falls through to upstream rather than reporting a false 200. The (digest, org_id)
    // scope is what keeps a blob HEAD from becoming a cross-tenant existence oracle over the shared
    // content-addressed cache store.
    private async Task<OciBlobMetadata?> TryGetCachedBlobMetadataByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (MediaType, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, string? BlobKey)>(
            "SELECT media_type AS MediaType, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        bool exists = await _blobs.Cache.ExistsAsync(BlobKey, ct)
            || await _blobs.Registry.ExistsAsync(BlobKey, ct);
        return exists ? new OciBlobMetadata(MediaType ?? "application/octet-stream") : null;
    }

    /// <summary>
    /// Returns the OCI blob for <paramref name="digest"/> from cache or from upstream.
    /// The digest is verified against the downloaded bytes; a mismatch evicts the
    /// partially-written cache entry and returns null.
    ///
    /// A hit on the shared content-addressed store is served only to an org that already
    /// holds its own <c>oci_blobs</c> row for the digest; any other caller falls through to
    /// its own org-scoped upstream fetch, which re-authenticates and re-verifies the digest.
    ///
    /// Concurrent cache-misses are collapsed by a single-flight coordinator keyed on
    /// (org id, content-addressed blob key), so one upstream pull runs per digest per org
    /// per process and a caller may only await a fetch made with its own org's credentials.
    /// Each waiter re-opens the cached blob independently after the shared fetch completes.
    ///
    /// Returns null when no upstream matches or the upstream returns 404.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciBlobResult?> FetchBlobAsync(
        string orgId,
        string repository,
        string digest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-blob::{repository}/{digest}");
        }

        string[] parts = digest.Split(':', DigestSplitParts);
        if (parts.Length != 2)
        {
            return null;
        }

        string algo = parts[0];
        string hex = parts[1];
        string blobKey = BlobKeys.OciBlob(algo, hex);

        // Blob may already be in the shared content-addressed store from a prior org or request.
        // A bare store hit is NOT authorization: the key (oci/{algo}/{hex}) has no org segment, so
        // in the default single-store deployment (cache == registry) another tenant's PRIVATE
        // uploaded or proxy-cached bytes live under the identical key. Serve the hit only when the
        // caller's own org already holds an oci_blobs row for this digest (its own prior upload or
        // proxy fetch); otherwise dispose the unused stream and fall through to a real upstream
        // fetch scoped to this org (which re-authenticates and re-verifies the digest before
        // caching, rather than trusting that any configured upstream proves entitlement). That
        // fallthrough is a real fetch even under concurrency: the single-flight entry below is
        // keyed per org, so it can never be satisfied by another org's in-flight pull.
        var existing = await _blobs.Cache.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            if (await CanServeSharedBlobAsync(orgId, digest, ct))
            {
                return new OciBlobResult(existing, "application/octet-stream");
            }

            await existing.DisposeAsync();
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        if (upstream is null)
        {
            return null;
        }

        // Single-flight: collapse concurrent misses for the same blob into one fetch, keyed on
        // (orgId, blobKey) — never on the content-addressed key alone. The work item captures
        // the org, upstream, and credentials of whichever caller creates the entry, so a key of
        // bytes alone lets a caller from another org await that fetch and receive a private
        // layer pulled with credentials it does not hold, from a registry it cannot reach: the
        // digest-guessing read the entitlement check above refuses, granted through the
        // in-flight window instead. With the org in the key, every caller sharing an entry is
        // from the org whose credentials the entry uses. Concurrent misses in different orgs
        // each pay their own upstream pull and prove their own entitlement; the bytes still
        // dedup in the store, because the write targets the content-addressed key and is
        // idempotent.
        //
        // The shared work item (FetchAndCacheBlobAsync) writes the verified blob to the cache
        // store, persists this org's oci_blobs row, and returns only metadata (blobKey +
        // mediaType). Each waiter below opens its OWN stream via _blobs.Cache.GetAsync so no
        // stream is shared across callers. CancellationToken.None: a caller disconnect must not
        // fault the shared Lazy and cancel all other waiters. Blob writes are idempotent
        // (content-addressed key).
        var inflightKey = new OciBlobInflightKey(orgId, blobKey);
        var lazy = _blobInflight.GetOrAdd(inflightKey, _ => new Lazy<Task<OciBlobFetchMetadata?>>(
            () => FetchAndCacheBlobAsync(orgId, upstream, repository, digest, blobKey, CancellationToken.None),
            LazyThreadSafetyMode.ExecutionAndPublication));
        _blobInflightArrivals.AddOrUpdate(inflightKey, 1, (_, count) => count + 1);

        // Removes exactly this (inflightKey, lazy) pair once the shared fetch genuinely
        // completes — success or failure — never when an individual caller's WaitAsync(ct) below
        // merely detaches early. A caller cancelling mid-fetch must not evict a live in-flight
        // entry while the shared upstream pull is still running for the remaining waiters, and
        // the pair-targeted removal never touches a newer generation that replaced this entry.
        // Every concurrent caller attaches its own continuation to the same Task; TryRemove is
        // idempotent — only the first continuation to run has any effect.
        _ = lazy.Value.ContinueWith(
            completedTask =>
            {
                _blobInflight.TryRemove(
                    new KeyValuePair<OciBlobInflightKey, Lazy<Task<OciBlobFetchMetadata?>>>(inflightKey, lazy));
                // Bounds _blobInflightArrivals to the same lifecycle as _blobInflight — otherwise
                // every distinct digest ever fetched would leak an entry for the life of the process.
                _blobInflightArrivals.TryRemove(inflightKey, out int _);
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

        // WaitAsync(ct) lets the caller's request token abort the wait without
        // cancelling the shared upstream fetch that other waiters depend on.
        var meta = await lazy.Value.WaitAsync(ct);
        if (meta is null)
        {
            return null;
        }

        // No per-caller oci_blobs row is written here: the in-flight entry is org-keyed, so the
        // work item that resolved it ran for THIS org and already persisted that org's row (with
        // the real media type and size) plus, on first insert, the config-blob arrival hook.
        // A row minted here for a caller the work item did not fetch for would be a grant of
        // another org's bytes on the strength of nothing but a digest.
        //
        // Each waiter opens an INDEPENDENT stream from the cache store — never shared.
        var stream = await _blobs.Cache.GetAsync(meta.BlobKey, ct);
        return stream is null ? null : new OciBlobResult(stream, meta.MediaType);
    }

    /// <summary>
    /// Returns the list of tags for <paramref name="repository"/> from upstream.
    /// Returns null when no upstream matches, the upstream returns 404, or the response is
    /// malformed.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<List<string>?> FetchTagsAsync(string orgId, string repository, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-tags::{repository}");
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        if (upstream is null)
        {
            return null;
        }

        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/tags/list";
        string logContext = $"OCI tags/{repository} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, [], upstream, repository, "pull", logContext, ct);
        return resp is null ? null : await ReadTagListFromResponseAsync(resp, repository, upstream.Host, url, ct);
    }

    // Sends an authenticated HTTP request with a single 401-triggered token eviction and retry.
    // Returns the successful response (caller owns disposal), or null on 404 or any other
    // non-success status (logged at Warning). The 401 on the first attempt evicts the cached
    // token and retries once; a 401 on the retry is treated as a non-success and returns null.
    // Pass HttpCompletionOption.ResponseHeadersRead for streaming body callers.
    // All 11 parameters are distinct protocol-layer inputs (orgId, HTTP client, method, URL,
    // accept types, upstream config, repository, auth scope, log context, cancellation,
    // completion option); grouping them into a request record would scatter the construction
    // across 5+ callers without reducing the conceptual surface.
#pragma warning disable S107 // Each parameter is a distinct protocol-layer input with no natural grouping
    private async Task<HttpResponseMessage?> SendUpstreamWithAuthRetryAsync(
        string orgId,
        HttpClient client,
        HttpMethod method,
        string url,
        IEnumerable<string> acceptTypes,
        OciUpstreamRegistryOptions upstream,
        string repository,
        string scope,
        string logContext,
        CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
#pragma warning restore S107
    {
        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            string? authHeader = await _auth.GetAuthorizationAsync(orgId, upstream, repository, scope, ct);
            var req = new HttpRequestMessage(method, url);
            foreach (string mt in acceptTypes)
            {
                req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue(mt));
            }

            if (authHeader is not null)
            {
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);
            }

            var resp = await client.SendAsync(req, completionOption, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
            {
                resp.Dispose();
                _auth.InvalidateToken(orgId, upstream, repository, scope);
                continue;
            }

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                resp.Dispose();
                return null;
            }

            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("{LogContext} returned {Status}", logContext, resp.StatusCode);
                resp.Dispose();
                return null;
            }

            return resp;
        }

        return null;
    }

    // Reads the tags/list JSON response body and extracts the tags array as a string list.
    // Returns null when the body exceeds the metadata cap or the tags property is absent.
    private async Task<List<string>?> ReadTagListFromResponseAsync(
        HttpResponseMessage resp, string repository, string host, string url, CancellationToken ct)
    {
        byte[] body;
        try
        {
            // Tag lists are small JSON documents; cap the buffered read like manifests.
            body = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "OCI tags/{Repository} from {Host} exceeded the metadata cap; refusing.",
                repository, host);
            return null;
        }

        using var doc = JsonDocument.Parse(body);
        return !doc.RootElement.TryGetProperty("tags", out var tagsEl)
            ? null
            : tagsEl.EnumerateArray()
            .Where(t => t.ValueKind == JsonValueKind.String)
            .Select(t => t.GetString()!)
            .ToList();
    }

    // ── Cache lookup helpers ───────────────────────────────────────────────────

    private async Task<OciManifestResult?> TryGetCachedManifestByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is already tenant-scoped.
        var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        if (BlobKey is null)
        {
            return null;
        }

        var stream = await _blobs.Cache.GetAsync(BlobKey, ct);
        if (stream is null)
        {
            return null; // evicted — fall through to upstream
        }

        return new OciManifestResult(stream, MediaType ?? "application/octet-stream", digest, SizeBytes);
    }

    private async Task<OciManifestResult?> TryGetCachedTagManifestAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });

        if (Digest is null)
        {
            return null;
        }

        var ttl = _options.Value.ManifestTagTtl;
        if (LastRevalidated is not null &&
            DateTimeOffset.TryParse(LastRevalidated, null, System.Globalization.DateTimeStyles.RoundtripKind, out var revalidated) &&
            _time.GetUtcNow() - revalidated < ttl)
        {
            return await TryGetCachedManifestByDigestAsync(orgId, Digest, ct);
        }

        // Stale or missing — fall through to upstream.
        return null;
    }

    // ── Upstream fetch + cache-write helpers ──────────────────────────────────

    private async Task<OciManifestResult?> FetchAndCacheManifestAsync(
        OciUpstreamRegistryOptions upstream,
        string orgId,
        string repository,
        string reference,
        CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        var manifest = await TryFetchManifestAsync(orgId, upstream, repository, reference, url, ct);
        return manifest is null ? null : await CacheAndReturnManifestAsync(upstream, orgId, repository, reference, manifest, ct);
    }

    private async Task<FetchedManifest?> TryFetchManifestAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string reference,
        string url, CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        // A non-success status (e.g. Docker Hub returns 401 — not 404 — for a
        // nonexistent/unauthorized repository even after the token retry) must surface
        // as a clean OCI MANIFEST_UNKNOWN 404 from the controller, not an unhandled
        // HttpRequestException → 500. Mirror the blob/tags paths: log and return null.
        string logContext = $"OCI manifest {repository}:{reference} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, ManifestAcceptTypes, upstream, repository, "pull", logContext, ct);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        byte[] bytes;
        try
        {
            // Manifests are small JSON documents (the spec recommends ≤ 4 MB); cap the buffered
            // read so a hostile upstream cannot materialise an arbitrarily large body in memory.
            bytes = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "OCI manifest {Repository}:{Reference} from {Host} exceeded the metadata cap; refusing.",
                repository, reference, upstream.Host);
            return null;
        }
        string digest = ResolveDigest(resp, repository, reference, bytes, out string? sha256Hex);

        // For by-digest references the caller already knows which digest to expect.
        // Verify the computed digest matches before caching — if upstream returns bytes
        // that hash to a different digest the fetch fails closed (no cache write, no DB
        // row) rather than serving attacker-controlled content under the requested key.
        if (OciCoordinatesParser.IsValidDigest(reference) &&
            !string.Equals(digest, reference, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "OCI manifest digest mismatch for {Repository}/{Reference}: computed {Computed} does not match requested digest",
                repository, reference, digest);
            return null;
        }

        return new FetchedManifest(bytes, mediaType, digest, sha256Hex);
    }

    private string ResolveDigest(
        HttpResponseMessage resp, string repository, string reference, byte[] bytes, out string sha256Hex)
    {
        byte[] sha256Bytes = SHA256.HashData(bytes);
        sha256Hex = Convert.ToHexString(sha256Bytes).ToLowerInvariant();
        string digest = "sha256:" + sha256Hex;

        // The content-addressed identity is the SHA-256 of the exact bytes cached and served, so
        // a by-digest fetch always returns bytes that hash to the requested digest (the OCI
        // Distribution Spec invariant). If upstream's Docker-Content-Digest disagrees, treat it
        // as an upstream integrity anomaly and keep the computed value — never adopt an
        // unverified header as the stored digest identity.
        if (resp.Headers.TryGetValues("Docker-Content-Digest", out var dcdValues))
        {
            string? upstreamDigest = dcdValues.FirstOrDefault();
            if (!string.IsNullOrEmpty(upstreamDigest) && upstreamDigest != digest)
            {
                _logger.LogWarning(
                    "OCI {Repository}/{Reference}: upstream Docker-Content-Digest {Upstream} differs from computed {Computed}; using computed",
                    repository, reference, upstreamDigest, digest);
            }
        }
        return digest;
    }

    private async Task<OciManifestResult> CacheAndReturnManifestAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string reference,
        FetchedManifest m, CancellationToken ct)
    {
        string blobKey = BlobKeys.OciBlob("sha256", m.Sha256Hex);

        // Write manifest bytes into the proxy cache tier.
        await _blobs.Cache.PutAsync(blobKey, new MemoryStream(m.Bytes), ct);

        await using var conn = await _db.OpenAsync(ct);

        // xtenant: (digest, org_id) PK is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy', @now)
            ON CONFLICT(digest, org_id) DO UPDATE SET
                upstream_checked_at = @now
            """,
            new
            {
                digest = m.Digest,
                orgId,
                mediaType = m.MediaType,
                sizeBytes = (long)m.Bytes.Length,
                blobKey,
                now = UtcTimestamp.Now(_time),
            });

        // Capture the image license from the config label onto this manifest row. Runs outside the
        // tag branch so by-digest child manifests of a pulled index are covered too. Best-effort.
        await _licenseRecorder.RecordManifestAsync(orgId, m.Digest, m.Bytes, ct);

        // Record what this manifest references, so eviction can tell a shared layer from an
        // orphaned one. Outside the tag branch for the same reason as the license capture: an
        // index's by-digest children are manifests in their own right and each has a closure.
        // A body that does not parse records nothing, leaving the manifest un-evictable — the
        // conservative direction, and the same posture the read path takes on a malformed body.
        if (OciManifestParser.ParseReferences(m.Bytes) is { } refs)
        {
            await _referenceGraph.RecordAsync(orgId, m.Digest, refs.Digests, ct);
        }

        // Upsert tag → digest when the reference is a tag (not a digest).
        if (!OciCoordinatesParser.IsValidDigest(reference))
        {
            // xtenant: (org_id, repository, tag) PK.
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
                VALUES (@orgId, @repo, @tag, @digest, @now, @now)
                ON CONFLICT(org_id, repository, tag) DO UPDATE SET
                    digest          = excluded.digest,
                    updated_at      = excluded.updated_at,
                    last_revalidated = excluded.last_revalidated
                """,
                new { orgId, repo = repository, tag = reference, digest = m.Digest, now = UtcTimestamp.Now(_time) });

            // Surface the pulled image in the shared package catalogue the dashboards +
            // Packages page read from. OCI otherwise lives only in oci_blobs/oci_tags and
            // counts as zero everywhere. Only tag pulls are catalogued (the user-facing
            // unit); by-digest sub-manifest fetches the daemon issues afterwards are not.
            string manifestUrl = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
            await RecordCatalogVersionAsync(
                orgId,
                new OciCatalogEntry(repository, reference, m.Digest, m.Sha256Hex, (long)m.Bytes.Length, blobKey, manifestUrl),
                ct);
        }

        _logger.LogInformation(
            "OCI manifest proxy {Repository}/{Reference} → {Digest} ({Bytes} B) from {Host}",
            repository, reference, m.Digest, m.Bytes.Length, upstream.Host);

        return new OciManifestResult(new MemoryStream(m.Bytes), m.MediaType, m.Digest, m.Bytes.Length);
    }

    private sealed record FetchedManifest(byte[] Bytes, string MediaType, string Digest, string Sha256Hex);

    private readonly record struct OciCatalogEntry(
        string Repository, string Tag, string Digest, string Sha256Hex, long SizeBytes, string BlobKey,
        string? UpstreamUrl);

    /// <summary>
    /// Records the pulled image in the shared package catalogue: a <c>packages</c> row (so the
    /// Packages page and its detail route resolve the repository name) plus a global-plane
    /// <c>cache_artifact</c> / <c>tenant_artifact_access</c> row pair — the same shared cache
    /// plane every other proxy ecosystem uses — rather than a <c>package_versions</c> row. The
    /// manifest digest is the content-addressed version identity; the resolving tag is captured
    /// in the PURL qualifier. Only manifest pulls land a row here — one per pullable image,
    /// matching a <c>docker pull</c> 1:1; layers and config blobs stay in <c>oci_blobs</c> as
    /// pure byte storage with no cache-plane entry.
    ///
    /// Best-effort: the caller (<see cref="CacheAndReturnManifestAsync"/>) awaits this before
    /// returning the manifest to the client, so an unhandled exception here would 500 a pull
    /// whose bytes are already durably cached (blob store + <c>oci_blobs</c> row, both written
    /// before this call). <see cref="CacheAccessRecorder.RecordAccessAsync"/> already swallows
    /// its own failures and <see cref="PackageRepository.GetOrCreateAsync"/> resolves races via
    /// <c>ON CONFLICT DO NOTHING</c> + re-read, but <see cref="CacheArtifactRepository.UpdateGlobalFactsAsync"/>
    /// and the <c>GetOrCreateAsync</c> call itself are plain Dapper calls that still throw on a
    /// transient fault (SQLITE_BUSY, a dropped connection) — caught here so cataloguing can never
    /// fail the pull.
    /// </summary>
    private async Task RecordCatalogVersionAsync(string orgId, OciCatalogEntry entry, CancellationToken ct)
    {
        try
        {
            // purl_name == repository so the Packages-page detail route (/packages/oci/{name})
            // resolves; isProxy=true marks the package as upstream-backed.
            await _packages.GetOrCreateAsync(orgId, "oci", entry.Repository, entry.Repository, isProxy: true, ct);
            string purl = PurlNormalizer.Oci(entry.Repository, entry.Digest, entry.Tag);

            // Name is entry.Repository, matching the purl_name GetOrCreateAsync just wrote onto
            // the packages row above — the cross-plane version-count join in PackageRepository
            // keys on ca.name = p.purl_name. BlobKey is left as the oci/{algo}/{hex} store key
            // rather than routed through BlobKeys.Proxy, which throws on a non-64-hex key.
            string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
                new CacheAccess(
                    orgId, "oci", entry.Repository, entry.Digest, ManifestCacheFilename,
                    entry.Sha256Hex, entry.SizeBytes, entry.BlobKey, entry.UpstreamUrl,
                    // The manifest was pulled and digested on this request. The coordinate is the
                    // digest itself, so two orgs resolving one coordinate to different bytes is
                    // not expressible here — the binding is recorded for uniformity, not defence.
                    CacheAccessOrigin.FirstFetch),
                ct);

            if (cacheArtifactId is not null)
            {
                await _cacheArtifacts.UpdateGlobalFactsAsync(
                    cacheArtifactId,
                    purl: purl,
                    checksumSha1: null,
                    publishedAt: null,
                    deprecated: null,
                    hasInstallScript: false,
                    installScriptKind: null,
                    provenanceStatus: null,
                    provenanceSigner: null,
                    upstreamIntegrityValue: null,
                    upstreamIntegrityAlgorithm: null,
                    ct: ct);
            }

            // The manifest's license was stamped onto oci_blobs before this row existed; project it
            // onto the row now so every license reader sees it through the shared table.
            await _licenseRecorder.ProjectLicenseToCatalogAsync(orgId, entry.Digest, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} cataloguing OCI version {Repository}@{Digest}; pull unaffected. BlobKey={BlobKey} TraceId={TraceId}",
                ex.GetType().Name, entry.Repository, entry.Digest, entry.BlobKey,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
        }
    }

    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<OciBlobFetchMetadata?> FetchAndCacheBlobAsync(
        string orgId,
        OciUpstreamRegistryOptions upstream,
        string repository,
        string digest,
        string blobKey,
        CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        string logContext = $"OCI blob {digest} upstream {upstream.Host}";

        // Expected hex for post-download verification.
        string[] digestParts = digest.Split(':', DigestSplitParts);
        string expectedHex = digestParts.Length == DigestSplitParts ? digestParts[1].ToLowerInvariant() : "";

        // ResponseHeadersRead → don't buffer response in memory; stream body directly to blob store.
        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, ["application/octet-stream"], upstream, repository, "pull", logContext, ct,
            completionOption: HttpCompletionOption.ResponseHeadersRead);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        long bytesWritten;

        // Cheap fail-fast on a declared Content-Length before streaming a single byte, mirroring
        // every other ecosystem's upstream-fetch path (UpstreamClient.FetchAndStageCoreAsync).
        // OciDigestVerifyStream below still enforces the same cap for chunked transfers that
        // arrive with no Content-Length header at all.
        if (resp.Content.Headers.ContentLength > UpstreamClient.MaxUpstreamResponseBytes)
        {
            _logger.LogWarning(
                "OCI blob {Repository}/{Digest} from {Host} declared Content-Length {ContentLength} exceeding the {MaxBytes}-byte upstream cap; refusing.",
                repository, digest, upstream.Host, resp.Content.Headers.ContentLength, UpstreamClient.MaxUpstreamResponseBytes);
            return null;
        }

        // Verify-then-commit: stream upstream bytes into an ephemeral staging key so
        // the content-addressed blobKey is never written until the digest is confirmed.
        // A concurrent cache-first reader (FetchBlobAsync) checks blobKey directly;
        // because blobKey is only populated after a successful verification here, a
        // cache-first branch can only ever serve verified bytes.
        string stagingKey = BlobKeys.OciStaging(Guid.NewGuid().ToString("N"));

        try
        {
            await using var contentStream = await resp.Content.ReadAsStreamAsync(ct);
            await using var verifyStream = new OciDigestVerifyStream(contentStream, UpstreamClient.MaxUpstreamResponseBytes);

            await _blobs.Cache.PutAsync(stagingKey, verifyStream, ct);
            bytesWritten = verifyStream.BytesWritten;

            string computedDigest = verifyStream.ComputedDigest;
            if (!string.Equals(computedDigest, $"sha256:{expectedHex}", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "OCI blob digest mismatch for {Repository}/{Digest}: expected sha256:{Expected}, computed {Computed}",
                    repository, digest, expectedHex, computedDigest);
                await _blobs.Cache.DeleteAsync(stagingKey, ct);
                return null;
            }
        }
        catch (UpstreamResponseTooLargeException)
        {
            // Delete-on-refuse: a coordinate-addressed staging entry left behind here would be a
            // permanent bypass of this cap for every future request that races the same digest.
            _logger.LogWarning(
                "OCI blob {Repository}/{Digest} from {Host} exceeded the {MaxBytes}-byte upstream cap mid-stream; refusing.",
                repository, digest, upstream.Host, UpstreamClient.MaxUpstreamResponseBytes);
            await _blobs.Cache.DeleteAsync(stagingKey, ct);
            return null;
        }

        // Digest verified — promote staging entry to the content-addressed key, then
        // clean up the staging slot so it never persists beyond this request.
        var stagedStream = await _blobs.Cache.GetAsync(stagingKey, ct);
        if (stagedStream is not null)
        {
            await _blobs.Cache.PutAsync(blobKey, stagedStream, ct);
        }

        await _blobs.Cache.DeleteAsync(stagingKey, ct);

        // Persist DB row for this org.
        bool inserted = await EnsureBlobDbRowAsync(orgId, digest, mediaType, bytesWritten, blobKey, ct);
        if (inserted)
        {
            // First insert of this blob for the org: reverse-lookup any manifest awaiting its
            // config license. Runs under the same single-flight token as the surrounding fetch.
            await _licenseRecorder.RecordConfigBlobArrivalAsync(orgId, digest, blobKey, ct);
        }

        _logger.LogInformation(
            "OCI blob proxy {Repository}/{Digest} ({Bytes} B) from {Host}",
            repository, digest, bytesWritten, upstream.Host);

        // Return only metadata — each waiter opens its own stream independently in
        // FetchBlobAsync, so the single shared result never carries a shared stream.
        return new OciBlobFetchMetadata(blobKey, mediaType);
    }

    // Decides whether a bare hit on the shared content-addressed blob store may be served to
    // orgId. The store is content-addressed with no org segment, so in the default
    // single-store deployment (cache == registry) one tenant's bytes — private uploads AND
    // proxy-cached layers pulled through an authenticated upstream — resolve under the same key
    // as anyone else's; a raw store hit is never proof of authorization on its own. Entitlement
    // holds only when the caller's own org already has an oci_blobs row for the digest: its own
    // upload, or a proxy fetch it already performed (and so already authenticated) itself.
    //
    // Deliberately no cross-org exception for proxy-origin rows: a repository name is
    // caller-supplied and an upstream with an empty prefix matches every repository, so "the
    // caller has some configured upstream" proves nothing about whether that upstream's
    // credentials can actually reach this digest — it lets a caller who guesses a digest (they
    // leak routinely via SBOMs, CI logs, pinned references) read another org's private layer
    // without ever presenting that org's upstream credentials. A non-owning org falls through to
    // its own real, org-scoped upstream fetch below, which re-authenticates and re-verifies the
    // digest — the only trustworthy proof the caller is entitled to the bytes. The single-flight
    // dedup on that path is keyed on (org, blob key), so a caller racing another org's in-flight
    // pull of the same digest still makes its own authenticated request rather than awaiting,
    // and inheriting the result of, a fetch made with another tenant's credentials.
    private async Task<bool> CanServeSharedBlobAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped — the same predicate the blob HEAD path
        // (TryGetCachedBlobMetadataByDigestAsync) answers existence with, so GET and HEAD cannot
        // disagree about which org may see a digest.
        int owned = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(1) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        return owned > 0;
    }

    // Returns true when a NEW row was inserted (ON CONFLICT DO NOTHING → 0 rows on an existing
    // row). Callers use the flag to run the config-blob license reverse-lookup ONLY on a genuine
    // first insert, so a warm blob GET — which runs this on every request — pays nothing extra.
    private async Task<bool> EnsureBlobDbRowAsync(
        string orgId, string digest, string mediaType, long sizeBytes, string blobKey, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        int rows = await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy', @now)
            ON CONFLICT(digest, org_id) DO NOTHING
            """,
            new { digest, orgId, mediaType, sizeBytes, blobKey, now = UtcTimestamp.Now(_time) });
        return rows > 0;
    }

    // In-flight identity for a blob fetch. The org is part of the identity because the fetch it
    // guards runs with one org's upstream and credentials, and its result may only be handed to
    // callers of that org.
    private readonly record struct OciBlobInflightKey(string OrgId, string BlobKey);
}

// ── Result types ────────────────────────────────────────────────

/// <summary>Resolved manifest with its content stream, media type, digest, and byte count.</summary>
public sealed record OciManifestResult(Stream Content, string MediaType, string Digest, long SizeBytes);

/// <summary>
/// Manifest header metadata returned by a HEAD-only upstream fetch: digest, media type, and
/// byte count. No content stream is opened — used by the manifest HEAD handler on a cache-miss
/// to populate response headers without downloading the manifest body.
/// </summary>
public sealed record OciManifestMetadata(string Digest, string MediaType, long SizeBytes);

/// <summary>Resolved blob with its content stream and media type.</summary>
public sealed record OciBlobResult(Stream Content, string MediaType);

/// <summary>
/// Blob header metadata returned by a HEAD-only upstream fetch: media type only.
/// The digest and size are already known from the request (digest is the request parameter;
/// size is not needed for OCI blob HEAD — <c>Content-Length</c> is set from the DB row or
/// omitted on a cache-miss HEAD where the blob has not yet been fetched).
/// </summary>
public sealed record OciBlobMetadata(string MediaType);

/// <summary>
/// Metadata returned by the single-flight blob fetch work item (<c>_blobInflight</c>).
/// Carries only the content-addressed cache key and media type — NOT an open stream.
/// Each concurrent waiter opens its own stream from the cache store after the Lazy resolves,
/// preventing use-after-dispose when multiple callers race on the same digest.
/// </summary>
internal sealed record OciBlobFetchMetadata(string BlobKey, string MediaType);

// ── Digest-verifying pass-through stream ─────────────────────────────────────

/// <summary>
/// A read-only pass-through stream that computes a running SHA-256 digest over all bytes read.
/// Used by <see cref="OciUpstreamResolver"/> to verify OCI blob integrity while streaming to
/// the blob store — avoids buffering large layer blobs in memory.
/// </summary>
internal sealed class OciDigestVerifyStream : Stream
{
    private readonly Stream _inner;
    private readonly IncrementalHash _hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly long _maxBytes;

    /// <param name="inner">The upstream response body to hash and pass through.</param>
    /// <param name="maxBytes">
    /// Hard ceiling on total bytes read. Every other ecosystem's binary download path caps the
    /// upstream body (<see cref="HashingFileStream"/> for the hash-and-stage MISS path); this is
    /// OCI's equivalent for the blob proxy path, which streams straight into the blob store
    /// without ever buffering the whole body. Catches a Content-Length-less (chunked) response
    /// that a fixed pre-check on the header alone would miss.
    /// </param>
    public OciDigestVerifyStream(Stream inner, long maxBytes)
    {
        _inner = inner;
        _maxBytes = maxBytes;
    }

    public long BytesWritten { get; private set; }

    /// <summary>Returns <c>sha256:{lowercaseHex}</c> of all bytes read so far.</summary>
    public string ComputedDigest
        => "sha256:" + Convert.ToHexString(_hasher.GetCurrentHash()).ToLowerInvariant();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    private void CheckCap()
    {
        if (BytesWritten > _maxBytes)
        {
            throw new UpstreamResponseTooLargeException("(oci-blob)", _maxBytes);
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            BytesWritten += read;
            CheckCap();
        }
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int read = await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            BytesWritten += read;
            CheckCap();
        }
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read = await _inner.ReadAsync(buffer, cancellationToken);
        if (read > 0)
        {
            _hasher.AppendData(buffer.Span[..read]);
            BytesWritten += read;
            CheckCap();
        }
        return read;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
            _hasher.Dispose();
        }
        base.Dispose(disposing);
    }
}
