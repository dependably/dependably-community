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

    // SQLite SQLITE_CONSTRAINT error code (unique constraint violation on insert).
    private const int SqliteConstraintErrorCode = 19;

    // All four manifest media types accepted by current Docker and OCI clients.
    private static readonly string[] ManifestAcceptTypes =
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];

    private readonly IHttpClientFactory _http;
    private readonly OciUpstreamAuthService _auth;
    private readonly IOptions<OciOptions> _options;
    private readonly TieredBlobStorage _blobs;
    private readonly IMetadataStore _db;
    private readonly PackageRepository _packages;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<OciUpstreamResolver> _logger;
    private readonly TimeProvider _time;

    // Single-flight dedup for concurrent OCI blob fetches: keyed by the content-addressed
    // blob key (BlobKeys.OciBlob(algo, hex)) so concurrent cache-misses for the same
    // digest collapse to one upstream pull. The shared work item writes the verified blob
    // to the cache store and returns only metadata (key + media type) — NOT an open stream.
    // Each waiter independently calls _blobs.Cache.GetAsync after the Lazy resolves to open
    // its OWN stream, avoiding use-after-dispose when N callers race on the same digest.
    // CancellationToken.None prevents a single caller disconnect from faulting the shared
    // Lazy and cancelling all other waiters — the blob write is idempotent.
    private readonly ConcurrentDictionary<string, Lazy<Task<OciBlobFetchMetadata?>>> _blobInflight = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification =
            "Resolver aggregates 8 independent DI-resolved services (HTTP client factory, auth service, " +
            "options, tiered blob storage, metadata store, air-gap mode, logger, clock). " +
            "Bundling into a wrapper record would obscure the DI graph.")]
    public OciUpstreamResolver(
        IHttpClientFactory http,
        OciUpstreamAuthService auth,
        IOptions<OciOptions> options,
        TieredBlobStorage blobs,
        IMetadataStore db,
        IAirGapMode airGap,
        ILogger<OciUpstreamResolver> logger,
        TimeProvider time)
    {
        _http = http;
        _auth = auth;
        _options = options;
        _blobs = blobs;
        _db = db;
        // PackageRepository is a stateless Dapper wrapper over the same IMetadataStore, so it is
        // built here rather than injected — this avoids a Scoped-style repository being captured
        // by this Singleton resolver.
        _packages = new PackageRepository(db, time: time);
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// Finds the first upstream registry whose prefix list matches <paramref name="repository"/>.
    /// An empty string prefix is the catch-all fallback. Returns null when no upstreams are
    /// configured or none matches.
    /// </summary>
    public OciUpstreamRegistryOptions? MatchUpstream(string repository)
    {
        foreach (var u in _options.Value.Upstreams)
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

        var upstream = MatchUpstream(repository);
        return upstream is null ? null : await FetchManifestMetadataFromUpstreamAsync(upstream, repository, reference, ct);
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
        OciUpstreamRegistryOptions upstream, string repository, string reference, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        const string scope = "pull";
        var client = _http.CreateClient("OciUpstream");

        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            string? authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
            using var req = new HttpRequestMessage(HttpMethod.Head, url);
            foreach (string mt in ManifestAcceptTypes)
            {
                req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue(mt));
            }

            if (authHeader is not null)
            {
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);
            }

            using var resp = await client.SendAsync(req, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
            {
                _auth.InvalidateToken(upstream, repository, scope);
                continue;
            }

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("OCI manifest HEAD {Repository}:{Reference} upstream {Host} returned {Status}",
                    repository, reference, upstream.Host, resp.StatusCode);
                return null;
            }

            return ExtractManifestMetadataFromHeadResponse(resp, repository, reference, upstream.Host);
        }

        return null;
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

        var upstream = MatchUpstream(repository);
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

        string algo = parts[0];
        string hex = parts[1];
        string blobKey = BlobKeys.OciBlob(algo, hex);

        // Blob may already be in cache from a prior request — just confirm existence.
        if (await _blobs.Cache.ExistsAsync(blobKey, ct))
        {
            return new OciBlobMetadata("application/octet-stream");
        }

        var upstream = MatchUpstream(repository);
        if (upstream is null)
        {
            return null;
        }

        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        const string scope = "pull";

        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            string? authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
            using var req = new HttpRequestMessage(HttpMethod.Head, url);
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/octet-stream"));
            if (authHeader is not null)
            {
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);
            }

            using var resp = await client.SendAsync(req, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
            {
                _auth.InvalidateToken(upstream, repository, scope);
                continue;
            }

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("OCI blob HEAD {Digest} upstream {Host} returned {Status}",
                    digest, upstream.Host, resp.StatusCode);
                return null;
            }

            string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
            return new OciBlobMetadata(mediaType);
        }

        return null;
    }

    /// <summary>
    /// Returns the OCI blob for <paramref name="digest"/> from cache or from upstream.
    /// The digest is verified against the downloaded bytes; a mismatch evicts the
    /// partially-written cache entry and returns null.
    ///
    /// Concurrent cache-misses for the same digest are collapsed by a single-flight
    /// coordinator (keyed by the content-addressed blob key) so only one upstream pull
    /// runs per digest per process. Each waiter re-opens the cached blob independently
    /// after the shared fetch completes.
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

        // Blob may already be in cache from a prior org or prior request.
        var existing = await _blobs.Cache.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            // Ensure a DB row exists for this org (another org may have primed the key).
            await EnsureBlobDbRowAsync(orgId, digest, "application/octet-stream", 0, blobKey, ct);
            return new OciBlobResult(existing, "application/octet-stream");
        }

        var upstream = MatchUpstream(repository);
        if (upstream is null)
        {
            return null;
        }

        // Single-flight: collapse concurrent misses for the same blob key into one fetch.
        // The shared work item (FetchAndCacheBlobAsync) writes the verified blob to the cache
        // store and returns only metadata (blobKey + mediaType). Each waiter below opens its
        // OWN stream via _blobs.Cache.GetAsync so no stream is shared across callers.
        // CancellationToken.None: a caller disconnect must not fault the shared Lazy and
        // cancel all other waiters. Blob writes are idempotent (content-addressed key).
        var lazy = _blobInflight.GetOrAdd(blobKey, _ => new Lazy<Task<OciBlobFetchMetadata?>>(
            () => FetchAndCacheBlobAsync(upstream, orgId, repository, digest, blobKey, CancellationToken.None),
            LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            // WaitAsync(ct) lets the caller's request token abort the wait without
            // cancelling the shared upstream fetch that other waiters depend on.
            var meta = await lazy.Value.WaitAsync(ct);
            if (meta is null)
            {
                return null;
            }

            // Each waiter opens an INDEPENDENT stream from the cache store — never shared.
            var stream = await _blobs.Cache.GetAsync(meta.BlobKey, ct);
            return stream is null ? null : new OciBlobResult(stream, meta.MediaType);
        }
        finally
        {
            _blobInflight.TryRemove(blobKey, out _);
        }
    }

    /// <summary>
    /// Returns the list of tags for <paramref name="repository"/> from upstream.
    /// Returns null when no upstream matches, the upstream returns 404, or the response is
    /// malformed.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<List<string>?> FetchTagsAsync(string repository, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-tags::{repository}");
        }

        var upstream = MatchUpstream(repository);
        if (upstream is null)
        {
            return null;
        }

        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/tags/list";
        const string scope = "pull";

        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            using var resp = await SendAuthenticatedTagRequestAsync(client, upstream, repository, url, scope, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
            {
                _auth.InvalidateToken(upstream, repository, scope);
                continue;
            }
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("OCI tags/{Repository} upstream {Host} returned {Status}",
                    repository, upstream.Host, resp.StatusCode);
                return null;
            }

            return await ReadTagListFromResponseAsync(resp, repository, upstream.Host, url, ct);
        }

        return null;
    }

    // Sends an authenticated GET request for the tags/list endpoint and returns the response.
    private async Task<HttpResponseMessage> SendAuthenticatedTagRequestAsync(
        HttpClient client, OciUpstreamRegistryOptions upstream,
        string repository, string url, string scope, CancellationToken ct)
    {
        string? authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (authHeader is not null)
        {
            req.Headers.TryAddWithoutValidation("Authorization", authHeader);
        }

        return await client.SendAsync(req, ct);
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
        const string scope = "pull";

        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            var (Retry, Result) = await TryFetchManifestAsync(upstream, repository, reference, scope, url, attempt, ct);
            if (Retry)
            {
                continue;
            }

            return Result is null ? null : await CacheAndReturnManifestAsync(upstream, orgId, repository, reference, Result, ct);
        }

        return null;
    }

    private async Task<(bool Retry, FetchedManifest? Result)> TryFetchManifestAsync(
        OciUpstreamRegistryOptions upstream, string repository, string reference, string scope,
        string url, int attempt, CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        string? authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        foreach (string mt in ManifestAcceptTypes)
        {
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue(mt));
        }

        if (authHeader is not null)
        {
            req.Headers.TryAddWithoutValidation("Authorization", authHeader);
        }

        using var resp = await client.SendAsync(req, ct);

        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
        {
            _auth.InvalidateToken(upstream, repository, scope);
            return (Retry: true, Result: null);
        }
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return (false, null);
        }
        // A non-success status here (e.g. Docker Hub returns 401 — not 404 — for a
        // nonexistent/unauthorized repository even after the token retry) must surface
        // as a clean OCI MANIFEST_UNKNOWN 404 from the controller, not an unhandled
        // HttpRequestException → 500. Mirror the blob/tags paths: log and return null.
        if (!resp.IsSuccessStatusCode)
        {
            _logger.LogWarning("OCI manifest {Repository}:{Reference} upstream {Host} returned {Status}",
                repository, reference, upstream.Host, resp.StatusCode);
            return (false, null);
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
            return (false, null);
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
            return (false, null);
        }

        return (false, new FetchedManifest(bytes, mediaType, digest, sha256Hex));
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
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy',
                    strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            ON CONFLICT(digest, org_id) DO UPDATE SET
                upstream_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
            """,
            new { digest = m.Digest, orgId, mediaType = m.MediaType, sizeBytes = (long)m.Bytes.Length, blobKey });

        // Upsert tag → digest when the reference is a tag (not a digest).
        if (!OciCoordinatesParser.IsValidDigest(reference))
        {
            // xtenant: (org_id, repository, tag) PK.
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
                VALUES (@orgId, @repo, @tag, @digest,
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                ON CONFLICT(org_id, repository, tag) DO UPDATE SET
                    digest          = excluded.digest,
                    updated_at      = strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                    last_revalidated = strftime('%Y-%m-%dT%H:%M:%SZ','now')
                """,
                new { orgId, repo = repository, tag = reference, digest = m.Digest });

            // Surface the pulled image in the shared package catalogue the dashboards +
            // Packages page read from. OCI otherwise lives only in oci_blobs/oci_tags and
            // counts as zero everywhere. Only tag pulls are catalogued (the user-facing
            // unit); by-digest sub-manifest fetches the daemon issues afterwards are not.
            await RecordCatalogVersionAsync(
                orgId,
                new OciCatalogEntry(repository, reference, m.Digest, m.Sha256Hex, (long)m.Bytes.Length, blobKey),
                ct);
        }

        _logger.LogInformation(
            "OCI manifest proxy {Repository}/{Reference} → {Digest} ({Bytes} B) from {Host}",
            repository, reference, m.Digest, m.Bytes.Length, upstream.Host);

        return new OciManifestResult(new MemoryStream(m.Bytes), m.MediaType, m.Digest, m.Bytes.Length);
    }

    private sealed record FetchedManifest(byte[] Bytes, string MediaType, string Digest, string Sha256Hex);

    private readonly record struct OciCatalogEntry(
        string Repository, string Tag, string Digest, string Sha256Hex, long SizeBytes, string BlobKey);

    /// <summary>
    /// Records the pulled image in the shared package catalogue (<c>packages</c> /
    /// <c>package_versions</c>) so the overview counts, Packages page, and disk chart see OCI
    /// like every other ecosystem — it otherwise lives only in <c>oci_blobs</c>/<c>oci_tags</c>
    /// and renders as zero. The manifest digest is the content-addressed version identity; the
    /// resolving tag is captured in the PURL qualifier.
    ///
    /// Best-effort and idempotent: a unique-constraint hit (SQLite error 19) is the expected
    /// re-pull / many-tags-to-one-digest / cross-org-same-image case and is swallowed silently;
    /// any other failure is logged at Warning but never propagated — the manifest has already
    /// streamed to the client, so cataloguing must not fail the pull.
    /// </summary>
    private async Task RecordCatalogVersionAsync(string orgId, OciCatalogEntry entry, CancellationToken ct)
    {
        try
        {
            // purl_name == repository so the Packages-page detail route (/packages/oci/{name})
            // resolves; isProxy=true marks the package as upstream-backed.
            var pkg = await _packages.GetOrCreateAsync(orgId, "oci", entry.Repository, entry.Repository, isProxy: true, ct);
            string purl = PurlNormalizer.Oci(entry.Repository, entry.Digest, entry.Tag);
            await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, entry.Digest, purl, entry.BlobKey, entry.SizeBytes, entry.Sha256Hex, FirstFetch: true, Origin: "proxy"),
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (ex is not Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: SqliteConstraintErrorCode })
            {
                _logger.LogWarning(
                    "{ExceptionType} cataloguing OCI version {Repository}@{Digest}; pull unaffected. BlobKey={BlobKey} TraceId={TraceId}",
                    ex.GetType().Name, entry.Repository, entry.Digest, entry.BlobKey,
                    System.Diagnostics.Activity.Current?.TraceId.ToString());
            }
        }
    }

    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<OciBlobFetchMetadata?> FetchAndCacheBlobAsync(
        OciUpstreamRegistryOptions upstream,
        string orgId,
        string repository,
        string digest,
        string blobKey,
        CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        const string scope = "pull";

        // Expected hex for post-download verification.
        string[] digestParts = digest.Split(':', DigestSplitParts);
        string expectedHex = digestParts.Length == DigestSplitParts ? digestParts[1].ToLowerInvariant() : "";

        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            string? authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/octet-stream"));
            if (authHeader is not null)
            {
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);
            }

            // ResponseHeadersRead → don't buffer response in memory.
            var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
            {
                resp.Dispose();
                _auth.InvalidateToken(upstream, repository, scope);
                continue;
            }
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                resp.Dispose();
                return null;
            }
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("OCI blob {Digest} upstream {Host} returned {Status}",
                    digest, upstream.Host, resp.StatusCode);
                resp.Dispose();
                return null;
            }

            string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
            long bytesWritten;

            // Verify-then-commit: stream upstream bytes into an ephemeral staging key so
            // the content-addressed blobKey is never written until the digest is confirmed.
            // A concurrent cache-first reader (FetchBlobAsync) checks blobKey directly;
            // because blobKey is only populated after a successful verification here, a
            // cache-first branch can only ever serve verified bytes.
            string stagingKey = BlobKeys.OciStaging(Guid.NewGuid().ToString("N"));

            await using (var contentStream = await resp.Content.ReadAsStreamAsync(ct))
            await using (var verifyStream = new OciDigestVerifyStream(contentStream))
            {
                await _blobs.Cache.PutAsync(stagingKey, verifyStream, ct);
                bytesWritten = verifyStream.BytesWritten;

                string computedDigest = verifyStream.ComputedDigest;
                if (!string.Equals(computedDigest, $"sha256:{expectedHex}", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "OCI blob digest mismatch for {Repository}/{Digest}: expected sha256:{Expected}, computed {Computed}",
                        repository, digest, expectedHex, computedDigest);
                    await _blobs.Cache.DeleteAsync(stagingKey, ct);
                    resp.Dispose();
                    return null;
                }
            }

            // Digest verified — promote staging entry to the content-addressed key, then
            // clean up the staging slot so it never persists beyond this request.
            var stagedStream = await _blobs.Cache.GetAsync(stagingKey, ct);
            if (stagedStream is not null)
            {
                await _blobs.Cache.PutAsync(blobKey, stagedStream, ct);
            }

            await _blobs.Cache.DeleteAsync(stagingKey, ct);

            resp.Dispose();

            // Persist DB row for this org.
            await EnsureBlobDbRowAsync(orgId, digest, mediaType, bytesWritten, blobKey, ct);

            _logger.LogInformation(
                "OCI blob proxy {Repository}/{Digest} ({Bytes} B) from {Host}",
                repository, digest, bytesWritten, upstream.Host);

            // Return only metadata — each waiter opens its own stream independently in
            // FetchBlobAsync, so the single shared result never carries a shared stream.
            return new OciBlobFetchMetadata(blobKey, mediaType);
        }

        return null;
    }

    private async Task EnsureBlobDbRowAsync(
        string orgId, string digest, string mediaType, long sizeBytes, string blobKey, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy',
                    strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            ON CONFLICT(digest, org_id) DO NOTHING
            """,
            new { digest, orgId, mediaType, sizeBytes, blobKey });
    }
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

    public OciDigestVerifyStream(Stream inner) => _inner = inner;

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

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            BytesWritten += read;
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
