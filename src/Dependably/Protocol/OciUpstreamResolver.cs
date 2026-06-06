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

    public OciUpstreamResolver(
        IHttpClientFactory http,
        OciUpstreamAuthService auth,
        IOptions<OciOptions> options,
        TieredBlobStorage blobs,
        IMetadataStore db,
        IAirGapMode airGap,
        ILogger<OciUpstreamResolver> logger)
    {
        _http = http;
        _auth = auth;
        _options = options;
        _blobs = blobs;
        _db = db;
        // PackageRepository is a stateless Dapper wrapper over the same IMetadataStore, so it is
        // built here rather than injected — this keeps the constructor within S107's 7-parameter
        // limit and avoids a Scoped-style repository being captured by this Singleton resolver.
        _packages = new PackageRepository(db);
        _airGap = airGap;
        _logger = logger;
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
            foreach (var prefix in u.Prefixes)
            {
                if (string.IsNullOrEmpty(prefix) ||
                    repository.StartsWith(prefix, StringComparison.Ordinal))
                    return u;
            }
        }
        return null;
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
        if (_airGap.IsEnabled) throw new AirGappedException($"oci-manifest::{repository}/{reference}");

        // For digest references, the cache is authoritative (content-addressed).
        if (isDigest)
        {
            var cached = await TryGetCachedManifestByDigestAsync(orgId, reference, ct);
            if (cached is not null) return cached;
        }
        else
        {
            // Tag reference: use cache only when within TTL.
            var cached = await TryGetCachedTagManifestAsync(orgId, repository, reference, ct);
            if (cached is not null) return cached;
        }

        var upstream = MatchUpstream(repository);
        if (upstream is null) return null;

        return await FetchAndCacheManifestAsync(upstream, orgId, repository, reference, ct);
    }

    /// <summary>
    /// Returns the OCI blob for <paramref name="digest"/> from cache or from upstream.
    /// The digest is verified against the downloaded bytes; a mismatch evicts the
    /// partially-written cache entry and returns null.
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
        if (_airGap.IsEnabled) throw new AirGappedException($"oci-blob::{repository}/{digest}");

        var parts = digest.Split(':', 2);
        if (parts.Length != 2) return null;
        var algo = parts[0];
        var hex  = parts[1];
        var blobKey = BlobKeys.OciBlob(algo, hex);

        // Blob may already be in cache from a prior org or prior request.
        var existing = await _blobs.Cache.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            // Ensure a DB row exists for this org (another org may have primed the key).
            await EnsureBlobDbRowAsync(orgId, digest, "application/octet-stream", 0, blobKey, ct);
            return new OciBlobResult(existing, "application/octet-stream");
        }

        var upstream = MatchUpstream(repository);
        if (upstream is null) return null;

        return await FetchAndCacheBlobAsync(upstream, orgId, repository, digest, blobKey, ct);
    }

    /// <summary>
    /// Returns the list of tags for <paramref name="repository"/> from upstream.
    /// Returns null when no upstream matches, the upstream returns 404, or the response is
    /// malformed.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<List<string>?> FetchTagsAsync(string repository, CancellationToken ct)
    {
        if (_airGap.IsEnabled) throw new AirGappedException($"oci-tags::{repository}");

        var upstream = MatchUpstream(repository);
        if (upstream is null) return null;

        var client = _http.CreateClient("OciUpstream");
        var url   = $"https://{upstream.Host}/v2/{repository}/tags/list";
        const string scope = "pull";

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (authHeader is not null)
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);

            using var resp = await client.SendAsync(req, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == 0)
            {
                _auth.InvalidateToken(upstream, repository, scope);
                continue;
            }
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("OCI tags/{Repository} upstream {Host} returned {Status}",
                    repository, upstream.Host, resp.StatusCode);
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("tags", out var tagsEl)) return null;
            return tagsEl.EnumerateArray()
                .Where(t => t.ValueKind == JsonValueKind.String)
                .Select(t => t.GetString()!)
                .ToList();
        }

        return null;
    }

    // ── Cache lookup helpers ───────────────────────────────────────────────────

    private async Task<OciManifestResult?> TryGetCachedManifestByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is already tenant-scoped.
        var row = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        if (row.BlobKey is null) return null;

        var stream = await _blobs.Cache.GetAsync(row.BlobKey, ct);
        if (stream is null) return null; // evicted — fall through to upstream

        return new OciManifestResult(stream, row.MediaType ?? "application/octet-stream", digest, row.SizeBytes);
    }

    private async Task<OciManifestResult?> TryGetCachedTagManifestAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var row = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });

        if (row.Digest is null) return null;

        var ttl = _options.Value.ManifestTagTtl;
        if (row.LastRevalidated is not null &&
            DateTimeOffset.TryParse(row.LastRevalidated, null, System.Globalization.DateTimeStyles.RoundtripKind, out var revalidated) &&
            DateTimeOffset.UtcNow - revalidated < ttl)
        {
            return await TryGetCachedManifestByDigestAsync(orgId, row.Digest, ct);
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
        var url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        const string scope = "pull";

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var fetched = await TryFetchManifestAsync(upstream, repository, reference, scope, url, attempt, ct);
            if (fetched.Retry) continue;
            if (fetched.Result is null) return null;

            return await CacheAndReturnManifestAsync(upstream, orgId, repository, reference, fetched.Result, ct);
        }

        return null;
    }

    private async Task<(bool Retry, FetchedManifest? Result)> TryFetchManifestAsync(
        OciUpstreamRegistryOptions upstream, string repository, string reference, string scope,
        string url, int attempt, CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        var authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        foreach (var mt in ManifestAcceptTypes)
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue(mt));
        if (authHeader is not null)
            req.Headers.TryAddWithoutValidation("Authorization", authHeader);

        using var resp = await client.SendAsync(req, ct);

        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == 0)
        {
            _auth.InvalidateToken(upstream, repository, scope);
            return (Retry: true, Result: null);
        }
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return (false, null);
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

        var mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        var digest = ResolveDigest(resp, repository, reference, bytes, out var sha256Hex);

        return (false, new FetchedManifest(bytes, mediaType, digest, sha256Hex));
    }

    private string ResolveDigest(
        HttpResponseMessage resp, string repository, string reference, byte[] bytes, out string sha256Hex)
    {
        var sha256Bytes = SHA256.HashData(bytes);
        sha256Hex = Convert.ToHexString(sha256Bytes).ToLowerInvariant();
        var digest = "sha256:" + sha256Hex;

        // The content-addressed identity is the SHA-256 of the exact bytes cached and served, so
        // a by-digest fetch always returns bytes that hash to the requested digest (the OCI
        // Distribution Spec invariant). If upstream's Docker-Content-Digest disagrees, treat it
        // as an upstream integrity anomaly and keep the computed value — never adopt an
        // unverified header as the stored digest identity.
        if (resp.Headers.TryGetValues("Docker-Content-Digest", out var dcdValues))
        {
            var upstreamDigest = dcdValues.FirstOrDefault();
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
        var blobKey = BlobKeys.OciBlob("sha256", m.Sha256Hex);

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
            var pkg  = await _packages.GetOrCreateAsync(orgId, "oci", entry.Repository, entry.Repository, isProxy: true, ct);
            var purl = PurlNormalizer.Oci(entry.Repository, entry.Digest, entry.Tag);
            await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, entry.Digest, purl, entry.BlobKey, entry.SizeBytes, entry.Sha256Hex, FirstFetch: true, Origin: "proxy"),
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (ex is not Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 19 })
                _logger.LogWarning(
                    "{ExceptionType} cataloguing OCI version {Repository}@{Digest}; pull unaffected. BlobKey={BlobKey} TraceId={TraceId}",
                    ex.GetType().Name, entry.Repository, entry.Digest, entry.BlobKey,
                    System.Diagnostics.Activity.Current?.TraceId.ToString());
        }
    }

    private async Task<OciBlobResult?> FetchAndCacheBlobAsync(
        OciUpstreamRegistryOptions upstream,
        string orgId,
        string repository,
        string digest,
        string blobKey,
        CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        var url    = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        const string scope = "pull";

        // Expected hex for post-download verification.
        var digestParts = digest.Split(':', 2);
        var expectedHex = digestParts.Length == 2 ? digestParts[1].ToLowerInvariant() : "";

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var authHeader = await _auth.GetAuthorizationAsync(upstream, repository, scope, ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/octet-stream"));
            if (authHeader is not null)
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);

            // ResponseHeadersRead → don't buffer response in memory.
            var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == 0)
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

            var mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
            long bytesWritten;

            // Stream upstream → OciDigestVerifyStream → blob cache (zero-copy buffering).
            await using (var contentStream = await resp.Content.ReadAsStreamAsync(ct))
            await using (var verifyStream = new OciDigestVerifyStream(contentStream))
            {
                await _blobs.Cache.PutAsync(blobKey, verifyStream, ct);
                bytesWritten = verifyStream.BytesWritten;

                var computedDigest = verifyStream.ComputedDigest;
                if (!string.Equals(computedDigest, $"sha256:{expectedHex}", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "OCI blob digest mismatch for {Repository}/{Digest}: expected sha256:{Expected}, computed {Computed}",
                        repository, digest, expectedHex, computedDigest);
                    await _blobs.Cache.DeleteAsync(blobKey, ct);
                    resp.Dispose();
                    return null;
                }
            }

            resp.Dispose();

            // Persist DB row for this org.
            await EnsureBlobDbRowAsync(orgId, digest, mediaType, bytesWritten, blobKey, ct);

            // Read back from cache for streaming to the controller.
            var cacheStream = await _blobs.Cache.GetAsync(blobKey, ct);
            if (cacheStream is null) return null;

            _logger.LogInformation(
                "OCI blob proxy {Repository}/{Digest} ({Bytes} B) from {Host}",
                repository, digest, bytesWritten, upstream.Host);

            return new OciBlobResult(cacheStream, mediaType);
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

// ── Result types ──────────────────────────────────────────────────────────────

/// <summary>Resolved manifest with its content stream, media type, digest, and byte count.</summary>
public sealed record OciManifestResult(Stream Content, string MediaType, string Digest, long SizeBytes);

/// <summary>Resolved blob with its content stream and media type.</summary>
public sealed record OciBlobResult(Stream Content, string MediaType);

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
    private long _bytesWritten;

    public OciDigestVerifyStream(Stream inner) => _inner = inner;

    public long BytesWritten => _bytesWritten;

    /// <summary>Returns <c>sha256:{lowercaseHex}</c> of all bytes read so far.</summary>
    public string ComputedDigest
        => "sha256:" + Convert.ToHexString(_hasher.GetCurrentHash()).ToLowerInvariant();

    public override bool CanRead  => true;
    public override bool CanSeek  => false;
    public override bool CanWrite => false;
    public override long Length   => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var read = _inner.Read(buffer, offset, count);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            _bytesWritten += read;
        }
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var read = await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            _bytesWritten += read;
        }
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await _inner.ReadAsync(buffer, cancellationToken);
        if (read > 0)
        {
            _hasher.AppendData(buffer.Span[..read]);
            _bytesWritten += read;
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
