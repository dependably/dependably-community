using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;

namespace Dependably.Protocol;

/// <summary>
/// Upstream fetch layer for Maven artifacts and metadata.
///
/// Outbound HTTP is routed through <see cref="UpstreamClient"/> so Maven shares the
/// platform-wide guarantees with PyPI / npm / NuGet / RPM: <c>IUpstreamUrlValidator</c>
/// SSRF defence on every URL, hash-and-stage memory bounding on the fetch path,
/// the audit hook on first proxy fetch, the <c>proxy_fetches</c> metric, and
/// single-flight thundering-herd dedup on concurrent fetches of the same artifact.
///
/// Maven-specific concerns that stay in this fetcher:
/// - Negative result cache (<c>upstream_negative_cache</c>) so 404s from Maven Central
///   don't hammer upstream on every client retry.
/// - Checksum verification — when upstream serves a <c>.sha256</c> sidecar we use it as the
///   <see cref="ChecksumSpec"/> for a streaming, memory-bounded fetch. Maven Central does
///   NOT serve <c>.sha256</c> for most artifacts (only <c>.sha1</c>/<c>.md5</c>), so the
///   common path is fetch-then-hash: buffer the body, derive the content-addressed key, and
///   verify against the <c>.sha1</c> sidecar (see <see cref="FetchThenHashAsync"/>).
/// - <c>maven-metadata.xml</c> merge: union upstream version list with local versions.
///
/// Stale-fallback semantics were intentionally simplified during the UpstreamClient
/// consolidation. The pre-refactor implementation had an explicit
/// "5xx → serve stale cached bytes with Warning: 110" branch; <see cref="UpstreamClient"/>
/// now checks the cache tier first on every call, so a previously-fetched blob is
/// served as a normal cache hit (<see cref="MavenArtifactFetchResult.IsFromCache"/>=true)
/// without contacting upstream. The stale-with-Warning-header pathway is unreachable
/// from this layer and has been removed.
/// </summary>
public sealed class MavenUpstreamFetcher
{
    // Hex character prefix length used as the url_key column (first 32 hex chars of SHA-256).
    private const int UrlHashPrefixLength = 32;

    private readonly UpstreamClient _upstream;
    private readonly IBlobStore _blobs;   // cache tier — matches UpstreamClient
    private readonly IMetadataStore _db;
    private readonly IConfiguration _config;
    private readonly ILogger<MavenUpstreamFetcher> _logger;
    private readonly TimeProvider _time;

    // SHA-256 of the upstream path (first 32 hex chars) is the url_key.
    private static string UrlHash(string upstreamPath)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(upstreamPath));
        return Convert.ToHexString(hash).ToLowerInvariant()[..UrlHashPrefixLength];
    }

    public MavenUpstreamFetcher(
        UpstreamClient upstream,
        TieredBlobStorage blobs,
        IMetadataStore db,
        IConfiguration config,
        ILogger<MavenUpstreamFetcher> logger,
        TimeProvider time)
    {
        _upstream = upstream;
        // Proxy artefacts land on the cache tier (recoverable, eviction-friendly) — the
        // same store UpstreamClient writes through on the sha256-sidecar streaming path.
        _blobs = blobs.Cache;
        _db = db;
        _config = config;
        _logger = logger;
        _time = time;
    }

    private TimeSpan NegativeCacheTtl =>
        TimeSpan.TryParse(_config["Maven:NegativeCacheTtl"], out var t) ? t : TimeSpan.FromHours(1);

    private bool VerifyWithUpstreamSha256 =>
        _config.GetValue("Maven:VerifyWithUpstreamSha256", defaultValue: true);

    // ── Negative cache ─────────────────────────────────────────────────────────

    public async Task<bool> IsNegativelyCachedAsync(string upstreamPath, CancellationToken ct)
    {
        string key = UrlHash(upstreamPath);
        await using var conn = await _db.OpenAsync(ct);
        string? fetchedAt = await conn.ExecuteScalarAsync<string?>(
            // xtenant: upstream_negative_cache is not tenant-scoped; ecosystem + url_key
            // uniquely identifies the upstream resource independent of tenant. Negative
            // cache entries are a per-instance concern (the upstream either has it or doesn't).
            "SELECT fetched_at FROM upstream_negative_cache WHERE ecosystem = 'maven' AND url_key = @key",
            new { key });

        if (fetchedAt is null)
        {
            return false;
        }

        var age = _time.GetUtcNow() - DateTimeOffset.Parse(fetchedAt,
            null, System.Globalization.DateTimeStyles.RoundtripKind);
        return age < NegativeCacheTtl;
    }

    public async Task RecordNegativeAsync(string upstreamPath, CancellationToken ct)
    {
        string key = UrlHash(upstreamPath);
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: see IsNegativelyCachedAsync — instance-scoped, not tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_negative_cache (url_key, ecosystem)
            VALUES (@key, 'maven')
            ON CONFLICT(url_key, ecosystem) DO UPDATE SET fetched_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
            """,
            new { key });
    }

    // ── Artifact fetch ─────────────────────────────────────────────────────────

    /// <summary>
    /// Fetches a primary artifact from upstream on cache miss.
    /// Returns the bytes+hashes on success; null if the resource doesn't exist upstream.
    /// Throws <see cref="ChecksumException"/> on checksum mismatch.
    /// Throws <see cref="AirGappedException"/> when running in air-gap mode (raised by
    /// <see cref="UpstreamClient"/>; air-gap precheck lives there now).
    ///
    /// Stale-fallback semantics were intentionally simplified during the UpstreamClient
    /// consolidation: there is no longer a "5xx → serve previously cached bytes" branch
    /// in this method. A previously-fetched blob is served by <see cref="UpstreamClient"/>'s
    /// cache-first check before this code ever runs.
    /// </summary>
    public async Task<MavenArtifactFetchResult?> FetchArtifactAsync(
        string upstreamBase,
        string upstreamPath,
        CancellationToken ct,
        string? orgId = null,
        string? purl = null,
        string? authorizationHeader = null)
    {
        if (await IsNegativelyCachedAsync(upstreamPath, ct))
        {
            return null; // negative cache hit
        }

        string upstreamUrl = $"{upstreamBase.TrimEnd('/')}/{upstreamPath.TrimStart('/')}";

        // Optional sidecar pre-fetch for integrity verification. When present this becomes
        // the ChecksumSpec on the GetOrFetchStreamAsync call below.
        string? expectedSha256 = null;
        if (VerifyWithUpstreamSha256)
        {
            expectedSha256 = await TryFetchSidecarAsync(upstreamBase, upstreamPath, "sha256", ct, authorizationHeader);
        }

        // No .sha256 sidecar. This is the COMMON case, not an edge case: Maven Central
        // (and most Maven repos) only serve .sha1 + .md5 sidecars — .sha256/.sha512 don't
        // exist for the vast majority of artefacts. We therefore can't compute the
        // content-addressed blob key up front, so we fall back to fetch-then-hash: buffer
        // the artefact via the single-flighted metadata path, derive the key locally, and
        // verify integrity against the .sha1 sidecar when present. This mirrors PyPi's
        // unknown-sha cold-start path and is bounded byte[] residue on the MISS path.
        if (expectedSha256 is null)
        {
            Dependably.Infrastructure.Observability.DependablyMeter.MavenSidecarMissing.Add(1,
                new KeyValuePair<string, object?>(
                    "reason", VerifyWithUpstreamSha256 ? "no_sha256_sidecar" : "verify_disabled"));
            return await FetchThenHashAsync(upstreamBase, upstreamPath, upstreamUrl, orgId, authorizationHeader, ct);
        }

        string blobKey = BlobKeys.Proxy(expectedSha256);

        try
        {
            // The caller's org context rides both fetch paths: it is what binds the fill to the
            // tenant's storage quota and per-org upstream URL policy, and what scopes the audit
            // trail this fetch writes.
            var (body, isHit) = await _upstream.GetOrFetchStreamAsync(
                blobKey,
                upstreamUrl,
                new ChecksumSpec(ChecksumAlgorithm.Sha256, expectedSha256),
                ecosystem: "maven",
                orgId: orgId,
                purl: purl,
                ct: ct,
                authorizationHeader: authorizationHeader);

            // Compute the .sha1/.md5 sidecar digests by streaming the already-staged/cached blob
            // once — no full-artifact byte[] is materialised even to derive the sidecar hashes.
            string sha1, md5;
            long size;
            await using (body.ConfigureAwait(false))
            {
                (sha1, md5, size) = await ComputeSidecarDigestsAsync(body, ct);
            }

            return new MavenArtifactFetchResult(
                BlobKey: blobKey,
                Sha256: expectedSha256,
                Sha1: sha1,
                Md5: md5,
                SizeBytes: size,
                IsFromCache: isHit);
        }
        catch (ChecksumException)
        {
            // Propagate so the controller can return 502 — security event, not transient.
            throw;
        }
        catch (AirGappedException)
        {
            // UpstreamClient raises this when AIR_GAPPED=true. Middleware turns it into 503.
            throw;
        }
        catch (UpstreamFetchFailedException)
        {
            // Transient upstream exhausted retries — propagate so middleware maps it to 503/502
            // rather than the caller silently returning 404.
            throw;
        }
        catch (TenantStorageQuotaExceededException)
        {
            // The tenant is at its storage ceiling — propagate so middleware answers 413. The
            // artefact exists upstream; reporting it absent would be a lie the client caches.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Transient upstream failure (network / 5xx / SSRF block / response-too-large).
            // A previously-fetched copy of this blob would have been served by
            // UpstreamClient's cache-first check at the top of GetOrFetchStreamAsync, so
            // by the time we get here there is no last-known-good copy to fall back to.
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven upstream fetch failed for {Path}; returning 404.",
                ex.GetType().Name, upstreamPath);
            return null;
        }
    }

    /// <summary>
    /// Fetch-then-hash fallback for artefacts whose upstream serves no <c>.sha256</c> sidecar
    /// — the norm on Maven Central, which only serves <c>.sha1</c>/<c>.md5</c>. Buffers the
    /// body through the SSRF-guarded, single-flighted metadata path, derives the
    /// content-addressed key locally, verifies against the <c>.sha1</c> sidecar when present,
    /// and writes the blob to the cache tier. Returns null when the artefact doesn't exist
    /// upstream (recording a negative-cache entry); throws <see cref="ChecksumException"/> on
    /// a <c>.sha1</c> mismatch and <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    private async Task<MavenArtifactFetchResult?> FetchThenHashAsync(
        string upstreamBase, string upstreamPath, string upstreamUrl, string? orgId,
        string? authorizationHeader, CancellationToken ct)
    {
        // Route through the shared hash-and-stage disk pipeline: FetchAndCacheByUrlAsync streams
        // the body to a staging temp file (SHA-256 computed inline), stores it under
        // BlobKeys.Proxy(sha), retries transient upstream failures, and single-flights concurrent
        // first-fetches of the same URL. No full-artifact byte[] is ever materialised — this
        // replaces the old buffered metadata-path fetch that held the whole JAR on the LOH.
        UpstreamFetchResult fetched;
        try
        {
            fetched = await _upstream.FetchAndCacheByUrlAsync(
                upstreamUrl, checksumSpec: null, ecosystem: "maven",
                orgId: orgId, authorizationHeader: authorizationHeader, ct);
        }
        catch (AirGappedException)
        {
            throw; // middleware turns it into 503
        }
        catch (UpstreamFetchFailedException)
        {
            throw; // middleware maps transient exhaustion to 503/502
        }
        catch (TenantStorageQuotaExceededException)
        {
            throw; // middleware answers 413 — the tenant is at its ceiling, not the artefact absent
        }
        catch (HttpRequestException ex) when (ex.StatusCode is not null)
        {
            // Genuine upstream absence (404/410/…): FetchWithRetryAsync surfaces it as an
            // HttpRequestException carrying the response StatusCode after EnsureSuccessStatusCode.
            // Only a real HTTP status is negative-cached. Transport-level failures (DNS, connection
            // reset, TLS) surface as HttpRequestException with a null StatusCode; those fall through
            // to the log-and-return-null path below so a one-off network blip is never poisoned into
            // a sticky 404 for the negative-cache TTL.
            await RecordNegativeAsync(upstreamPath, ct);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven upstream fetch-then-hash failed for {Path}; returning 404.",
                ex.GetType().Name, upstreamPath);
            return null;
        }

        // Derive the .sha1/.md5 sidecar digests by streaming the freshly-cached blob once.
        string sha1, md5;
        await using (var blob = await _blobs.GetAsync(fetched.BlobKey, ct)
            ?? throw new InvalidOperationException($"Blob {fetched.BlobKey} vanished after caching."))
        {
            (sha1, md5, _) = await ComputeSidecarDigestsAsync(blob, ct);
        }

        // Verify the cached bytes against the checksum upstream ADVERTISES. We already know
        // .sha256 is absent here (this path is the no-.sha256-sidecar fallback), so check the
        // strongest remaining advertised digest: .sha1 (universal on Maven Central), then .md5.
        // A mismatch is a supply-chain integrity failure — caller maps ChecksumException → 502
        // and the artefact is never served. The content-addressed blob is keyed by its true
        // SHA-256 (computed inline during staging), so an advertised-sidecar mismatch never
        // serves; it only leaves an evictable, correctly-content-addressed cache entry.
        if (VerifyWithUpstreamSha256)
        {
            await VerifyAgainstSidecarsAsync(upstreamBase, upstreamPath, upstreamUrl, sha1, md5, authorizationHeader, ct);
        }

        return new MavenArtifactFetchResult(
            BlobKey: fetched.BlobKey, Sha256: fetched.Sha256Hex, Sha1: sha1, Md5: md5,
            SizeBytes: fetched.SizeBytes, IsFromCache: false);
    }

    /// <summary>
    /// Verifies the computed sha1 (and md5 as fallback) against the upstream-advertised
    /// sidecar values. Throws <see cref="ChecksumException"/> on mismatch; logs and accepts
    /// the artefact when upstream advertises no digest at all.
    /// </summary>
    private async Task VerifyAgainstSidecarsAsync(
        string upstreamBase, string upstreamPath, string upstreamUrl,
        string sha1, string md5, string? authorizationHeader, CancellationToken ct)
    {
        string? upstreamSha1 = await TryFetchSidecarAsync(upstreamBase, upstreamPath, "sha1", ct, authorizationHeader);
        if (upstreamSha1 is not null)
        {
            if (!string.Equals(upstreamSha1, sha1, StringComparison.OrdinalIgnoreCase))
            {
                throw new ChecksumException(
                    $"Upstream sha1 mismatch for {upstreamUrl} (advertised {upstreamSha1}, computed {sha1})");
            }

            return;
        }

        string? upstreamMd5 = await TryFetchSidecarAsync(upstreamBase, upstreamPath, "md5", ct, authorizationHeader);
        if (upstreamMd5 is not null)
        {
            if (!string.Equals(upstreamMd5, md5, StringComparison.OrdinalIgnoreCase))
            {
                throw new ChecksumException(
                    $"Upstream md5 mismatch for {upstreamUrl} (advertised {upstreamMd5}, computed {md5})");
            }

            return;
        }

        _logger.LogWarning(
            "Maven upstream advertised no sha256/sha1/md5 for {Path}; caching unverified.",
            upstreamPath);
    }

    // ── Metadata fetch and merge ───────────────────────────────────────────────

    /// <summary>
    /// Fetches <c>maven-metadata.xml</c> from upstream and returns the version list it
    /// declares. Returns null on upstream error (caller falls back to local-only metadata).
    /// Routed through <see cref="UpstreamClient.GetOrFetchMetadataAsync"/> so concurrent
    /// CI runners hitting a cold coordinate share a single upstream round-trip.
    /// </summary>
    public async Task<List<string>?> FetchUpstreamVersionsAsync(
        string upstreamBase,
        string artifactPath,
        CancellationToken ct,
        string? authorizationHeader = null)
    {
        string upstreamUrl = $"{upstreamBase.TrimEnd('/')}/{artifactPath.TrimStart('/')}/maven-metadata.xml";

        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, authorizationHeader, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            string xml = response.BodyAsString();
            return ParseVersionsFromMetadata(xml);
        }
        catch (AirGappedException)
        {
            return null; // air-gapped: caller serves local-only.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven upstream metadata fetch failed for {Url}",
                ex.GetType().Name, upstreamUrl);
            return null;
        }
    }

    /// <summary>
    /// Resolves the timestamped artifact filename for a SNAPSHOT version by fetching the
    /// version-level <c>maven-metadata.xml</c> from upstream. The metadata's
    /// <c>snapshotVersions</c> section lists each classifier+extension with its current
    /// timestamped value. Returns null when upstream returns a non-success response or the
    /// document is missing. Propagates <see cref="AirGappedException"/> so middleware turns
    /// it into 503.
    /// </summary>
    public async Task<MavenSnapshotMetadata?> FetchSnapshotMetadataAsync(
        string upstreamBase,
        string groupPath,
        string artifactId,
        string snapshotVersion,
        CancellationToken ct,
        string? authorizationHeader = null)
    {
        string metaPath = $"{groupPath}/{artifactId}/{snapshotVersion}/maven-metadata.xml";
        string upstreamUrl = $"{upstreamBase.TrimEnd('/')}/{metaPath.TrimStart('/')}";

        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, authorizationHeader, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            string xml = response.BodyAsString();
            return ParseSnapshotMetadata(xml);
        }
        catch (AirGappedException)
        {
            throw; // middleware converts to 503
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven SNAPSHOT metadata fetch failed for {Url}",
                ex.GetType().Name, upstreamUrl);
            return null;
        }
    }

    private static MavenSnapshotMetadata? ParseSnapshotMetadata(string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            var ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

            // Read the snapshot timestamp and buildNumber from the top-level <snapshot> element.
            var snapshotEl = doc.Descendants(ns + "snapshot").FirstOrDefault();
            string? timestamp = snapshotEl?.Element(ns + "timestamp")?.Value?.Trim();
            string? buildNumStr = snapshotEl?.Element(ns + "buildNumber")?.Value?.Trim();
            int? buildNumber = int.TryParse(buildNumStr, out int bn) ? bn : null;

            // Collect per-extension/classifier timestamped values from <snapshotVersions>.
            var snapshotVersions = doc.Descendants(ns + "snapshotVersion")
                .Select(el => new MavenSnapshotVersionEntry(
                    Classifier: el.Element(ns + "classifier")?.Value?.Trim(),
                    Extension: el.Element(ns + "extension")?.Value?.Trim() ?? "",
                    Value: el.Element(ns + "value")?.Value?.Trim() ?? ""))
                .Where(e => !string.IsNullOrEmpty(e.Value))
                .ToList();

            return new MavenSnapshotMetadata(timestamp, buildNumber, snapshotVersions);
        }
        catch
        {
            return null;
        }
    }

    private static List<string> ParseVersionsFromMetadata(string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            var ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;
            return doc.Descendants(ns + "version")
                .Select(e => e.Value.Trim())
                .Where(v => !string.IsNullOrEmpty(v))
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    // ── Sidecar fetching ───────────────────────────────────────────────────────

    /// <summary>
    /// Fetches the detached OpenPGP <c>.asc</c> signature sidecar for a Maven artefact.
    /// Returns the raw bytes of the sidecar, or null when no <c>.asc</c> exists upstream or
    /// the fetch fails. Used by the Maven proxy ingest path to run provenance verification.
    /// </summary>
    public async Task<byte[]?> TryFetchAscSidecarAsync(
        string upstreamBase,
        string upstreamPath,
        CancellationToken ct,
        string? authorizationHeader = null)
    {
        string sidecarPath = $"{upstreamPath}.asc";
        string sidecarUrl = $"{upstreamBase.TrimEnd('/')}/{sidecarPath.TrimStart('/')}";
        try
        {
            using var response = await _upstream.GetMetadataAsync(sidecarUrl, authorizationHeader, ct);
            return !response.IsSuccessStatusCode
                ? null
                : await UpstreamClient.ReadBodyCappedAsync(
                    response, UpstreamClient.MaxMetadataResponseBytes, sidecarUrl, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not AirGappedException)
        {
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven .asc sidecar fetch failed for {Url}",
                ex.GetType().Name, sidecarUrl);
            return null;
        }
    }

    private async Task<string?> TryFetchSidecarAsync(
        string upstreamBase,
        string upstreamPath,
        string algorithm,
        CancellationToken ct,
        string? authorizationHeader = null)
    {
        string sidecarPath = $"{upstreamPath}.{algorithm}";
        string sidecarUrl = $"{upstreamBase.TrimEnd('/')}/{sidecarPath.TrimStart('/')}";
        try
        {
            // Sidecars are tiny (64 hex chars) and ephemeral — single-flight is overkill
            // but GetMetadataAsync gives us the SSRF guard with the lowest overhead and
            // keeps the call path consistent with the other ecosystems. AirGappedException
            // intentionally propagates so callers get a clean 503 from the middleware
            // rather than a silent null-then-404.
            using var response = await _upstream.GetMetadataAsync(sidecarUrl, authorizationHeader, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            // Capped read: a sidecar is 64 hex chars, but the body is upstream-controlled
            // and the shared client auto-decompresses — never buffer it unbounded.
            byte[] body = await UpstreamClient.ReadBodyCappedAsync(
                response, UpstreamClient.MaxMetadataResponseBytes, sidecarUrl, ct);
            string text = Encoding.UTF8.GetString(body);
            return ExtractHex(text.Trim());
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not AirGappedException)
        {
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven sidecar fetch failed for {Url}",
                ex.GetType().Name, sidecarUrl);
            return null;
        }
    }

    private static string? ExtractHex(string input)
    {
        var sb = new StringBuilder();
        foreach (char c in input)
        {
            if (Uri.IsHexDigit(c))
            {
                sb.Append(c);
            }
            else if (sb.Length > 0)
            {
                break;
            }
        }
        return sb.Length > 0 ? sb.ToString().ToLowerInvariant() : null;
    }

    // Streams an artifact once to compute the Maven .sha1/.md5 sidecar digests (and the byte
    // count) without ever holding the full artifact in managed memory. SHA-1/MD5 are Maven
    // client-compatibility sidecars only — the integrity gate and cache key are SHA-256.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0006",
        Justification = "MD5/SHA-1 used only for Maven sidecar compatibility, not authentication.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350",
        Justification = "SHA-1 used only for Maven sidecar compatibility, not a security decision.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5351",
        Justification = "MD5 used only for Maven sidecar compatibility, not a security decision.")]
    private static async Task<(string Sha1, string Md5, long Size)> ComputeSidecarDigestsAsync(
        Stream stream, CancellationToken ct)
    {
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        byte[] buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            sha1.AppendData(buffer, 0, read);
            md5.AppendData(buffer, 0, read);
            total += read;
        }
        return (
            Convert.ToHexString(sha1.GetHashAndReset()).ToLowerInvariant(),
            Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant(),
            total);
    }
}

/// <summary>
/// Result of a Maven upstream artifact fetch attempt. The artifact itself is never carried as a
/// byte[]; it lives in the cache tier under <see cref="BlobKey"/> (hash-and-staged to disk during
/// the fetch), and the controller opens a fresh blob stream to serve it. Only the small digest
/// triple and byte count travel with the result, so a 300 MB shaded JAR never sits on the LOH.
/// </summary>
public sealed record MavenArtifactFetchResult(
    string BlobKey,
    string Sha256,
    string Sha1,
    string Md5,
    long SizeBytes,
    bool IsFromCache);

/// <summary>
/// Parsed representation of a SNAPSHOT version-level <c>maven-metadata.xml</c> document.
/// Drives timestamped artifact filename resolution: the <c>snapshotVersions</c> entries map
/// each classifier+extension to its current timestamped <c>value</c> (e.g.
/// <c>1.0-20240101.120000-1</c>).
/// </summary>
public sealed record MavenSnapshotMetadata(
    string? Timestamp,
    int? BuildNumber,
    IReadOnlyList<MavenSnapshotVersionEntry> SnapshotVersions)
{
    /// <summary>
    /// Resolves the timestamped artifact filename for the given extension and optional
    /// classifier. Returns null when no matching snapshotVersion entry exists.
    /// </summary>
    public string? ResolveTimestampedValue(string extension, string? classifier)
    {
        foreach (var entry in SnapshotVersions)
        {
            bool extMatch = string.Equals(entry.Extension, extension, StringComparison.OrdinalIgnoreCase);
            bool classMatch = string.Equals(entry.Classifier ?? "", classifier ?? "", StringComparison.OrdinalIgnoreCase);
            if (extMatch && classMatch)
            {
                return entry.Value;
            }
        }
        return null;
    }
}

/// <summary>One <c>snapshotVersion</c> entry from the version-level metadata document.</summary>
public sealed record MavenSnapshotVersionEntry(
    string? Classifier,
    string Extension,
    string Value);
