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
        string? purl = null)
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
            expectedSha256 = await TryFetchSidecarAsync(upstreamBase, upstreamPath, "sha256", ct);
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
            return await FetchThenHashAsync(upstreamBase, upstreamPath, upstreamUrl, ct);
        }

        string blobKey = BlobKeys.Proxy(expectedSha256);

        try
        {
            var (body, isHit) = await _upstream.GetOrFetchStreamAsync(
                blobKey,
                upstreamUrl,
                new ChecksumSpec(ChecksumAlgorithm.Sha256, expectedSha256),
                ecosystem: "maven",
                orgId: null,
                purl: null,
                ct: ct);

            byte[] bytes;
            await using (body.ConfigureAwait(false))
            {
                bytes = await ReadStreamAsync(body, ct);
            }

            string sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
            string md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

            return new MavenArtifactFetchResult(
                Bytes: bytes,
                BlobKey: blobKey,
                Sha256: expectedSha256,
                Sha1: sha1,
                Md5: md5,
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
        string upstreamBase, string upstreamPath, string upstreamUrl, CancellationToken ct)
    {
        byte[] bytes;
        try
        {
            // Artifact bytes flow through the buffered path here, so the cap is the artifact
            // limit, not the (much smaller) default metadata limit.
            //
            // The buffered metadata path does not itself classify/retry transient upstream
            // statuses, so this loop does it — mirroring the blob-fetch paths in UpstreamClient.
            // A transient CDN error (403/429/5xx) on a Maven cache-miss must be retried and,
            // on exhaustion, surfaced as the retryable UpstreamFetchFailedException (the
            // middleware maps it to 503/502). It must NOT be negative-cached or returned as a
            // sticky 404: that would poison the artefact into a 404 (short-circuiting upstream
            // on every later request) until the negative-cache entry expires. Only a genuine
            // absence (404/410/…) is negative-cached.
            const int MaxUpstreamFetchAttempts = 3;
            // Initial backoff delay before first retry; doubled on each subsequent attempt.
            const int RetryBackoffBaseMs = 200;
            const double RetryBackoffExponent = 2.0;
            UpstreamMetadataResponse resp;
            int attempt = 0;
            while (true)
            {
                resp = await _upstream.GetOrFetchMetadataAsync(
                    upstreamUrl, UpstreamClient.MaxUpstreamResponseBytes, ct);
                if (resp.IsSuccessStatusCode)
                {
                    break;
                }

                bool transient = resp.StatusCode is 429 or 403 or >= 500;
                if (transient && attempt < MaxUpstreamFetchAttempts - 1)
                {
                    attempt++;
                    await Task.Delay(TimeSpan.FromMilliseconds(RetryBackoffBaseMs * Math.Pow(RetryBackoffExponent, attempt - 1)), ct);
                    continue;
                }
                if (transient)
                {
                    throw new UpstreamFetchFailedException
                    {
                        Url = upstreamUrl,
                        StatusCode = resp.StatusCode,
                        RetryAfter = null,
                        Transient = true,
                    };
                }

                await RecordNegativeAsync(upstreamPath, ct);
                return null;
            }
            bytes = resp.Body;
        }
        catch (AirGappedException)
        {
            throw; // middleware turns it into 503
        }
        catch (UpstreamFetchFailedException)
        {
            throw; // middleware maps transient exhaustion to 503/502
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "ExceptionType={ExceptionType} Maven upstream fetch-then-hash failed for {Path}; returning 404.",
                ex.GetType().Name, upstreamPath);
            return null;
        }

        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        string md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

        // Verify the downloaded bytes against the checksum upstream ADVERTISES, before we
        // pass the artefact along. We already know .sha256 is absent here (the caller falls
        // back to this path precisely when no .sha256 sidecar exists), so check the strongest
        // remaining advertised digest: .sha1 (universal on Maven Central), then .md5. A
        // mismatch is a supply-chain integrity failure — caller maps ChecksumException → 502
        // and the artefact is never served or cached. The advertised digest is recorded as
        // provenance via the computed columns (computed == advertised once verified).
        if (VerifyWithUpstreamSha256)
        {
            await VerifyAgainstSidecarsAsync(upstreamBase, upstreamPath, upstreamUrl, sha1, md5, ct);
        }

        string blobKey = BlobKeys.Proxy(sha256);
        if (!await _blobs.ExistsAsync(blobKey, ct))
        {
            await _blobs.PutAsync(blobKey, new MemoryStream(bytes), ct);
        }

        return new MavenArtifactFetchResult(
            Bytes: bytes, BlobKey: blobKey, Sha256: sha256, Sha1: sha1, Md5: md5, IsFromCache: false);
    }

    /// <summary>
    /// Verifies the computed sha1 (and md5 as fallback) against the upstream-advertised
    /// sidecar values. Throws <see cref="ChecksumException"/> on mismatch; logs and accepts
    /// the artefact when upstream advertises no digest at all.
    /// </summary>
    private async Task VerifyAgainstSidecarsAsync(
        string upstreamBase, string upstreamPath, string upstreamUrl,
        string sha1, string md5, CancellationToken ct)
    {
        string? upstreamSha1 = await TryFetchSidecarAsync(upstreamBase, upstreamPath, "sha1", ct);
        if (upstreamSha1 is not null)
        {
            if (!string.Equals(upstreamSha1, sha1, StringComparison.OrdinalIgnoreCase))
            {
                throw new ChecksumException(
                    $"Upstream sha1 mismatch for {upstreamUrl} (advertised {upstreamSha1}, computed {sha1})");
            }

            return;
        }

        string? upstreamMd5 = await TryFetchSidecarAsync(upstreamBase, upstreamPath, "md5", ct);
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
        CancellationToken ct)
    {
        string upstreamUrl = $"{upstreamBase.TrimEnd('/')}/{artifactPath.TrimStart('/')}/maven-metadata.xml";

        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, ct);
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
        CancellationToken ct)
    {
        string metaPath = $"{groupPath}/{artifactId}/{snapshotVersion}/maven-metadata.xml";
        string upstreamUrl = $"{upstreamBase.TrimEnd('/')}/{metaPath.TrimStart('/')}";

        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, ct);
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
        CancellationToken ct)
    {
        string sidecarPath = $"{upstreamPath}.asc";
        string sidecarUrl = $"{upstreamBase.TrimEnd('/')}/{sidecarPath.TrimStart('/')}";
        try
        {
            using var response = await _upstream.GetMetadataAsync(sidecarUrl, ct);
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
        CancellationToken ct)
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
            using var response = await _upstream.GetMetadataAsync(sidecarUrl, ct);
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

    private static async Task<byte[]> ReadStreamAsync(Stream stream, CancellationToken ct)
    {
        if (stream.CanSeek && stream.Length > 0)
        {
            byte[] buf = new byte[stream.Length];
            int total = 0;
            while (total < buf.Length)
            {
                int n = await stream.ReadAsync(buf.AsMemory(total), ct);
                if (n == 0)
                {
                    break;
                }

                total += n;
            }
            return total == buf.Length ? buf : buf.AsSpan(0, total).ToArray();
        }

        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        return ms.ToArray();
    }
}

/// <summary>
/// Result of a Maven upstream artifact fetch attempt.
/// </summary>
public sealed record MavenArtifactFetchResult(
    byte[] Bytes,
    string BlobKey,
    string Sha256,
    string Sha1,
    string Md5,
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
