using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Caching.Memory;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Protocol;

// ── Public result types ───────────────────────────────────────────────────────

/// <summary>
/// Result from an upstream repodata fetch. <see cref="NotModified"/> is true when the
/// caller's <c>If-None-Match</c> matched the upstream <c>ETag</c> (or the cached copy
/// was still fresh and the caller already has it).
/// </summary>
public sealed record RepodataResult(
    byte[] Body,
    string ContentType,
    string? ETag,
    string? LastModified,
    bool NotModified);

/// <summary>
/// Resolved location of an upstream RPM package together with metadata extracted from
/// the upstream <c>primary.xml.gz</c>. Used by <see cref="Dependably.Api.RpmController"/>
/// to cache the fetched blob and populate the <c>rpm_metadata</c> row without re-parsing
/// the RPM header.
/// </summary>
public sealed record PackageResolution(
    string PackageUrl,
    string Sha256,
    string Name,
    int Epoch,
    string Version,
    string Release,
    string Arch,
    string? Summary,
    string? Description,
    string? License);

// ── Proxy ─────────────────────────────────────────────────────────────────────

/// <summary>
/// Upstream mirror proxy for the RPM ecosystem.
///
/// Responsibilities:
///  - <c>repomd.xml</c> / <c>repomd.xml.asc</c>: short-TTL passthrough with
///    <c>ETag</c> / <c>If-None-Match</c> support (<see cref="Rpm:RepomdTtl"/>, default 60 s).
///  - Hash-prefixed metadata files (e.g. <c>{sha256}-primary.xml.gz</c>): cache
///    forever in blob store keyed by <see cref="BlobKeys.RpmRepodataProxy(sha256)"/>.
///  - GPG key: cached for <see cref="Rpm:GpgKeyTtl"/> (default 1 day).
///  - Package resolution: parses the cached <c>primary.xml.gz</c> to locate download
///    URL + SHA-256 for a requested NEVRA filename.
///  - Negative cache: DB-backed via <c>upstream_negative_cache</c> (xtenant-exempt,
///    content-addressed), TTL <see cref="Rpm:NegativeCacheTtl"/> (default 5 min).
/// </summary>
public interface IRpmUpstreamProxy
{
    bool IsPassthroughModeSelected { get; }
    bool IsMergedModeSelected { get; }
    Task<RepodataResult?> GetRepodataAsync(string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct);
    Task<PackageResolution?> ResolvePackageUrlAsync(string orgId, string upstreamBase, string filename, CancellationToken ct);
    /// <summary>
    /// Returns the upstream <c>primary.xml.gz</c> bytes (checksum-verified, blob-cached), or null
    /// when the upstream repomd / primary cannot be fetched or verified. When the org has a trust
    /// anchor configured, repomd.xml's detached OpenPGP signature is verified before parsing;
    /// a failed signature rejects the response. Merged mode unions this upstream package set with
    /// locally published RPMs. Throws <see cref="AirGappedException"/> in air-gapped deployments.
    /// </summary>
    Task<byte[]?> GetUpstreamPrimaryXmlGzAsync(string orgId, string upstreamBase, CancellationToken ct);
    /// <summary>
    /// Returns the upstream <c>filelists.xml.gz</c> bytes (blob-cached), or null when the
    /// upstream repomd has no filelists entry or the file cannot be fetched.
    /// </summary>
    Task<byte[]?> GetUpstreamFilelistsXmlGzAsync(string orgId, string upstreamBase, CancellationToken ct);
    /// <summary>
    /// Parses the upstream <c>repomd.xml</c> and returns the non-primary <c>&lt;data&gt;</c>
    /// elements verbatim (filelists, other, group, modules, updateinfo, …) so the merged
    /// repomd can pass them through. Returns an empty list when repomd cannot be fetched.
    /// </summary>
    Task<IReadOnlyList<System.Xml.Linq.XElement>> GetUpstreamNonPrimaryRepomdEntriesAsync(string orgId, string upstreamBase, CancellationToken ct);
    Task<byte[]?> GetGpgKeyAsync(string upstreamBase, CancellationToken ct);
    Task<bool> IsNegativelyCachedAsync(string upstreamPath, CancellationToken ct);
    Task RecordNegativeAsync(string upstreamPath, CancellationToken ct);
}

// S5332 flags the XML namespace identifiers ("http://linux.duke.edu/metadata/...") used
// in ParsePrimaryFromRepomd / ParsePrimaryXmlGz as insecure HTTP. Those strings are
// XMLNS identifiers fixed by the repodata schema — they are never used as HTTP request
// targets, so swapping in https:// would break XPath matching against upstream files.
[System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S5332:Using clear-text protocols is security-sensitive",
    Justification = "XML namespace identifiers from the repodata schema, not HTTP request targets.")]
public sealed class RpmUpstreamProxy : IRpmUpstreamProxy
{
    // SHA-256 produces a 64-character lowercase hex string.
    private const int Sha256HexLength = 64;

    // Minimum length of a hash-prefixed filename: 64-char hex + '-' + at least one char.
    private const int HashPrefixedFilenameMinLength = Sha256HexLength + 2;

    // Length of the hex prefix used as the URL negative-cache key (first 32 hex chars of SHA-256).
    private const int UrlKeyPrefixLength = 32;

    private readonly IHttpClientFactory _http;
    private readonly IBlobStore _cacheStore;  // blobs.Cache
    private readonly IMetadataStore _db;
    private readonly IMemoryCache _memCache;
    private readonly IAirGapMode _airGap;
    private readonly IUpstreamUrlValidator _urlValidator;
    private readonly ILogger<RpmUpstreamProxy> _logger;
    private readonly TimeProvider _time;
    private readonly IPerOrgTrustAnchorStore _trustStore;

    private readonly string _upstreamMode;  // "passthrough" | "merged"
    private readonly TimeSpan _repomdTtl;
    private readonly TimeSpan _gpgKeyTtl;
    private readonly TimeSpan _negativeCacheTtl;

    // When true, repomd.xml signature verification is enforced regardless of whether the org
    // has a trust anchor. Setting Rpm:VerifyRepomdSignature=true with no per-org anchor
    // fails every resolution closed. When unset, verification is enabled iff the org has an
    // anchor at fetch time.
    private readonly bool? _verifyRepomdSignatureOverride;

    // Dedup concurrent repomd.xml fetches — only one HTTP round-trip per (base URL, file) at a time.
    private readonly ConcurrentDictionary<string, Lazy<Task<(byte[] Body, string? ETag, string? LastModified)>>> _repomdInflight = new();

    /// <summary>
    /// True when the instance-level mode is 'passthrough'. Per-org configured-ness comes
    /// from the upstream registry list (resolved controller-side); the controller combines
    /// this selector with "the org has at least one rpm registry" to decide effective passthrough.
    /// </summary>
    public bool IsPassthroughModeSelected => string.Equals(_upstreamMode, "passthrough", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the instance-level mode is 'merged'. In this mode hosted publishing is allowed
    /// and the controller serves a combined repodata document (local ∪ upstream); local versions
    /// shadow upstream on collision. Like passthrough, the controller still requires the org to
    /// have at least one rpm registry before the merge actually engages.
    /// </summary>
    public bool IsMergedModeSelected => string.Equals(_upstreamMode, "merged", StringComparison.OrdinalIgnoreCase);

    public RpmUpstreamProxy(RpmUpstreamProxyServices svc)
    {
        _http = svc.HttpClientFactory;
        _cacheStore = svc.Blobs.Cache;
        _db = svc.Db;
        _memCache = svc.MemoryCache;
        _airGap = svc.AirGap;
        _urlValidator = svc.UrlValidator;
        _logger = svc.Logger;
        _time = svc.Time;
        _trustStore = svc.TrustStore;

        var configuration = svc.Configuration;
        _upstreamMode = configuration["Rpm:UpstreamMode"] ?? "passthrough";

        _repomdTtl = TimeSpan.TryParse(configuration["Rpm:RepomdTtl"], out var r) ? r : TimeSpan.FromSeconds(60);
        _gpgKeyTtl = TimeSpan.TryParse(configuration["Rpm:GpgKeyTtl"], out var g) ? g : TimeSpan.FromDays(1);
        _negativeCacheTtl = TimeSpan.TryParse(configuration["Rpm:NegativeCacheTtl"], out var n) ? n : TimeSpan.FromMinutes(5);

        // Rpm:VerifyRepomdSignature overrides the per-org default when explicitly set.
        // When unset, verification is enabled iff the org has a configured trust anchor.
        _verifyRepomdSignatureOverride = bool.TryParse(configuration["Rpm:VerifyRepomdSignature"], out bool vf)
            ? vf
            : null;
    }

    // ── Repodata ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Fetches repodata from upstream.
    ///
    /// Three buckets:
    /// <list type="bullet">
    ///   <item><c>repomd.xml</c> / <c>repomd.xml.asc</c> — TTL-based, <c>ETag</c>-aware.</item>
    ///   <item>Hash-prefixed files (<c>{sha256}-*.{xml.gz,sqlite.bz2,yaml.gz}</c>) — cached
    ///         forever in blob store (content-addressed).</item>
    ///   <item>Everything else — not recognised; returns null.</item>
    /// </list>
    ///
    /// Returns null when the upstream returns 404 or when the filename is not in a known
    /// category. <paramref name="upstreamBase"/> is the org's top-priority rpm registry base
    /// (trailing-slash-trimmed), used for both URL building and cache keys.
    /// Throws <see cref="AirGappedException"/> in air-gapped deployments.
    /// </summary>
    public async Task<RepodataResult?> GetRepodataAsync(
        string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
    {
        return _airGap.IsEnabled
            ? throw new AirGappedException($"rpm:repodata:{filename}")
            : filename.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase)
         || filename.Equals("repomd.xml.asc", StringComparison.OrdinalIgnoreCase)
            ? await GetRepomdAsync(upstreamBase, filename, ifNoneMatch, ifModifiedSince, ct)
            : IsHashPrefixedFilename(filename) ? await GetHashPrefixedAsync(upstreamBase, filename, ct) : null;
    }

    // ── Package resolution ────────────────────────────────────────────────────

    /// <summary>
    /// Resolves a package filename (e.g. <c>tree-2.1.1-1.fc40.x86_64.rpm</c>) to its
    /// upstream download URL and SHA-256 checksum by parsing the cached
    /// <c>primary.xml.gz</c>. Also returns the metadata fields needed to populate the
    /// <c>rpm_metadata</c> table without re-parsing the RPM binary header.
    ///
    /// Returns null when <c>repomd.xml</c> cannot be fetched, when <c>primary.xml.gz</c> is
    /// not found, or when the package is absent from the index. <paramref name="upstreamBase"/>
    /// is the org's top-priority rpm registry base (trailing-slash-trimmed).
    /// Throws <see cref="AirGappedException"/> in air-gapped deployments.
    /// </summary>
    public async Task<PackageResolution?> ResolvePackageUrlAsync(string orgId, string upstreamBase, string filename, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"rpm:resolve:{filename}");
        }

        var primary = await GetUpstreamPrimaryGzAsync(orgId, upstreamBase, ct);
        if (primary is null)
        {
            return null;
        }

        var (primaryGzBytes, primarySha256) = primary.Value;

        // Parse primary.xml.gz (cached by sha256 so it automatically tracks repodata rotation)
        string mapKey = $"rpm:primary-map:{primarySha256}";
        if (!_memCache.TryGetValue<Dictionary<string, PackageResolution>>(mapKey, out var packageMap))
        {
            packageMap = ParsePrimaryXmlGz(primaryGzBytes, upstreamBase);
            // Long TTL is fine — the map invalidates naturally when repomd.xml rotates to a
            // new primary.xml.gz sha256, creating a new cache slot and letting the old one GC.
            _memCache.Set(mapKey, packageMap, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(4),
                Size = 1,
            });
        }

        return packageMap!.GetValueOrDefault(filename);
    }

    /// <inheritdoc />
    public async Task<byte[]?> GetUpstreamPrimaryXmlGzAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException("rpm:primary");
        }

        var primary = await GetUpstreamPrimaryGzAsync(orgId, upstreamBase, ct);
        return primary?.Bytes;
    }

    /// <inheritdoc />
    public async Task<byte[]?> GetUpstreamFilelistsXmlGzAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException("rpm:filelists");
        }

        byte[]? repomdBytes = await GetRepomdBodyAsync(orgId, upstreamBase, ct);
        if (repomdBytes is null)
        {
            return null;
        }

        var (filelistsFilename, filelistsSha256) = ParseRepodataEntryFromRepomd(repomdBytes, "filelists");
        return filelistsFilename is null || filelistsSha256 is null
            ? null
            : await GetOrFetchRepodataBlobAsync(upstreamBase, filelistsFilename, filelistsSha256, ct);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<XElement>> GetUpstreamNonPrimaryRepomdEntriesAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException("rpm:repomd-entries");
        }

        byte[]? repomdBytes = await GetRepomdBodyAsync(orgId, upstreamBase, ct);
        return repomdBytes is null
            ? Array.Empty<XElement>()
            : ParseNonPrimaryRepomdEntries(repomdBytes);
    }

    /// <summary>
    /// Fetches the current upstream <c>primary.xml.gz</c>: read <c>repomd.xml</c> (memory cache
    /// or upstream, signature-verified when the org has a trust anchor pinned), locate the primary
    /// href + checksum, then fetch the content-addressed primary blob (blob cache or upstream,
    /// checksum-verified). Returns the bytes together with the primary's SHA-256 (used as a
    /// cache key by callers), or null on any fetch/verification failure.
    /// </summary>
    private async Task<(byte[] Bytes, string Sha256)?> GetUpstreamPrimaryGzAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        byte[]? repomdBytes = await GetRepomdBodyAsync(orgId, upstreamBase, ct);
        if (repomdBytes is null)
        {
            return null;
        }

        var (primaryFilename, primarySha256) = ParsePrimaryFromRepomd(repomdBytes);
        if (primaryFilename is null || primarySha256 is null)
        {
            return null;
        }

        byte[]? primaryGzBytes = await GetOrFetchRepodataBlobAsync(upstreamBase, primaryFilename, primarySha256, ct);
        return primaryGzBytes is null ? null : (primaryGzBytes, primarySha256);
    }

    // ── GPG key ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Fetches the upstream GPG public key. Tries common paths used by Fedora / RHEL mirrors.
    /// Cached for <c>Rpm:GpgKeyTtl</c> (default 1 day).
    /// Returns null when no key path responds with 200. <paramref name="upstreamBase"/> is the
    /// org's top-priority rpm registry base (trailing-slash-trimmed).
    /// Throws <see cref="AirGappedException"/> in air-gapped deployments.
    /// </summary>
    public async Task<byte[]?> GetGpgKeyAsync(string upstreamBase, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException("rpm:gpg-key");
        }

        string cacheKey = $"rpm:gpgkey:{upstreamBase}";
        if (_memCache.TryGetValue<byte[]>(cacheKey, out byte[]? cached))
        {
            return cached;
        }

        // Fedora / EPEL mirrors serve the key at one of these paths.
        string[] paths = ["RPM-GPG-KEY", "repodata/repomd.xml.key"];
        var client = _http.CreateClient("upstream");
        foreach (string? path in paths)
        {
            string url = $"{upstreamBase}/{path}";
            if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
            {
                continue;
            }

            using var resp = await client.GetAsync(url, ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            byte[] bytes;
            try
            {
                bytes = await UpstreamClient.ReadBodyCappedAsync(
                    resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
            }
            catch (UpstreamResponseTooLargeException ex)
            {
                _logger.LogWarning(ex,
                    "RPM GPG key response exceeded the metadata cap for {Url}; trying next key path.", url);
                continue;
            }
            _memCache.Set(cacheKey, bytes, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _gpgKeyTtl,
                Size = bytes.Length,
            });
            return bytes;
        }

        return null;
    }

    // ── Negative cache ────────────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the given upstream path was recorded as a 404 within the
    /// configured TTL.
    /// </summary>
    public async Task<bool> IsNegativelyCachedAsync(string upstreamPath, CancellationToken ct)
    {
        string urlKey = UrlKey(upstreamPath);
        string cutoff = _time.GetUtcNow().UtcDateTime.Add(-_negativeCacheTtl).ToString("yyyy-MM-ddTHH:mm:ssZ");
        // xtenant: upstream_negative_cache is content-addressed (SHA-256 of URL → 404) and
        // intentionally shared across tenants. A URL either 404s or it doesn't.
        await using var conn = await _db.OpenAsync(ct);
        string? hit = await conn.ExecuteScalarAsync<string?>(
            "SELECT url_key FROM upstream_negative_cache WHERE url_key = @key AND ecosystem = 'rpm' AND fetched_at >= @cutoff",
            new { key = urlKey, cutoff });
        return hit is not null;
    }

    /// <summary>Records a 404 response for <paramref name="upstreamPath"/> in the negative cache.</summary>
    public async Task RecordNegativeAsync(string upstreamPath, CancellationToken ct)
    {
        string urlKey = UrlKey(upstreamPath);
        string now = _time.GetUtcNow().UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        // xtenant: see IsNegativelyCachedAsync.
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_negative_cache (url_key, ecosystem, fetched_at)
            VALUES (@key, 'rpm', @now)
            ON CONFLICT(url_key, ecosystem) DO UPDATE SET fetched_at = excluded.fetched_at
            """,
            new { key = urlKey, now });
    }

    // ── Internal: repomd fetch ─────────────────────────────────────────────────

    private sealed record CachedRepomd(byte[] Body, string? ETag, string? LastModified);

    /// <summary>
    /// Fetches <c>repomd.xml</c> or <c>repomd.xml.asc</c> from upstream, honoring
    /// <c>If-None-Match</c> / <c>If-Modified-Since</c> from the client. Both files share
    /// the same TTL so they always invalidate together (a stale asc against a fresh index
    /// would fail GPG verification in dnf).
    /// </summary>
    private async Task<RepodataResult?> GetRepomdAsync(
        string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
    {
        string cacheKey = $"rpm:repomd:{upstreamBase}:{filename}";

        // Memory cache hit — serve immediately, propagating 304 if client's ETag matches.
        if (_memCache.TryGetValue<CachedRepomd>(cacheKey, out var cached))
        {
            return ifNoneMatch is not null && cached!.ETag is not null &&
                ifNoneMatch.Contains(cached.ETag)
                ? new RepodataResult([], ContentTypeFor(filename), cached.ETag, cached.LastModified, NotModified: true)
                : new RepodataResult(cached!.Body, ContentTypeFor(filename), cached.ETag, cached.LastModified, NotModified: false);
        }

        // Cache miss — single-flight fetch to avoid thundering herd.
        var lazy = _repomdInflight.GetOrAdd(
            cacheKey,
            _ => new Lazy<Task<(byte[], string?, string?)>>(
                () => FetchRepomdFromUpstreamAsync(upstreamBase, filename, ifNoneMatch, ifModifiedSince, CancellationToken.None)));

        (byte[] body, string? etag, string? lastModified) result;
        try
        {
            result = await lazy.Value.WaitAsync(ct);
        }
        finally
        {
            _repomdInflight.TryRemove(cacheKey, out _);
        }

        if (result.body.Length == 0)
        {
            // Upstream returned 304 (or 404). Don't cache.
            return result.etag is null
                ? null  // 404
                : new RepodataResult([], ContentTypeFor(filename), result.etag, result.lastModified, NotModified: true);
        }

        _memCache.Set(cacheKey, new CachedRepomd(result.body, result.etag, result.lastModified), new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = _repomdTtl,
            Size = result.body.Length,
        });
        return new RepodataResult(result.body, ContentTypeFor(filename), result.etag, result.lastModified, NotModified: false);
    }

    private async Task<(byte[] Body, string? ETag, string? LastModified)> FetchRepomdFromUpstreamAsync(
        string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
    {
        string url = $"{upstreamBase}/repodata/{filename}";
        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
        {
            return ([], null, null);
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (!string.IsNullOrEmpty(ifNoneMatch))
        {
            req.Headers.TryAddWithoutValidation("If-None-Match", ifNoneMatch);
        }

        if (!string.IsNullOrEmpty(ifModifiedSince))
        {
            req.Headers.TryAddWithoutValidation("If-Modified-Since", ifModifiedSince);
        }

        var client = _http.CreateClient("upstream");
        using var resp = await client.SendAsync(req, ct);

        if (resp.StatusCode == System.Net.HttpStatusCode.NotModified)
        {
            return ([], resp.Headers.ETag?.ToString() ?? "304", null); // etag acts as sentinel
        }

        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return ([], null, null); // null ETag = 404
        }

        resp.EnsureSuccessStatusCode();

        byte[] body;
        try
        {
            body = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            // Treat an over-cap repomd like an unavailable upstream (the 404 sentinel)
            // rather than buffering an attacker-inflatable body.
            _logger.LogWarning(ex,
                "RPM repomd response exceeded the metadata cap for {Url}; treating as unavailable.", url);
            return ([], null, null);
        }
        string? etag = resp.Headers.ETag?.ToString();
        string? lastMod = resp.Content.Headers.LastModified?.ToString("R");
        return (body, etag, lastMod);
    }

    /// <summary>
    /// Returns the raw bytes of the current <c>repomd.xml</c> (from memory cache if present,
    /// fetching from upstream otherwise). When the org has a per-org RPM trust anchor configured
    /// (or when <c>Rpm:VerifyRepomdSignature=true</c> is forced), the detached OpenPGP signature
    /// (<c>repomd.xml.asc</c>) is verified against the per-org key ring before these bytes are
    /// parsed into the package-checksum map. A failed verification returns null so tampered upstream
    /// metadata is never trusted. The raw <c>repomd.xml</c>/<c>repomd.xml.asc</c> passthrough GET
    /// is intentionally not gated — dnf clients re-verify the signature themselves.
    /// </summary>
    private async Task<byte[]?> GetRepomdBodyAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        string cacheKey = $"rpm:repomd:{upstreamBase}:repomd.xml";
        byte[]? body;
        if (_memCache.TryGetValue<CachedRepomd>(cacheKey, out var cached))
        {
            body = cached!.Body;
        }
        else
        {
            var result = await GetRepomdAsync(upstreamBase, "repomd.xml", null, null, ct);
            body = result?.NotModified == false ? result.Body : null;
        }
        if (body is null)
        {
            return null;
        }

        // Resolve per-org key ring from the trust store; null means no anchors for this org.
        var keyRing = await _trustStore.GetRpmKeyRingAsync(orgId, ct);

        // Determine whether signature verification is required:
        // - Rpm:VerifyRepomdSignature override wins when explicitly set.
        // - Otherwise, verify iff the org has a trust anchor (per-org default).
        bool shouldVerify = _verifyRepomdSignatureOverride ?? keyRing is not null;

        if (shouldVerify)
        {
            if (keyRing is null)
            {
                RecordRepomdSignatureFailure("no_trusted_key", upstreamBase);
                return null;
            }
            byte[]? asc = await GetRepomdAscBytesAsync(upstreamBase, ct);
            if (asc is null)
            {
                RecordRepomdSignatureFailure("missing_signature", upstreamBase);
                return null;
            }
            if (!VerifyRepomdSignature(body, asc, keyRing))
            {
                RecordRepomdSignatureFailure("bad_signature", upstreamBase);
                return null;
            }
        }

        return body;
    }

    private void RecordRepomdSignatureFailure(string reason, string upstreamBase)
    {
        DependablyMeter.RpmRepomdSignatureFailures.Add(1, new KeyValuePair<string, object?>("reason", reason));
        _logger.LogWarning(
            "RPM proxy: repomd.xml signature verification failed for {UpstreamBase} (reason={Reason}); " +
            "refusing to trust upstream metadata.", upstreamBase, reason);
    }

    /// <summary>
    /// Fetches <c>repodata/repomd.xml.asc</c> (the detached signature), memory-cached for the
    /// repomd TTL so the pair refreshes together and HTTP is bounded. Returns null on a missing
    /// signature or a blocked URL.
    /// </summary>
    private async Task<byte[]?> GetRepomdAscBytesAsync(string upstreamBase, CancellationToken ct)
    {
        string cacheKey = $"rpm:repomd-asc:{upstreamBase}";
        if (_memCache.TryGetValue<byte[]>(cacheKey, out byte[]? cached))
        {
            return cached;
        }

        string url = $"{upstreamBase}/repodata/repomd.xml.asc";
        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
        {
            return null;
        }

        var client = _http.CreateClient("upstream");
        using var resp = await client.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode)
        {
            return null;
        }

        byte[] asc;
        try
        {
            asc = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            // A detached signature is a few hundred bytes; an over-cap body is treated as
            // missing (verification then fails closed when a trust anchor is pinned).
            _logger.LogWarning(ex,
                "RPM repomd.xml.asc response exceeded the metadata cap for {Url}; treating as missing.", url);
            return null;
        }
        _memCache.Set(cacheKey, asc, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = _repomdTtl,
            Size = asc.Length,
        });
        return asc;
    }

    /// <summary>
    /// Verifies a detached, ASCII-armored OpenPGP signature (<paramref name="asc"/>) over the
    /// exact bytes of <paramref name="repomd"/> against the trusted key ring. Returns false when
    /// the signature is malformed, was made by a key not in the ring, or does not verify.
    /// </summary>
    internal static bool VerifyRepomdSignature(byte[] repomd, byte[] asc, PgpPublicKeyRingBundle keyRing)
    {
        try
        {
            using var sigStream = PgpUtilities.GetDecoderStream(new MemoryStream(asc));
            var factory = new PgpObjectFactory(sigStream);
            var obj = factory.NextPgpObject();
            if (obj is PgpCompressedData compressed)
            {
                obj = new PgpObjectFactory(compressed.GetDataStream()).NextPgpObject();
            }

            if (obj is not PgpSignatureList { Count: > 0 } sigList)
            {
                return false;
            }

            var sig = sigList[0];

            var publicKey = keyRing.GetPublicKey(sig.KeyId);  // null when signed by an untrusted key
            if (publicKey is null)
            {
                return false;
            }

            sig.InitVerify(publicKey);
            sig.Update(repomd);
            return sig.Verify();
        }
        catch
        {
            return false;
        }
    }

    // ── Internal: hash-prefixed metadata files ────────────────────────────────

    private async Task<RepodataResult?> GetHashPrefixedAsync(string upstreamBase, string filename, CancellationToken ct)
    {
        string? sha256 = ExtractSha256Prefix(filename);
        if (sha256 is null)
        {
            return null;
        }

        string blobKey = BlobKeys.RpmRepodataProxy(sha256);

        // Blob store hit — serve from cache tier forever (content-addressed = immutable).
        var existing = await _cacheStore.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            byte[] bytes = await ReadStreamAsync(existing, ct);
            return new RepodataResult(bytes, ContentTypeFor(filename), ETag: null, LastModified: null, NotModified: false);
        }

        // Fetch from upstream, cache, serve.
        byte[]? body = await GetOrFetchRepodataBlobAsync(upstreamBase, filename, sha256, ct);
        return body is null ? null : new RepodataResult(body, ContentTypeFor(filename), ETag: null, LastModified: null, NotModified: false);
    }

    /// <summary>
    /// Gets a hash-prefixed metadata blob from blob store or upstream.
    /// Stores fetched bytes in the Cache tier at <c>BlobKeys.RpmRepodataProxy(sha256)</c>.
    /// </summary>
    private async Task<byte[]?> GetOrFetchRepodataBlobAsync(string upstreamBase, string filename, string sha256, CancellationToken ct)
    {
        string blobKey = BlobKeys.RpmRepodataProxy(sha256);
        var existing = await _cacheStore.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            return await ReadStreamAsync(existing, ct);
        }

        string url = $"{upstreamBase}/repodata/{filename}";
        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
        {
            return null;
        }

        var client = _http.CreateClient("upstream");
        using var resp = await client.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode)
        {
            return null;
        }

        byte[] body;
        try
        {
            // Hash-prefixed repodata (primary.xml.gz et al.) can legitimately reach tens of
            // megabytes on large distro repos, so the cap here is the artifact limit; the
            // SHA-256 verification below still rejects any body that isn't the expected file.
            body = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxUpstreamResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "RPM repodata response exceeded the artifact cap for {Url}; treating as unavailable.", url);
            return null;
        }

        // Verify the fetched bytes against the expected SHA-256 before caching. RPM repodata
        // is content-addressed and cached "forever", and ResolvePackageUrlAsync lifts the
        // per-package download checksums out of this primary.xml.gz — so caching an unverified
        // body from a malicious or MITM'd upstream would poison the package-integrity chain.
        if (!RepodataBodyMatches(body, sha256))
        {
            DependablyMeter.UpstreamChecksumFailures.Add(
                1, new KeyValuePair<string, object?>("ecosystem", "rpm"));
            return null;
        }

        await _cacheStore.PutAsync(blobKey, new MemoryStream(body), ct);
        return body;
    }

    /// <summary>
    /// True if <paramref name="body"/> hashes to <paramref name="expectedSha256"/>. The
    /// expected value is either the compressed-file checksum (repomd <c>&lt;checksum&gt;</c>,
    /// and the hash-prefixed filename DNF derives from it) or the decompressed checksum
    /// (<c>&lt;open-checksum&gt;</c>), so the body is accepted if it matches under either
    /// interpretation. An attacker cannot forge a preimage for a hash they do not control
    /// under either transform, so accepting both does not weaken the check.
    /// </summary>
    private static bool RepodataBodyMatches(byte[] body, string expectedSha256)
    {
        if (Sha256Hex(body).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        try
        {
            using var limited = new LimitedReadStream(
                new GZipStream(new MemoryStream(body), CompressionMode.Decompress),
                RepodataDecompressLimits.MaxDecompressedBytes, "repodata checksum probe");
            using var ms = new MemoryStream();
            limited.CopyTo(ms);
            return Sha256Hex(ms.ToArray()).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // Not gzip / corrupt / over decompression limit: only the compressed-form check applies,
            // and it already failed.
            return false;
        }
    }

    private static string Sha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Parsing helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Parses <c>repomd.xml</c> and returns the href and SHA-256 of the <c>primary</c>
    /// data element. Returns <c>(null, null)</c> on any parse failure.
    /// </summary>
    internal static (string? Filename, string? Sha256) ParsePrimaryFromRepomd(byte[] repomdBytes)
        => ParseRepodataEntryFromRepomd(repomdBytes, "primary");

    /// <summary>
    /// Parses <c>repomd.xml</c> and returns the href + SHA-256 for the <c>&lt;data
    /// type="<paramref name="dataType"/>"&gt;</c> entry. Returns <c>(null, null)</c> when
    /// the entry is absent or on any parse failure.
    /// </summary>
    internal static (string? Filename, string? Sha256) ParseRepodataEntryFromRepomd(byte[] repomdBytes, string dataType)
    {
        try
        {
            XNamespace ns = "http://linux.duke.edu/metadata/repo";
            var doc = XDocument.Load(new MemoryStream(repomdBytes));

            var dataEl = doc.Descendants(ns + "data")
                .FirstOrDefault(e => (string?)e.Attribute("type") == dataType);
            if (dataEl is null)
            {
                return (null, null);
            }

            string? href = (string?)dataEl.Element(ns + "location")?.Attribute("href");
            if (href is null)
            {
                return (null, null);
            }

            // Try both <checksum> (sha256 type) and <open-checksum>
            var sha256 = dataEl.Elements(ns + "checksum")
                             .FirstOrDefault(e => (string?)e.Attribute("type") == "sha256")
                         ?? dataEl.Elements(ns + "open-checksum")
                             .FirstOrDefault(e => (string?)e.Attribute("type") == "sha256");

            string filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;
            return (filename, (string?)sha256);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Parses <c>repomd.xml</c> and returns all non-primary <c>&lt;data&gt;</c> elements verbatim
    /// (filelists, other, group, modules, updateinfo, …). The caller filters these down to
    /// servable hash-prefixed entries before including them in the merged repomd, so upstream's
    /// supplemental metadata remains reachable via hash-prefixed routes.
    /// Returns an empty list on any parse failure.
    /// </summary>
    internal static IReadOnlyList<XElement> ParseNonPrimaryRepomdEntries(byte[] repomdBytes)
    {
        try
        {
            XNamespace ns = "http://linux.duke.edu/metadata/repo";
            var doc = XDocument.Load(new MemoryStream(repomdBytes));

            return doc.Descendants(ns + "data")
                .Where(e => (string?)e.Attribute("type") != "primary")
                .Select(e => new XElement(e))
                .ToArray();
        }
        catch
        {
            return Array.Empty<XElement>();
        }
    }

    /// <summary>
    /// Decompresses and parses <c>primary.xml.gz</c>, building a filename → resolution map.
    /// <paramref name="upstreamBase"/> is used to construct absolute download URLs from the
    /// relative <c>href</c> values in the XML.
    /// </summary>
    internal static Dictionary<string, PackageResolution> ParsePrimaryXmlGz(byte[] gzBytes, string upstreamBase)
    {
        byte[] xmlBytes;
        using (var limited = new LimitedReadStream(
            new GZipStream(new MemoryStream(gzBytes), CompressionMode.Decompress),
            RepodataDecompressLimits.MaxDecompressedBytes, "primary.xml.gz parse"))
        using (var ms = new MemoryStream())
        {
            limited.CopyTo(ms);
            xmlBytes = ms.ToArray();
        }

        XNamespace common = "http://linux.duke.edu/metadata/common";
        XNamespace rpmNs = "http://linux.duke.edu/metadata/rpm";

        var doc = XDocument.Load(new MemoryStream(xmlBytes));
        var map = new Dictionary<string, PackageResolution>(StringComparer.OrdinalIgnoreCase);

        foreach (var pkg in doc.Descendants(common + "package"))
        {
            if ((string?)pkg.Attribute("type") != "rpm")
            {
                continue;
            }

            string? href = (string?)pkg.Element(common + "location")?.Attribute("href");
            if (href is null)
            {
                continue;
            }

            string filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;

            string? sha256 = (string?)pkg.Elements(common + "checksum")
                .FirstOrDefault(e => (string?)e.Attribute("type") == "sha256");
            if (sha256 is null)
            {
                continue;
            }

            string name = (string?)pkg.Element(common + "name") ?? "";
            string arch = (string?)pkg.Element(common + "arch") ?? "";
            var versionEl = pkg.Element(common + "version");
            int epoch = int.TryParse((string?)versionEl?.Attribute("epoch"), out int e) ? e : 0;
            string ver = (string?)versionEl?.Attribute("ver") ?? "";
            string rel = (string?)versionEl?.Attribute("rel") ?? "";
            string? summary = (string?)pkg.Element(common + "summary");
            string? description = (string?)pkg.Element(common + "description");
            string? license = (string?)pkg.Element(common + "format")
                ?.Element(rpmNs + "license");

            // href may be relative (Packages/t/tree-...) or absolute; normalise to absolute.
            string packageUrl = href.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                          || href.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? href
                : $"{upstreamBase}/{href.TrimStart('/')}";

            map[filename] = new PackageResolution(packageUrl, sha256, name, epoch, ver, rel, arch, summary, description, license);
        }

        return map;
    }

    // ── Static helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the filename begins with a 64-character lowercase hex string
    /// (SHA-256) followed by a hyphen — the DNF content-addressed naming convention for
    /// <c>primary.xml.gz</c>, <c>filelists.xml.gz</c>, etc.
    /// </summary>
    internal static bool IsHashPrefixedFilename(string filename)
    {
        if (filename.Length < HashPrefixedFilenameMinLength)
        {
            return false; // 64 hex + '-' + at least one char
        }

        int dashIdx = filename.IndexOf('-');
        return dashIdx == Sha256HexLength && filename[..Sha256HexLength].All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    /// <summary>Extracts the 64-char lowercase hex prefix from a hash-prefixed filename, or null.</summary>
    private static string? ExtractSha256Prefix(string filename)
    {
        return !IsHashPrefixedFilename(filename) ? null : filename[..Sha256HexLength];
    }

    /// <summary>
    /// Returns the <c>SHA-256(url)[..32]</c> hex string used as the negative-cache key.
    /// </summary>
    internal static string UrlKey(string url)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(url));
        return Convert.ToHexString(hash).ToLowerInvariant()[..UrlKeyPrefixLength];
    }

    private static string ContentTypeFor(string filename)
    {
        return filename.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? "application/x-gzip"
            : filename.EndsWith(".bz2", StringComparison.OrdinalIgnoreCase) ? "application/x-bzip2"
            : filename.EndsWith(".zst", StringComparison.OrdinalIgnoreCase) ? "application/zstd"
            : filename.EndsWith(".asc", StringComparison.OrdinalIgnoreCase) ||
            filename.EndsWith(".key", StringComparison.OrdinalIgnoreCase) ? "application/pgp-keys"
            : "application/xml";
    }

    private static async Task<byte[]> ReadStreamAsync(Stream stream, CancellationToken ct)
    {
        await using (stream.ConfigureAwait(false))
        {
            if (stream.CanSeek && stream.Length > 0 && stream.Length <= int.MaxValue)
            {
                byte[] buf = new byte[stream.Length];
                await stream.ReadExactlyAsync(buf, ct);
                return buf;
            }

            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
    }
}

// DI-injected dependency aggregate for RpmUpstreamProxy. Single param avoids S107 on the
// constructor; field unpacking in the ctor keeps the rest of the class untouched.
public sealed record RpmUpstreamProxyServices(
    IHttpClientFactory HttpClientFactory,
    TieredBlobStorage Blobs,
    IMetadataStore Db,
    IMemoryCache MemoryCache,
    IConfiguration Configuration,
    IAirGapMode AirGap,
    IUpstreamUrlValidator UrlValidator,
    ILogger<RpmUpstreamProxy> Logger,
    TimeProvider Time,
    IPerOrgTrustAnchorStore TrustStore);
