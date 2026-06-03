using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Caching.Memory;

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
    Task<RepodataResult?> GetRepodataAsync(string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct);
    Task<PackageResolution?> ResolvePackageUrlAsync(string upstreamBase, string filename, CancellationToken ct);
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
    private readonly IHttpClientFactory _http;
    private readonly IBlobStore _cacheStore;  // blobs.Cache
    private readonly IMetadataStore _db;
    private readonly IMemoryCache _memCache;
    private readonly IAirGapMode _airGap;
    private readonly IUpstreamUrlValidator _urlValidator;

    private readonly string _upstreamMode;  // "passthrough" | "merged"
    private readonly TimeSpan _repomdTtl;
    private readonly TimeSpan _gpgKeyTtl;
    private readonly TimeSpan _negativeCacheTtl;

    // Dedup concurrent repomd.xml fetches — only one HTTP round-trip per (base URL, file) at a time.
    private readonly ConcurrentDictionary<string, Lazy<Task<(byte[] Body, string? ETag, string? LastModified)>>> _repomdInflight = new();

    /// <summary>
    /// True when the instance-level mode is 'passthrough'. Per-org configured-ness comes
    /// from the upstream registry list (resolved controller-side); the controller combines
    /// this selector with "the org has at least one rpm registry" to decide effective passthrough.
    /// </summary>
    public bool IsPassthroughModeSelected => string.Equals(_upstreamMode, "passthrough", StringComparison.OrdinalIgnoreCase);

    public RpmUpstreamProxy(
        IHttpClientFactory httpClientFactory,
        TieredBlobStorage blobs,
        IMetadataStore db,
        IMemoryCache memoryCache,
        IConfiguration configuration,
        IAirGapMode airGap,
        IUpstreamUrlValidator urlValidator)
    {
        _http = httpClientFactory;
        _cacheStore = blobs.Cache;
        _db = db;
        _memCache = memoryCache;
        _airGap = airGap;
        _urlValidator = urlValidator;

        _upstreamMode = configuration["Rpm:UpstreamMode"] ?? "passthrough";

        _repomdTtl = TimeSpan.TryParse(configuration["Rpm:RepomdTtl"], out var r) ? r : TimeSpan.FromSeconds(60);
        _gpgKeyTtl = TimeSpan.TryParse(configuration["Rpm:GpgKeyTtl"], out var g) ? g : TimeSpan.FromDays(1);
        _negativeCacheTtl = TimeSpan.TryParse(configuration["Rpm:NegativeCacheTtl"], out var n) ? n : TimeSpan.FromMinutes(5);
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
        if (_airGap.IsEnabled) throw new AirGappedException($"rpm:repodata:{filename}");

        if (filename.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase)
         || filename.Equals("repomd.xml.asc", StringComparison.OrdinalIgnoreCase))
            return await GetRepomdAsync(upstreamBase, filename, ifNoneMatch, ifModifiedSince, ct);

        if (IsHashPrefixedFilename(filename))
            return await GetHashPrefixedAsync(upstreamBase, filename, ct);

        return null;
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
    public async Task<PackageResolution?> ResolvePackageUrlAsync(string upstreamBase, string filename, CancellationToken ct)
    {
        if (_airGap.IsEnabled) throw new AirGappedException($"rpm:resolve:{filename}");

        // 1. Get current repomd.xml bytes (from memory cache or upstream)
        var repomdBytes = await GetRepomdBodyAsync(upstreamBase, ct);
        if (repomdBytes is null) return null;

        // 2. Parse repomd.xml to find primary.xml.gz href + checksum
        var (primaryFilename, primarySha256) = ParsePrimaryFromRepomd(repomdBytes);
        if (primaryFilename is null || primarySha256 is null) return null;

        // 3. Get primary.xml.gz bytes (from blob cache or upstream)
        var primaryGzBytes = await GetOrFetchRepodataBlobAsync(upstreamBase, primaryFilename, primarySha256, ct);
        if (primaryGzBytes is null) return null;

        // 4. Parse primary.xml.gz (cached by sha256 so it automatically tracks repodata rotation)
        var mapKey = $"rpm:primary-map:{primarySha256}";
        if (!_memCache.TryGetValue<Dictionary<string, PackageResolution>>(mapKey, out var packageMap))
        {
            packageMap = ParsePrimaryXmlGz(primaryGzBytes, upstreamBase);
            // Long TTL is fine — the map invalidates naturally when repomd.xml rotates to a
            // new primary.xml.gz sha256, creating a new cache slot and letting the old one GC.
            _memCache.Set(mapKey, packageMap, TimeSpan.FromHours(4));
        }

        return packageMap!.GetValueOrDefault(filename);
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
        if (_airGap.IsEnabled) throw new AirGappedException("rpm:gpg-key");

        var cacheKey = $"rpm:gpgkey:{upstreamBase}";
        if (_memCache.TryGetValue<byte[]>(cacheKey, out var cached))
            return cached;

        // Fedora / EPEL mirrors serve the key at one of these paths.
        var paths = new[] { "RPM-GPG-KEY", "repodata/repomd.xml.key" };
        var client = _http.CreateClient("upstream");
        foreach (var path in paths)
        {
            var url = $"{upstreamBase}/{path}";
            if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct)) continue;

            using var resp = await client.GetAsync(url, ct);
            if (!resp.IsSuccessStatusCode) continue;

            var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
            _memCache.Set(cacheKey, bytes, _gpgKeyTtl);
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
        var urlKey = UrlKey(upstreamPath);
        var cutoff = DateTime.UtcNow.Add(-_negativeCacheTtl).ToString("yyyy-MM-ddTHH:mm:ssZ");
        // xtenant: upstream_negative_cache is content-addressed (SHA-256 of URL → 404) and
        // intentionally shared across tenants. A URL either 404s or it doesn't.
        await using var conn = await _db.OpenAsync(ct);
        var hit = await conn.ExecuteScalarAsync<string?>(
            "SELECT url_key FROM upstream_negative_cache WHERE url_key = @key AND ecosystem = 'rpm' AND fetched_at >= @cutoff",
            new { key = urlKey, cutoff });
        return hit is not null;
    }

    /// <summary>Records a 404 response for <paramref name="upstreamPath"/> in the negative cache.</summary>
    public async Task RecordNegativeAsync(string upstreamPath, CancellationToken ct)
    {
        var urlKey = UrlKey(upstreamPath);
        var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
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
        var cacheKey = $"rpm:repomd:{upstreamBase}:{filename}";

        // Memory cache hit — serve immediately, propagating 304 if client's ETag matches.
        if (_memCache.TryGetValue<CachedRepomd>(cacheKey, out var cached))
        {
            if (ifNoneMatch is not null && cached!.ETag is not null &&
                ifNoneMatch.Contains(cached.ETag))
                return new RepodataResult([], ContentTypeFor(filename), cached.ETag, cached.LastModified, NotModified: true);

            return new RepodataResult(cached!.Body, ContentTypeFor(filename), cached.ETag, cached.LastModified, NotModified: false);
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

        _memCache.Set(cacheKey, new CachedRepomd(result.body, result.etag, result.lastModified), _repomdTtl);
        return new RepodataResult(result.body, ContentTypeFor(filename), result.etag, result.lastModified, NotModified: false);
    }

    private async Task<(byte[] Body, string? ETag, string? LastModified)> FetchRepomdFromUpstreamAsync(
        string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
    {
        var url = $"{upstreamBase}/repodata/{filename}";
        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
            return ([], null, null);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (!string.IsNullOrEmpty(ifNoneMatch))
            req.Headers.TryAddWithoutValidation("If-None-Match", ifNoneMatch);
        if (!string.IsNullOrEmpty(ifModifiedSince))
            req.Headers.TryAddWithoutValidation("If-Modified-Since", ifModifiedSince);

        var client = _http.CreateClient("upstream");
        using var resp = await client.SendAsync(req, ct);

        if (resp.StatusCode == System.Net.HttpStatusCode.NotModified)
            return ([], resp.Headers.ETag?.ToString() ?? "304", null); // etag acts as sentinel

        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            return ([], null, null); // null ETag = 404

        resp.EnsureSuccessStatusCode();

        var body = await resp.Content.ReadAsByteArrayAsync(ct);
        var etag = resp.Headers.ETag?.ToString();
        var lastMod = resp.Content.Headers.LastModified?.ToString("R");
        return (body, etag, lastMod);
    }

    /// <summary>
    /// Returns the raw bytes of the current <c>repomd.xml</c> (from memory cache if present,
    /// fetching from upstream otherwise). Used internally by <see cref="ResolvePackageUrlAsync"/>.
    /// </summary>
    private async Task<byte[]?> GetRepomdBodyAsync(string upstreamBase, CancellationToken ct)
    {
        var cacheKey = $"rpm:repomd:{upstreamBase}:repomd.xml";
        if (_memCache.TryGetValue<CachedRepomd>(cacheKey, out var cached))
            return cached!.Body;

        var result = await GetRepomdAsync(upstreamBase, "repomd.xml", null, null, ct);
        return result?.NotModified == false ? result.Body : null;
    }

    // ── Internal: hash-prefixed metadata files ────────────────────────────────

    private async Task<RepodataResult?> GetHashPrefixedAsync(string upstreamBase, string filename, CancellationToken ct)
    {
        var sha256 = ExtractSha256Prefix(filename);
        if (sha256 is null) return null;

        var blobKey = BlobKeys.RpmRepodataProxy(sha256);

        // Blob store hit — serve from cache tier forever (content-addressed = immutable).
        var existing = await _cacheStore.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            var bytes = await ReadStreamAsync(existing, ct);
            return new RepodataResult(bytes, ContentTypeFor(filename), ETag: null, LastModified: null, NotModified: false);
        }

        // Fetch from upstream, cache, serve.
        var body = await GetOrFetchRepodataBlobAsync(upstreamBase, filename, sha256, ct);
        if (body is null) return null;
        return new RepodataResult(body, ContentTypeFor(filename), ETag: null, LastModified: null, NotModified: false);
    }

    /// <summary>
    /// Gets a hash-prefixed metadata blob from blob store or upstream.
    /// Stores fetched bytes in the Cache tier at <c>BlobKeys.RpmRepodataProxy(sha256)</c>.
    /// </summary>
    private async Task<byte[]?> GetOrFetchRepodataBlobAsync(string upstreamBase, string filename, string sha256, CancellationToken ct)
    {
        var blobKey = BlobKeys.RpmRepodataProxy(sha256);
        var existing = await _cacheStore.GetAsync(blobKey, ct);
        if (existing is not null)
            return await ReadStreamAsync(existing, ct);

        var url = $"{upstreamBase}/repodata/{filename}";
        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct)) return null;

        var client = _http.CreateClient("upstream");
        using var resp = await client.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return null;

        var body = await resp.Content.ReadAsByteArrayAsync(ct);
        await _cacheStore.PutAsync(blobKey, new MemoryStream(body), ct);
        return body;
    }

    // ── Parsing helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Parses <c>repomd.xml</c> and returns the href and SHA-256 of the <c>primary</c>
    /// data element. Returns <c>(null, null)</c> on any parse failure.
    /// </summary>
    internal static (string? Filename, string? Sha256) ParsePrimaryFromRepomd(byte[] repomdBytes)
    {
        try
        {
            XNamespace ns = "http://linux.duke.edu/metadata/repo";
            var doc = XDocument.Load(new MemoryStream(repomdBytes));

            var primaryData = doc.Descendants(ns + "data")
                .FirstOrDefault(e => (string?)e.Attribute("type") == "primary");
            if (primaryData is null) return (null, null);

            var href = (string?)primaryData.Element(ns + "location")?.Attribute("href");
            if (href is null) return (null, null);

            // Try both <checksum> (sha256 type) and <open-checksum>
            var sha256 = primaryData.Elements(ns + "checksum")
                             .FirstOrDefault(e => (string?)e.Attribute("type") == "sha256")
                         ?? primaryData.Elements(ns + "open-checksum")
                             .FirstOrDefault(e => (string?)e.Attribute("type") == "sha256");

            var filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;
            return (filename, (string?)sha256);
        }
        catch
        {
            return (null, null);
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
        using (var gz = new GZipStream(new MemoryStream(gzBytes), CompressionMode.Decompress))
        using (var ms = new MemoryStream())
        {
            gz.CopyTo(ms);
            xmlBytes = ms.ToArray();
        }

        XNamespace common = "http://linux.duke.edu/metadata/common";
        XNamespace rpmNs = "http://linux.duke.edu/metadata/rpm";

        var doc = XDocument.Load(new MemoryStream(xmlBytes));
        var map = new Dictionary<string, PackageResolution>(StringComparer.OrdinalIgnoreCase);

        foreach (var pkg in doc.Descendants(common + "package"))
        {
            if ((string?)pkg.Attribute("type") != "rpm") continue;

            var href = (string?)pkg.Element(common + "location")?.Attribute("href");
            if (href is null) continue;
            var filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;

            var sha256 = (string?)pkg.Elements(common + "checksum")
                .FirstOrDefault(e => (string?)e.Attribute("type") == "sha256");
            if (sha256 is null) continue;

            var name = (string?)pkg.Element(common + "name") ?? "";
            var arch = (string?)pkg.Element(common + "arch") ?? "";
            var versionEl = pkg.Element(common + "version");
            var epoch = int.TryParse((string?)versionEl?.Attribute("epoch"), out var e) ? e : 0;
            var ver = (string?)versionEl?.Attribute("ver") ?? "";
            var rel = (string?)versionEl?.Attribute("rel") ?? "";
            var summary = (string?)pkg.Element(common + "summary");
            var description = (string?)pkg.Element(common + "description");
            var license = (string?)pkg.Element(common + "format")
                ?.Element(rpmNs + "license");

            // href may be relative (Packages/t/tree-...) or absolute; normalise to absolute.
            var packageUrl = href.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
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
        if (filename.Length < 66) return false; // 64 hex + '-' + at least one char
        var dashIdx = filename.IndexOf('-');
        if (dashIdx != 64) return false;
        var prefix = filename.AsSpan(0, 64);
        foreach (var c in prefix)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        return true;
    }

    /// <summary>Extracts the 64-char lowercase hex prefix from a hash-prefixed filename, or null.</summary>
    private static string? ExtractSha256Prefix(string filename)
    {
        if (!IsHashPrefixedFilename(filename)) return null;
        return filename[..64];
    }

    /// <summary>
    /// Returns the <c>SHA-256(url)[..32]</c> hex string used as the negative-cache key.
    /// </summary>
    internal static string UrlKey(string url)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(url));
        return Convert.ToHexString(hash).ToLowerInvariant()[..32];
    }

    private static string ContentTypeFor(string filename)
    {
        if (filename.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) return "application/x-gzip";
        if (filename.EndsWith(".bz2", StringComparison.OrdinalIgnoreCase)) return "application/x-bzip2";
        if (filename.EndsWith(".zst", StringComparison.OrdinalIgnoreCase)) return "application/zstd";
        if (filename.EndsWith(".asc", StringComparison.OrdinalIgnoreCase) ||
            filename.EndsWith(".key", StringComparison.OrdinalIgnoreCase)) return "application/pgp-keys";
        return "application/xml";
    }

    private static async Task<byte[]> ReadStreamAsync(Stream stream, CancellationToken ct)
    {
        await using (stream.ConfigureAwait(false))
        {
            if (stream.CanSeek && stream.Length > 0 && stream.Length <= int.MaxValue)
            {
                var buf = new byte[stream.Length];
                await stream.ReadExactlyAsync(buf, ct);
                return buf;
            }

            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
    }
}
