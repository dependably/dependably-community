using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Api;

/// <summary>
/// Alpine apk pull-through proxy surface. Routes <c>GET|HEAD /apk/{**path}</c> where
/// <c>path = {release}/{repo}/{arch}/{file}</c> — 1:1 with dl-cdn.alpinelinux.org's layout, so
/// a sed host-rewrite of <c>/etc/apk/repositories</c> is the only client-side change. Release
/// names (<c>edge</c>, <c>latest-stable</c>, <c>v3.22</c>) pass through uninterpreted.
///
/// Two request shapes:
/// <list type="bullet">
///   <item><c>.apk</c> package files — TOFU-cached (<c>checksumSpec: null</c>): APKINDEX's
///   <c>C:Q1…</c> digest is a control-segment SHA-1, not a full-file digest, so RPM-style
///   index-sealed verification is impossible. The observed SHA-256 is recorded into
///   <c>cache_artifact</c> global facts on first fetch; apk clients verify the embedded RSA
///   package signature themselves.</item>
///   <item>Everything else (<c>APKINDEX.tar.gz</c>, <c>.SIGN.RSA.*</c>, and any other
///   index-adjacent file) — short-TTL memory-cached passthrough via
///   <see cref="ApkIndexFetchCoordinator"/>. <c>APKINDEX.tar.gz</c> specifically is verified
///   server-side against the org's apk RSA trust anchors before it is cached or served — see
///   <see cref="ApkIndexFetchCoordinator"/> for the gating rule. apk clients also verify the
///   same embedded signature against <c>/etc/apk/keys</c> on their end.</item>
/// </list>
///
/// Proxy-only surface, same as Go: no hosted push path, no org_settings column. Auth follows
/// the RPM/Go ordering (resolve token, then the AnonymousPull gate); apk clients authenticate
/// via <c>https://user:token@host</c> userinfo, which <see cref="TokenAuthExtensions"/> resolves
/// on the Basic branch.
/// </summary>
[ApiController]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075",
    Justification = "Default apk upstream URL is a well-known public mirror. Override via Apk:Upstream.")]
public sealed class ApkController : OrgScopedControllerBase
{
    private readonly ApkControllerServices _svc;

    public ApkController(ApkControllerServices svc) => _svc = svc;

    // ── Route entry point ────────────────────────────────────────────────────

    /// <summary>
    /// GET|HEAD /apk/{**path} — catch-all route. <paramref name="path"/> must split into
    /// exactly four segments: release/repo/arch/file.
    /// </summary>
    [HttpGet("/apk/{**path}")]
    [HttpHead("/apk/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> HandleApkRequest(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return NotFound();
        }

        string[] segments = path.Split('/');
        if (segments.Length != 4)
        {
            return NotFound();
        }

        string release = segments[0];
        string repo = segments[1];
        string arch = segments[2];
        string file = segments[3];

        foreach (var (value, field) in new[] { (release, "release"), (repo, "repo"), (arch, "arch"), (file, "file") })
        {
            var result = PathSafeValidator.ValidateUpstreamSegment(value, field);
            if (!result.IsValid)
            {
                return BadRequest($"Invalid {field}: {result.Message}");
            }
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        return IsApkArtifact(file)
            ? await ServeApkArtifactAsync(orgId, release, repo, arch, file, settings, token, ct)
            : await ServeApkIndexAsync(orgId, release, repo, arch, file, settings, ct);
    }

    private static bool IsApkArtifact(string file) =>
        file.EndsWith(".apk", StringComparison.OrdinalIgnoreCase);

    // ── Package (.apk) serving ───────────────────────────────────────────────

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct fetch-coordinate input; the trailing optional context params add no cohesion when bundled.")]
    private async Task<IActionResult> ServeApkArtifactAsync(
        string orgId, string release, string repo, string arch, string file,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // A non-matching filename (parsed is null) has no stable name/version to key the
        // global-plane / block-gate / reserved-namespace checks on — those are skipped and the
        // artifact is served (or fetched) purely by blob key, matching the design's "never 500
        // on an unparsable filename" contract.
        var parsed = ParseApkFilename(file);
        string? purl = parsed is { } p ? PurlNormalizer.Apk(p.PkgName, p.PkgVer, p.PkgRel, arch) : null;
        string blobKey = BlobKeys.Apk(orgId, release, repo, arch, file);

        var cached = await _svc.Blobs.GetAsync(blobKey, ct);
        if (cached is not null)
        {
            if (parsed is { } cp
                && await IsApkBlockedAsync(orgId, cp, repo, arch, file, token, settings, ct))
            {
                await cached.DisposeAsync();
                return StatusCode(StatusCodes.Status403Forbidden);
            }

            Response.Headers["X-Cache"] = "HIT";
            if (parsed is { } hp)
            {
                await RecordApkCacheHitAsync(orgId, hp, repo, arch, file, blobKey, ct);
            }
            return File(cached, "application/octet-stream", file);
        }

        bool proxyOff = settings is not null && !settings.ProxyPassthroughEffective;
        bool reserved = parsed is { } rp
            && await _svc.Reserved.IsReservedAsync(orgId, "apk", rp.PkgName, ct);
        if (proxyOff || reserved)
        {
            return NotFound();
        }

        string negativeCacheKey = $"{release}/{repo}/{arch}/{file}";
        if (await IsApkNegativelyCachedAsync(negativeCacheKey, ct))
        {
            return NotFound();
        }

        var upstreamBases = await _svc.Registries.ResolveAsync(orgId, "apk", ct);
        return upstreamBases.Count == 0
            ? NotFound()
            : await FetchApkArtifactFromUpstreamsAsync(
                orgId, release, repo, arch, file, parsed, purl, blobKey, negativeCacheKey, upstreamBases, token, ct);
    }

    // Walks the configured upstream sources in priority order (Go precedent — apk is
    // proxy-only, so every configured registry is tried rather than only the top-priority one).
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct fetch-coordinate input; the trailing optional context params add no cohesion when bundled.")]
    private async Task<IActionResult> FetchApkArtifactFromUpstreamsAsync(
        string orgId, string release, string repo, string arch, string file,
        (string PkgName, string PkgVer, string PkgRel)? parsed, string? purl, string blobKey,
        string negativeCacheKey, IReadOnlyList<UpstreamSource> upstreamBases, TokenRecord? token,
        CancellationToken ct)
    {
        bool sawNotFound = false;
        foreach (var source in upstreamBases)
        {
            string upstreamUrl = $"{source.Url}/{release}/{repo}/{arch}/{file}";
            UpstreamFetchResult fetchResult;
            try
            {
                // TOFU (checksumSpec: null): APKINDEX's C:Q1… digest is a control-segment SHA-1,
                // not a full-file digest — RPM-style index-sealed verification is impossible for
                // apk. apk clients verify the embedded RSA package signature themselves; the
                // fetched SHA-256 is recorded as an observed fact on first sight, not a check.
                fetchResult = await _svc.Upstream.GetOrFetchToBlobKeyAsync(
                    blobKey, upstreamUrl, checksumSpec: null, "apk", orgId, purl,
                    authorizationHeader: source.AuthorizationHeader, ct: ct);
            }
            catch (UpstreamResponseTooLargeException)
            {
                _svc.Logger.LogWarning(
                    "Upstream response too large fetching apk {File} from {UpstreamBase}", file, source.Url);
                return StatusCode(StatusCodes.Status502BadGateway, "Upstream response exceeded size limit.");
            }
            catch (HttpRequestException ex)
            {
                if (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    sawNotFound = true;
                    continue;
                }

                _svc.Logger.LogWarning(
                    ex, "HTTP error fetching apk {File} from {UpstreamBase}: {ExceptionType}",
                    file, source.Url, ex.GetType().Name);
                return StatusCode(StatusCodes.Status502BadGateway, "Upstream fetch failed.");
            }
            catch (SsrfBlockedException ex)
            {
                _svc.Logger.LogWarning(
                    ex, "SSRF-blocked apk upstream fetching {File} from {UpstreamBase}: {ExceptionType}",
                    file, source.Url, ex.GetType().Name);
                return StatusCode(StatusCodes.Status502BadGateway, "Upstream fetch failed.");
            }

            if (parsed is { } p)
            {
                await RecordApkFirstFetchAsync(orgId, p, repo, arch, file, fetchResult, upstreamUrl, purl, ct);
            }

            await _svc.Audit.LogActivityAsync(
                orgId, "apk", purl, "first_fetch", token?.UserId,
                sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

            Response.Headers["X-Cache"] = "MISS";
            var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(fetchResult.BlobKey), ct);
            return stream is null ? NotFound() : File(stream, "application/octet-stream", file);
        }

        if (sawNotFound)
        {
            await RecordApkNegativeAsync(negativeCacheKey, ct);
        }

        return NotFound();
    }

    // ── Filename parsing ──────────────────────────────────────────────────────

    /// <summary>
    /// Parses <c>{pkgname}-{pkgver}-r{pkgrel}.apk</c> from the right: Alpine forbids <c>-</c>
    /// in <c>pkgver</c>, so the rightmost <c>-r{digits}</c> segment is unambiguously
    /// <c>pkgrel</c>, and the dash before it unambiguously separates <c>pkgname</c> from
    /// <c>pkgver</c> (mirrors <see cref="RpmController.ParseNevra"/>'s from-the-right strategy).
    /// Returns null for a filename that doesn't match the convention — callers skip the
    /// name/version-keyed lookups (global plane, block gate, reserved namespace) rather than
    /// failing the request.
    /// </summary>
    internal static (string PkgName, string PkgVer, string PkgRel)? ParseApkFilename(string filename)
    {
        if (!filename.EndsWith(".apk", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string stem = filename[..^4];

        int relDash = stem.LastIndexOf('-');
        if (relDash <= 0)
        {
            return null;
        }

        string relPart = stem[(relDash + 1)..];
        if (relPart.Length < 2 || relPart[0] != 'r' || !relPart[1..].All(char.IsAsciiDigit))
        {
            return null;
        }

        string pkgrel = relPart[1..];
        string nameVer = stem[..relDash];

        int verDash = nameVer.LastIndexOf('-');
        if (verDash <= 0 || verDash == nameVer.Length - 1)
        {
            return null;
        }

        string pkgname = nameVer[..verDash];
        string pkgver = nameVer[(verDash + 1)..];
        return (pkgname, pkgver, pkgrel);
    }

    // ── Global-plane recording ──────────────────────────────────────────────

    // The cache_artifact coordinate is (ecosystem, name, version, filename), UNIQUE on the
    // schema. apk package filenames carry no arch segment (unlike RPM's NEVRA), so the same
    // {pkgname}-{pkgver}-r{pkgrel}.apk filename legitimately holds different bytes per (repo,
    // arch) — folding repo+arch into the coordinate filename keeps every (repo, arch) build a
    // distinct global-plane row instead of colliding on the bare filename. The release is
    // deliberately left out: a rebuild-without-pkgrel-bump across releases is rare enough that
    // the existing content-divergence detection in CacheAccessRecorder (logged, non-blocking)
    // is the right amount of defense.
    private static string ApkCoordinateFilename(string repo, string arch, string file) => $"{repo}/{arch}/{file}";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct fetch-coordinate input; the trailing optional context params add no cohesion when bundled.")]
    private async Task<bool> IsApkBlockedAsync(
        string orgId, (string PkgName, string PkgVer, string PkgRel) p, string repo, string arch, string file,
        TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        var caFacts = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "apk", p.PkgName, $"{p.PkgVer}-r{p.PkgRel}", ApkCoordinateFilename(repo, arch, file), ct);
        return caFacts is not null
            && await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(
                    orgId, "apk", caFacts, token, settings, HttpContext.GetNormalizedRemoteIp()), ct)
                == BlockDecision.Blocked;
    }

    private async Task RecordApkCacheHitAsync(
        string orgId, (string PkgName, string PkgVer, string PkgRel) p, string repo, string arch, string file,
        string blobKey, CancellationToken ct)
    {
        string version = $"{p.PkgVer}-r{p.PkgRel}";
        string coordFilename = ApkCoordinateFilename(repo, arch, file);
        var caFacts = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "apk", p.PkgName, version, coordFilename, ct);
        string contentHash = caFacts?.ContentHash ?? "";
        long sizeBytes = caFacts?.SizeBytes ?? 0;

        string? cacheArtifactId = await _svc.CacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, "apk", p.PkgName, version, coordFilename,
                contentHash, sizeBytes, blobKey, UpstreamUrl: null), ct);
        if (cacheArtifactId is not null)
        {
            await _svc.TenantAccess.RecordDownloadHitAsync(orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);
        }
    }

    // Records an apk package first-fetch into the global cache plane. Mirrors the
    // GoController zip first-fetch pattern: a per-tenant packages row for discoverability, plus
    // the global cache_artifact + tenant_artifact_access rows carrying the TOFU-observed
    // SHA-256 as an upstream-integrity fact (not a verified checksum — apk clients verify the
    // embedded RSA signature themselves).
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct fetch-coordinate input; the trailing optional context params add no cohesion when bundled.")]
    private async Task RecordApkFirstFetchAsync(
        string orgId, (string PkgName, string PkgVer, string PkgRel) p, string repo, string arch, string file,
        UpstreamFetchResult fetchResult, string upstreamUrl, string? purl, CancellationToken ct)
    {
        string version = $"{p.PkgVer}-r{p.PkgRel}";
        string coordFilename = ApkCoordinateFilename(repo, arch, file);

        await _svc.Packages.GetOrCreateAsync(orgId, "apk", p.PkgName, p.PkgName, isProxy: true, ct);

        string? cacheArtifactId = await _svc.CacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, "apk", p.PkgName, version, coordFilename,
                fetchResult.Sha256Hex, fetchResult.SizeBytes, fetchResult.BlobKey, upstreamUrl), ct);
        if (cacheArtifactId is not null)
        {
            await _svc.TenantAccess.UpsertStateAsync(orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);

            await _svc.CacheArtifacts.UpdateGlobalFactsAsync(
                cacheArtifactId,
                purl: purl,
                checksumSha1: null,
                publishedAt: null,
                deprecated: null,
                hasInstallScript: false,
                installScriptKind: null,
                provenanceStatus: null,
                provenanceSigner: null,
                upstreamIntegrityValue: fetchResult.Sha256Hex,
                upstreamIntegrityAlgorithm: "sha256",
                ct: ct);
        }
    }

    // ── Negative cache ────────────────────────────────────────────────────────
    // Reuses upstream_negative_cache with ecosystem='apk', keyed on the route coordinate
    // (release/repo/arch/file) rather than a full upstream URL — mirrors RpmController's
    // filename-keyed negative cache (RPM keys on the flat NEVRA filename; apk's namespace is
    // scoped by repo path, so the coordinate is the key here).

    private async Task<bool> IsApkNegativelyCachedAsync(string coordinate, CancellationToken ct)
    {
        string urlKey = NegativeCacheUrlKey(coordinate);
        string cutoff = _svc.Time.GetUtcNow().UtcDateTime.Add(-_svc.NegativeCacheTtl).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _svc.Db.OpenAsync(ct);
        string? hit = await conn.ExecuteScalarAsync<string?>(
            "SELECT url_key FROM upstream_negative_cache WHERE url_key = @key AND ecosystem = 'apk' AND fetched_at >= @cutoff",
            new { key = urlKey, cutoff });
        return hit is not null;
    }

    private async Task RecordApkNegativeAsync(string coordinate, CancellationToken ct)
    {
        string urlKey = NegativeCacheUrlKey(coordinate);
        string now = _svc.Time.GetUtcNow().UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _svc.Db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_negative_cache (url_key, ecosystem, fetched_at)
            VALUES (@key, 'apk', @now)
            ON CONFLICT(url_key, ecosystem) DO UPDATE SET fetched_at = excluded.fetched_at
            """,
            new { key = urlKey, now });
    }

    private static string NegativeCacheUrlKey(string coordinate)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(coordinate));
        return Convert.ToHexString(hash).ToLowerInvariant()[..32];
    }

    // ── Index / index-adjacent passthrough ───────────────────────────────────

    private async Task<IActionResult> ServeApkIndexAsync(
        string orgId, string release, string repo, string arch, string file,
        OrgSettings? settings, CancellationToken ct)
    {
        if (settings is not null && !settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        var upstreamBases = await _svc.Registries.ResolveAsync(orgId, "apk", ct);
        if (upstreamBases.Count == 0)
        {
            return NotFound();
        }

        var source = upstreamBases[0];
        string? ifNoneMatch = Request.Headers.IfNoneMatch.FirstOrDefault();

        ApkIndexResult? result;
        try
        {
            result = await _svc.IndexCoordinator.GetAsync(
                source.Url, release, repo, arch, file, ifNoneMatch, source.AuthorizationHeader, orgId, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            _svc.Logger.LogWarning(
                ex, "apk index fetch failed for {Release}/{Repo}/{Arch}/{File}: {ExceptionType}",
                release, repo, arch, file, ex.GetType().Name);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream apk index fetch failed.");
        }

        if (result is null)
        {
            return NotFound();
        }

        if (result.ETag is not null)
        {
            Response.Headers.ETag = result.ETag;
        }

        return result.NotModified
            ? StatusCode(StatusCodes.Status304NotModified)
            : File(result.Body, result.ContentType);
    }
}

/// <summary>Scoped DI bundle for the apk controller.</summary>
public sealed record ApkControllerServices(
    OrgRepository Orgs,
    TokenRepository Tokens,
    AuditRepository Audit,
    PackageRepository Packages,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    UpstreamRegistryResolver Registries,
    IMetadataStore Db,
    CacheAccessRecorder CacheRecorder,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    TimeProvider Time,
    ILogger<ApkController> Logger,
    ReservedNamespaceService Reserved,
    BlockGateService BlockGate,
    ApkIndexFetchCoordinator IndexCoordinator,
    TimeSpan NegativeCacheTtl);

/// <summary>Result of an apk index/index-adjacent file fetch (see <see cref="ApkIndexFetchCoordinator"/>).</summary>
public sealed record ApkIndexResult(Stream Body, string ContentType, string? ETag, bool NotModified);

/// <summary>
/// Thrown by <see cref="ApkIndexFetchCoordinator.GetAsync"/> when <c>APKINDEX.tar.gz</c> fails
/// server-side RSA signature verification. <see cref="ApkController"/>'s existing catch-all
/// around the index fetch maps this — like any other upstream failure — to a 502,
/// refusing to cache or serve upstream metadata that failed to verify.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class ApkIndexSignatureVerificationFailedException : Exception
{
    public ApkIndexSignatureVerificationFailedException(string upstreamBase)
        : base($"APKINDEX.tar.gz signature verification failed for upstream {upstreamBase}.")
    {
    }
}

/// <summary>
/// Short-TTL memory-cached passthrough for apk index and index-adjacent files
/// (<c>APKINDEX.tar.gz</c>, <c>.SIGN.RSA.*</c>, and anything else under a
/// <c>{release}/{repo}/{arch}/</c> directory that isn't a <c>.apk</c> package). Cloned from
/// <see cref="Dependably.Protocol.RpmUpstreamProxy"/>'s repomd.xml passthrough: single-flight
/// dedup, client-facing ETag/304 within the TTL window, and the shared 32 MB metadata cap.
///
/// <c>APKINDEX.tar.gz</c> specifically is verified server-side against the requesting org's
/// apk RSA trust anchors — mirroring <c>Rpm:VerifyRepomdSignature</c> exactly: verification is
/// enabled when <c>Apk:VerifyIndexSignature</c> is explicitly set, or otherwise iff the org has
/// at least one configured anchor. Setting the override <c>true</c> with no per-org anchor
/// fails every resolution closed. Verification runs on every request that reaches this method
/// (cache hit or miss) using the caller's own org anchors, not once at fetch time — the byte
/// cache is shared across orgs (keyed by upstream base + filename only), so a per-request
/// re-check keeps one org's anchor configuration from vouching for bytes served to another. A
/// failed check throws <see cref="ApkIndexSignatureVerificationFailedException"/> before the
/// bytes are cached (on a fresh fetch) or re-served (on a cache hit); the controller's existing
/// catch-all maps this — like every other upstream failure — to a 502. Every other
/// index-adjacent file (raw <c>.SIGN.RSA.*</c> blobs, checksums, etc.) passes through
/// unverified; apk clients re-verify the embedded index signature against <c>/etc/apk/keys</c>
/// themselves regardless.
/// </summary>
public sealed class ApkIndexFetchCoordinator
{
    private const string IndexFilename = "APKINDEX.tar.gz";

    private readonly IHttpClientFactory _http;
    private readonly IMemoryCache _cache;
    private readonly IAirGapMode _airGap;
    private readonly IUpstreamUrlValidator _urlValidator;
    private readonly IPerOrgTrustAnchorStore _trustStore;
    private readonly ILogger<ApkIndexFetchCoordinator> _logger;
    private readonly TimeSpan _ttl;

    // When true, APKINDEX.tar.gz signature verification is enforced regardless of whether the
    // org has a trust anchor. Setting Apk:VerifyIndexSignature=true with no per-org anchor
    // fails every resolution closed. When unset, verification is enabled iff the org has an
    // anchor at fetch time.
    private readonly bool? _verifyIndexSignatureOverride;

    private readonly ConcurrentDictionary<string, Lazy<Task<CachedIndexFile?>>> _inflight = new();

    private sealed record CachedIndexFile(byte[] Body, string? ETag);

    public ApkIndexFetchCoordinator(
        IHttpClientFactory http, IMemoryCache cache, IAirGapMode airGap,
        IUpstreamUrlValidator urlValidator, IPerOrgTrustAnchorStore trustStore, IConfiguration configuration,
        ILogger<ApkIndexFetchCoordinator> logger)
    {
        _http = http;
        _cache = cache;
        _airGap = airGap;
        _urlValidator = urlValidator;
        _trustStore = trustStore;
        _logger = logger;
        _ttl = TimeSpan.TryParse(configuration["Apk:IndexTtl"], out var t) ? t : TimeSpan.FromSeconds(60);
        _verifyIndexSignatureOverride = bool.TryParse(configuration["Apk:VerifyIndexSignature"], out bool vf)
            ? vf
            : null;
    }

    /// <summary>
    /// Fetches <c>{upstreamBase}/{release}/{repo}/{arch}/{filename}</c>, memory-cached for the
    /// configured TTL. Returns null on a 404 or a blocked/invalid URL; throws
    /// <see cref="AirGappedException"/> in air-gapped deployments and
    /// <see cref="ApkIndexSignatureVerificationFailedException"/> when <paramref name="filename"/>
    /// is <c>APKINDEX.tar.gz</c> and it fails server-side signature verification.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct fetch-coordinate input; the trailing optional context params add no cohesion when bundled.")]
    public async Task<ApkIndexResult?> GetAsync(
        string upstreamBase, string release, string repo, string arch, string filename,
        string? ifNoneMatch, string? authorizationHeader, string? orgId, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"apk:index:{release}/{repo}/{arch}/{filename}");
        }

        string cacheKey = $"apk:index:{upstreamBase}:{release}/{repo}/{arch}/{filename}";
        bool isIndex = filename.Equals(IndexFilename, StringComparison.OrdinalIgnoreCase);

        if (_cache.TryGetValue(cacheKey, out CachedIndexFile? cached) && cached is not null)
        {
            return isIndex && !await VerifyIndexSignatureAsync(orgId, cached.Body, upstreamBase, ct)
                ? throw new ApkIndexSignatureVerificationFailedException(upstreamBase)
                : BuildResult(cached, ifNoneMatch);
        }

        var lazy = _inflight.GetOrAdd(
            cacheKey,
            _ => new Lazy<Task<CachedIndexFile?>>(
                () => FetchFromUpstreamAsync(upstreamBase, release, repo, arch, filename, authorizationHeader, orgId, CancellationToken.None)));

        // Removes exactly this (key, lazy) pair once the shared fetch genuinely completes —
        // success or failure — never when this caller's WaitAsync(ct) below merely detaches
        // early. Attaching per-caller (instead of once at registration) is safe: TryRemove is
        // idempotent, so joiners' redundant continuations are no-ops.
        InFlightCoordination.ScheduleRemoval(_inflight, cacheKey, lazy);

        var result = await lazy.Value.WaitAsync(ct);

        if (result is null)
        {
            return null;
        }

        if (isIndex && !await VerifyIndexSignatureAsync(orgId, result.Body, upstreamBase, ct))
        {
            // Do not cache unverified/tampered index bytes.
            throw new ApkIndexSignatureVerificationFailedException(upstreamBase);
        }

        _cache.Set(cacheKey, result, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = _ttl,
            Size = result.Body.Length,
        });
        return BuildResult(result, ifNoneMatch);
    }

    // Resolves the requesting org's apk RSA anchors and applies the Rpm:VerifyRepomdSignature-
    // style gate: verify iff the override says so, or (when unset) iff the org has at least one
    // anchor. Returns true when verification is not required or succeeds; false (with a
    // reason-tagged metric + warning log) when it is required and fails.
    private async Task<bool> VerifyIndexSignatureAsync(string? orgId, byte[] body, string upstreamBase, CancellationToken ct)
    {
        var anchors = orgId is null
            ? Array.Empty<RSA>()
            : await _trustStore.GetApkKeysAsync(orgId, ct);

        bool shouldVerify = _verifyIndexSignatureOverride ?? anchors.Count > 0;
        if (!shouldVerify)
        {
            return true;
        }

        if (anchors.Count == 0)
        {
            RecordIndexSignatureFailure("no_trusted_key", upstreamBase);
            return false;
        }

        var (verified, reason) = ApkIndexSignatureVerifier.VerifyWithReason(body, anchors, _logger);
        if (!verified)
        {
            RecordIndexSignatureFailure(reason, upstreamBase);
            return false;
        }

        return true;
    }

    private void RecordIndexSignatureFailure(string reason, string upstreamBase)
    {
        DependablyMeter.ApkIndexSignatureFailures.Add(1, new KeyValuePair<string, object?>("reason", reason));
        _logger.LogWarning(
            "apk proxy: APKINDEX.tar.gz signature verification failed for {UpstreamBase} (reason={Reason}); " +
            "refusing to trust upstream index.", upstreamBase, reason);
    }

    private static ApkIndexResult BuildResult(CachedIndexFile cached, string? ifNoneMatch) =>
        ifNoneMatch is not null && cached.ETag is not null && ifNoneMatch.Contains(cached.ETag)
            ? new ApkIndexResult(Stream.Null, ContentTypeFor(""), cached.ETag, NotModified: true)
            : new ApkIndexResult(new MemoryStream(cached.Body), ContentTypeFor(""), cached.ETag, NotModified: false);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct fetch-coordinate input; the trailing optional context params add no cohesion when bundled.")]
    private async Task<CachedIndexFile?> FetchFromUpstreamAsync(
        string upstreamBase, string release, string repo, string arch, string filename,
        string? authorizationHeader, string? orgId, CancellationToken ct)
    {
        string url = $"{upstreamBase}/{release}/{repo}/{arch}/{filename}";
        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
        {
            return null;
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (authorizationHeader is not null)
        {
            req.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        var client = _http.CreateClient("upstream");
        using var resp = await client.SendAsync(req, ct);
        if (resp.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        resp.EnsureSuccessStatusCode();

        byte[] body;
        try
        {
            body = await UpstreamClient.ReadBodyCappedAsync(resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "apk index response exceeded the metadata cap for {Url}; treating as unavailable.", url);
            return null;
        }

        return new CachedIndexFile(body, resp.Headers.ETag?.ToString());
    }

    // filename-driven content-type is not needed today (every index-adjacent file is served as
    // application/octet-stream — apk clients don't consult Content-Type), kept as a seam so a
    // future ContentTypeFor(filename) refinement doesn't have to touch call sites.
    private static string ContentTypeFor(string filename)
    {
        _ = filename;
        return "application/octet-stream";
    }
}
