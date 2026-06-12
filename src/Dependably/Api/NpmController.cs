using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Api;

[ApiController]
public class NpmController : ControllerBase
{
    // Single-flight map: deduplicates concurrent packument rebuilds for the same key.
    // Removed after the rebuild completes so stale Lazy instances don't accumulate.
    private static readonly ConcurrentDictionary<string, Lazy<Task<byte[]?>>> _packumentInFlight = new();

    // TTL for proxy-merged packuments (upstream can change); local-only packuments use
    // a longer TTL because invalidation on mutation is the primary expiry mechanism.
    private static readonly TimeSpan PackumentProxyTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PackumentLocalTtl = TimeSpan.FromMinutes(10);

    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly TokenRepository _tokens;
    private readonly AuditRepository _audit;
    private readonly IBlobStore _blobs;
    private readonly UpstreamClient _upstream;
    private readonly AllowlistService _allowlist;
    private readonly BlocklistRepository _blocklist;
    private readonly BlockGateService _blockGate;
    private readonly LicenseRepository _licenses;
    private readonly IPublicUrlBuilder _urls;
    private readonly IPackagePublishService _publish;
    private readonly ClaimResolver _claimResolver;
    private readonly ReservedNamespaceService _reserved;
    private readonly Dependably.Storage.ProxyFetchService _proxyFetch;
    private readonly UpstreamRegistryResolver _registries;
    private readonly IUploadLimitResolver _uploadLimits;
    private readonly NpmDistTagRepository _distTags;
    private readonly IMemoryCache _cache;

    public NpmController(NpmControllerServices svc)
    {
        _orgs = svc.Orgs;
        _packages = svc.Packages;
        _tokens = svc.Tokens;
        _audit = svc.Audit;
        _blobs = svc.Blobs;
        _upstream = svc.Upstream;
        _allowlist = svc.Allowlist;
        _blocklist = svc.Blocklist;
        _blockGate = svc.BlockGate;
        _licenses = svc.Licenses;
        _urls = svc.Urls;
        _publish = svc.Publish;
        _claimResolver = svc.ClaimResolver;
        _reserved = svc.ReservedNamespaces;
        _proxyFetch = svc.ProxyFetch;
        _registries = svc.Registries;
        _uploadLimits = svc.UploadLimits;
        _distTags = svc.DistTags;
        _cache = svc.Cache;
    }

    // Builds the IMemoryCache key for a packument response.
    private static string PackumentCacheKey(string orgId, string fullName) =>
        $"metadata:{orgId}:npm:{fullName}";

    // ── npm client probes ────────────────────────────────────────────────────

    /// <summary>
    /// GET /npm/-/ping — connectivity probe (<c>npm ping</c>). No auth required and
    /// no tenant data touched: the response shape is identical to registry.npmjs.org's empty
    /// JSON object, so npm/yarn/pnpm clients treat a 200 as "registry reachable" without
    /// further inspection. Literal <c>-/ping</c> segments win the route match over
    /// <c>/npm/{package}/{version}</c> by ASP.NET's literal-beats-parameter precedence.
    /// </summary>
    [HttpGet("/npm/-/ping")]
    public IActionResult Ping() => new JsonResult(new JsonObject());

    /// <summary>
    /// GET /npm/-/whoami — identity probe (<c>npm whoami</c>). Bearer-only: returns
    /// 200 <c>{"username":"..."}</c> on a valid token, 401 with <c>WWW-Authenticate: Bearer</c>
    /// otherwise. User tokens project the owner's email; service tokens project
    /// <c>service:&lt;name&gt;</c> (see <see cref="TokenRepository.GetWhoAmIIdentifierAsync"/>) —
    /// chosen over a 401 so CI pipelines using service tokens get a stable identifier they
    /// can echo into logs. Cross-tenant tokens are coerced to null by the org-scoped resolver
    /// and fall into the same 401 branch as anonymous callers (no information leak).
    /// </summary>
    [HttpGet("/npm/-/whoami")]
    public async Task<IActionResult> WhoAmI(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        string? username = await _tokens.GetWhoAmIIdentifierAsync(token, ct);
        if (username is null)
        {
            // Token row resolved but the user/service row vanished between auth and lookup
            // (e.g. owner removed mid-request). Treat as unauthenticated rather than 500.
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        return new JsonResult(new JsonObject { ["username"] = username });
    }

    // ── Read endpoints ─────────────────────────────────────────────────

    /// <summary>GET /npm/{package} — CouchDB package metadata</summary>
    [HttpGet("/npm/{package}")]
    public Task<IActionResult> GetPackage(string package, CancellationToken ct)
        => GetPackageMetadata(DecodeNpmName(package), scope: null, ct);

    /// <summary>GET /npm/@{scope}/{package} — scoped package metadata</summary>
    [HttpGet("/npm/@{scope}/{package}")]
    public Task<IActionResult> GetScopedPackage(string scope, string package, CancellationToken ct)
        => GetPackageMetadata(package, scope: "@" + scope, ct);

    /// <summary>GET /npm/{package}/{version} — specific version metadata</summary>
    [HttpGet("/npm/{package}/{version}")]
    public async Task<IActionResult> GetVersion(string package, string version, CancellationToken ct)
    {
        var full = await GetPackageMetadata(package, null, ct);
        // Extract just the version object from the full metadata response.
        // GetPackageMetadata returns either a JsonResult (live build) or a FileContentResult
        // (cached bytes); both cases are parsed to a JsonObject for the version lookup.
        var obj = full switch
        {
            JsonResult { Value: JsonObject jo } => jo,
            FileContentResult fcr => JsonNode.Parse(fcr.FileContents) as JsonObject,
            _ => null,
        };
        if (obj is not null)
        {
            var versionData = obj["versions"]?[version];
            return versionData is null ? NotFound() : new JsonResult(versionData);
        }
        return full;
    }

    private async Task<IActionResult> GetPackageMetadata(string package, string? scope, CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        string fullName = scope is not null ? $"{scope}/{package}" : package;

        // The name flows into upstream proxy URLs — reject traversal-shaped values before
        // any lookup, mirroring the upload-side validation.
        if (!IsUpstreamSafeNpmName(fullName))
        {
            return NotFound();
        }

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        // Read paths use the org-scoped overload: a token bound to a different tenant is
        // coerced to null so the existing token-null branches respect AnonymousPull
        // consistently for both anonymous and cross-org callers.
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);

        // Route by passthrough + claims, not packages.is_proxy. A name with uploaded versions
        // is still a namespace that can hold proxy-fetched versions.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && !await _reserved.IsReservedAsync(orgId, "npm", fullName, ct)
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", fullName, ct);

        return passthroughAllowed
            ? await ServePassthroughPackumentAsync(orgId, fullName, pkg, settings, token, ct)
            : await ServeLocalPackumentAsync(orgId, fullName, pkg, token, ct);
    }

    // Passthrough packument path: anonymous-pull gate, then cached bytes, then a
    // single-flight proxy-merged rebuild.
    private async Task<IActionResult> ServePassthroughPackumentAsync(
        string orgId, string fullName, Package? pkg, OrgSettings settings, TokenRecord? token, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        string cacheKey = PackumentCacheKey(orgId, fullName);
        if (_cache.TryGetValue<byte[]>(cacheKey, out byte[]? cachedBytes) && cachedBytes is not null)
        {
            return ServePackumentBytes(cachedBytes, "private, max-age=60");
        }

        byte[]? bytes = await RebuildProxyPackumentAsync(cacheKey, orgId, fullName, pkg, ct);
        if (bytes is not null)
        {
            return new FileContentResult(bytes, "application/json");
        }

        // Rebuild without cache on non-JSON result (e.g. NotFound from proxy path).
        var passthroughTagsFallback = pkg is not null
            ? await _distTags.GetTagsAsync(orgId, pkg.Id, ct)
            : null;
        return await ProxyNpmMetadata(fullName, pkg, passthroughTagsFallback?.Count > 0 ? passthroughTagsFallback : null, ct);
    }

    // Rebuilds the proxy-merged packument and caches the serialized bytes. Single-flight:
    // concurrent rebuilds for the same key collapse onto one shared task. Returns null when
    // the proxy path produced a non-JSON result (e.g. NotFound).
    private async Task<byte[]?> RebuildProxyPackumentAsync(
        string cacheKey, string orgId, string fullName, Package? pkg, CancellationToken ct)
    {
        var lazy = _packumentInFlight.GetOrAdd(cacheKey,
            _ => new Lazy<Task<byte[]?>>(async () =>
            {
                // CancellationToken.None: the shared task must not be cancelled by any
                // one caller's disconnection — individual callers detach via WaitAsync(ct).
                var passthroughTags = pkg is not null
                    ? await _distTags.GetTagsAsync(orgId, pkg.Id, CancellationToken.None)
                    : null;
                var result = await ProxyNpmMetadata(fullName, pkg, passthroughTags?.Count > 0 ? passthroughTags : null, CancellationToken.None);
                if (result is not JsonResult jr)
                {
                    return null;
                }

                byte[] entryBytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(jr.Value);
                _cache.Set(cacheKey, entryBytes, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = PackumentProxyTtl,
                    Size = entryBytes.Length,
                });
                return entryBytes;
            }));

        try
        {
            return await lazy.Value.WaitAsync(ct);
        }
        finally
        {
            _packumentInFlight.TryRemove(new KeyValuePair<string, Lazy<Task<byte[]?>>>(cacheKey, lazy));
        }
    }

    // Local-only packument path (passthrough disabled or claim-local): authenticated reads
    // over hosted versions, served from cache when fresh.
    private async Task<IActionResult> ServeLocalPackumentAsync(
        string orgId, string fullName, Package? pkg, TokenRecord? token, CancellationToken ct)
    {
        if (pkg is null)
        {
            return NotFound();
        }

        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        string cacheKey = PackumentCacheKey(orgId, fullName);
        if (_cache.TryGetValue<byte[]>(cacheKey, out byte[]? localCached) && localCached is not null)
        {
            return ServePackumentBytes(localCached, "private, max-age=300");
        }

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var tags = await _distTags.GetTagsAsync(orgId, pkg.Id, ct);
        var metadata = BuildNpmMetadata(pkg, versions, tags.Count > 0 ? tags : null);
        byte[] localBytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(metadata);
        _cache.Set(cacheKey, localBytes, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = PackumentLocalTtl,
            Size = localBytes.Length,
        });
        return ServePackumentBytes(localBytes, "private, max-age=300");
    }

    // ETag-aware response over packument bytes: 304 on an If-None-Match hit, otherwise the
    // bytes with the given Cache-Control.
    private IActionResult ServePackumentBytes(byte[] bytes, string cacheControl)
    {
        string etag = ComputeETag(bytes);
        Response.Headers.ETag = etag;
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            return StatusCode(304);
        }

        Response.Headers.CacheControl = cacheControl;
        return new FileContentResult(bytes, "application/json");
    }

    private async Task<IActionResult> ProxyNpmMetadata(
        string fullName, Package? localPkg, Dictionary<string, string>? persistedTags, CancellationToken ct)
    {
        var localVersions = localPkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await _packages.GetVersionsAsync(localPkg.Id, ct);

        var metadata = await FetchUpstreamPackumentAsync(fullName, ct);

        if (metadata is null)
        {
            if (localPkg is null || localVersions.Count == 0)
            {
                return NotFound();
            }

            var fallbackMeta = BuildNpmMetadata(localPkg, localVersions, persistedTags);
            return ServePackumentJson(fallbackMeta, "private, max-age=300");
        }

        // Splice uploaded local versions into the upstream packument so npm install can
        // discover both private and public versions of the same name.
        if (localPkg is not null && localVersions.Count > 0)
        {
            MergeLocalVersionsIntoPackument(metadata, localPkg, localVersions);
        }

        return ServePackumentJson(metadata, "private, max-age=60");
    }

    // Walks the org's configured upstreams in priority order; the first that answers wins.
    // No configured upstream ⇒ proxying is disabled for this ecosystem — returns null so
    // the caller serves local-only metadata.
    private async Task<JsonNode?> FetchUpstreamPackumentAsync(string fullName, CancellationToken ct)
    {
        var bases = await _registries.ResolveAsync(CurrentTenantId(), "npm", ct);
        foreach (string upstreamBase in bases)
        {
            try
            {
                // Single-flight packument fetch — collapses N concurrent npm-install
                // requests onto one upstream call when a coordinate first warms up.
                var response = await _upstream.GetOrFetchMetadataAsync($"{upstreamBase}/{fullName}", ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var metadata = JsonNode.Parse(response.BodyAsString());
                if (metadata is not null)
                {
                    RewriteTarballUrls(metadata, fullName, NpmTarballBase());
                }

                return metadata;
            }
            catch
            {
                // Upstream unreachable — try the next one, then fall back to local-only.
            }
        }

        return null;
    }

    // ETag-aware response for a freshly-built packument node: 304 on an If-None-Match hit,
    // otherwise the JSON body with the given Cache-Control.
    private IActionResult ServePackumentJson(JsonNode metadata, string cacheControl)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(metadata.ToJsonString());
        string etag = ComputeETag(bytes);
        Response.Headers.ETag = etag;
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            return StatusCode(304);
        }

        Response.Headers.CacheControl = cacheControl;
        return new JsonResult(metadata);
    }

    private void MergeLocalVersionsIntoPackument(JsonNode packument, Package localPkg, IReadOnlyList<PackageVersion> localVersions)
    {
        var versionsObj = packument["versions"]?.AsObject();
        if (versionsObj is null)
        {
            versionsObj = new JsonObject();
            packument["versions"] = versionsObj;
        }

        string tarballBase = NpmTarballBase();
        foreach (var v in localVersions)
        {
            if (versionsObj.ContainsKey(v.Version))
            {
                continue;
            }

            string filename = v.BlobKey.Split('/').Last();
            var dist = new JsonObject
            {
                ["tarball"] = $"{tarballBase}/{localPkg.Name}/{filename}"
            };
            // dist.shasum is hex SHA-1 by spec — emit only when we have a real SHA-1
            // (populated at publish time / captured from upstream packuments on first-fetch).
            // Omit rather than fall back to SHA-256: clients that verify shasum would reject
            // the tarball, and clients that trust it would write the wrong hash to lockfiles.
            if (v.ChecksumSha1 is not null)
            {
                dist["shasum"] = v.ChecksumSha1;
            }

            versionsObj[v.Version] = new JsonObject
            {
                ["name"] = localPkg.Name,
                ["version"] = v.Version,
                ["dist"] = dist
            };
        }
    }

    /// <summary>
    /// Tarball download URL base. Tenant-implicit: every request is already on the tenant's host,
    /// so URLs are host-relative under <c>/npm/tarballs</c>.
    /// </summary>
    private string NpmTarballBase() => _urls.Absolute(HttpContext, "/npm/tarballs");

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    private static void RewriteTarballUrls(JsonNode metadata, string packageName, string tarballBase)
    {
        var versions = metadata["versions"]?.AsObject();
        if (versions is null)
        {
            return;
        }

        foreach (var (_, versionNode) in versions)
        {
            var dist = versionNode?["dist"];
            if (dist is null)
            {
                continue;
            }

            string? tarball = dist["tarball"]?.GetValue<string>();
            if (tarball is null)
            {
                continue;
            }

            string filename = tarball.Split('/').Last();
            dist["tarball"] = $"{tarballBase}/{packageName}/{filename}";
        }
    }

    private JsonObject BuildNpmMetadata(
        Package pkg, IReadOnlyList<PackageVersion> versions,
        Dictionary<string, string>? persistedTags = null)
    {
        string tarballBase = NpmTarballBase();
        var versionsObj = new JsonObject();

        // Non-yanked versions ordered newest-first for the lazy-latest calculation below.
        var activeVersions = versions
            .Where(v => !v.Yanked)
            .OrderByDescending(x => x.CreatedAt)
            .ToList();

        foreach (var v in activeVersions)
        {
            string filename = v.BlobKey.Split('/').Last();
            var dist = new JsonObject
            {
                ["tarball"] = $"{tarballBase}/{pkg.Name}/{filename}"
            };
            // dist.shasum is hex SHA-1 by spec — see MergeLocalVersionsIntoPackument for why
            // we omit the field when no SHA-1 is recorded instead of substituting SHA-256.
            if (v.ChecksumSha1 is not null)
            {
                dist["shasum"] = v.ChecksumSha1;
            }

            var verObj = new JsonObject
            {
                ["name"] = pkg.Name,
                ["version"] = v.Version,
                ["dist"] = dist
            };

            // Surface the deprecation message in the per-version packument object so
            // npm CLI shows the deprecation warning when the package is installed.
            if (v.Deprecated is not null)
            {
                verObj["deprecated"] = v.Deprecated;
            }

            versionsObj[v.Version] = verObj;
        }

        // Dist-tags from persisted rows take priority. If no tags are persisted (e.g. a
        // package published before dist-tag persistence), fall back to a lazy default:
        // prefer the highest non-prerelease semver as 'latest'; if all versions are
        // prerelease, use the newest by CreatedAt. This produces a stable 'latest' across
        // republishes without requiring a migration of historical rows.
        var distTagsObj = new JsonObject();
        if (persistedTags is not null && persistedTags.Count > 0)
        {
            foreach (var (tag, ver) in persistedTags)
            {
                distTagsObj[tag] = ver;
            }
        }
        else
        {
            // Lazy default: highest non-prerelease semver, falling back to newest by CreatedAt.
            string? lazyLatest = ComputeLazyLatest(activeVersions);
            distTagsObj["latest"] = lazyLatest;
        }

        return new JsonObject
        {
            ["_id"] = pkg.Name,
            ["name"] = pkg.Name,
            ["dist-tags"] = distTagsObj,
            ["versions"] = versionsObj
        };
    }

    /// <summary>
    /// Computes a lazy default for the 'latest' dist-tag when no persisted tags exist.
    /// Prefers the highest stable (non-prerelease) semver version. When all versions are
    /// prerelease, returns the version with the most recent CreatedAt. Returns null only
    /// when there are no active (non-yanked) versions.
    /// </summary>
    private static string? ComputeLazyLatest(List<PackageVersion> activeVersions)
    {
        if (activeVersions.Count == 0)
        {
            return null;
        }

        // Stable versions: no prerelease label (semver prerelease = label after '-').
        var stable = activeVersions
            .Where(v => !v.Version.Contains('-'))
            .ToList();

        var candidates = stable.Count > 0 ? stable : activeVersions;

        // Pick highest by semver when parseable; fall back to newest by CreatedAt.
        var best = candidates
            .Select(v => (Version: v, Parsed: NuGet.Versioning.NuGetVersion.TryParse(v.Version, out var sv) ? sv : null))
            .OrderByDescending(x => x.Parsed, Comparer<NuGet.Versioning.NuGetVersion?>.Create((a, b) =>
                a is null && b is null ? 0 : a is null ? -1 : b is null ? 1 : a.CompareTo(b)))
            .ThenByDescending(x => x.Version.CreatedAt)
            .FirstOrDefault();

        return best.Version?.Version;
    }

    /// <summary>GET /npm/tarballs/{pkg}/{file} — tarball download</summary>
    [HttpGet("/npm/tarballs/{pkg}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetTarball(string pkg, string file, CancellationToken ct)
        => ServeTarballByPackagePath(pkg, file, ct);

    /// <summary>GET /npm/tarballs/@{scope}/{pkg}/{file} — scoped package tarball download</summary>
    [HttpGet("/npm/tarballs/@{scope}/{pkg}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetScopedTarball(string scope, string pkg, string file, CancellationToken ct)
        => GetTarballImpl(fullName: "@" + scope + "/" + pkg, shortName: pkg, file, ct);

    /// <summary>
    /// GET /npm/{pkg}/-/{file} — tarball download at the <em>conventional</em> npm path.
    /// <c>npm ci</c> installs from package-lock.json's <c>resolved</c> URLs; when those
    /// point at the public registry but the configured <c>registry</c> is this one, npm swaps
    /// only the host and keeps the canonical <c>/{pkg}/-/{file}</c> layout — it never fetches
    /// the packument, so it never sees the rewritten <c>/npm/tarballs/…</c> URL. Routing the
    /// conventional path to the same handler lets <c>npm ci</c> resolve against a public lockfile.
    /// </summary>
    [HttpGet("/npm/{pkg}/-/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetTarballConventional(string pkg, string file, CancellationToken ct)
        => ServeTarballByPackagePath(pkg, file, ct);

    /// <summary>GET /npm/@{scope}/{pkg}/-/{file} — scoped tarball at the conventional npm path (see <see cref="GetTarballConventional"/>).</summary>
    [HttpGet("/npm/@{scope}/{pkg}/-/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetScopedTarballConventional(string scope, string pkg, string file, CancellationToken ct)
        => GetTarballImpl(fullName: "@" + scope + "/" + pkg, shortName: pkg, file, ct);

    // Shared by the rewritten (/npm/tarballs/…) and conventional (/npm/{pkg}/-/…) unscoped
    // tarball routes: decode the package name, derive the short name, and delegate.
    private Task<IActionResult> ServeTarballByPackagePath(string pkg, string file, CancellationToken ct)
    {
        string fullName = DecodeNpmName(pkg);
        string shortName = fullName.Contains('/') ? fullName[(fullName.LastIndexOf('/') + 1)..] : fullName;
        return GetTarballImpl(fullName, shortName, file, ct);
    }

    private async Task<IActionResult> GetTarballImpl(
        string fullName, string shortName, string file, CancellationToken ct)
    {
        // Name and filename flow into the upstream proxy URL ({base}/{fullName}/-/{file}) —
        // reject traversal-shaped values before any lookup or upstream call, mirroring the
        // upload-side validation.
        if (!IsUpstreamSafeNpmName(fullName) ||
            !PathSafeValidator.ValidateUpstreamSegment(file, "file").IsValid)
        {
            return NotFound();
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens behave as anonymous (respecting AnonymousPull).
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        // Route by per-version origin, not packages.is_proxy. Extract version from the tarball
        // filename ({shortName}-{version}.tgz) and branch on that row's origin.
        var pkgVersion = await LookupVersionByFilenameAsync(orgId, fullName, shortName, file, ct);

        if (pkgVersion is not null && pkgVersion.Origin == "uploaded")
        {
            return await ServeHostedTarballVersionAsync(orgId, pkgVersion, file, token, settings!, ct);
        }

        if (pkgVersion is not null && pkgVersion.Origin == "proxy")
        {
            var cached = await ServeCachedProxyTarballAsync(orgId, pkgVersion, file, token, settings!, ct);
            if (cached is not null)
            {
                return cached;
            }
            // Same version row exists but the cached blob doesn't match the requested file — fall through.
        }

        var gate = await CheckProxyGatesAsync(orgId, fullName, token, settings!, ct);
        if (gate is not null)
        {
            return gate;
        }

        // Claim state and reserved namespaces gate the proxy fetch — both reject with the
        // same silent 404 so probing cannot map which internal names exist.
        return await _reserved.IsReservedAsync(orgId, "npm", fullName, ct)
            || !await _claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", fullName, ct)
            ? NotFound()
            : await ProxyFetchAndCacheAsync(orgId, fullName, shortName, file, token, settings!, ct);
    }

    // Looks up the package version record whose tarball filename matches the request.
    private async Task<PackageVersion?> LookupVersionByFilenameAsync(
        string orgId, string fullName, string shortName, string file, CancellationToken ct)
    {
        var pkgRecord = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        string? versionFromFilename = ExtractVersionFromTarballFilename(shortName, file);
        return pkgRecord is null || versionFromFilename is null
            ? null
            : await _packages.GetVersionAsync(pkgRecord.Id, versionFromFilename, ct);
    }

    // Evaluates allowlist, blocklist, and proxy-passthrough gates for the proxy fetch path.
    // Returns null when all gates pass; returns the blocking IActionResult otherwise.
    private async Task<IActionResult?> CheckProxyGatesAsync(
        string orgId, string fullName, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        string purlCheck = PurlNormalizer.Npm(fullName, "0.0.0").Split('@')[0]; // name-only PURL
        if (settings.AllowlistMode && !await _allowlist.IsAllowedAsync(orgId, purlCheck, ct))
        {
            return StatusCode(403);
        }

        if (await _blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "npm", purlCheck, "blocked", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
            return StatusCode(403);
        }

        return !settings.ProxyPassthroughEffective ? NotFound() : null;
    }

    private static string? ExtractVersionFromTarballFilename(string shortName, string file)
    {
        string baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
        return baseName.Length > shortName.Length + 1 && baseName.StartsWith(shortName + "-", StringComparison.Ordinal)
            ? baseName[(shortName.Length + 1)..]
            : null;
    }

    private async Task<IActionResult> ServeHostedTarballVersionAsync(
        string orgId, PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }
        if (!token.HasCapability(Capabilities.ReadArtifact))
        {
            return Forbid();
        }

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
        {
            return NotFound();
        }

        string? sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (await _blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated,
                    BlockMaliciousMode: settings.BlockMalicious,
                    BlockKevMode: settings.BlockKev,
                    MaxEpssTolerance: settings.MaxEpssTolerance), ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(403);
        }

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        if (pkgVersion.ChecksumSha256 is not null)
        {
            Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await _audit.LogActivityAsync(orgId, "npm", pkgVersion.Purl, "download", token.UserId,
            actorKind: token.ActorKind, sourceIp: sourceIp, ct: ct);
        await _packages.IncrementDownloadCountAsync(pkgVersion.Id, ct);
        return File(stream, "application/octet-stream", file);
    }

    private async Task<IActionResult?> ServeCachedProxyTarballAsync(
        string orgId, PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        string? sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (await _blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token?.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated,
                    BlockMaliciousMode: settings.BlockMalicious,
                    BlockKevMode: settings.BlockKev,
                    MaxEpssTolerance: settings.MaxEpssTolerance), ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(403);
        }

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null)
        {
            return null;
        }

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        if (pkgVersion.ChecksumSha256 is not null)
        {
            Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await _audit.LogActivityAsync(orgId, "npm", pkgVersion.Purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        await _packages.IncrementDownloadCountAsync(pkgVersion.Id, ct);
        return File(stream, "application/octet-stream", file);
    }

    private async Task<IActionResult> ProxyFetchAndCacheAsync(
        string orgId, string fullName, string shortName, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // Walk the org's configured upstreams in priority order. No configured upstream ⇒
        // proxying is disabled for npm, so a miss is a 404 (mirrors ProxyPassthroughEnabled=false).
        var bases = await _registries.ResolveAsync(orgId, "npm", ct);
        if (bases.Count == 0)
        {
            return NotFound();
        }

        Response.Headers["X-Cache"] = "MISS";

        try
        {
            var fetched = await FetchTarballFromUpstreamsAsync(bases, fullName, file, orgId, ct);
            if (fetched is null)
            {
                return NotFound();
            }

            var (fetchResult, upstreamBase, upstreamUrl) = fetched.Value;

            string baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
            string version = baseName.Length > shortName.Length + 1 ? baseName[(shortName.Length + 1)..] : "unknown";
            string purl = PurlNormalizer.Npm(fullName, version);

            var meta = await TryFetchNpmFirstFetchMetadataAsync(upstreamBase, fullName, version, ct);

            // The streaming MISS path already wrote the blob and computed the SHA-256 inline —
            // no large byte[] allocation needed. Wrap the result in a BlobHandle so
            // ProxyFetchService can open a fresh blob-store stream for licence extraction
            // or non-SHA-256 checksum re-verification without buffering.
            string proxyKey = fetchResult.BlobKey;
            string sha = fetchResult.Sha256Hex;
            long sizeBytes = fetchResult.SizeBytes;
            var blob = new BlobHandle(proxyKey, sha, sizeBytes,
                async openCt => await _blobs.GetAsync(proxyKey, openCt)
                    ?? Stream.Null);

            // deepcode ignore PT,LogForging: ProxyFetchService stores under BlobKeys.Proxy(sha256),
            // which validates a 64-char lowercase hex — path traversal cannot escape that key. All
            // structured logs use Serilog RenderedCompactJsonFormatter (CRLF-safe).
            var result = await _proxyFetch.RecordAndScanAsync(
                BuildNpmProxyFetchRequest(orgId, fullName, version, purl, file, blob, upstreamUrl, token, settings, meta), ct);

            if (result.Decision == BlockDecision.Blocked)
            {
                return StatusCode(403);
            }

            // Stream the cached blob back to the client (response memory is one read
            // buffer, not the whole artefact).
            var blobStream = await _blobs.GetAsync(result.BlobKey, ct);
            return blobStream is null
                ? NotFound()
                : File(blobStream, "application/octet-stream", file);
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch (ChecksumException)
        {
            // Upstream bytes didn't match upstream-supplied integrity — refuse the response
            // rather than serve poison. ProxyFetchService already audited + emitted the metric.
            return StatusCode(502);
        }
        catch (UpstreamResponseTooLargeException)
        {
            // Upstream body crossed the streaming cap — a malformed or hostile upstream.
            return StatusCode(502);
        }
        catch
        {
            return NotFound();
        }
    }

    // Walks upstreams in priority order; streams and stages the first successful tarball
    // to disk, hashing inline. Memory usage is bounded by the staging buffer regardless of
    // artifact size. Returns (UpstreamFetchResult, upstreamBase, upstreamUrl) on success,
    // or null when no upstream returns a success response. Single-flight: concurrent
    // first-fetches of the same tarball coordinate share one upstream call.
    private async Task<(UpstreamFetchResult FetchResult, string UpstreamBase, string UpstreamUrl)?> FetchTarballFromUpstreamsAsync(
        IReadOnlyList<string> bases, string fullName, string file, string orgId, CancellationToken ct)
    {
        foreach (string candidateBase in bases)
        {
            string candidateUrl = $"{candidateBase}/{fullName}/-/{file}";
            try
            {
                // Streams upstream → staging file (hashing inline) → blob store.
                // No upstream checksum is known at request time; the ingest-time SHA-256
                // computed inline is the canonical reference and is verified by the
                // upstream-declared hash in ProxyFetchService after staging.
                var fetchResult = await _upstream.FetchAndCacheByUrlAsync(
                    candidateUrl, null, "npm", orgId, ct);
                return (fetchResult, candidateBase, candidateUrl);
            }
            catch (HttpRequestException)
            {
                // Unreachable upstream — try the next one. Checksum, size-cap, SSRF, and
                // air-gap failures are not HttpRequestExceptions; they propagate to the
                // caller instead of falling through to the next upstream.
            }
        }

        return null;
    }

    // Builds the ProxyFetchRequest record for an npm tarball, including integrity metadata
    // from the upstream packument. npm publishes integrity as an SRI string ("sha512-{b64}") —
    // stored verbatim; null when upstream only sent shasum or no integrity at all.
    // The parameters are the assembly inputs of the ProxyFetchRequest record itself; grouping
    // them into an intermediate type would add indirection without cohesion.
#pragma warning disable S107
    private Dependably.Storage.ProxyFetchRequest BuildNpmProxyFetchRequest(
        string orgId, string fullName, string version, string purl, string file,
        BlobHandle blob, string upstreamUrl, TokenRecord? token, OrgSettings settings,
        NpmFirstFetchMetadata meta)
#pragma warning restore S107
    {
        var (integrityValue, integrityAlgo) = meta.IntegritySri is not null
            ? (meta.IntegritySri, "sha512-sri")
            : ((string?)null, (string?)null);

        return new Dependably.Storage.ProxyFetchRequest(
            OrgId: orgId, Ecosystem: "npm",
            PackageName: fullName, PurlName: fullName,
            Version: version, Purl: purl, File: file, Blob: blob,
            ExtractLicenses: LicenseExtractor.FromNpmTarballPackageJson,
            UserId: token?.UserId,
            ActorKind: token?.ActorKind,
            SourceIp: HttpContext.GetNormalizedRemoteIp(),
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            CacheAccess: new CacheAccess(orgId, "npm", fullName, version, file,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: upstreamUrl),
            PublishedAt: meta.PublishedAt,
            UpstreamChecksum: meta.Checksum,
            Sha1Hex: meta.Sha1Hex,
            UpstreamIntegrityValue: integrityValue,
            UpstreamIntegrityAlgorithm: integrityAlgo,
            Deprecated: meta.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance);
    }

    /// <summary>
    /// Fetches the npm packument once on proxy first-fetch and extracts everything we care
    /// about: the per-version published timestamp, an upstream integrity spec for fail-fast
    /// verification (<c>dist.integrity</c> SRI sha512 preferred, <c>dist.shasum</c> SHA-1
    /// fallback), the raw <c>dist.shasum</c> hex so the packument we re-emit later can carry
    /// the correct SHA-1, and the verbatim SRI string for the version detail UI. Fail-soft:
    /// any error returns a record full of nulls and the caller proceeds without verification
    /// or capture.
    /// </summary>
    private async Task<NpmFirstFetchMetadata> TryFetchNpmFirstFetchMetadataAsync(
        string upstreamBase, string fullName, string version, CancellationToken ct)
    {
        try
        {
            // Route through single-flighted metadata fetch — TryFetchNpmFirstFetchMetadataAsync
            // is called inline with the tarball-fetch handler, so a stampede on the tarball
            // path otherwise drives a duplicate stampede on the packument URL too.
            var resp = await _upstream.GetOrFetchMetadataAsync($"{upstreamBase}/{fullName}", ct);
            if (!resp.IsSuccessStatusCode)
            {
                return NpmFirstFetchMetadata.Empty;
            }

            string json = resp.BodyAsString();
            var node = JsonNode.Parse(json);

            DateTimeOffset? publishedAt = null;
            string? time = node?["time"]?[version]?.GetValue<string>();
            if (DateTimeOffset.TryParse(time, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
            {
                publishedAt = ts;
            }

            var versionNode = node?["versions"]?[version];
            var dist = versionNode?["dist"];
            string? integrity = dist?["integrity"]?.GetValue<string>();
            string? shasum = dist?["shasum"]?.GetValue<string>();
            var checksum = ChecksumVerifier.ParseNpmIntegrity(integrity, shasum);

            // Only surface the integrity string when it's actually the SHA-512 SRI form; older
            // packages might carry a non-SRI value in this field, in which case the UI label
            // ("SHA-512 SRI") would lie. Anything else stays NULL.
            string? integritySri = integrity is not null
                && integrity.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase)
                ? integrity : null;

            string? deprecated = LicenseExtractor.FromNpmPackumentVersion(versionNode).Deprecated;

            return new NpmFirstFetchMetadata(publishedAt, checksum, shasum, integritySri, deprecated);
        }
        catch { return NpmFirstFetchMetadata.Empty; }
    }

    private readonly record struct NpmFirstFetchMetadata(
        DateTimeOffset? PublishedAt,
        ChecksumSpec? Checksum,
        string? Sha1Hex,
        string? IntegritySri,
        string? Deprecated)
    {
        public static NpmFirstFetchMetadata Empty => new(null, null, null, null, null);
    }


    // ── Publish endpoint ───────────────────────────────────────────────

    /// <summary>PUT /npm/{package} — npm publish</summary>
    [HttpPut("/npm/{package}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> Publish(string package, CancellationToken ct)
        => PublishPackage(package, scope: null, ct);

    /// <summary>PUT /npm/@{scope}/{package} — scoped npm publish</summary>
    [HttpPut("/npm/@{scope}/{package}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> PublishScoped(string scope, string package, CancellationToken ct)
        => PublishPackage(package, scope: "@" + scope, ct);

    private async Task<IActionResult> PublishPackage(string package, string? scope, CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        // [Authorize] above already enforced auth + capability. We still resolve the token
        // for the cross-tenant guard (token.OrgId vs requested org) and to attribute the
        // audit row to the token owner (token.UserId).
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // Resolve the effective npm upload limit before reading any body bytes. The resolved
        // limit gates both the body read (via LimitedReadStream) and the attachment pre-check
        // (declared length vs limit before base64 decode). Falls back to the 500 MB route
        // ceiling when no org/instance npm limit is configured, so the explicit cap always
        // applies regardless of whether the middleware set MaxRequestBodySize.
        const long RouteHardCeiling = 500L * 1024 * 1024;
        long npmBodyCap = (await _uploadLimits.ResolveAsync(orgId, "npm", ct)) ?? RouteHardCeiling;

        // ── Format-specific extraction (lives here; shape is npm-only) ─────────
        var (body, parseError) = await ParsePublishBodyAsync(npmBodyCap, ct);
        if (parseError is not null)
        {
            return parseError;
        }

        string fullName = scope is not null ? $"{scope}/{package}" : package;
        string plainName = scope is not null ? package : fullName;

        var nameError = ValidatePackageName(body, fullName, plainName);
        if (nameError is not null)
        {
            return nameError;
        }

        // Detect the no-attachments shape: npm deprecate sends a packument PUT without the
        // _attachments key at all. Route to the deprecation handler before the attachment
        // validator rejects the body with 422. An empty _attachments object (key present but
        // empty) is an invalid publish, not a deprecate — let ExtractAttachment return 422.
        if (body?["_attachments"] is null)
        {
            return await HandleDeprecateAsync(orgId, body, fullName, token, ct);
        }

        var (attachmentKey, tarball, attachmentError) = ExtractAttachment(body, npmBodyCap);
        if (attachmentError is not null)
        {
            return attachmentError;
        }

        var (innerName, innerVersion, tarballError) = ValidateTarballAndExtractNameVersion(tarball!);
        if (tarballError is not null)
        {
            return tarballError;
        }

        var versions = body?["versions"]?.AsObject();
        string? versionKey = versions?.First().Key;
        var matchError = ValidateBodyMatch(versionKey, innerName, innerVersion, fullName);
        if (matchError is not null)
        {
            return matchError;
        }

        string filename = attachmentKey!.Split('/').Last(); // e.g. package-1.0.0.tgz

        // Per-tenant + per-ecosystem upload size cap. The publish service enforces it again
        // as a safety net but we keep this lookup here so the existing UploadSizeLimitError
        // shape (413 with the same body the older code returned) is preserved verbatim.
        var sizeError = await CheckUploadSizeAsync(orgId, tarball!, ct);
        if (sizeError is not null)
        {
            return sizeError;
        }

        // ── Shared tail (path safety, claim gate, dedup, blob put, version, audit) ──
        var orgSettings = await _orgs.GetSettingsAsync(orgId, ct);
        var claim = await _claimResolver.ResolveAsync(orgId, "npm", fullName, ct);
        var request = BuildNpmPublishRequest(new NpmPublishContext(
            orgId, fullName, versionKey!, filename, tarball!,
            token.UserId, token.ActorKind, orgSettings?.AllowVersionOverwrite ?? false, claim.State));
        var result = await _publish.StoreAndRecordAsync(request, ct);

        if (result is PublishResult.Rejected rej)
        {
            return MapPublishRejection(rej, versionKey!);
        }

        string versionId = ((PublishResult.Accepted)result).VersionId;
        await EmitNpmLicensesAndDeprecationAsync(versionId, tarball!, versions?[versionKey!], ct);

        // Persist dist-tags from the packument. npm sends {"dist-tags":{"beta":"1.0.0-beta.1"}}
        // on `npm publish --tag beta`. When no dist-tags object is present, default to 'latest'.
        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is not null)
        {
            await PersistPublishDistTagsAsync(orgId, pkg.Id, body, versionKey!, ct);
        }

        // Evict the cached packument so the newly-published version appears immediately.
        _cache.Remove(PackumentCacheKey(orgId, fullName));

        return Ok();
    }

    // Reads the dist-tags map from the publish body and persists each tag. When no
    // dist-tags object is in the body (or it is empty) the version is set as 'latest'
    // only when no 'latest' tag already exists — so a pre-release publish without an
    // explicit --tag does not silently take over 'latest'.
    private async Task PersistPublishDistTagsAsync(
        string orgId, string packageId, JsonNode? body, string version, CancellationToken ct)
    {
        var distTagsNode = body?["dist-tags"]?.AsObject();
        bool anySaved = false;
        if (distTagsNode is not null)
        {
            foreach (var (tag, tagVal) in distTagsNode)
            {
                string? tagVersion = tagVal?.GetValue<string>();
                if (tagVersion is null)
                {
                    continue;
                }
                await _distTags.SetTagAsync(orgId, packageId, tag, tagVersion, ct);
                anySaved = true;
            }
        }

        // No explicit tags: seed 'latest' only when the package has no persisted 'latest' yet,
        // so a bare `npm publish` on a fresh package gets a 'latest' pointer without overwriting
        // a tag that was set by a previous publish with an explicit --tag.
        if (!anySaved)
        {
            var existing = await _distTags.GetTagsAsync(orgId, packageId, ct);
            if (!existing.ContainsKey("latest"))
            {
                await _distTags.SetTagAsync(orgId, packageId, "latest", version, ct);
            }
        }
    }

    // Bundles BuildNpmPublishRequest's tail-end coordinates into a single param to keep the
    // builder's signature within S107's threshold while preserving the ergonomic call shape.
    private sealed record NpmPublishContext(
        string OrgId, string FullName, string VersionKey, string Filename, byte[] Tarball,
        string? ActorUserId, string? ActorKind, bool AllowOverwrite, string ClaimState);

    private PublishRequest BuildNpmPublishRequest(NpmPublishContext ctx)
        => new()
        {
            OrgId = ctx.OrgId,
            Ecosystem = "npm",
            Name = ctx.FullName,
            PurlName = ctx.FullName,
            Version = ctx.VersionKey,
            Filename = ctx.Filename,
            Purl = PurlNormalizer.Npm(ctx.FullName, ctx.VersionKey),
            ArtifactBytes = ctx.Tarball,
            // Already enforced by CheckUploadSizeAsync; service-side cap is defence in depth.
            SizeCap = long.MaxValue,
            Origin = "uploaded",
            ActorUserId = ctx.ActorUserId,
            ActorKind = ctx.ActorKind,
            AuditAction = "push",
            AllowOverwrite = ctx.AllowOverwrite,
            ClaimState = ctx.ClaimState,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
        };

    /// <summary>
    /// License: read the tarball's package.json (canonical, matches the proxy first-fetch
    /// path). Fall back to the packument when the tarball lacks a parseable
    /// package/package.json — many publish clients don't include license in the
    /// packument's version object. Deprecation only ever lives in the packument (npm
    /// deprecate writes there), so it must always come from the packument extractor.
    /// </summary>
    private async Task EmitNpmLicensesAndDeprecationAsync(
        string versionId, byte[] tarball, JsonNode? packumentVersion, CancellationToken ct)
    {
        // Push path holds the tarball bytes in memory (upload validation concern,
        // out of scope for this change). Wrap in a MemoryStream for the unified extractor.
        var fromTarball = LicenseExtractor.FromNpmTarballPackageJson(
            new MemoryStream(tarball, writable: false));
        var fromPackument = LicenseExtractor.FromNpmPackumentVersion(packumentVersion);
        var spdx = fromTarball.Spdx.Count > 0 ? fromTarball.Spdx : fromPackument.Spdx;
        if (spdx.Count > 0)
        {
            await _licenses.SetLicensesAsync(versionId, spdx, "upstream", ct);
        }

        if (fromPackument.Deprecated is not null)
        {
            await _packages.UpdateDeprecatedAsync(versionId, fromPackument.Deprecated, ct);
        }
    }

    // Handles the no-attachments PUT shape sent by `npm deprecate`. The body contains a
    // versions map where each version object may carry a `deprecated` string (empty string
    // means undeprecate). Updates the deprecated column for every version present in the
    // body; versions absent from the body are left unchanged.
    private async Task<IActionResult> HandleDeprecateAsync(
        string orgId, JsonNode? body, string fullName,
        TokenRecord token, CancellationToken ct)
    {
        var versionsNode = body?["versions"]?.AsObject();
        if (versionsNode is null || versionsNode.Count == 0)
        {
            return UnprocessableEntity(new ProblemDetails
            {
                Detail = "No versions found in body. Both _attachments and versions are missing.",
                Status = 422
            });
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return NotFound();
        }

        foreach (var (versionKey, versionNode) in versionsNode)
        {
            var ver = await _packages.GetVersionAsync(pkg.Id, versionKey, ct);
            if (ver is null)
            {
                continue;
            }

            // An empty string means "undeprecate" per npm protocol conventions.
            // Non-string values (e.g. booleans, numbers) in the deprecated field are
            // treated as absent — GetValue<string>() throws on mismatched kinds, so the
            // node kind is checked first.
            var deprecatedNode = versionNode?["deprecated"];
            if (deprecatedNode is not null
                && deprecatedNode.GetValueKind() != System.Text.Json.JsonValueKind.String)
            {
                continue;
            }

            string? deprecatedMsg = deprecatedNode?.GetValue<string>();
            string? stored = string.IsNullOrEmpty(deprecatedMsg) ? null : deprecatedMsg;
            await _packages.UpdateDeprecatedAsync(ver.Id, stored, ct);
        }

        await _audit.LogActivityAsync(orgId, "npm", fullName, "deprecate", token.UserId,
            actorKind: token.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the deprecation change is visible immediately.
        _cache.Remove(PackumentCacheKey(orgId, fullName));

        return Ok();
    }

    private ObjectResult MapPublishRejection(PublishResult.Rejected rej, string versionKey) => rej.Code switch
    {
        "version_exists" => Conflict(new ProblemDetails { Detail = $"Version {versionKey} already exists.", Status = 409 }),
        _ => StatusCode(rej.HttpStatus, new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus }),
    };

    private async Task<(JsonNode? Body, IActionResult? Error)> ParsePublishBodyAsync(long bodyCap, CancellationToken ct)
    {
        // Wrap the request body in a byte-counting stream so the full JSON string read is
        // bounded by the resolved npm upload limit before any parsing or allocation occurs.
        // A cap overflow surfaces as an InvalidDataException from LimitedReadStream.
        // All other exceptions indicate malformed JSON.
        var limited = new LimitedReadStream(Request.Body, bodyCap, "npm publish body");
        try
        {
            using var reader = new StreamReader(limited, Encoding.UTF8, leaveOpen: true);
            string json = await reader.ReadToEndAsync(ct);
            return (JsonNode.Parse(json), null);
        }
        catch (InvalidDataException)
        {
            return (null, StatusCode(413, new ProblemDetails { Detail = $"Request body exceeds the npm publish limit of {bodyCap} bytes.", Status = 413 }));
        }
        catch
        {
            return (null, UnprocessableEntity(new ProblemDetails { Detail = "Invalid JSON body.", Status = 422 }));
        }
    }

    private UnprocessableEntityObjectResult? ValidatePackageName(JsonNode? body, string fullName, string plainName)
    {
        string bodyName = body?["name"]?.GetValue<string>() ?? "";
        return bodyName != fullName
            ? UnprocessableEntity(new ProblemDetails { Detail = "name in body does not match URL.", Status = 422 })
            : !NpmNameValidator.IsValidPlainName(plainName)
            ? UnprocessableEntity(new ProblemDetails { Detail = $"Invalid npm package name: {plainName}", Status = 422 })
            : null;
    }

    private (string? Key, byte[]? Tarball, IActionResult? Error) ExtractAttachment(JsonNode? body, long limit)
    {
        var attachments = body?["_attachments"]?.AsObject();
        if (attachments is null || attachments.Count != 1)
        {
            return (null, null, UnprocessableEntity(new ProblemDetails { Detail = "_attachments must contain exactly one entry.", Status = 422 }));
        }

        var (attachmentKey, attachmentNode) = attachments.First();
        string? base64Data = attachmentNode?["data"]?.GetValue<string>();
        if (base64Data is null)
        {
            return (null, null, UnprocessableEntity(new ProblemDetails { Detail = "_attachments.data is required.", Status = 422 }));
        }

        // Reject before materializing the byte[] when the declared decoded size already
        // exceeds the upload limit — avoids a ~1.33x allocation for an oversized attachment.
        long declaredLength = attachmentNode?["length"]?.GetValue<long>() ?? -1;
        if (declaredLength > limit)
        {
            return (null, null, StatusCode(413, new ProblemDetails { Detail = $"Attachment declared length {declaredLength} exceeds the npm publish limit of {limit} bytes.", Status = 413 }));
        }

        byte[] tarball;
        try { tarball = Convert.FromBase64String(base64Data); }
        catch { return (null, null, UnprocessableEntity(new ProblemDetails { Detail = "Invalid base64 in _attachments.data.", Status = 422 })); }

        if (declaredLength >= 0 && tarball.Length != declaredLength)
        {
            return (null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Attachment length mismatch: declared {declaredLength}, actual {tarball.Length}.", Status = 422 }));
        }

        return (attachmentKey, tarball, null);
    }

    private async Task<IActionResult?> CheckUploadSizeAsync(string orgId, byte[] tarball, CancellationToken ct)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        long limit = await _orgs.GetUploadLimitAsync(settings, "npm", ct);
        return tarball.Length > limit
            ? StatusCode(413, new ProblemDetails { Detail = "Upload exceeds npm size limit.", Status = 413 })
            : null;
    }

    private (string? InnerName, string? InnerVersion, IActionResult? Error) ValidateTarballAndExtractNameVersion(byte[] tarball)
    {
        var tarValidation = ValidateTarball(tarball, out string? innerName, out string? innerVersion);
        return tarValidation.IsValid
            ? (innerName, innerVersion, null)
            : (null, null, UnprocessableEntity(new ProblemDetails { Detail = tarValidation.Message, Status = 422 }));
    }

    private UnprocessableEntityObjectResult? ValidateBodyMatch(string? versionKey, string? innerName, string? innerVersion, string fullName)
    {
        return versionKey is null
            ? UnprocessableEntity(new ProblemDetails { Detail = "versions object is empty.", Status = 422 })
            : innerName != fullName
            ? UnprocessableEntity(new ProblemDetails { Detail = $"package.json name '{innerName}' does not match published name '{fullName}'.", Status = 422 })
            : innerVersion != versionKey
            ? UnprocessableEntity(new ProblemDetails { Detail = $"package.json version '{innerVersion}' does not match declared version '{versionKey}'.", Status = 422 })
            : null;
    }

    private static ValidationResult ValidateTarball(byte[] bytes, out string? name, out string? version) =>
        NpmTarballValidator.Validate(bytes, out name, out version);

    private static string DecodeNpmName(string name) => NpmRouteHelper.DecodeRouteName(name);

    /// <summary>
    /// True when a decoded npm name ("name" or "@scope/name") is safe to embed in an
    /// upstream proxy URL: at most two path segments, each passing
    /// <see cref="PathSafeValidator.ValidateUpstreamSegment"/>.
    /// </summary>
    private static bool IsUpstreamSafeNpmName(string fullName)
    {
        string[] segments = fullName.Split('/');
        return segments.Length <= 2 &&
            Array.TrueForAll(segments, s => PathSafeValidator.ValidateUpstreamSegment(s, "package").IsValid);
    }

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");

    private static string ComputeETag(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..16].ToLowerInvariant() + "\"";
    }

    // ── dist-tag management endpoints ──────────────────────────────────────────

    /// <summary>GET /o/{org}/npm/-/package/{pkg}/dist-tags — list all dist-tags</summary>
    [HttpGet("/npm/-/package/{pkg}/dist-tags")]
    public Task<IActionResult> GetDistTags(string pkg, CancellationToken ct)
        => GetDistTagsImpl(DecodeNpmName(pkg), ct);

    /// <summary>GET /o/{org}/npm/-/package/@{scope}/{pkg}/dist-tags — list dist-tags for scoped package</summary>
    [HttpGet("/npm/-/package/@{scope}/{pkg}/dist-tags")]
    public Task<IActionResult> GetScopedDistTags(string scope, string pkg, CancellationToken ct)
        => GetDistTagsImpl("@" + scope + "/" + pkg, ct);

    private async Task<IActionResult> GetDistTagsImpl(string fullName, CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var tags = await _distTags.GetTagsAsync(orgId, pkg.Id, ct);
        if (tags.Count == 0)
        {
            // Lazy seed: compute the default latest and return it without persisting.
            var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
            string? latest = ComputeLazyLatest(versions.Where(v => !v.Yanked).OrderByDescending(v => v.CreatedAt).ToList());
            tags = latest is not null ? new Dictionary<string, string> { ["latest"] = latest } : tags;
        }

        var result = new JsonObject();
        foreach (var (tag, ver) in tags)
        {
            result[tag] = ver;
        }
        return new JsonResult(result);
    }

    /// <summary>PUT /o/{org}/npm/-/package/{pkg}/dist-tags/{tag} — set a dist-tag</summary>
    [HttpPut("/npm/-/package/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> PutDistTag(string pkg, string tag, CancellationToken ct)
        => PutDistTagImpl(DecodeNpmName(pkg), tag, ct);

    /// <summary>PUT /o/{org}/npm/-/package/@{scope}/{pkg}/dist-tags/{tag} — set a dist-tag for scoped package</summary>
    [HttpPut("/npm/-/package/@{scope}/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> PutScopedDistTag(string scope, string pkg, string tag, CancellationToken ct)
        => PutDistTagImpl("@" + scope + "/" + pkg, tag, ct);

    private async Task<IActionResult> PutDistTagImpl(string fullName, string tag, CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // Body is a JSON string: the target version number.
        string? version;
        try
        {
            using var reader = new StreamReader(Request.Body, Encoding.UTF8);
            string raw = await reader.ReadToEndAsync(ct);
            version = System.Text.Json.JsonSerializer.Deserialize<string>(raw);
        }
        catch
        {
            return UnprocessableEntity(new ProblemDetails { Detail = "Body must be a JSON string (the target version).", Status = 422 });
        }

        if (string.IsNullOrWhiteSpace(version))
        {
            return UnprocessableEntity(new ProblemDetails { Detail = "Version must not be empty.", Status = 422 });
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return NotFound();
        }

        // Validate that the requested version actually exists in this org.
        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null)
        {
            return NotFound(new ProblemDetails { Detail = $"Version '{version}' does not exist for package '{fullName}'.", Status = 404 });
        }

        await _distTags.SetTagAsync(orgId, pkg.Id, tag, version, ct);
        await _audit.LogActivityAsync(orgId, "npm", pkg.Name, "dist-tag.set", token.UserId,
            actorKind: token.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the updated dist-tag is visible immediately.
        _cache.Remove(PackumentCacheKey(orgId, fullName));

        var result = new JsonObject { [tag] = version };
        return new JsonResult(result);
    }

    /// <summary>DELETE /o/{org}/npm/-/package/{pkg}/dist-tags/{tag} — remove a dist-tag</summary>
    [HttpDelete("/npm/-/package/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> DeleteDistTag(string pkg, string tag, CancellationToken ct)
        => DeleteDistTagImpl(DecodeNpmName(pkg), tag, ct);

    /// <summary>DELETE /o/{org}/npm/-/package/@{scope}/{pkg}/dist-tags/{tag} — remove a dist-tag for scoped package</summary>
    [HttpDelete("/npm/-/package/@{scope}/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> DeleteScopedDistTag(string scope, string pkg, string tag, CancellationToken ct)
        => DeleteDistTagImpl("@" + scope + "/" + pkg, tag, ct);

    private async Task<IActionResult> DeleteDistTagImpl(string fullName, string tag, CancellationToken ct)
    {
        // npm refuses to delete the 'latest' tag — it must always point somewhere.
        if (tag == "latest")
        {
            return BadRequest(new ProblemDetails { Detail = "The 'latest' tag cannot be deleted.", Status = 400 });
        }

        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return NotFound();
        }

        bool deleted = await _distTags.DeleteTagAsync(orgId, pkg.Id, tag, ct);
        if (!deleted)
        {
            return NotFound(new ProblemDetails { Detail = $"Tag '{tag}' not found.", Status = 404 });
        }

        await _audit.LogActivityAsync(orgId, "npm", pkg.Name, "dist-tag.delete", token.UserId,
            actorKind: token.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the removed dist-tag is visible immediately.
        _cache.Remove(PackumentCacheKey(orgId, fullName));

        return NoContent();
    }

    // ── Unpublish endpoint ─────────────────────────────────────────────────────

    /// <summary>
    /// DELETE /o/{org}/npm/{pkg}/-rev/{rev} — version unpublish (<c>npm unpublish pkg@version</c>).
    /// The npm CLI sends this shape for per-version unpublish. The version row and its tarball
    /// are hard-deleted from the registry, and any dist-tags pointing at the removed version are
    /// pruned; 'latest' is re-anchored to the highest remaining stable version when it was among
    /// the pruned tags. Requires the YankNpm capability.
    /// Whole-package unpublish (all versions at once) returns 403 — use the management API.
    /// </summary>
    [HttpDelete("/npm/{pkg}/-rev/{rev}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.YankNpm)]
    public Task<IActionResult> Unpublish(string pkg, string rev, CancellationToken ct)
        => UnpublishImpl(DecodeNpmName(pkg), rev, ct);

    /// <summary>DELETE /o/{org}/npm/@{scope}/{pkg}/-rev/{rev} — scoped package version unpublish</summary>
    [HttpDelete("/npm/@{scope}/{pkg}/-rev/{rev}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.YankNpm)]
    public Task<IActionResult> UnpublishScoped(string scope, string pkg, string rev, CancellationToken ct)
        => UnpublishImpl("@" + scope + "/" + pkg, rev, ct);

    private async Task<IActionResult> UnpublishImpl(string fullName, string rev, CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // rev encodes the version: npm sends "{version}-{rev}" or just the version.
        // Extract the version portion: the part before the first '-' following a digit,
        // but more reliably just strip the known pattern by checking for an existing version row.
        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return NotFound();
        }

        // Resolve version from the rev parameter. npm sends the version string directly as
        // the rev in modern clients; older clients may append "-N". Try the rev as-is first,
        // then strip a trailing dash-suffix if no match.
        var ver = await _packages.GetVersionAsync(pkg.Id, rev, ct);
        if (ver is null)
        {
            // Try stripping the last "-N" rev suffix that some clients append.
            int dash = rev.LastIndexOf('-');
            if (dash > 0)
            {
                string candidate = rev[..dash];
                ver = await _packages.GetVersionAsync(pkg.Id, candidate, ct);
            }
        }

        if (ver is null)
        {
            // Whole-package unpublish would need all versions to be listed in the body, so
            // we conservatively return 403 and direct the caller to the management API.
            return StatusCode(403, new ProblemDetails
            {
                Detail = "Whole-package unpublish is not supported via the npm protocol. " +
                         "Use the management API to delete individual versions.",
                Status = 403
            });
        }

        if (ver.Origin != "uploaded")
        {
            return StatusCode(403, new ProblemDetails
            {
                Detail = "Only user-published versions can be unpublished via this endpoint.",
                Status = 403
            });
        }

        await _blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        await _packages.DeleteVersionAsync(ver.Id, ct);

        // Remove any dist-tags that pointed at the deleted version, then re-anchor
        // 'latest' when it was among the removed tags and the package still has other
        // versions. The package row is deleted last so the version list query above is
        // still valid at this point.
        var removedTags = await _distTags.DeleteTagsForVersionAsync(orgId, pkg.Id, ver.Version, ct);
        bool packageStillExists = !(await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct));
        if (packageStillExists && removedTags.Contains("latest"))
        {
            var remaining = await _packages.GetVersionsAsync(pkg.Id, ct);
            var activeRemaining = remaining.Where(v => !v.Yanked).ToList();
            string? newLatest = ComputeLazyLatest(activeRemaining);
            if (newLatest is not null)
            {
                await _distTags.SetTagAsync(orgId, pkg.Id, "latest", newLatest, ct);
            }
        }

        await _audit.LogActivityAsync(orgId, "npm", ver.Purl, "delete", token.UserId,
            actorKind: token.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the deleted version disappears immediately.
        _cache.Remove(PackumentCacheKey(orgId, fullName));

        return Ok();
    }

    // ── Search endpoint ────────────────────────────────────────────────────────

    /// <summary>
    /// GET /o/{org}/npm/-/v1/search?text=&amp;size=&amp;from= — package search.
    /// Returns a minimal npm search response over the org's hosted packages.
    /// text is a LIKE pattern applied to package names. size is clamped 1..50.
    /// Auth: same anonymous-pull gate as packument GET.
    /// </summary>
    [HttpGet("/npm/-/v1/search")]
    public async Task<IActionResult> Search(
        [FromQuery] string? text,
        [FromQuery] int size = 20,
        [FromQuery] int from = 0,
        CancellationToken ct = default)
    {
        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // Clamp size to 1..50 per npm search spec.
        size = Math.Clamp(size, 1, 50);

        var query = new PackageListQuery(
            OrgId: orgId,
            Limit: size,
            Offset: Math.Max(0, from),
            Ecosystem: "npm",
            Search: text,
            SortBy: "name",
            SortDir: "asc");

        var (packages, total) = await _packages.ListPaginatedAsync(query, ct);

        // Build the minimal npm search shape: objects[] with {package:{name,version,description}}.
        var objectsArr = new System.Text.Json.Nodes.JsonArray();
        foreach (var p in packages)
        {
            // Find the 'latest' version for each package by checking persisted tags first,
            // then falling back to the lazy latest calculation.
            var tags = await _distTags.GetTagsAsync(orgId, p.Id, ct);
            string? latestVersion = null;
            if (tags.TryGetValue("latest", out string? tagVer))
            {
                latestVersion = tagVer;
            }
            else
            {
                var vers = await _packages.GetVersionsAsync(p.Id, ct);
                latestVersion = ComputeLazyLatest(vers.Where(v => !v.Yanked).OrderByDescending(v => v.CreatedAt).ToList());
            }

            objectsArr.Add(new JsonObject
            {
                ["package"] = new JsonObject
                {
                    ["name"] = p.Name,
                    ["version"] = latestVersion,
                }
            });
        }

        return new JsonResult(new JsonObject
        {
            ["objects"] = objectsArr,
            ["total"] = total,
            ["time"] = DateTimeOffset.UtcNow.ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'", System.Globalization.CultureInfo.InvariantCulture)
        });
    }
}

// DI-injected dependency aggregate for NpmController. Single param avoids S107 on the
// controller constructor; field unpacking in the ctor keeps the rest of the controller
// body untouched.
public sealed record NpmControllerServices(
    OrgRepository Orgs,
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    AllowlistService Allowlist,
    BlocklistRepository Blocklist,
    IConfiguration Config,
    BlockGateService BlockGate,
    LicenseRepository Licenses,
    IPublicUrlBuilder Urls,
    IPackagePublishService Publish,
    ClaimResolver ClaimResolver,
    ReservedNamespaceService ReservedNamespaces,
    Dependably.Storage.ProxyFetchService ProxyFetch,
    UpstreamRegistryResolver Registries,
    IUploadLimitResolver UploadLimits,
    NpmDistTagRepository DistTags,
    IMemoryCache Cache);
