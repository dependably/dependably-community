using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Handles NuGet v3 registration index and leaf endpoints. Serves locally-published versions
/// from a cache-fronted local index and merges with upstream when proxy passthrough is active.
/// Block-gate version filtering keeps the registration surface in sync with the flatcontainer
/// download surface — a blocked version is excluded from both.
/// </summary>
public sealed class NuGetRegistrationHandler(
    OrgRepository orgs,
    PackageRepository packages,
    CacheArtifactRepository cacheArtifacts,
    TokenRepository tokens,
    VulnerabilityRepository vulns,
    UpstreamClient upstream,
    UpstreamRegistryResolver registries,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    RenderedResponseCache<NuGetRegistrationKey> cache,
    IPublicUrlBuilder urls,
    TimeProvider time,
    ILogger<NuGetRegistrationHandler> logger)
{
    // TTL for proxy-merged registration pages (upstream can change); local-only registrations
    // use a longer TTL because invalidation on mutation is the primary expiry mechanism.
    private static readonly TimeSpan RegistrationProxyTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RegistrationLocalTtl = TimeSpan.FromMinutes(10);

    // SHA-256 hex digest prefix length used for ETags (16 hex chars = 64 bits of entropy).
    private const int ETagHexPrefixLength = 16;

    public Task<IActionResult> RegistrationIndexAsync(HttpContext httpContext, string orgId, string id, bool semVer2, CancellationToken ct)
        => RegistrationIndexCoreAsync(httpContext, orgId, id, semVer2, ct);

    public Task<IActionResult> RegistrationLeafAsync(HttpContext httpContext, string orgId, string id, string version, bool semVer2, CancellationToken ct)
        => RegistrationLeafCoreAsync(httpContext, orgId, id, version, semVer2, ct);

    private async Task<IActionResult> RegistrationLeafCoreAsync(
        HttpContext httpContext, string orgId, string id, string version, bool semVer2, CancellationToken ct)
    {
        // Both route values flow into the upstream registration-leaf URL — reject
        // traversal-shaped values before any lookup or upstream call.
        if (!AreUpstreamSafeNuGetSegments(id, version))
        {
            return new NotFoundResult();
        }

        var (settings, _, authError) = await AuthorizeNuGetReadAsync(httpContext, orgId, ct);
        if (authError is not null)
        {
            return authError;
        }

        string normalizedId = id.ToLowerInvariant();
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // A version with a local row (uploaded or proxy-cached) is served from our own data — its
        // packageContent points at our flatcontainer, matching per-version download routing.
        if (pkg is not null)
        {
            var pkgVersion = await packages.GetVersionAsync(pkg.Id, NuGetNormalization.NormalizeVersion(version), ct);
            if (pkgVersion is not null && !pkgVersion.Yanked)
            {
                return BuildLocalLeafResponse(httpContext, normalizedId, pkg.Name, pkgVersion.Version);
            }
        }

        // Otherwise the version lives upstream — proxy its leaf when passthrough + claims
        // allow and the name is not operator-reserved.
        return settings!.ProxyPassthroughEffective
            && !await reserved.IsReservedAsync(orgId, "nuget", normalizedId, ct)
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct)
            ? await ProxyRegistrationLeafAsync(httpContext, orgId, normalizedId, version, semVer2, ct)
            : new NotFoundResult();
    }

    private ContentResult BuildLocalLeafResponse(HttpContext httpContext, string normalizedId, string pkgName, string version)
    {
        string baseUrl = urls.Absolute(httpContext, "/nuget");
        string leafId = $"{baseUrl}/registration/{normalizedId}/{version}.json";
        string registration = $"{baseUrl}/registration/{normalizedId}/index.json";
        string packageContent = $"{baseUrl}/flatcontainer/{normalizedId}/{version}/{normalizedId}.{version}.nupkg";
        var leaf = new Dictionary<string, object?>
        {
            ["@id"] = leafId,
            ["@type"] = "Package",
            ["catalogEntry"] = LocalCatalogEntry(leafId, pkgName, version, packageContent),
            ["listed"] = true,
            ["packageContent"] = packageContent,
            ["registration"] = registration
        };
        return new ContentResult
        {
            Content = JsonSerializer.Serialize(leaf, NuGetRegistrationHelpers.RelaxedJsonOptions),
            ContentType = "application/json"
        };
    }

    // The NuGet v3 registration format is JSON-LD: the document keys "@id" and "@type" carry the
    // leading "@". A C# anonymous property `@id` is a *verbatim identifier* whose name is "id"
    // (no "@"), so anonymous objects silently emit a spec-violating document the NuGet client
    // rejects with "Value cannot be null or an empty string". Build these documents with explicit
    // dictionary keys so the "@" survives serialization. (The proxy-merge path already does this
    // via NuGetRegistrationHelpers' JsonObject builders; this is the local-only render path.)
    private static Dictionary<string, object?> LocalCatalogEntry(
        string leafId, string pkgName, string version, string packageContent) => new()
        {
            ["@id"] = leafId,
            ["@type"] = "PackageDetails",
            ["id"] = pkgName,
            ["version"] = version,
            ["listed"] = true,
            ["packageContent"] = packageContent
        };

    private async Task<IActionResult> ProxyRegistrationLeafAsync(
        HttpContext httpContext, string orgId, string normalizedId, string version, bool semVer2, CancellationToken ct)
    {
        string variant = semVer2 ? "registration5-gz-semver2" : "registration5-semver1";
        string baseUrl = urls.Absolute(httpContext, "/nuget");
        // Walk the org's configured upstreams in priority order; the first that answers wins.
        // No configured upstream ⇒ proxying is disabled for nuget, so the loop is skipped and
        // the leaf 404s.
        var bases = await registries.ResolveAsync(orgId, "nuget", ct);
        foreach (var source in bases)
        {
            string upstreamUrl = $"{source.Url}/{variant}/{normalizedId}/{version.ToLowerInvariant()}.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                var resp = await upstream.GetOrFetchMetadataAsync(upstreamUrl, source.AuthorizationHeader, linkedCts.Token);
                if (resp.IsSuccessStatusCode)
                {
                    string rewritten = NuGetRegistrationHelpers.RewriteRegistrationLeafUrls(
                        resp.BodyAsString(), normalizedId, baseUrl);
                    return new ContentResult { Content = rewritten, ContentType = "application/json" };
                }
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning("NuGet upstream registration leaf fetch failed: {Status} for {Url}", resp.StatusCode, upstreamUrl);
            }
            catch (Exception ex)
            {
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning(ex, "NuGet upstream registration leaf fetch threw for {Url}", upstreamUrl);
            }
        }
        return new NotFoundResult();
    }

    private async Task<IActionResult> RegistrationIndexCoreAsync(
        HttpContext httpContext, string orgId, string id, bool semVer2, CancellationToken ct)
    {
        // The id flows into the upstream registration URL — reject traversal-shaped values
        // before any lookup or upstream call.
        if (!AreUpstreamSafeNuGetSegments(id))
        {
            return new NotFoundResult();
        }

        var (settings, _, authError) = await AuthorizeNuGetReadAsync(httpContext, orgId, ct);
        if (authError is not null)
        {
            return authError;
        }

        string normalizedId = id.ToLowerInvariant();
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // Always merge upstream + local versions when passthrough + claims allow. An existing
        // local pkg is just a namespace marker, not a signal to suppress upstream — uploading
        // a private prerelease must not delete the public version line from the listing, or
        // downstream packages pinning ">= <stable>" of the same name fail NU1103. Mirrors
        // FlatcontainerVersions and PyPi's PackageIndex.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && !await reserved.IsReservedAsync(orgId, "nuget", normalizedId, ct)
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct);

        if (passthroughAllowed)
        {
            return await ServeProxyMergedRegistrationAsync(httpContext, orgId, id, normalizedId, pkg, semVer2, ct);
        }

        // Passthrough disabled or claim-local — local-only.
        return pkg is null
            ? new NotFoundResult()
            : await ServeLocalRegistrationAsync(httpContext, orgId, id, normalizedId, pkg, semVer2, ct);
    }

    // Sets the payload's ETag and reports whether the client's If-None-Match header already
    // matches it — the caller responds 304 Not Modified (ETag only, no Cache-Control) in
    // that case.
    private static bool IsClientCopyCurrent(HttpContext httpContext, byte[] bytes)
    {
        string etag = ComputeETag(bytes);
        httpContext.Response.Headers.ETag = etag;
        return httpContext.Request.Headers.IfNoneMatch.FirstOrDefault() == etag;
    }

    // Serves a cached registration payload with the ETag / If-None-Match handshake:
    // 304 when the client already holds the current bytes, otherwise the payload with
    // ETag and Cache-Control headers set.
    private static IActionResult RegistrationBytesResult(HttpContext httpContext, byte[] bytes, string cacheControl)
    {
        if (IsClientCopyCurrent(httpContext, bytes))
        {
            return new StatusCodeResult(StatusCodes.Status304NotModified);
        }
        httpContext.Response.Headers.CacheControl = cacheControl;
        return new FileContentResult(bytes, "application/json");
    }

    // Upstream-merged registration with an IMemoryCache front: cache hit serves the stored
    // bytes; a miss rebuilds via single-flighted ProxyMergedRegistrationAsync.
    // Uses IsProxy:true so the proxy-merged entry occupies a distinct cache slot from the
    // local-only entry written by ServeLocalRegistrationAsync. Without the distinction,
    // a local-only entry cached before an operator adds a mixed claim would be served
    // as the merged upstream response, dropping all upstream versions.
    private async Task<IActionResult> ServeProxyMergedRegistrationAsync(
        HttpContext httpContext, string orgId, string id, string normalizedId, Package? pkg, bool semVer2, CancellationToken ct)
    {
        var proxyCacheKey = new NuGetRegistrationKey(orgId, normalizedId, semVer2) { IsProxy = true };
        if (cache.TryGet(proxyCacheKey, out byte[]? proxyHit) && proxyHit is not null)
        {
            return RegistrationBytesResult(httpContext, proxyHit, "private, max-age=60");
        }

        // Single-flight: collapse concurrent registration rebuilds for the same key.
        byte[]? proxyBytes = await cache.GetOrRebuildAsync(proxyCacheKey, RegistrationProxyTtl, async rebuildCt =>
        {
            var result = await ProxyMergedRegistrationAsync(httpContext, orgId, id, pkg, semVer2, rebuildCt);
            string? json = result switch
            {
                ContentResult cr => cr.Content,
                JsonResult jr => System.Text.Json.JsonSerializer.Serialize(jr.Value, NuGetRegistrationHelpers.RelaxedJsonOptions),
                _ => null,
            };
            return json is null ? null : System.Text.Encoding.UTF8.GetBytes(json);
        }, ct);

        if (proxyBytes is not null)
        {
            return new FileContentResult(proxyBytes, "application/json");
        }

        // Non-cacheable result (e.g. NotFound) — fall through to direct return.
        return await ProxyMergedRegistrationAsync(httpContext, orgId, id, pkg, semVer2, ct);
    }

    // Local-only registration with an IMemoryCache front: a cache hit serves the stored
    // bytes, and a miss rebuilds from the package's version rows (uploaded + proxy cached)
    // and caches the document.
    private async Task<IActionResult> ServeLocalRegistrationAsync(
        HttpContext httpContext, string orgId, string id, string normalizedId, Package pkg, bool semVer2, CancellationToken ct)
    {
        var localCacheKey = new NuGetRegistrationKey(orgId, normalizedId, semVer2);
        if (cache.TryGet(localCacheKey, out byte[]? localHit) && localHit is not null)
        {
            return RegistrationBytesResult(httpContext, localHit, "private, max-age=300");
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, normalizedId, ct);
        var signals = await LoadCombinedVulnSignalsAsync(versions, ct);
        object localResult = BuildLocalRegistration(httpContext, id, pkg, versions, settings!, signals, time.GetUtcNow());
        string localJson = System.Text.Json.JsonSerializer.Serialize(localResult, NuGetRegistrationHelpers.RelaxedJsonOptions);
        byte[] localBytes = System.Text.Encoding.UTF8.GetBytes(localJson);
        cache.Set(localCacheKey, localBytes, RegistrationLocalTtl);
        return RegistrationBytesResult(httpContext, localBytes, "private, max-age=300");
    }

    // Loads vuln gate signals for a combined (uploaded + proxy synthetic) version list.
    // Uploaded versions key on package_version_id; synthetic proxy versions key on
    // cache_artifact_id (stored in PackageVersion.Id via ToPackageVersionSynthetic).
    private async Task<IReadOnlyDictionary<string, VulnGateSignals>> LoadCombinedVulnSignalsAsync(
        IReadOnlyList<PackageVersion> versions, CancellationToken ct)
    {
        if (versions.Count == 0)
        {
            return new Dictionary<string, VulnGateSignals>();
        }

        var uploadedIds = versions.Where(v => v.Origin == "uploaded").Select(v => v.Id).ToList();
        var proxyIds = versions.Where(v => v.Origin == "proxy").Select(v => v.Id).ToList();

        var uploadedSignals = uploadedIds.Count > 0
            ? await vulns.GetGateSignalsBatchAsync(uploadedIds, ct)
            : new Dictionary<string, VulnGateSignals>();
        var proxySignals = proxyIds.Count > 0
            ? await vulns.GetGateSignalsBatchForCacheArtifactsAsync(proxyIds, ct)
            : new Dictionary<string, VulnGateSignals>();

        if (uploadedSignals.Count == 0)
        {
            return proxySignals;
        }

        if (proxySignals.Count == 0)
        {
            return uploadedSignals;
        }

        var merged = new Dictionary<string, VulnGateSignals>(uploadedSignals);
        foreach (var (k, v) in proxySignals)
        {
            merged[k] = v;
        }

        return merged;
    }

    // Returns the combined list of uploaded package_versions and synthetic PackageVersion
    // objects projected from global-plane proxy cache entries. NuGet registration lists all
    // cached versions for a package id; proxy entries whose version already appears in uploaded
    // versions are deduplicated. Each NuGet version may produce multiple cache_artifact rows
    // (.nupkg, .nuspec, .sha512); version deduplication ensures one entry per version string.
    private async Task<IReadOnlyList<PackageVersion>> LoadCombinedVersionsAsync(
        string orgId, string packageId, string normalizedId, CancellationToken ct)
    {
        var uploadedVersions = await packages.GetVersionsAsync(packageId, ct);
        var proxyEntries = await cacheArtifacts.ListServeFactsForNameAsync(orgId, "nuget", normalizedId, ct);

        if (proxyEntries.Count == 0)
        {
            return uploadedVersions;
        }

        var uploadedVersionSet = uploadedVersions
            .Select(v => v.Version)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var proxyIds = proxyEntries.Select(e => e.Id).ToList();
        var proxySignals = proxyIds.Count > 0
            ? await vulns.GetGateSignalsBatchForCacheArtifactsAsync(proxyIds, ct)
            : new Dictionary<string, VulnGateSignals>();

        var synthetic = proxyEntries
            .Where(e => !uploadedVersionSet.Contains(e.Version))
            .GroupBy(e => e.Version, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First().ToPackageVersionSynthetic(proxySignals))
            .ToList();

        if (synthetic.Count == 0)
        {
            return uploadedVersions;
        }

        var combined = new List<PackageVersion>(uploadedVersions.Count + synthetic.Count);
        combined.AddRange(uploadedVersions);
        combined.AddRange(synthetic);
        return combined;
    }

    private Dictionary<string, object?> BuildLocalRegistration(
        HttpContext httpContext,
        string id, Package pkg, IReadOnlyList<PackageVersion> versions,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        string normalizedId = id.ToLowerInvariant();
        string baseUrl = urls.Absolute(httpContext, "/nuget");
        string registration = $"{baseUrl}/registration/{normalizedId}/index.json";

        // Exclude yanked versions and versions the block gate will hard-block on the download
        // path. The registration index must not advertise a version the flatcontainer endpoint
        // will 403 — keeping the two surfaces in sync is the invariant this renderer enforces.
        var leaves = versions
            .Where(v => !v.Yanked
                && !BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            .Select(v =>
            {
                string leafId = $"{baseUrl}/registration/{normalizedId}/{v.Version}.json";
                string packageContent = $"{baseUrl}/flatcontainer/{normalizedId}/{v.Version}/{normalizedId}.{v.Version}.nupkg";
                return new Dictionary<string, object?>
                {
                    ["@id"] = leafId,
                    ["@type"] = "Package",
                    ["catalogEntry"] = LocalCatalogEntry(leafId, pkg.Name, v.Version, packageContent),
                    ["packageContent"] = packageContent,
                    ["registration"] = registration
                };
            }).ToList();

        var page = new Dictionary<string, object?>
        {
            ["@id"] = $"{registration}#page",
            ["@type"] = "catalog:CatalogPage",
            ["count"] = leaves.Count,
            ["items"] = leaves
        };

        return new Dictionary<string, object?>
        {
            ["@id"] = registration,
            ["@type"] = new[] { "catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink" },
            ["count"] = 1,
            ["items"] = new[] { page }
        };
    }

    private async Task<IActionResult> ProxyMergedRegistrationAsync(
        HttpContext httpContext, string orgId, string id, Package? pkg, bool semVer2, CancellationToken ct)
    {
        string normalizedId = id.ToLowerInvariant();
        // semver1 excludes SemVer-2 build metadata (+suffix); semver2 is the superset. Pick the
        // upstream variant that matches what the client asked for. api.nuget.org publishes
        // -semver1 uncompressed but only -gz-semver2 for the SemVer 2 superset (the
        // registration5-semver2 path returns 404); HttpClient's AutomaticDecompression handles
        // the gzip transparently.
        string variant = semVer2 ? "registration5-gz-semver2" : "registration5-semver1";

        string? upstreamJson = await FetchUpstreamRegistrationJsonAsync(orgId, variant, normalizedId, ct);

        var localVersions = pkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await LoadCombinedVersionsAsync(orgId, pkg.Id, normalizedId, ct);

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var signals = await LoadCombinedVulnSignalsAsync(localVersions, ct);
        var now = time.GetUtcNow();
        string baseUrl = urls.Absolute(httpContext, "/nuget");

        if (upstreamJson is null)
        {
            if (pkg is null || localVersions.Count == 0)
            {
                return new NotFoundResult();
            }

            object localFallback = BuildLocalRegistration(httpContext, id, pkg, localVersions, settings!, signals, now);
            byte[] localFallbackBytes = System.Text.Encoding.UTF8.GetBytes(
                System.Text.Json.JsonSerializer.Serialize(localFallback, NuGetRegistrationHelpers.RelaxedJsonOptions));
            if (IsClientCopyCurrent(httpContext, localFallbackBytes))
            {
                return new StatusCodeResult(StatusCodes.Status304NotModified);
            }
            httpContext.Response.Headers.CacheControl = "private, max-age=300";
            return new ContentResult
            {
                Content = System.Text.Json.JsonSerializer.Serialize(localFallback, NuGetRegistrationHelpers.RelaxedJsonOptions),
                ContentType = "application/json"
            };
        }

        // Filter local-only versions through the block gate before merging them into the
        // upstream registration so a blocked local version is never listed alongside its
        // upstream neighbours.
        var servableLocalVersions = localVersions
            .Where(v => !BlockGateService.IsHardBlockedByStoredState(v, settings!, signals.GetValueOrDefault(v.Id), now))
            .ToList();

        string responseJson = pkg is null || servableLocalVersions.Count == 0
            ? NuGetRegistrationHelpers.RewriteRegistrationIndexUrls(upstreamJson, normalizedId, baseUrl)
            : NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(upstreamJson, servableLocalVersions, pkg, id, baseUrl);

        byte[] regBytes = System.Text.Encoding.UTF8.GetBytes(responseJson);
        if (IsClientCopyCurrent(httpContext, regBytes))
        {
            return new StatusCodeResult(StatusCodes.Status304NotModified);
        }
        httpContext.Response.Headers.CacheControl = "private, max-age=60";
        return new ContentResult { Content = responseJson, ContentType = "application/json" };
    }

    // Walks the org's configured upstreams in priority order and returns the first
    // registration index that answers successfully. No configured upstream ⇒ proxying is
    // disabled for nuget, so the loop is skipped; null means the caller falls back to
    // local-only data.
    private async Task<string?> FetchUpstreamRegistrationJsonAsync(
        string orgId, string variant, string normalizedId, CancellationToken ct)
    {
        var bases = await registries.ResolveAsync(orgId, "nuget", ct);
        foreach (var source in bases)
        {
            string upstreamUrl = $"{source.Url}/{variant}/{normalizedId}/index.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                // Single-flight registration fetch.
                var resp = await upstream.GetOrFetchMetadataAsync(upstreamUrl, source.AuthorizationHeader, linkedCts.Token);
                if (resp.IsSuccessStatusCode)
                {
                    return resp.BodyAsString();
                }
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning("NuGet upstream registration fetch failed: {Status} for {Url}", resp.StatusCode, upstreamUrl);
            }
            catch (Exception ex)
            {
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning(ex, "NuGet upstream registration fetch threw for {Url}", upstreamUrl);
            }
        }
        return null;
    }

    // Returns (settings, token) when the caller is authorized to read NuGet packages from this org,
    // or sets errorResult to a 401 challenge when AnonymousPull is disabled and no valid token was
    // presented. Org-scoped token resolution means cross-org tokens are coerced to null so the
    // AnonymousPull gate governs — this is a BOLA guard and must not be relaxed.
    private async Task<(OrgSettings? Settings, TokenRecord? Token, IActionResult? Error)>
        AuthorizeNuGetReadAsync(HttpContext httpContext, string orgId, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return (null, null, new UnauthorizedResult());
        }
        return (settings, token, null);
    }

    private static bool AreUpstreamSafeNuGetSegments(params string[] values)
        => Array.TrueForAll(values, v => PathSafeValidator.ValidateUpstreamSegment(v, "segment").IsValid);

    private static string ComputeETag(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }
}
