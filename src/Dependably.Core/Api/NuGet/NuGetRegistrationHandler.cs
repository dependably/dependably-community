using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Observability;
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
    TokenRepository tokens,
    VulnerabilityRepository vulns,
    ArtifactInventoryRepository inventory,
    UpstreamClient upstream,
    UpstreamRegistryResolver registries,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    RenderedResponseCache<NuGetRegistrationKey> cache,
    RenderedMetadataCacheOptions cacheOptions,
    IPublicUrlBuilder urls,
    TimeProvider time,
    ILogger<NuGetRegistrationHandler> logger)
{
    // TTL for proxy-merged registration pages (upstream can change); local-only registrations
    // use a longer TTL because invalidation on mutation is the primary expiry mechanism. Both are
    // operator-tunable via METADATA_PROXY/LOCAL_CACHE_TTL_SECONDS (see RenderedMetadataCacheOptions).
    private TimeSpan RegistrationProxyTtl => cacheOptions.ProxyTtl;
    private TimeSpan RegistrationLocalTtl => cacheOptions.LocalTtl;

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
                    string? rewritten = NuGetRegistrationHelpers.RewriteRegistrationLeafUrls(
                        resp.BodyAsString(), normalizedId, baseUrl);
                    if (rewritten is null)
                    {
                        // No usable version on the leaf, so its download URL cannot be pointed at
                        // this instance. Serving it verbatim would route the client past the
                        // proxy's verification and gate, so the leaf is refused, not forwarded.
                        // RenderedCompactJsonFormatter JSON-encodes {Url}.
                        logger.LogWarning(
                            "NuGet upstream registration leaf carries no usable version; refusing to "
                            + "serve its upstream-controlled download URL for {Url}", upstreamUrl);
                        continue;
                    }

                    return new ContentResult { Content = rewritten, ContentType = "application/json" };
                }
                // RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning("NuGet upstream registration leaf fetch failed: {Status} for {Url}", resp.StatusCode, upstreamUrl);
            }
            catch (Exception ex)
            {
                // RenderedCompactJsonFormatter JSON-encodes {Url}.
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
    // bytes; a miss rebuilds via single-flighted BuildProxyMergedRegistrationBytesAsync.
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
            // This request made no upstream call, so it reports neither ok nor error. The
            // flatcontainer path's vocabulary, extended with the one outcome only a cached
            // document has.
            httpContext.Response.Headers["X-Upstream-Status"] = "cached";
            return RegistrationBytesResult(httpContext, proxyHit, "private, max-age=60");
        }

        // Resolve the tenant base URL on the request thread, before entering single-flight.
        // The rebuild below runs under CancellationToken.None and is shared across concurrent
        // callers for the same key, so it must never touch the initiating caller's HttpContext:
        // that context may have completed (its response object recycled) by the time the shared
        // task runs, and the registration/flatcontainer URLs baked into the cached JSON are
        // served org-wide for the whole TTL — they cannot depend on whichever caller happened
        // to win the race.
        string baseUrl = urls.Absolute(httpContext, "/nuget");

        // Single-flight: collapse concurrent registration rebuilds for the same key. The
        // rebuild yields pure bytes (no HttpContext reads, no response-header writes); the
        // ETag / If-None-Match decision is made below against the returned bytes, so one
        // caller's conditional-request header can never suppress caching for the others.
        // An upstream-unreachable local fallback carries the longer local-only max-age hint;
        // the merged/rewritten upstream response uses the shorter proxy max-age.
        //
        // The rebuild also reports whether upstream answered, so a caller can see per-request that
        // it was served the local-only fallback — the state that hid a permanently misconfigured
        // upstream until clients started crashing on the document it produced. A caller that JOINS
        // another's single flight does not run this lambda and keeps the "cached" default: it made
        // no upstream call of its own, which is what the header describes.
        string cacheControl = "private, max-age=60";
        string upstreamStatus = "cached";
        byte[]? proxyBytes = await cache.GetOrRebuildAsync(proxyCacheKey, RegistrationProxyTtl, async rebuildCt =>
        {
            var (bytes, upstreamReached) = await BuildProxyMergedRegistrationBytesAsync(orgId, id, pkg, semVer2, baseUrl, rebuildCt);
            cacheControl = upstreamReached ? "private, max-age=60" : "private, max-age=300";
            upstreamStatus = upstreamReached ? "ok" : "error";
            return bytes;
        }, ct);

        httpContext.Response.Headers["X-Upstream-Status"] = upstreamStatus;
        return proxyBytes is null
            ? new NotFoundResult()
            : RegistrationBytesResult(httpContext, proxyBytes, cacheControl);
    }

    // Local-only registration with an IMemoryCache front: a cache hit serves the stored
    // bytes, and a miss rebuilds from the package's version rows (uploaded + proxy cached)
    // and caches the document.
    private async Task<IActionResult> ServeLocalRegistrationAsync(
        HttpContext httpContext, string orgId, string id, string normalizedId, Package pkg, bool semVer2, CancellationToken ct)
    {
        var localCacheKey = new NuGetRegistrationKey(orgId, normalizedId, semVer2);

        // Capture the invalidation generation AND the org policy epoch token before reading any
        // policy-dependent state below — mirroring RenderedResponseCache.GetOrRebuildAsync. A
        // proxy-settings PUT that commits its DB write and invalidates the org's epoch between
        // this read and the Set below must not be lost: binding the Set to the token captured
        // here means it is already expired the instant it lands, instead of picking up whichever
        // epoch happens to be live once the write actually runs.
        long generation = cache.GetGeneration(localCacheKey);
        var epochToken = cache.CaptureEpochToken(localCacheKey);
        if (cache.TryGet(localCacheKey, out byte[]? localHit) && localHit is not null)
        {
            return RegistrationBytesResult(httpContext, localHit, "private, max-age=300");
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, normalizedId, ct);
        var signals = await LoadCombinedVulnSignalsAsync(versions, ct);
        string baseUrl = urls.Absolute(httpContext, "/nuget");
        object localResult = BuildLocalRegistration(baseUrl, id, pkg, versions, settings!, signals, time.GetUtcNow());
        string localJson = System.Text.Json.JsonSerializer.Serialize(localResult, NuGetRegistrationHelpers.RelaxedJsonOptions);
        byte[] localBytes = System.Text.Encoding.UTF8.GetBytes(localJson);
        cache.SetIfGenerationUnchanged(localCacheKey, localBytes, RegistrationLocalTtl, generation, epochToken);
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
    // versions are dropped. The registration document is version-level, but each proxied NuGet
    // version casts up to three cache_artifact rows (.nupkg, .nuspec, .sha512) sharing one
    // version string — DedupeProxyVersionsByVersion collapses those down to the .nupkg row so
    // the version is listed exactly once.
    private async Task<IReadOnlyList<PackageVersion>> LoadCombinedVersionsAsync(
        string orgId, string packageId, string normalizedId, CancellationToken ct)
    {
        var versions = await inventory.ListServeableVersionsAsync(orgId, packageId, "nuget", normalizedId, ct);
        return ArtifactInventoryRepository.DedupeProxyVersionsByVersion(versions);
    }

    private static Dictionary<string, object?> BuildLocalRegistration(
        string baseUrl,
        string id, Package pkg, IReadOnlyList<PackageVersion> versions,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        string normalizedId = id.ToLowerInvariant();
        string registration = $"{baseUrl}/registration/{normalizedId}/index.json";

        // Exclude yanked versions and versions the block gate will hard-block on the download
        // path. The registration index must not advertise a version the flatcontainer endpoint
        // will 403 — keeping the two surfaces in sync is the invariant this renderer enforces.
        var servable = versions
            .Where(v => !v.Yanked
                && !BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            .ToList();

        if (servable.Count == 0)
        {
            // No servable versions: a spec-valid empty registration index with no page object.
            // A page always carries lower/upper semver bounds computed from at least one version,
            // so emitting one here with neither would repeat the crash this renderer exists to avoid.
            return new Dictionary<string, object?>
            {
                ["@id"] = registration,
                ["@type"] = new[] { "catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink" },
                ["count"] = 0,
                ["items"] = Array.Empty<object?>()
            };
        }

        var leaves = servable
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

        var (lower, upper) = NuGetRegistrationHelpers.ComputeRange(servable);
        var page = new Dictionary<string, object?>
        {
            ["@id"] = $"{registration}#page",
            ["@type"] = "catalog:CatalogPage",
            ["count"] = leaves.Count,
            ["items"] = leaves,
            ["lower"] = lower,
            ["upper"] = upper
        };

        return new Dictionary<string, object?>
        {
            ["@id"] = registration,
            ["@type"] = new[] { "catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink" },
            ["count"] = 1,
            ["items"] = new[] { page }
        };
    }

    // Builds the serialized proxy-merged registration document: the upstream index rewritten
    // to tenant URLs, with servable local versions merged in, or a local-only fallback when
    // upstream is unreachable. Bytes are null when neither upstream nor local has anything to
    // serve (the caller maps that to 404); UpstreamReached is false on the local-only fallback
    // so the caller can pick the longer local max-age hint. Takes a precomputed baseUrl and
    // returns pure bytes — never reading the initiating caller's HttpContext nor writing
    // response headers — so the single-flight cache decision stays independent of any one
    // caller's conditional-request headers and the shared task cannot touch a completed or
    // recycled response.
    private async Task<(byte[]? Bytes, bool UpstreamReached)> BuildProxyMergedRegistrationBytesAsync(
        string orgId, string id, Package? pkg, bool semVer2, string baseUrl, CancellationToken ct)
    {
        string normalizedId = id.ToLowerInvariant();
        // semver1 excludes SemVer-2 build metadata (+suffix); semver2 is the superset. Pick the
        // upstream variant that matches what the client asked for. api.nuget.org publishes
        // -semver1 uncompressed but only -gz-semver2 for the SemVer 2 superset (the
        // registration5-semver2 path returns 404); HttpClient's AutomaticDecompression handles
        // the gzip transparently.
        string variant = semVer2 ? "registration5-gz-semver2" : "registration5-semver1";

        var (upstreamJsonResult, upstreamFailures, upstreamUrls) =
            await FetchUpstreamRegistrationJsonAsync(orgId, variant, normalizedId, ct);
        string? upstreamJson = upstreamJsonResult;
        if (upstreamJson is not null)
        {
            // Resolve externalized pages before anything reads the document: the dedupe and the
            // URL rewrite both walk page items, and a page that only carries an @id has none.
            upstreamJson = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
                upstreamJson,
                (pageUrl, pageCt) => FetchUpstreamRegistrationPageAsync(orgId, pageUrl, pageCt),
                MaxExternalizedPagesPerIndex,
                ct);
        }

        var localVersions = pkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await LoadCombinedVersionsAsync(orgId, pkg.Id, normalizedId, ct);

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var signals = await LoadCombinedVulnSignalsAsync(localVersions, ct);
        var now = time.GetUtcNow();

        if (upstreamJson is null)
        {
            if (pkg is null || localVersions.Count == 0)
            {
                // No local row to fall back on either. A genuine "every configured upstream
                // confirmed absent (404/410)" answer stays a 404 below; a non-clean failure
                // (timeout, 5xx, refusal, ...) on at least one upstream must surface as a real
                // upstream failure instead of the silent, non-retryable 404 that makes
                // `dotnet restore` report NU1101 even when the package genuinely exists.
                upstreamFailures.ThrowIfFailed();
                return (null, false);
            }

            object localFallback = BuildLocalRegistration(baseUrl, id, pkg, localVersions, settings!, signals, now);
            byte[] localFallbackBytes = System.Text.Encoding.UTF8.GetBytes(
                System.Text.Json.JsonSerializer.Serialize(localFallback, NuGetRegistrationHelpers.RelaxedJsonOptions));
            return (localFallbackBytes, false);
        }

        // Filter local-only versions through the block gate before merging them into the
        // upstream registration so a blocked local version is never listed alongside its
        // upstream neighbours.
        var servableLocalVersions = localVersions
            .Where(v => !BlockGateService.IsHardBlockedByStoredState(v, settings!, signals.GetValueOrDefault(v.Id), now))
            .ToList();

        // The upstream leaves merged in below carry no local row, so only the release-age and
        // deprecated (unlisted) arms are decidable — see VersionFacts.ForUpstreamOnly — from
        // catalogEntry.published/listed, the same facts the first-fetch path reads off this same
        // registration leaf shape (NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync).
        var upstreamGate = (BlockPolicyFrom(settings!), now);

        string responseJson = pkg is null || servableLocalVersions.Count == 0
            ? NuGetRegistrationHelpers.RewriteRegistrationIndexUrls(
                upstreamJson, normalizedId, baseUrl, upstreamGate, upstreamUrls)
            : NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(
                upstreamJson, servableLocalVersions, pkg, id, upstreamGate, baseUrl, upstreamUrls);

        return (System.Text.Encoding.UTF8.GetBytes(responseJson), true);
    }

    // Bounds the upstream fan-out one registration request can trigger. api.nuget.org pages hold
    // 64 leaves each, so even a thousand-version package externalizes well under this; the cap is
    // a backstop against a hostile or malformed index listing pages without end, not a limit any
    // real package reaches. A page past the cap keeps its upstream @id and stays dereferenceable.
    private const int MaxExternalizedPagesPerIndex = 32;

    // Fetches one externalized registration page document, or returns null when it must not be
    // fetched.
    //
    // The page @id is upstream-controlled, so it is host-pinned to one of the org's configured
    // nuget upstreams before any request is made: a compromised or hostile index could otherwise
    // name any host and turn this into a server-side request forgery with the upstream's
    // credentials attached. The credential is only threaded for the upstream whose host matched,
    // never carried to a host named by the document.
    private async Task<string?> FetchUpstreamRegistrationPageAsync(
        string orgId, string pageUrl, CancellationToken ct)
    {
        var bases = await registries.ResolveAsync(orgId, "nuget", ct);
        var source = bases.FirstOrDefault(b => UpstreamHostPin.IsSameHost(b.Url, pageUrl));
        if (source is null)
        {
            // RenderedCompactJsonFormatter JSON-encodes {Url}.
            logger.LogWarning(
                "NuGet upstream registration page {Url} is not on a configured upstream host; " +
                "leaving the page externalized.", pageUrl);
            return null;
        }

        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            var resp = await upstream.GetOrFetchMetadataAsync(pageUrl, source.AuthorizationHeader, linkedCts.Token);
            if (resp.IsSuccessStatusCode)
            {
                return resp.BodyAsString();
            }

            // RenderedCompactJsonFormatter JSON-encodes {Url}.
            logger.LogWarning(
                "NuGet upstream registration page fetch failed: {Status} for {Url}", resp.StatusCode, pageUrl);
        }
        catch (Exception ex)
        {
            // RenderedCompactJsonFormatter JSON-encodes {Url}.
            logger.LogWarning(ex, "NuGet upstream registration page fetch threw for {Url}", pageUrl);
        }

        return null;
    }

    // Walks the org's configured upstreams in priority order and returns the first
    // registration index that answers successfully. No configured upstream ⇒ proxying is
    // disabled for nuget, so the loop is skipped; a null Json means the caller falls back to
    // local-only data. The returned tracker distinguishes a genuine "every upstream confirmed
    // absent (404/410)" outcome from "at least one upstream failed non-cleanly" — the caller
    // decides whether that failure must surface as an UpstreamFetchFailedException, since only
    // it knows whether a local fallback exists.
    private async Task<(string? Json, UpstreamMetadataFailureTracker Failures, IReadOnlyCollection<string> UpstreamUrls)>
        FetchUpstreamRegistrationJsonAsync(
        string orgId, string variant, string normalizedId, CancellationToken ct)
    {
        var failures = new UpstreamMetadataFailureTracker();
        var bases = await registries.ResolveAsync(orgId, "nuget", ct);
        // The same resolved set governs the host-pin applied to whatever URLs survive the rewrite,
        // so a configuration change mid-request cannot widen the pin past what was fetched.
        var upstreamUrls = bases.Select(b => b.Url).ToList();
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
                    return (resp.BodyAsString(), failures, upstreamUrls);
                }
                failures.RecordHttpStatus(upstreamUrl, resp.StatusCode, source.AuthorizationHeader);
                DependablyMeter.NuGetRegistrationUpstreamFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "http_error"));
                // RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning("NuGet upstream registration fetch failed: {Status} for {Url}", resp.StatusCode, upstreamUrl);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // The 10s per-upstream deadline, not the caller giving up. Counted separately from
                // a refusal: a timing-out upstream and a 404ing one are different operator
                // problems, and the 404 is the one a bad base URL produces.
                failures.RecordFailure(upstreamUrl);
                DependablyMeter.NuGetRegistrationUpstreamFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "timeout"));
                // RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning("NuGet upstream registration fetch timed out for {Url}", upstreamUrl);
            }
            catch (Exception ex)
            {
                failures.RecordFailure(upstreamUrl);
                DependablyMeter.NuGetRegistrationUpstreamFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "exception"));
                // RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning(ex, "NuGet upstream registration fetch threw for {Url}", upstreamUrl);
            }
        }
        return (null, failures, upstreamUrls);
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

    // The tenant policy an upstream-merged registration leaf is gated against. Projects the whole
    // policy — not just the release-age and deprecated modes the leaf-level facts can decide —
    // mirroring BlockGateService.IsHardBlockedByStoredState's own projection, so an arm that
    // becomes decidable from registration metadata later needs no change here.
    private static BlockPolicy BlockPolicyFrom(OrgSettings settings) =>
        new(MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            VerifyProvenanceMode: settings.VerifyProvenanceMode("nuget"),
            BlockRevokedMode: settings.BlockRevoked);

    private static bool AreUpstreamSafeNuGetSegments(params string[] values)
        => Array.TrueForAll(values, v => PathSafeValidator.ValidateUpstreamSegment(v, "segment").IsValid);

    private static string ComputeETag(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }
}
