using System.Globalization;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Handles GET /simple/ (package listing) and GET /simple/{package}/ (per-package version
/// listing) per PEP 503/592, with PEP 691 JSON Simple API content negotiation. Serves
/// local-only or proxy-merged simple indices with in-process caching, ETag-based conditional
/// responses, and block-gate filtering. Both representations share the byte cache: the
/// negotiated representation is part of the <see cref="PyPiSimpleIndexKey"/>, so JSON and HTML
/// occupy distinct entries for one URL and each is served from cache rather than re-fetched
/// upstream per request.
/// </summary>
public sealed class PyPiSimpleIndexHandler(
    OrgRepository orgs,
    PackageRepository packages,
    PackageVersionFilesRepository versionFiles,
    TokenRepository tokens,
    VulnerabilityRepository vulns,
    ArtifactInventoryRepository inventory,
    UpstreamClient upstream,
    UpstreamRegistryResolver registries,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    RenderedResponseCache<PyPiSimpleIndexKey> cache,
    RenderedMetadataCacheOptions cacheOptions,
    TimeProvider time)
{
    public async Task<IActionResult> SimpleIndexAsync(
        HttpContext httpContext, string orgId, CancellationToken ct)
    {
        SetVaryOnAccept(httpContext);
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var pkgs = await packages.ListAsync(orgId, "pypi", ct);

        if (PrefersJson(httpContext))
        {
            string projectListJson = PyPiSimpleIndexHelper.RenderProjectListJson(pkgs.Select(pkg => pkg.PurlName));
            return new ContentResult { Content = projectListJson, ContentType = PyPiSimpleIndexHelper.JsonContentType, StatusCode = StatusCodes.Status200OK };
        }

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head><title>Simple Index</title></head><body>");
        sb.AppendLine("<h1>Simple Index</h1>");
        foreach (string? name in pkgs.Select(pkg => pkg.PurlName))
        {
            string simpleHref = PyPiSimpleIndexHelper.OrgPath($"simple/{name}/");
            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(simpleHref)}\">{System.Web.HttpUtility.HtmlEncode(name)}</a><br/>");
        }
        sb.AppendLine("</body></html>");

        return new ContentResult { Content = sb.ToString(), ContentType = HtmlContentType, StatusCode = StatusCodes.Status200OK };
    }

    public async Task<IActionResult> PackageIndexAsync(
        HttpContext httpContext, string orgId, string package, CancellationToken ct)
    {
        SetVaryOnAccept(httpContext);
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        string purlName = PurlNormalizer.PyPiName(package);

        // The name flows into the upstream simple-index URL — reject traversal-shaped
        // values before any lookup or upstream call, mirroring the upload-side validation.
        if (!PathSafeValidator.ValidateUpstreamSegment(purlName, "package").IsValid)
        {
            return new NotFoundResult();
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "pypi", purlName, ct);

        // Auth gate runs before any cache access so an unauthenticated request never
        // receives a cached response when AnonymousPull is disabled.
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        bool wantsJson = PrefersJson(httpContext);

        // Always merge upstream + local versions when passthrough + claims allow. Routing must
        // not gate on packages.is_proxy — a name with privately uploaded versions is still a
        // namespace that holds proxy-fetched versions; clients need to discover both.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && !await reserved.IsReservedAsync(orgId, "pypi", purlName, ct)
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlName, ct);

        if (passthroughAllowed)
        {
            return await ServeProxySimpleIndexAsync(
                new SimpleIndexRequest(httpContext, orgId, purlName, pkg, settings!, token, wantsJson), ct);
        }

        // Passthrough disabled or name is claim-local — return only local versions.
        return pkg is null
            ? new NotFoundResult()
            : await ServeLocalSimpleIndexAsync(httpContext, orgId, purlName, pkg, settings!, wantsJson, ct);
    }

    // Bundles the per-request context threaded through the proxy simple-index path — the
    // pieces past the .NET 7-recommended parameter count are all facets of one logical request,
    // never independently varying, so they travel together rather than as separate parameters.
    private sealed record SimpleIndexRequest(
        HttpContext HttpContext, string OrgId, string PurlName, Package? Pkg,
        OrgSettings Settings, TokenRecord? Token, bool WantsJson);

    private async Task<IActionResult> ServeProxySimpleIndexAsync(SimpleIndexRequest req, CancellationToken ct)
    {
        // The negotiated representation is part of the key, so the JSON form is cached
        // alongside the HTML form instead of re-fetching upstream on every request.
        var cacheKey = new PyPiSimpleIndexKey(req.OrgId, req.PurlName) { WantsJson = req.WantsJson };
        string contentType = ContentTypeFor(req.WantsJson);
        if (cache.TryGet(cacheKey, out byte[]? proxyHit) && proxyHit is not null)
        {
            return ServeNotModifiedOrSetCacheHeaders(req.HttpContext, proxyHit, "private, max-age=60")
                ?? (IActionResult)new FileContentResult(proxyHit, contentType);
        }

        // Single-flight: collapse concurrent rebuilds for the same proxy simple index.
        byte[]? proxyBytes = await cache.GetOrRebuildAsync(cacheKey, cacheOptions.ProxyTtl, async rebuildCt =>
        {
            var result = await ProxyUpstreamSimpleIndexAsync(req, rebuildCt);
            return result is ContentResult cr && cr.Content is not null
                ? Encoding.UTF8.GetBytes(cr.Content)
                : null;
        }, ct);

        if (proxyBytes is not null)
        {
            return new FileContentResult(proxyBytes, contentType);
        }

        // Non-ContentResult result (e.g. Unauthorized or NotFound) — return as-is.
        return await ProxyUpstreamSimpleIndexAsync(req, ct);
    }

    private async Task<IActionResult> ServeLocalSimpleIndexAsync(
        HttpContext httpContext, string orgId, string purlName, Package pkg,
        OrgSettings settings, bool wantsJson, CancellationToken ct)
    {
        // The negotiated representation is part of the key, so both forms are cached without
        // one ever being served under the other's content type.
        var localCacheKey = new PyPiSimpleIndexKey(orgId, purlName) { WantsJson = wantsJson };
        string contentType = ContentTypeFor(wantsJson);

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
            return ServeNotModifiedOrSetCacheHeaders(httpContext, localHit, "private, max-age=300")
                ?? (IActionResult)new FileContentResult(localHit, contentType);
        }

        var allVersions = await LoadCombinedVersionsAsync(orgId, pkg.Id, "pypi", purlName, ct);
        var signals = await LoadVulnSignalsAsync(allVersions, ct);
        // Per-file records exist only for hosted (uploaded) versions; synthetic proxy
        // projections miss the lookup and render their single version-row artifact.
        var hostedFiles = await versionFiles.GetByPackageAsync(pkg.Id, ct);
        var now = time.GetUtcNow();
        string localBody = wantsJson
            ? PyPiSimpleIndexHelper.RenderLocalSimpleIndexJson(pkg.PurlName, allVersions, hostedFiles, settings, signals, now)
            : PyPiSimpleIndexHelper.RenderLocalSimpleIndex(pkg.PurlName, allVersions, hostedFiles, settings, signals, now);
        byte[] localBytes = Encoding.UTF8.GetBytes(localBody);
        cache.SetIfGenerationUnchanged(localCacheKey, localBytes, cacheOptions.LocalTtl, generation, epochToken);
        return ServeNotModifiedOrSetCacheHeaders(httpContext, localBytes, "private, max-age=300")
            ?? (IActionResult)new ContentResult { Content = localBody, ContentType = contentType, StatusCode = StatusCodes.Status200OK };
    }

    private async Task<IActionResult> ProxyUpstreamSimpleIndexAsync(SimpleIndexRequest req, CancellationToken ct)
    {
        var (httpContext, orgId, purlName, localPkg, settings, token, wantsJson) = req;

        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        // Collect local versions up-front (uploaded + globally-cached proxy) so a missing
        // upstream still serves what we have cached, and locally-cached proxy versions
        // appear in the index with correct block-gate state.
        var localVersions = localPkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await LoadCombinedVersionsAsync(orgId, localPkg.Id, "pypi", purlName, ct);

        // Walk the org's configured upstreams in priority order; the first that answers wins.
        // No configured upstream ⇒ proxying is disabled for this ecosystem, so fall through to
        // local-only below.
        var bases = await registries.ResolveAsync(orgId, "pypi", ct);
        bool upstreamOk = false;
        List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry> upstreamEntries = [];
        foreach (var source in bases)
        {
            try
            {
                // Single-flight simple-index fetch — collapses N concurrent pip-install
                // requests onto a single upstream call when a coordinate first warms up.
                var response = await upstream.GetOrFetchMetadataAsync($"{source.Url}/simple/{purlName}/", source.AuthorizationHeader, ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                // Parse only the anchor filename/sha256 pairs out of the upstream page — the
                // served index is rendered from this parsed data below, never from the raw
                // upstream body, so hostile upstream markup (inside or outside an anchor) never
                // reaches the client.
                upstreamEntries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(response.BodyAsString());
                upstreamOk = true;
                break;
            }
            catch
            {
                // Upstream unreachable — try the next one, then fall back to local-only.
            }
        }

        // Load vuln gate signals for all local versions in one batch query. Used by both the
        // fallback renderer and the merged renderer so neither fans out N per-version I/O calls.
        var signals = await LoadVulnSignalsAsync(localVersions, ct);
        // Per-file records exist only for hosted (uploaded) versions; synthetic proxy
        // projections miss the lookup and render their single version-row artifact.
        var hostedFiles = localPkg is null
            ? PyPiSimpleIndexHelper.NoHostedFiles
            : await versionFiles.GetByPackageAsync(localPkg.Id, ct);
        var now = time.GetUtcNow();

        if (!upstreamOk)
        {
            if (localVersions.Count == 0)
            {
                return new NotFoundResult();
            }

            string fallbackBody = wantsJson
                ? PyPiSimpleIndexHelper.RenderLocalSimpleIndexJson(purlName, localVersions, hostedFiles, settings, signals, now)
                : PyPiSimpleIndexHelper.RenderLocalSimpleIndex(purlName, localVersions, hostedFiles, settings, signals, now);
            byte[] fallbackBytes = Encoding.UTF8.GetBytes(fallbackBody);
            return ServeNotModifiedOrSetCacheHeaders(httpContext, fallbackBytes, "private, max-age=300")
                ?? (IActionResult)new ContentResult { Content = fallbackBody, ContentType = ContentTypeFor(wantsJson), StatusCode = StatusCodes.Status200OK };
        }

        // Render the merged index entirely from parsed upstream entries + local versions —
        // mixed-origin namespaces expose private versions alongside upstream, with filenames
        // already present upstream skipped to avoid duplicates.
        string merged = wantsJson
            ? PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(purlName, upstreamEntries, localVersions, hostedFiles, settings, signals, now)
            : PyPiSimpleIndexHelper.RenderMergedSimpleIndex(purlName, upstreamEntries, localVersions, hostedFiles, settings, signals, now);
        byte[] mergedBytes = Encoding.UTF8.GetBytes(merged);
        return ServeNotModifiedOrSetCacheHeaders(httpContext, mergedBytes, "private, max-age=60")
            ?? (IActionResult)new ContentResult { Content = merged, ContentType = ContentTypeFor(wantsJson), StatusCode = StatusCodes.Status200OK };
    }

    private const string HtmlContentType = "text/html; charset=utf-8";

    // Resolves the content type from the same flag that selects the body renderer, so a serve
    // site cannot declare one representation while emitting the other.
    private static string ContentTypeFor(bool wantsJson) =>
        wantsJson ? PyPiSimpleIndexHelper.JsonContentType : HtmlContentType;

    // These routes serve two representations of one URL, chosen by the Accept header, with an
    // ETag and Cache-Control on each. Vary: Accept tells per-URL HTTP caches (pip's own cache,
    // an intermediary proxy, a CDN) to key on Accept as well, so a JSON client is never handed
    // a cached HTML body or vice versa. Set on every response from the negotiated routes —
    // including 304s and the single-flight path that returns already-rendered bytes.
    private static void SetVaryOnAccept(HttpContext httpContext) =>
        httpContext.Response.Headers.Vary = "Accept";

    // Negotiates PEP 691 JSON vs. PEP 503 HTML from the request's Accept header: the media type
    // (exact match, or a wildcard covering it) with the higher quality value wins, and JSON must
    // win outright — a tie keeps the HTML default. A bare "*/*" from a generic client counts
    // toward HTML alone, and no Accept header at all keeps HTML too, so only a client that
    // explicitly asks for JSON receives it.
    private static bool PrefersJson(HttpContext httpContext)
    {
        var acceptValues = httpContext.Request.Headers.Accept;
        if (acceptValues.Count == 0)
        {
            return false;
        }

        double jsonQuality = -1;
        double htmlQuality = -1;
        foreach (string? header in acceptValues)
        {
            if (string.IsNullOrEmpty(header))
            {
                continue;
            }

            foreach (string rawEntry in header.Split(','))
            {
                string entry = rawEntry.Trim();
                if (entry.Length == 0)
                {
                    continue;
                }

                string[] parts = entry.Split(';');
                string mediaType = parts[0].Trim().ToLowerInvariant();
                double quality = ParseQuality(parts);

                if (IsJsonMediaType(mediaType))
                {
                    jsonQuality = Math.Max(jsonQuality, quality);
                }
                else if (IsHtmlOrWildcardMediaType(mediaType))
                {
                    htmlQuality = Math.Max(htmlQuality, quality);
                }
            }
        }

        return jsonQuality >= 0 && jsonQuality > htmlQuality;
    }

    private static double ParseQuality(string[] mediaTypeParts)
    {
        for (int i = 1; i < mediaTypeParts.Length; i++)
        {
            string param = mediaTypeParts[i].Trim();
            if (param.StartsWith("q=", StringComparison.OrdinalIgnoreCase)
                && double.TryParse(param.AsSpan(2), NumberStyles.Float, CultureInfo.InvariantCulture, out double q))
            {
                return q;
            }
        }
        return 1.0;
    }

    // A bare "*/*" is deliberately absent here and present in IsHtmlOrWildcardMediaType: a
    // client that expresses no preference between the two representations gets the PEP 503
    // HTML one, which is what generic scrapers and older pip releases parse.
    private static bool IsJsonMediaType(string mediaType) =>
        mediaType is "application/vnd.pypi.simple.v1+json" or "application/json" or "application/*";

    private static bool IsHtmlOrWildcardMediaType(string mediaType) =>
        mediaType is "text/html" or "application/vnd.pypi.simple.v1+html" or "text/*" or "*/*";

    // Stamps the ETag for a simple-index body and answers 304 when the client's
    // If-None-Match matches; otherwise sets Cache-Control and returns null so the
    // caller serves the body.
    private static StatusCodeResult? ServeNotModifiedOrSetCacheHeaders(
        HttpContext httpContext, byte[] body, string cacheControl)
    {
        string etag = PyPiSimpleIndexHelper.ComputeETag(body);
        httpContext.Response.Headers.ETag = etag;
        if (httpContext.Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            return new StatusCodeResult(StatusCodes.Status304NotModified);
        }
        httpContext.Response.Headers.CacheControl = cacheControl;
        return null;
    }

    // Loads vuln gate signals for a combined (uploaded + proxy synthetic) version list.
    // Uploaded versions key on package_version_id; synthetic proxy versions key on
    // cache_artifact_id (stored in PackageVersion.Id via ToPackageVersionSynthetic).
    // The two signal dictionaries are merged so block-gate filtering works uniformly for
    // both origin types.
    private async Task<IReadOnlyDictionary<string, VulnGateSignals>> LoadVulnSignalsAsync(
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
    // objects projected from global-plane proxy cache entries for the given package. Used by
    // both the local-only and proxy-passthrough renderers so proxy-cached versions appear in
    // the index even when no package_versions row exists for them.
    private async Task<IReadOnlyList<PackageVersion>> LoadCombinedVersionsAsync(
        string orgId, string packageId, string ecosystem, string purlName, CancellationToken ct)
    {
        return await inventory.ListServeableVersionsAsync(orgId, packageId, ecosystem, purlName, ct);
    }
}
