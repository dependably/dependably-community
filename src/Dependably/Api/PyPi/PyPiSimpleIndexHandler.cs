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
/// listing) per PEP 503/592. Serves local-only or proxy-merged simple indices with
/// in-process caching, ETag-based conditional responses, and block-gate filtering.
/// </summary>
public sealed class PyPiSimpleIndexHandler(
    OrgRepository orgs,
    PackageRepository packages,
    CacheArtifactRepository cacheArtifacts,
    TokenRepository tokens,
    VulnerabilityRepository vulns,
    UpstreamClient upstream,
    UpstreamRegistryResolver registries,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    RenderedResponseCache<PyPiSimpleIndexKey> cache,
    TimeProvider time)
{
    public async Task<IActionResult> SimpleIndexAsync(
        HttpContext httpContext, string orgId, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var pkgs = await packages.ListAsync(orgId, "pypi", ct);

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

        return new ContentResult { Content = sb.ToString(), ContentType = "text/html; charset=utf-8", StatusCode = StatusCodes.Status200OK };
    }

    public async Task<IActionResult> PackageIndexAsync(
        HttpContext httpContext, string orgId, string package, CancellationToken ct)
    {
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

        // Always merge upstream + local versions when passthrough + claims allow. Routing must
        // not gate on packages.is_proxy — a name with privately uploaded versions is still a
        // namespace that holds proxy-fetched versions; clients need to discover both.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && !await reserved.IsReservedAsync(orgId, "pypi", purlName, ct)
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlName, ct);

        if (passthroughAllowed)
        {
            return await ServeProxySimpleIndexAsync(httpContext, orgId, purlName, pkg, settings, token, ct);
        }

        // Passthrough disabled or name is claim-local — return only local versions.
        return pkg is null
            ? new NotFoundResult()
            : await ServeLocalSimpleIndexAsync(httpContext, orgId, purlName, pkg, settings!, ct);
    }

    private async Task<IActionResult> ServeProxySimpleIndexAsync(
        HttpContext httpContext, string orgId, string purlName, Package? pkg,
        OrgSettings settings, TokenRecord? token, CancellationToken ct)
    {
        var cacheKey = new PyPiSimpleIndexKey(orgId, purlName);
        if (cache.TryGet(cacheKey, out byte[]? proxyHit) && proxyHit is not null)
        {
            return ServeNotModifiedOrSetCacheHeaders(httpContext, proxyHit, "private, max-age=60")
                ?? (IActionResult)new FileContentResult(proxyHit, "text/html; charset=utf-8");
        }

        // Single-flight: collapse concurrent rebuilds for the same proxy simple index.
        byte[]? proxyBytes = await cache.GetOrRebuildAsync(cacheKey, PyPiConstants.SimpleIndexProxyTtl, async rebuildCt =>
        {
            var result = await ProxyUpstreamSimpleIndexAsync(httpContext, orgId, purlName, pkg, settings, token, rebuildCt);
            return result is ContentResult cr && cr.Content is not null
                ? Encoding.UTF8.GetBytes(cr.Content)
                : null;
        }, ct);

        if (proxyBytes is not null)
        {
            return new FileContentResult(proxyBytes, "text/html; charset=utf-8");
        }

        // Non-ContentResult result (e.g. Unauthorized or NotFound) — return as-is.
        return await ProxyUpstreamSimpleIndexAsync(httpContext, orgId, purlName, pkg, settings, token, ct);
    }

    private async Task<IActionResult> ServeLocalSimpleIndexAsync(
        HttpContext httpContext, string orgId, string purlName, Package pkg,
        OrgSettings settings, CancellationToken ct)
    {
        var localCacheKey = new PyPiSimpleIndexKey(orgId, purlName);
        if (cache.TryGet(localCacheKey, out byte[]? localHit) && localHit is not null)
        {
            return ServeNotModifiedOrSetCacheHeaders(httpContext, localHit, "private, max-age=300")
                ?? (IActionResult)new FileContentResult(localHit, "text/html; charset=utf-8");
        }

        var allVersions = await LoadCombinedVersionsAsync(orgId, pkg.Id, "pypi", purlName, ct);
        var signals = await LoadVulnSignalsAsync(allVersions, ct);
        string localHtml = PyPiSimpleIndexHelper.RenderLocalSimpleIndex(pkg.PurlName, allVersions, settings, signals, time.GetUtcNow());
        byte[] localBytes = Encoding.UTF8.GetBytes(localHtml);
        cache.Set(localCacheKey, localBytes, PyPiConstants.SimpleIndexLocalTtl);
        return ServeNotModifiedOrSetCacheHeaders(httpContext, localBytes, "private, max-age=300")
            ?? (IActionResult)new ContentResult { Content = localHtml, ContentType = "text/html; charset=utf-8", StatusCode = StatusCodes.Status200OK };
    }

    private async Task<IActionResult> ProxyUpstreamSimpleIndexAsync(
        HttpContext httpContext, string orgId, string purlName,
        Package? localPkg, OrgSettings settings, TokenRecord? token, CancellationToken ct)
    {
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
        string? upstreamHtml = null;
        foreach (string upstreamBase in bases)
        {
            try
            {
                // Single-flight simple-index fetch — collapses N concurrent pip-install
                // requests onto a single upstream call when a coordinate first warms up.
                var response = await upstream.GetOrFetchMetadataAsync($"{upstreamBase}/simple/{purlName}/", ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                upstreamHtml = PyPiSimpleIndexHelper.RewriteUpstreamSimpleIndexHtml(response.BodyAsString());
                break;
            }
            catch
            {
                // Upstream unreachable — try the next one, then fall back to local-only.
            }
        }

        // Load vuln gate signals for all local versions in one batch query. Used by both the
        // fallback renderer and the merge helper so neither fans out N per-version I/O calls.
        var signals = await LoadVulnSignalsAsync(localVersions, ct);
        var now = time.GetUtcNow();

        if (upstreamHtml is null)
        {
            if (localVersions.Count == 0)
            {
                return new NotFoundResult();
            }

            string fallbackHtml = PyPiSimpleIndexHelper.RenderLocalSimpleIndex(purlName, localVersions, settings, signals, now);
            byte[] fallbackBytes = Encoding.UTF8.GetBytes(fallbackHtml);
            return ServeNotModifiedOrSetCacheHeaders(httpContext, fallbackBytes, "private, max-age=300")
                ?? (IActionResult)new ContentResult { Content = fallbackHtml, ContentType = "text/html; charset=utf-8", StatusCode = StatusCodes.Status200OK };
        }

        // Splice local-only filenames into the upstream index so mixed-origin namespaces
        // expose private versions alongside upstream. Filenames already present in the
        // upstream HTML are skipped to avoid duplicates.
        string merged = PyPiSimpleIndexHelper.MergeLocalVersionsIntoUpstreamIndex(upstreamHtml, localVersions, settings, signals, now);
        byte[] mergedBytes = Encoding.UTF8.GetBytes(merged);
        return ServeNotModifiedOrSetCacheHeaders(httpContext, mergedBytes, "private, max-age=60")
            ?? (IActionResult)new ContentResult { Content = merged, ContentType = "text/html; charset=utf-8", StatusCode = StatusCodes.Status200OK };
    }

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
        var uploadedVersions = await packages.GetVersionsAsync(packageId, ct);
        var proxyEntries = await cacheArtifacts.ListServeFactsForNameAsync(orgId, ecosystem, purlName, ct);

        if (proxyEntries.Count == 0)
        {
            return uploadedVersions;
        }

        // Deduplicate: skip proxy entries whose version already appears in uploaded versions
        // so a name that was cached before upload does not double-list that version.
        var uploadedVersionSet = uploadedVersions
            .Select(v => v.Version)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Load proxy signals once to populate IsMalicious on the synthetic PackageVersion.
        var proxyIds = proxyEntries.Select(e => e.Id).ToList();
        var proxySignals = proxyIds.Count > 0
            ? await vulns.GetGateSignalsBatchForCacheArtifactsAsync(proxyIds, ct)
            : new Dictionary<string, VulnGateSignals>();

        var synthetic = proxyEntries
            .Where(e => !uploadedVersionSet.Contains(e.Version))
            .Select(e => e.ToPackageVersionSynthetic(proxySignals))
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
}
