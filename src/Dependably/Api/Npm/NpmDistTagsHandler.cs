using System.Text;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Handles npm dist-tag management (GET/PUT/DELETE), package search, and the
/// lightweight probe endpoints (ping, whoami).
/// </summary>
public sealed class NpmDistTagsHandler(
    OrgRepository orgs,
    PackageRepository packages,
    CacheArtifactRepository cacheArtifacts,
    VulnerabilityRepository vulns,
    TokenRepository tokens,
    AuditRepository audit,
    NpmDistTagRepository distTags,
    RenderedResponseCache<NpmPackumentKey> cache,
    TimeProvider time)
{
    // Maximum packages returned per search page (per npm search specification).
    private const int MaxSearchPageSize = 50;

    public IActionResult Ping() => new JsonResult(new JsonObject());

    public async Task<IActionResult> WhoAmIAsync(
        HttpContext httpContext, string orgId, CancellationToken ct)
    {
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string? username = await tokens.GetWhoAmIIdentifierAsync(token, ct);
        if (username is null)
        {
            // Token row resolved but the user/service row vanished between auth and lookup
            // (e.g. owner removed mid-request). Treat as unauthenticated rather than 500.
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        return new JsonResult(new JsonObject { ["username"] = username });
    }

    public Task<IActionResult> GetDistTagsAsync(
        HttpContext httpContext, string orgId, string pkg, CancellationToken ct)
        => GetDistTagsImplAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(pkg), ct);

    public Task<IActionResult> GetScopedDistTagsAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, CancellationToken ct)
        => GetDistTagsImplAsync(httpContext, orgId, "@" + scope + "/" + pkg, ct);

    private async Task<IActionResult> GetDistTagsImplAsync(
        HttpContext httpContext, string orgId, string fullName, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        var tags = await distTags.GetTagsAsync(orgId, pkg.Id, ct);
        if (tags.Count == 0)
        {
            // Lazy seed: compute the default latest across both uploaded and global-plane proxy
            // versions so the dist-tag reflects the true newest version in this tenant.
            var allVersions = await LoadCombinedVersionsAsync(orgId, pkg.Id, fullName, ct);
            string? latest = NpmSharedHelpers.ComputeLazyLatest(
                allVersions.Where(v => !v.Yanked).OrderByDescending(v => v.CreatedAt).ToList());
            tags = latest is not null ? new Dictionary<string, string> { ["latest"] = latest } : tags;
        }

        var result = new JsonObject();
        foreach (var (tag, ver) in tags)
        {
            result[tag] = ver;
        }
        return new JsonResult(result);
    }

    public Task<IActionResult> PutDistTagAsync(
        HttpContext httpContext, string orgId, string pkg, string tag, CancellationToken ct)
        => PutDistTagImplAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(pkg), tag, ct);

    public Task<IActionResult> PutScopedDistTagAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string tag, CancellationToken ct)
        => PutDistTagImplAsync(httpContext, orgId, "@" + scope + "/" + pkg, tag, ct);

    private async Task<IActionResult> PutDistTagImplAsync(
        HttpContext httpContext, string orgId, string fullName, string tag, CancellationToken ct)
    {
        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        // Body is a JSON string: the target version number.
        string? version;
        try
        {
            using var reader = new StreamReader(httpContext.Request.Body, Encoding.UTF8);
            string raw = await reader.ReadToEndAsync(ct);
            version = System.Text.Json.JsonSerializer.Deserialize<string>(raw);
        }
        catch
        {
            return new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "Body must be a JSON string (the target version).", Status = StatusCodes.Status422UnprocessableEntity });
        }

        if (string.IsNullOrWhiteSpace(version))
        {
            return new UnprocessableEntityObjectResult(new ProblemDetails { Detail = "Version must not be empty.", Status = StatusCodes.Status422UnprocessableEntity });
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        // Validate that the requested version actually exists in this org.
        var ver = await packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null)
        {
            return new NotFoundObjectResult(new ProblemDetails { Detail = $"Version '{version}' does not exist for package '{fullName}'.", Status = StatusCodes.Status404NotFound });
        }

        await distTags.SetTagAsync(orgId, pkg.Id, tag, version, ct);
        await audit.LogActivityAsync(orgId, "npm", pkg.Name, "dist-tag.set", token.UserId,
            actorKind: token.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the updated dist-tag is visible immediately.
        cache.Evict(new NpmPackumentKey(orgId, fullName));

        var result = new JsonObject { [tag] = version };
        return new JsonResult(result);
    }

    public Task<IActionResult> DeleteDistTagAsync(
        HttpContext httpContext, string orgId, string pkg, string tag, CancellationToken ct)
        => DeleteDistTagImplAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(pkg), tag, ct);

    public Task<IActionResult> DeleteScopedDistTagAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string tag, CancellationToken ct)
        => DeleteDistTagImplAsync(httpContext, orgId, "@" + scope + "/" + pkg, tag, ct);

    private async Task<IActionResult> DeleteDistTagImplAsync(
        HttpContext httpContext, string orgId, string fullName, string tag, CancellationToken ct)
    {
        // npm refuses to delete the 'latest' tag — it must always point somewhere.
        if (tag == "latest")
        {
            return new BadRequestObjectResult(new ProblemDetails { Detail = "The 'latest' tag cannot be deleted.", Status = StatusCodes.Status400BadRequest });
        }

        var token = await httpContext.Request.ResolveTokenAsync(tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        bool deleted = await distTags.DeleteTagAsync(orgId, pkg.Id, tag, ct);
        if (!deleted)
        {
            return new NotFoundObjectResult(new ProblemDetails { Detail = $"Tag '{tag}' not found.", Status = StatusCodes.Status404NotFound });
        }

        await audit.LogActivityAsync(orgId, "npm", pkg.Name, "dist-tag.delete", token.UserId,
            actorKind: token.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);

        // Evict the cached packument so the removed dist-tag is visible immediately.
        cache.Evict(new NpmPackumentKey(orgId, fullName));

        return new NoContentResult();
    }

    public async Task<IActionResult> SearchAsync(
        HttpContext httpContext, string orgId,
        string? text, int size, int from, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        // Clamp size to 1..50 per npm search spec.
        size = Math.Clamp(size, 1, MaxSearchPageSize);

        var query = new PackageListQuery(
            OrgId: orgId,
            Limit: size,
            Offset: Math.Max(0, from),
            Ecosystem: "npm",
            Search: text,
            SortBy: "name",
            SortDir: "asc");

        var (pkgs, total) = await packages.ListPaginatedAsync(query, ct);

        // Build the minimal npm search shape: objects[] with {package:{name,version,description}}.
        var objectsArr = new System.Text.Json.Nodes.JsonArray();
        foreach (var p in pkgs)
        {
            // Find the 'latest' version for each package by checking persisted tags first,
            // then falling back to the lazy latest calculation across both uploaded and
            // global-plane proxy versions.
            var tags = await distTags.GetTagsAsync(orgId, p.Id, ct);
            string? latestVersion = null;
            if (tags.TryGetValue("latest", out string? tagVer))
            {
                latestVersion = tagVer;
            }
            else
            {
                var vers = await LoadCombinedVersionsAsync(orgId, p.Id, p.Name, ct);
                latestVersion = NpmSharedHelpers.ComputeLazyLatest(
                    vers.Where(v => !v.Yanked).OrderByDescending(v => v.CreatedAt).ToList());
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
            ["time"] = time.GetUtcNow().ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'",
                System.Globalization.CultureInfo.InvariantCulture)
        });
    }

    // Combines uploaded (package_versions) and global-plane proxy (cache_artifact) versions
    // for a package. Proxy entries whose version already appears in uploaded versions are
    // deduplicated. Used by dist-tag lazy-latest computation and search result version lookup.
    private async Task<IReadOnlyList<PackageVersion>> LoadCombinedVersionsAsync(
        string orgId, string packageId, string fullName, CancellationToken ct)
    {
        var uploadedVersions = await packages.GetVersionsAsync(packageId, ct);
        var proxyEntries = await cacheArtifacts.ListServeFactsForNameAsync(orgId, "npm", fullName, ct);

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
