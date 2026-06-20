using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NuGet.Versioning;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Handles NuGet v3 search (/nuget/query) and autocomplete (/nuget/autocomplete) endpoints.
/// Search and autocomplete merge uploaded package_versions with global-plane proxy entries
/// (cache_artifact + tenant_artifact_access) so proxy-cached packages are discoverable.
/// </summary>
public sealed class NuGetSearchHandler(
    OrgRepository orgs,
    PackageRepository packages,
    CacheArtifactRepository cacheArtifacts,
    VulnerabilityRepository vulns,
    TokenRepository tokens,
    IPublicUrlBuilder urls)
{
    // Maximum take (page size) for search and autocomplete queries.
    private const int MaxSearchTake = 100;

    public async Task<IActionResult> SearchAsync(
        HttpContext httpContext, string orgId,
        string? q, int skip, int take, CancellationToken ct)
    {
        // Clamp paging: bound the per-result N+1 version lookups, and guard a negative skip
        // (which would throw in Enumerable.Skip → 500). 100 covers any legitimate UI page.
        skip = Math.Max(0, skip);
        take = Math.Clamp(take, 0, MaxSearchTake);

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string baseUrl = urls.Absolute(httpContext, "/nuget");
        var allPkgs = await packages.ListAsync(orgId, "nuget", ct);
        var filtered = string.IsNullOrWhiteSpace(q)
            ? allPkgs
            : allPkgs.Where(p => p.Name.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();

        var results = new List<object>();

        foreach (var pkg in filtered.Skip(skip).Take(take))
        {
            var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, pkg.Name.ToLowerInvariant(), ct);
            var latestVersion = versions.Where(v => !v.Yanked).MaxBy(v => v.CreatedAt);
            if (latestVersion is null)
            {
                continue;
            }

            results.Add(new
            {
                id = pkg.Name,
                version = latestVersion.Version,
                versions = versions.Where(v => !v.Yanked).Select(v => new { version = v.Version }),
                registration = $"{baseUrl}/registration/{pkg.Name.ToLowerInvariant()}/"
            });
        }

        return new JsonResult(new { totalHits = results.Count, data = results });
    }

    public async Task<IActionResult> AutocompleteAsync(
        HttpContext httpContext, string orgId, NuGetAutocompleteParams query, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        // Version enumeration form: ?id={id}
        if (!string.IsNullOrWhiteSpace(query.Id))
        {
            return await AutocompleteVersionsAsync(orgId, query.Id.Trim(), query.Prerelease, ct);
        }

        // Id-prefix search form: ?q=...&skip=...&take=...
        // Clamp paging: guard a negative skip and bound the result set.
        // 100 covers any legitimate UI page.
        int skip = Math.Max(0, query.Skip);
        int take = Math.Clamp(query.Take, 0, MaxSearchTake);

        var allPkgs = await packages.ListAsync(orgId, "nuget", ct);
        var filtered = string.IsNullOrWhiteSpace(query.Q)
            ? allPkgs
            : allPkgs.Where(p => p.Name.Contains(query.Q.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();

        // Return only packages that have at least one non-yanked version. prerelease=false
        // excludes packages whose only versions are pre-release, mirroring the spec's intent.
        var ids = new List<string>();
        foreach (var pkg in filtered.Skip(skip).Take(take))
        {
            var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, pkg.Name.ToLowerInvariant(), ct);
            bool hasMatchingVersion = versions.Any(v =>
                !v.Yanked && (query.Prerelease || !IsPrerelease(v.Version)));
            if (hasMatchingVersion)
            {
                ids.Add(pkg.Name);
            }
        }

        return new JsonResult(new { totalHits = ids.Count, data = ids });
    }

    private async Task<IActionResult> AutocompleteVersionsAsync(
        string orgId, string packageId, bool prerelease, CancellationToken ct)
    {
        string normalizedId = packageId.ToLowerInvariant();
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);
        if (pkg is null)
        {
            return new JsonResult(new { data = Array.Empty<string>() });
        }

        var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, normalizedId, ct);
        var matching = versions
            .Where(v => !v.Yanked && (prerelease || !IsPrerelease(v.Version)))
            .Select(v => v.Version)
            .ToList();

        return new JsonResult(new { data = matching });
    }

    private static bool IsPrerelease(string version) =>
        NuGetVersion.TryParse(version, out var nv) && nv.IsPrerelease;

    // Combines uploaded (package_versions) and global-plane proxy (cache_artifact) versions
    // for a NuGet package. NuGet may have multiple cache_artifact rows per version (.nupkg,
    // .nuspec, .sha512); deduplication groups by version so each version string appears once.
    // Proxy entries whose version already appears in uploaded versions are skipped.
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

        // Each NuGet version may have multiple cache_artifact rows; take one representative
        // entry per version string (first in first_cached_at DESC order from the query).
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
}

/// <summary>
/// Autocomplete query parameters bundled so <see cref="NuGetSearchHandler.AutocompleteAsync"/>
/// stays within the S107 parameter limit.
/// </summary>
public sealed record NuGetAutocompleteParams(
    string? Q, string? Id, int Skip, int Take, bool Prerelease);
