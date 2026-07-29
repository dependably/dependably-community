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
    ArtifactInventoryRepository inventory,
    TokenRepository tokens,
    IPublicUrlBuilder urls)
{
    // Maximum take (page size) for search and autocomplete queries.
    private const int MaxSearchTake = 100;

    public async Task<IActionResult> SearchAsync(
        HttpContext httpContext, string orgId,
        string? q, int skip, int take, bool prerelease, CancellationToken ct)
    {
        // Clamp paging: bound the page's result payload, and guard a negative skip. 100 covers
        // any legitimate UI page.
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

        // totalHits is the total number of matches disregarding skip/take (NuGet V3 Search
        // Query Service contract) — clients rely on it to decide whether more pages exist. A
        // "match" excludes name-matching packages with no version meeting the prerelease
        // eligibility rule (same rule the page loop below applies, and the same rule
        // AutocompleteAsync's MatchesFilter already applies) — mirrors the spec and nuget.org:
        // with prerelease=false a package whose only versions are prerelease does not count as
        // a match at all. This is computed set-based, in one batched query over every filtered
        // package's version facts, rather than by loading each package's full combined version
        // list — an empty query matches an org's entire NuGet catalogue, and fanning the
        // expensive per-package version lookup out across all of it (instead of just the page
        // below) turns one request into an org-size-scaling DB round-trip storm.
        var versionFacts = await inventory.ListVersionFactsForPackagesAsync(
            orgId, "nuget", filtered.Select(p => p.Id).ToList(), ct);
        int totalHits = filtered.Count(p => versionFacts[p.Id].Any(v =>
            !v.IsYanked && (prerelease || !IsPrerelease(v.Version))));

        // The expensive per-package version fan-out (LoadCombinedVersionsAsync, 2-3 round trips
        // each) stays bounded to the page actually returned.
        var results = new List<object>();
        foreach (var pkg in filtered.Skip(skip).Take(take))
        {
            var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, pkg.Name.ToLowerInvariant(), ct);
            // Eligibility (yanked + prerelease) is decided once, up front: it drives both which
            // versions are considered for "latest" and which versions the response's own
            // 'versions' array lists. A package with no eligible version does not appear in the
            // page at all — matching AutocompleteAsync's hasMatchingVersion rule and nuget.org,
            // which omits a prerelease-only package entirely when the caller has not opted into
            // prereleases, rather than falling back to its prerelease as "latest".
            var eligible = versions.Where(v => !v.Yanked && (prerelease || !IsPrerelease(v.Version))).ToList();
            if (eligible.Count == 0)
            {
                continue;
            }

            // The Search Query Service resolves "latest" by SemVer 2.0.0 precedence among the
            // eligible set computed above.
            var latestVersion = VersionPrecedenceResolver.ResolveLatest(eligible)!;

            results.Add(new
            {
                id = pkg.Name,
                version = latestVersion.Version,
                versions = eligible.Select(v => new { version = v.Version }),
                registration = $"{baseUrl}/registration/{pkg.Name.ToLowerInvariant()}/"
            });
        }

        return new JsonResult(new { totalHits, data = results });
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
        // totalHits is the total id-prefix match count disregarding skip/take (same contract
        // as Search above). This is computed set-based, in one batched query over every
        // filtered package's version facts, rather than by loading each package's full
        // combined version list — an empty query matches an org's entire NuGet catalogue, and
        // fanning the expensive per-package version lookup out across all of it (instead of
        // just the page below) turns one request into an org-size-scaling DB round-trip storm.
        var versionFacts = await inventory.ListVersionFactsForPackagesAsync(
            orgId, "nuget", filtered.Select(p => p.Id).ToList(), ct);
        bool MatchesFilter(Package pkg) => versionFacts[pkg.Id].Any(v =>
            !v.IsYanked && (query.Prerelease || !IsPrerelease(v.Version)));
        int totalHits = filtered.Count(MatchesFilter);

        // The expensive per-package version fan-out (LoadCombinedVersionsAsync, 2-3 round trips
        // each) stays bounded to the page actually returned.
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

        return new JsonResult(new { totalHits, data = ids });
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
    // .nuspec, .sha512) — DedupeProxyVersionsByVersion collapses those to the .nupkg row so
    // search and autocomplete list each version once. Proxy entries whose version already
    // appears in uploaded versions are skipped upstream in ListServeableVersionsAsync.
    private async Task<IReadOnlyList<PackageVersion>> LoadCombinedVersionsAsync(
        string orgId, string packageId, string normalizedId, CancellationToken ct)
    {
        var versions = await inventory.ListServeableVersionsAsync(orgId, packageId, "nuget", normalizedId, ct);
        return ArtifactInventoryRepository.DedupeProxyVersionsByVersion(versions);
    }
}

/// <summary>
/// Autocomplete query parameters bundled so <see cref="NuGetSearchHandler.AutocompleteAsync"/>
/// stays within the S107 parameter limit.
/// </summary>
public sealed record NuGetAutocompleteParams(
    string? Q, string? Id, int Skip, int Take, bool Prerelease);
