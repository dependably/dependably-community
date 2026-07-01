using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Handles npm packument (CouchDB metadata) GET endpoints: unscoped and scoped package
/// metadata, per-version metadata, and the supporting proxy-merge and block-gate-filter
/// paths. Also exposes <see cref="ServePackumentJson"/> so the tarball handler can
/// reuse the ETag/Cache-Control response shape.
/// </summary>
public sealed class NpmPackumentHandler(
    OrgRepository orgs,
    PackageRepository packages,
    CacheArtifactRepository cacheArtifacts,
    TokenRepository tokens,
    VulnerabilityRepository vulns,
    IPublicUrlBuilder urls,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    UpstreamClient upstream,
    UpstreamRegistryResolver registries,
    NpmDistTagRepository distTags,
    RenderedResponseCache<NpmPackumentKey> cache,
    TimeProvider time)
{
    // TTL for proxy-merged packuments (upstream can change); local-only packuments use
    // a longer TTL because invalidation on mutation is the primary expiry mechanism.
    private static readonly TimeSpan PackumentProxyTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PackumentLocalTtl = TimeSpan.FromMinutes(10);

    public async Task<IActionResult> GetPackageAsync(
        HttpContext httpContext, string orgId, string package, CancellationToken ct)
        => await GetPackageMetadataAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(package), scope: null, ct);

    public async Task<IActionResult> GetScopedPackageAsync(
        HttpContext httpContext, string orgId, string scope, string package, CancellationToken ct)
        => await GetPackageMetadataAsync(httpContext, orgId, package, scope: "@" + scope, ct);

    public async Task<IActionResult> GetVersionAsync(
        HttpContext httpContext, string orgId, string package, string version, CancellationToken ct)
    {
        var full = await GetPackageMetadataAsync(httpContext, orgId, package, null, ct);
        // Extract just the version object from the full metadata response.
        // GetPackageMetadataAsync returns either a JsonResult (live build) or a FileContentResult
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
            return versionData is null ? new NotFoundResult() : new JsonResult(versionData);
        }
        return full;
    }

    private async Task<IActionResult> GetPackageMetadataAsync(
        HttpContext httpContext, string orgId, string package, string? scope, CancellationToken ct)
    {
        string fullName = scope is not null ? $"{scope}/{package}" : package;

        // The name flows into upstream proxy URLs — reject traversal-shaped values before
        // any lookup, mirroring the upload-side validation.
        if (!NpmSharedHelpers.IsUpstreamSafeNpmName(fullName))
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Read paths use the org-scoped overload: a token bound to a different tenant is
        // coerced to null so the existing token-null branches respect AnonymousPull
        // consistently for both anonymous and cross-org callers.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);

        // Route by passthrough + claims, not packages.is_proxy. A name with uploaded versions
        // is still a namespace that can hold proxy-fetched versions.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && !await reserved.IsReservedAsync(orgId, "npm", fullName, ct)
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", fullName, ct);

        return passthroughAllowed
            ? await ServePassthroughPackumentAsync(httpContext, orgId, fullName, pkg, settings, token, ct)
            : await ServeLocalPackumentAsync(httpContext, orgId, fullName, pkg, token, settings!, ct);
    }

    // Passthrough packument path: anonymous-pull gate, then cached bytes, then a
    // single-flight proxy-merged rebuild.
    private async Task<IActionResult> ServePassthroughPackumentAsync(
        HttpContext httpContext, string orgId, string fullName,
        Package? pkg, OrgSettings settings, TokenRecord? token, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var cacheKey = new NpmPackumentKey(orgId, fullName);
        if (cache.TryGet(cacheKey, out byte[]? cachedBytes) && cachedBytes is not null)
        {
            return ServePackumentBytes(httpContext, cachedBytes, "private, max-age=60");
        }

        byte[]? bytes = await RebuildProxyPackumentAsync(httpContext, cacheKey, orgId, fullName, pkg, settings, ct);
        if (bytes is not null)
        {
            return ServePackumentBytes(httpContext, bytes, "private, max-age=60");
        }

        // Rebuild without cache on non-JSON result (e.g. NotFound from proxy path).
        var passthroughTagsFallback = pkg is not null
            ? await distTags.GetTagsAsync(orgId, pkg.Id, ct)
            : null;
        return await ProxyNpmMetadataAsync(httpContext, orgId, fullName, pkg,
            passthroughTagsFallback?.Count > 0 ? passthroughTagsFallback : null, settings, ct);
    }

    // Rebuilds the proxy-merged packument and caches the serialized bytes. Single-flight:
    // concurrent rebuilds for the same key collapse onto one shared task. Returns null when
    // the proxy path produced a non-JSON result (e.g. NotFound). ProxyNpmMetadataAsync calls
    // ServePackumentJson which returns FileContentResult with already-serialized bytes —
    // extract them directly to avoid a second serialize call.
    private Task<byte[]?> RebuildProxyPackumentAsync(
        HttpContext httpContext, NpmPackumentKey cacheKey, string orgId, string fullName,
        Package? pkg, OrgSettings settings, CancellationToken ct) =>
        cache.GetOrRebuildAsync(cacheKey, PackumentProxyTtl, async rebuildCt =>
        {
            var passthroughTags = pkg is not null
                ? await distTags.GetTagsAsync(orgId, pkg.Id, rebuildCt)
                : null;
            var result = await ProxyNpmMetadataAsync(httpContext, orgId, fullName, pkg,
                passthroughTags?.Count > 0 ? passthroughTags : null, settings, rebuildCt);
            return result is FileContentResult fcr ? fcr.FileContents : null;
        }, ct);

    // Local-only packument path (passthrough disabled or claim-local): when AnonymousPull is
    // disabled, a token is required; otherwise anonymous reads are permitted.
    private async Task<IActionResult> ServeLocalPackumentAsync(
        HttpContext httpContext, string orgId, string fullName, Package? pkg, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (pkg is null)
        {
            return new NotFoundResult();
        }

        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var cacheKey = new NpmPackumentKey(orgId, fullName);
        if (cache.TryGet(cacheKey, out byte[]? localCached) && localCached is not null)
        {
            return ServePackumentBytes(httpContext, localCached, "private, max-age=300");
        }

        var versions = await LoadCombinedVersionsAsync(orgId, pkg.Id, fullName, ct);
        var signals = await LoadVulnSignalsAsync(versions, ct);
        var tags = await distTags.GetTagsAsync(orgId, pkg.Id, ct);
        var metadata = BuildNpmMetadata(httpContext, pkg, versions,
            tags.Count > 0 ? tags : null, settings, signals, time.GetUtcNow());
        byte[] localBytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(metadata);
        cache.Set(cacheKey, localBytes, PackumentLocalTtl);
        return ServePackumentBytes(httpContext, localBytes, "private, max-age=300");
    }

    // ETag-aware response over packument bytes: 304 on an If-None-Match hit, otherwise the
    // bytes with the given Cache-Control.
    private static IActionResult ServePackumentBytes(HttpContext httpContext, byte[] bytes, string cacheControl)
    {
        string etag = NpmSharedHelpers.ComputeETag(bytes);
        httpContext.Response.Headers.ETag = etag;
        if (httpContext.Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            return new StatusCodeResult(StatusCodes.Status304NotModified);
        }

        httpContext.Response.Headers.CacheControl = cacheControl;
        return new FileContentResult(bytes, "application/json");
    }

    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<IActionResult> ProxyNpmMetadataAsync(
        HttpContext httpContext, string orgId, string fullName, Package? localPkg,
        Dictionary<string, string>? persistedTags, OrgSettings settings, CancellationToken ct)
    {
        var localVersions = localPkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await LoadCombinedVersionsAsync(orgId, localPkg.Id, fullName, ct);

        // Load vuln signals once for the local version list (uploaded + proxy cached) — used
        // in both the fallback (BuildNpmMetadata) and the merge (MergeLocalVersionsIntoPackument)
        // paths so block-gate filtering is consistent across both without extra I/O.
        var localSignals = await LoadVulnSignalsAsync(localVersions, ct);

        var metadata = await FetchUpstreamPackumentAsync(httpContext, orgId, fullName, ct);

        var now = time.GetUtcNow();

        if (metadata is null)
        {
            if (localPkg is null || localVersions.Count == 0)
            {
                return new NotFoundResult();
            }

            var fallbackMeta = BuildNpmMetadata(httpContext, localPkg, localVersions,
                persistedTags, settings, localSignals, now);
            return ServePackumentJson(httpContext, fallbackMeta, "private, max-age=300");
        }

        // Filter the upstream packument to exclude versions the download path will hard-block.
        // This mirrors the block-gate parity pattern: the packument never advertises a version
        // that the tarball endpoint returns 403 for. Only upstream-evaluable arms are filtered
        // here (release-age from the packument time map, deprecated block_all from versions[V]);
        // vuln/KEV/EPSS/CVSS arms require a fetched-and-scanned local row and are covered on
        // the serve path for cached versions.
        FilterPackumentToServableVersions(metadata, settings, now);

        // Splice uploaded local versions into the upstream packument so npm install can
        // discover both private and public versions of the same name. Block-gate filtering
        // applies to local versions so the merge never injects a version the download path
        // will 403.
        if (localPkg is not null && localVersions.Count > 0)
        {
            MergeLocalVersionsIntoPackument(httpContext, metadata, localPkg, localVersions,
                settings, localSignals, now);
        }

        return ServePackumentJson(httpContext, metadata, "private, max-age=60");
    }

    // Walks the org's configured upstreams in priority order; the first that answers wins.
    // No configured upstream ⇒ proxying is disabled for this ecosystem — returns null so
    // the caller serves local-only metadata.
    private async Task<JsonNode?> FetchUpstreamPackumentAsync(
        HttpContext httpContext, string orgId, string fullName, CancellationToken ct)
    {
        var bases = await registries.ResolveAsync(orgId, "npm", ct);
        foreach (var source in bases)
        {
            try
            {
                // Single-flight packument fetch — collapses N concurrent npm-install
                // requests onto one upstream call when a coordinate first warms up.
                var response = await upstream.GetOrFetchMetadataAsync($"{source.Url}/{fullName}", source.AuthorizationHeader, ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var metadata = JsonNode.Parse(response.BodyAsString());
                if (metadata is not null)
                {
                    RewriteTarballUrls(metadata, fullName, NpmTarballBase(httpContext));
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

    // Filters a packument's versions and dist-tags in-place to remove entries that the
    // download path will hard-block. This mirrors the block-gate parity pattern so a client
    // never discovers a version in the packument that the tarball endpoint returns 403 for.
    //
    // Routes every per-version decision through BlockGateService.Evaluate so the policy has
    // one home. Upstream-only (not-yet-cached) versions are projected with no scan data
    // (Scanned=false, HasMalicious=false, HasKev=false, MaxEpss=null, MaxCvss=null), meaning
    // only the Manual, Deprecated, and ReleaseAge arms can fire — exactly the evaluable subset
    // for versions that have no local row.
    //
    // After dropping versions, dist-tags pointing at removed versions are repointed: the
    // latest tag is updated to the newest surviving version by publish timestamp so npm
    // install always resolves to an installable coordinate. Other tags pointing at removed
    // versions are dropped. Corresponding time[] entries for removed versions are also
    // removed for cleanliness.
    private static void FilterPackumentToServableVersions(JsonNode packument, OrgSettings settings, DateTimeOffset now)
    {
        var versionsObj = packument["versions"]?.AsObject();
        if (versionsObj is null)
        {
            return;
        }

        var timeObj = packument["time"]?.AsObject();
        var publishedAtByVersion = ParsePublishTimestamps(timeObj);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts);

        var (removed, survivingWithTime) = EvaluateVersionsAgainstPolicy(versionsObj, policy, publishedAtByVersion, now);

        if (removed.Count == 0)
        {
            return; // Nothing was dropped — no repair needed.
        }

        RepairPackumentAfterFilter(packument, timeObj, removed, survivingWithTime);
    }

    // Parses the packument time[] map into a version → timestamp lookup. Keys that are
    // not parseable as DateTimeOffset (e.g. the "created"/"modified" meta-keys) are omitted;
    // only version-string entries are included.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private static Dictionary<string, DateTimeOffset> ParsePublishTimestamps(JsonObject? timeObj)
    {
        var result = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        if (timeObj is null)
        {
            return result;
        }

        foreach (var (key, node) in timeObj)
        {
            string? raw = node?.GetValue<string>();
            if (raw is not null && DateTimeOffset.TryParse(raw, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
            {
                result[key] = ts;
            }
        }

        return result;
    }

    // Evaluates each version in the packument against the block policy. Removes blocked
    // versions from versionsObj in-place and returns the removed set plus the surviving
    // versions with their publish timestamps (for dist-tag repair). Iterates over a
    // snapshot of the keys to avoid mutation-during-iteration.
    private static (HashSet<string> Removed, List<(string Version, DateTimeOffset PublishedAt)> Surviving)
        EvaluateVersionsAgainstPolicy(
            JsonObject versionsObj,
            BlockPolicy policy,
            Dictionary<string, DateTimeOffset> publishedAtByVersion,
            DateTimeOffset now)
    {
        var versionKeys = versionsObj.Select(kv => kv.Key).ToList();
        var removed = new HashSet<string>(StringComparer.Ordinal);
        var survivingWithTime = new List<(string Version, DateTimeOffset PublishedAt)>();

        foreach (string ver in versionKeys)
        {
            // Project the upstream-only version entry into VersionFacts. Upstream versions
            // have no local row: no scan data, no manual state. The deprecated field comes
            // from the packument version object via LicenseExtractor so boolean/empty/whitespace
            // values are treated identically to the first-fetch download path.
            publishedAtByVersion.TryGetValue(ver, out var publishedAt);
            string? deprecated = LicenseExtractor.FromNpmPackumentVersion(versionsObj[ver]).Deprecated;
            var facts = new VersionFacts(
                ManualState: null,
                Deprecated: deprecated,
                PublishedAt: publishedAtByVersion.ContainsKey(ver) ? publishedAt : null,
                Scanned: false,
                HasMalicious: false,
                HasKev: false,
                MaxEpss: null,
                MaxCvss: null);

            if (!BlockGateService.Evaluate(facts, policy, now).Servable)
            {
                versionsObj.Remove(ver);
                removed.Add(ver);
            }
            else
            {
                // Track surviving versions with their publish timestamp for dist-tag repair.
                survivingWithTime.Add(publishedAtByVersion.TryGetValue(ver, out var survivingTs)
                    ? (ver, survivingTs)
                    : (ver, DateTimeOffset.MinValue));
            }
        }

        return (removed, survivingWithTime);
    }

    // Removes time[] entries for dropped versions and repairs dist-tags so that no tag
    // points at a removed version. When latest pointed at a removed version it is repointed
    // to the newest surviving version by publish timestamp.
    private static void RepairPackumentAfterFilter(
        JsonNode packument,
        JsonObject? timeObj,
        HashSet<string> removed,
        List<(string Version, DateTimeOffset PublishedAt)> survivingWithTime)
    {
        // Remove time[] entries for dropped versions; preserve non-version meta-keys.
        if (timeObj is not null)
        {
            foreach (string ver in removed)
            {
                timeObj.Remove(ver);
            }
        }

        // Repair dist-tags: drop tags targeting removed versions; if latest pointed at a
        // removed version, repoint it to the newest surviving version by publish timestamp.
        var distTagsObj = packument["dist-tags"]?.AsObject();
        if (distTagsObj is null)
        {
            return;
        }

        var tagKeys = distTagsObj.Select(kv => kv.Key).ToList();
        foreach (string tag in tagKeys)
        {
            string? target = distTagsObj[tag]?.GetValue<string>();
            if (target is null || !removed.Contains(target))
            {
                continue;
            }

            distTagsObj.Remove(tag);
            if (tag == "latest" && survivingWithTime.Count > 0)
            {
                // Repoint latest to the newest surviving version by publish timestamp.
                string bestVer = survivingWithTime
                    .OrderByDescending(x => x.PublishedAt)
                    .First().Version;
                distTagsObj["latest"] = bestVer;
            }
        }
    }

    /// <summary>
    /// ETag-aware response for a freshly-built packument node: 304 on an If-None-Match hit,
    /// otherwise the JSON bytes with the given Cache-Control. Returns FileContentResult
    /// carrying the already-serialized bytes so the rebuild path can extract them without
    /// a second serialize call.
    /// </summary>
    internal static IActionResult ServePackumentJson(HttpContext httpContext, JsonNode metadata, string cacheControl)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(metadata.ToJsonString());
        string etag = NpmSharedHelpers.ComputeETag(bytes);
        httpContext.Response.Headers.ETag = etag;
        if (httpContext.Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            return new StatusCodeResult(StatusCodes.Status304NotModified);
        }

        httpContext.Response.Headers.CacheControl = cacheControl;
        return new FileContentResult(bytes, "application/json");
    }

    private void MergeLocalVersionsIntoPackument(
        HttpContext httpContext, JsonNode packument, Package localPkg,
        IReadOnlyList<PackageVersion> localVersions,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        var versionsObj = packument["versions"]?.AsObject();
        if (versionsObj is null)
        {
            versionsObj = new JsonObject();
            packument["versions"] = versionsObj;
        }

        string tarballBase = NpmTarballBase(httpContext);
        foreach (var v in localVersions)
        {
            if (versionsObj.ContainsKey(v.Version))
            {
                continue;
            }

            // Skip versions the download path will block — the packument must not advertise
            // an artifact the tarball endpoint will 403. Mirrors the local packument path.
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
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

    // Loads vuln gate signals for a combined (uploaded + proxy synthetic) version list.
    // Uploaded versions key on package_version_id; synthetic proxy versions key on
    // cache_artifact_id (stored in PackageVersion.Id via ToPackageVersionSynthetic).
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
    // objects projected from global-plane proxy cache entries for the given package. Proxy
    // entries whose version already appears in uploaded versions are deduplicated so a name
    // cached before upload does not double-list that version.
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

    /// <summary>
    /// Tarball download URL base. Tenant-implicit: every request is already on the tenant's host,
    /// so URLs are host-relative under <c>/npm/tarballs</c>.
    /// </summary>
    private string NpmTarballBase(HttpContext httpContext) => urls.Absolute(httpContext, "/npm/tarballs");

    internal JsonObject BuildNpmMetadata(
        HttpContext httpContext, Package pkg, IReadOnlyList<PackageVersion> versions,
        Dictionary<string, string>? persistedTags,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        string tarballBase = NpmTarballBase(httpContext);
        var versionsObj = new JsonObject();

        // Non-yanked versions, excluding those the block gate will hard-block on the download
        // path. Block-gate filtering here keeps the packument in sync with the tarball endpoint
        // so a client never installs a version it cannot download.
        var activeVersions = versions
            .Where(v => !v.Yanked
                && !BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            .OrderByDescending(x => x.CreatedAt)
            .ToList();

        foreach (var v in activeVersions)
        {
            string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
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
            string? lazyLatest = NpmSharedHelpers.ComputeLazyLatest(activeVersions);
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
}
