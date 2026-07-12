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
/// paths.
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
    RenderedMetadataCacheOptions cacheOptions,
    TimeProvider time,
    ILogger<NpmPackumentHandler> logger)
{
    // TTL for proxy-merged packuments (upstream can change); local-only packuments use
    // a longer TTL because invalidation on mutation is the primary expiry mechanism. Both are
    // operator-tunable via METADATA_PROXY/LOCAL_CACHE_TTL_SECONDS (see RenderedMetadataCacheOptions).
    private TimeSpan PackumentProxyTtl => cacheOptions.ProxyTtl;
    private TimeSpan PackumentLocalTtl => cacheOptions.LocalTtl;

    public async Task<IActionResult> GetPackageAsync(
        HttpContext httpContext, string orgId, string package, CancellationToken ct)
        => await GetPackageMetadataAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(package), scope: null, ct);

    public async Task<IActionResult> GetScopedPackageAsync(
        HttpContext httpContext, string orgId, string scope, string package, CancellationToken ct)
    {
        // npm encodes the scoped-name slash, so a scoped per-version request
        // (GET /npm/@scope%2Fname/1.0.0) matches the scoped-packument route with the whole
        // name in {scope} and the version in {package} — the "@"-prefixed segment outranks
        // the unscoped {package}/{version} template. Detect the embedded slash after
        // decoding and dispatch as a per-version request.
        string decodedScope = NpmSharedHelpers.DecodeNpmName(scope);
        return decodedScope.Contains('/')
            ? await GetVersionCoreAsync(httpContext, orgId, "@" + decodedScope, package, ct)
            : await GetPackageMetadataAsync(httpContext, orgId, package, scope: "@" + decodedScope, ct);
    }

    public async Task<IActionResult> GetVersionAsync(
        HttpContext httpContext, string orgId, string package, string version, CancellationToken ct)
        => await GetVersionCoreAsync(httpContext, orgId, NpmSharedHelpers.DecodeNpmName(package), version, ct);

    private async Task<IActionResult> GetVersionCoreAsync(
        HttpContext httpContext, string orgId, string fullName, string version, CancellationToken ct)
    {
        var full = await GetPackageMetadataAsync(httpContext, orgId, fullName, scope: null, ct);
        // Extract just the version object from the full metadata response. Serving paths
        // return the packument bytes as FileContentResult; anything else (404/401/304)
        // passes through unchanged.
        if (full is FileContentResult fcr && JsonNode.Parse(fcr.FileContents) is JsonObject obj)
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

        // Distinct cache variant from the local-only path (see MetadataCacheKeys.NpmPackument):
        // a claim flip must not serve the other path's stale body until TTL.
        var cacheKey = new NpmPackumentKey(orgId, fullName) { IsProxy = true };
        if (cache.TryGet(cacheKey, out byte[]? cachedBytes) && cachedBytes is not null)
        {
            return ServePackumentBytes(httpContext, cachedBytes, "private, max-age=60");
        }

        // Single-flight rebuild: concurrent rebuilds for the same key collapse onto one shared
        // task. The rebuild returns serialized bytes (never a response decision), so one
        // caller's If-None-Match can never prevent the bytes from being cached — the ETag/304
        // comparison happens in ServePackumentBytes against the rebuilt bytes.
        byte[]? bytes = await cache.GetOrRebuildAsync(cacheKey, PackumentProxyTtl, async rebuildCt =>
        {
            var passthroughTags = pkg is not null
                ? await distTags.GetTagsAsync(orgId, pkg.Id, rebuildCt)
                : null;
            return await BuildProxyPackumentBytesAsync(httpContext, orgId, fullName, pkg,
                passthroughTags?.Count > 0 ? passthroughTags : null, settings, rebuildCt);
        }, ct);

        return bytes is null
            ? new NotFoundResult()
            : ServePackumentBytes(httpContext, bytes, "private, max-age=60");
    }

    // Local-only packument path (passthrough disabled or claim-local): when AnonymousPull is
    // disabled, a token is required; otherwise anonymous reads are permitted.
    private async Task<IActionResult> ServeLocalPackumentAsync(
        HttpContext httpContext, string orgId, string fullName, Package? pkg, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // Auth gate before any existence signal — a 404-before-401 would let anonymous
        // callers enumerate which private hosted names exist. Mirrors the passthrough
        // packument path and every tarball path.
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        if (pkg is null)
        {
            return new NotFoundResult();
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
    // bytes with the given Cache-Control. Every packument serving path funnels through here,
    // so the conditional-request decision is always made against already-cached bytes.
    internal static IActionResult ServePackumentBytes(HttpContext httpContext, byte[] bytes, string cacheControl)
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

    // Builds the serialized proxy-merged packument: the upstream document filtered to
    // servable versions, local versions spliced in, and the tenant's persisted dist-tags
    // applied. Returns null when neither upstream nor local has anything to serve (the
    // caller maps null to 404). Returns bytes rather than a response so the single-flight
    // cache decision stays independent of any one caller's conditional-request headers.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<byte[]?> BuildProxyPackumentBytesAsync(
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
                return null;
            }

            var fallbackMeta = BuildNpmMetadata(httpContext, localPkg, localVersions,
                persistedTags, settings, localSignals, now);
            return System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(fallbackMeta);
        }

        // Filter the upstream packument to exclude versions the download path will hard-block.
        // This mirrors the block-gate parity pattern: the packument never advertises a version
        // that the tarball endpoint returns 403 for. Upstream-only versions carry no scan
        // data, so only the Manual, Deprecated, and ReleaseAge arms can fire here; versions
        // that DO have a local row (uploaded, or proxy-cached and scanned) are re-checked
        // against their stored state in MergeLocalVersionsIntoPackument below.
        FilterPackumentToServableVersions(metadata, settings, now);

        // Splice local versions into the upstream packument so npm install can discover both
        // private and public versions of the same name, and drop upstream entries whose local
        // row the download path hard-blocks (scan verdicts arrive after first fetch — the
        // upstream projection above cannot see them).
        if (localPkg is not null && localVersions.Count > 0)
        {
            var blockedUpstream = MergeLocalVersionsIntoPackument(httpContext, metadata, localPkg,
                localVersions, settings, localSignals, now);
            if (blockedUpstream.Count > 0)
            {
                RepairPackumentAfterFilter(metadata, blockedUpstream);
            }
        }

        // The tenant's persisted dist-tags apply last, over the repaired upstream tags: local
        // tags are authoritative for the tenant's registry view (upstream must not shadow a
        // hosted 'latest'), but a tag is only applied when its target version survived
        // filtering, so a dist-tag never points at a version absent from the packument.
        ApplyLocalDistTags(metadata, persistedTags);

        return Encoding.UTF8.GetBytes(metadata.ToJsonString());
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
                // requests onto one upstream call when a coordinate first warms up. Falls
                // back to the abbreviated (install-v1) document when the full packument
                // overflows the metadata byte cap, so huge packages (vite, aws-sdk, …)
                // still resolve with real dependency lists instead of degrading to the
                // local-only fallback below.
                var response = await NpmPackumentFetcher.FetchAsync(
                    upstream, $"{source.Url}/{fullName}", source.AuthorizationHeader, logger, ct);
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

        var publishedAtByVersion = ParsePublishTimestamps(packument["time"]?.AsObject());

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts);

        var removed = EvaluateVersionsAgainstPolicy(versionsObj, policy, publishedAtByVersion, now);

        if (removed.Count == 0)
        {
            return; // Nothing was dropped — no repair needed.
        }

        RepairPackumentAfterFilter(packument, removed);
    }

    // Parses the packument time[] map into a key → timestamp lookup. Entries whose value is
    // not a parseable timestamp string are omitted. The "created"/"modified" meta-keys parse
    // fine and land in the map, harmlessly — every consumer looks up version strings only.
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
            if (AsString(node) is string raw && DateTimeOffset.TryParse(raw, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
            {
                result[key] = ts;
            }
        }

        return result;
    }

    // Reads a JSON node as a string, or null when the node is absent or not a string —
    // upstream documents are semi-trusted, so a malformed node must degrade, not throw.
    private static string? AsString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out string? s) ? s : null;

    // Evaluates each version in the packument against the block policy. Removes blocked
    // versions from versionsObj in-place and returns the removed set. Iterates over a
    // snapshot of the keys to avoid mutation-during-iteration.
    private static HashSet<string> EvaluateVersionsAgainstPolicy(
        JsonObject versionsObj,
        BlockPolicy policy,
        Dictionary<string, DateTimeOffset> publishedAtByVersion,
        DateTimeOffset now)
    {
        var versionKeys = versionsObj.Select(kv => kv.Key).ToList();
        var removed = new HashSet<string>(StringComparer.Ordinal);

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
        }

        return removed;
    }

    // Removes time[] entries for dropped versions and repairs dist-tags so that no tag
    // points at a removed version. When latest pointed at a removed version it is repointed
    // to the newest surviving stable version by publish timestamp — a prerelease is chosen
    // only when no stable version survives, matching the lazy-latest policy on the local
    // path. Surviving versions are read from the packument itself so the repair is correct
    // for both the upstream filter pass and the post-merge stored-state pass.
    private static void RepairPackumentAfterFilter(JsonNode packument, HashSet<string> removed)
    {
        var timeObj = packument["time"]?.AsObject();
        var publishedAtByVersion = ParsePublishTimestamps(timeObj);

        // Remove time[] entries for dropped versions; preserve non-version meta-keys.
        RemoveTimeEntriesForRemoved(timeObj, removed);

        var distTagsObj = packument["dist-tags"]?.AsObject();
        if (distTagsObj is null)
        {
            return;
        }

        var surviving = packument["versions"]?.AsObject()?.Select(kv => kv.Key).ToList()
            ?? new List<string>();
        RepairDistTagsForRemoved(distTagsObj, removed, surviving, publishedAtByVersion);
    }

    private static void RemoveTimeEntriesForRemoved(JsonObject? timeObj, HashSet<string> removed)
    {
        if (timeObj is null)
        {
            return;
        }

        foreach (string ver in removed)
        {
            timeObj.Remove(ver);
        }
    }

    // Repoints (or drops) every dist-tag pointing at a removed version. When 'latest' pointed
    // at a removed version it is repointed to the newest surviving stable version by publish
    // timestamp — a prerelease is chosen only when no stable version survives.
    private static void RepairDistTagsForRemoved(
        JsonObject distTagsObj, HashSet<string> removed, List<string> surviving,
        Dictionary<string, DateTimeOffset> publishedAtByVersion)
    {
        var tagKeys = distTagsObj.Select(kv => kv.Key).ToList();
        foreach (string tag in tagKeys)
        {
            string? target = AsString(distTagsObj[tag]);
            if (target is null || !removed.Contains(target))
            {
                continue;
            }

            distTagsObj.Remove(tag);
            if (tag == "latest" && surviving.Count > 0)
            {
                distTagsObj["latest"] = PickNewLatest(surviving, publishedAtByVersion);
            }
        }
    }

    // Prefer stable survivors (semver prerelease = label after '-'); among the candidates pick
    // the newest by publish timestamp. Versions with no time[] entry sort oldest.
    private static string PickNewLatest(
        List<string> surviving, Dictionary<string, DateTimeOffset> publishedAtByVersion)
    {
        var candidates = surviving.Where(v => !v.Contains('-')).ToList();
        if (candidates.Count == 0)
        {
            candidates = surviving;
        }

        return candidates
            .OrderByDescending(v =>
                publishedAtByVersion.TryGetValue(v, out var ts) ? ts : DateTimeOffset.MinValue)
            .First();
    }

    // Splices local versions into the upstream packument and enforces stored-state block
    // parity in both directions: local versions the download path would 403 are not added,
    // and upstream entries for versions whose local row is hard-blocked (scan verdicts,
    // manual state — facts the upstream-only projection cannot see) are removed. Returns
    // the removed upstream versions so the caller can repair dist-tags and time[]. Spliced
    // versions get a time[] entry from the stored publish timestamp so date-based client
    // behaviour sees them. Yanked local versions are not spliced (they are hidden from the
    // local packument too) but do not remove a colliding upstream entry — yank withdraws
    // the local advertisement, not upstream's.
    private HashSet<string> MergeLocalVersionsIntoPackument(
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

        var removed = new HashSet<string>(StringComparer.Ordinal);
        string tarballBase = NpmTarballBase(httpContext);
        foreach (var v in localVersions)
        {
            bool blocked = BlockGateService.IsHardBlockedByStoredState(
                v, settings, signals.GetValueOrDefault(v.Id), now);

            if (versionsObj.ContainsKey(v.Version))
            {
                if (blocked)
                {
                    versionsObj.Remove(v.Version);
                    removed.Add(v.Version);
                }

                continue;
            }

            // Skip versions the download path will block — the packument must not advertise
            // an artifact the tarball endpoint will 403. Mirrors the local packument path,
            // which also hides yanked versions.
            if (blocked || v.Yanked)
            {
                continue;
            }

            versionsObj[v.Version] = BuildVersionObject(localPkg.Name, v, tarballBase);
            AddSplicedTimeEntry(packument, v);
        }

        return removed;
    }

    // Records the stored publish timestamp for a spliced local version in the packument
    // time[] map when upstream has no entry for it, so date-based client behaviour
    // (npm view, --before) sees spliced versions.
    private static void AddSplicedTimeEntry(JsonNode packument, PackageVersion v)
    {
        if (packument["time"] is not JsonObject timeObj)
        {
            timeObj = new JsonObject();
            packument["time"] = timeObj;
        }

        if (!timeObj.ContainsKey(v.Version))
        {
            timeObj[v.Version] = v.CreatedAt.ToString("o");
        }
    }

    // Applies the tenant's persisted dist-tags over the merged packument. Local tags win on
    // collision — the tenant's own tags are authoritative for its registry view — but a tag
    // is only applied when its target version survived filtering, so a dist-tag never points
    // at a version absent from the packument.
    private static void ApplyLocalDistTags(JsonNode packument, Dictionary<string, string>? persistedTags)
    {
        if (persistedTags is null || persistedTags.Count == 0)
        {
            return;
        }

        var versionsObj = packument["versions"]?.AsObject();
        if (versionsObj is null)
        {
            return;
        }

        if (packument["dist-tags"] is not JsonObject distTagsObj)
        {
            distTagsObj = new JsonObject();
            packument["dist-tags"] = distTagsObj;
        }

        foreach (var (tag, ver) in persistedTags)
        {
            if (versionsObj.ContainsKey(ver))
            {
                distTagsObj[tag] = ver;
            }
        }
    }

    /// <summary>
    /// Builds the per-version packument object for a locally-stored version: the
    /// registry-authoritative core (name, version, dist.tarball) plus the stored
    /// install-manifest fields (bin, dependencies, engines, …), dist.shasum/dist.integrity,
    /// hasInstallScript, and deprecated. Shared by the fully-local build and the
    /// proxy-merge splice so both paths emit an identical shape. Legacy rows with no
    /// stored manifest render the historical minimal shape.
    /// </summary>
    private static JsonObject BuildVersionObject(string packageName, PackageVersion v, string tarballBase)
    {
        string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
        var dist = new JsonObject
        {
            ["tarball"] = $"{tarballBase}/{packageName}/{filename}"
        };
        // dist.shasum is hex SHA-1 by spec — emit only when we have a real SHA-1
        // (populated at publish time / captured from upstream packuments on first-fetch).
        // Omit rather than fall back to SHA-256: clients that verify shasum would reject
        // the tarball, and clients that trust it would write the wrong hash to lockfiles.
        if (v.ChecksumSha1 is not null)
        {
            dist["shasum"] = v.ChecksumSha1;
        }

        // dist.integrity is the sha512 SRI npm verifies on install and writes to lockfiles.
        // Stored at hosted publish (publisher-declared or server-computed) and captured from
        // upstream packuments on proxy first-fetch; only the SRI encoding is emittable.
        if (v.UpstreamIntegrityAlgorithm == "sha512-sri" && v.UpstreamIntegrityValue is not null)
        {
            dist["integrity"] = v.UpstreamIntegrityValue;
        }

        var verObj = new JsonObject
        {
            ["name"] = packageName,
            ["version"] = v.Version,
            ["dist"] = dist
        };

        MergeStoredManifestFields(verObj, v.ManifestJson);

        // npm's abbreviated packument advertises install scripts so clients can prompt/skip;
        // the flag is detected at publish/first-fetch and stored on the row.
        if (v.HasInstallScript)
        {
            verObj["hasInstallScript"] = true;
        }

        // Surface the deprecation message in the per-version packument object so
        // npm CLI shows the deprecation warning when the package is installed.
        if (v.Deprecated is not null)
        {
            verObj["deprecated"] = v.Deprecated;
        }

        return verObj;
    }

    // Merges the install-relevant fields persisted at publish (package_versions.manifest_json)
    // into the version object. name/version/dist stay registry-authoritative regardless of
    // stored content, and a NULL or unparseable stored value degrades to the minimal shape —
    // a corrupt row must never take down the packument.
    private static void MergeStoredManifestFields(JsonObject verObj, string? manifestJson)
    {
        if (manifestJson is null)
        {
            return;
        }

        JsonObject? manifest;
        try
        {
            manifest = JsonNode.Parse(manifestJson) as JsonObject;
        }
        catch (System.Text.Json.JsonException)
        {
            return;
        }

        if (manifest is null)
        {
            return;
        }

        foreach (var (key, node) in manifest)
        {
            if (key is "name" or "version" or "dist")
            {
                continue;
            }

            verObj[key] = node?.DeepClone();
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
        // Publish-timestamp map for the versions this packument advertises. Sourced from the
        // stored publish timestamp (upstream first-publish for proxy rows, row creation for
        // hosted rows) rather than left absent — pnpm warns when a packument has no "time" field.
        // This packument is always locally-derived (the fully-local build here, or the fallback
        // build when upstream is unreachable); the verbatim upstream packument on the passthrough
        // merge path already carries its own upstream-authoritative "time" map and is never routed
        // through this method.
        var timeObj = new JsonObject();

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
            versionsObj[v.Version] = BuildVersionObject(pkg.Name, v, tarballBase);
            timeObj[v.Version] = (v.PublishedAt ?? v.CreatedAt).ToString("o");
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
            ["versions"] = versionsObj,
            ["time"] = timeObj
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

            string? tarball = AsString(dist["tarball"]);
            if (tarball is null)
            {
                continue;
            }

            string filename = tarball.Split('/').Last();
            dist["tarball"] = $"{tarballBase}/{packageName}/{filename}";
        }
    }
}
