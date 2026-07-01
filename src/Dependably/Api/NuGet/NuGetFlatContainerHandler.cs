using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Handles NuGet v3 flatcontainer endpoints: version list, package download, and HEAD probe.
/// Block-gate filtering applies on both the version list and download paths so a blocked
/// version is never listed or served. Proxy cache-hits are served from the global plane
/// (<c>cache_artifact</c> + <c>tenant_artifact_access</c>). Proxy-fetch helpers are in
/// <see cref="NuGetNupkgProxyHelper"/>.
/// </summary>
public sealed class NuGetFlatContainerHandler(
    OrgRepository orgs,
    PackageRepository packages,
    CacheArtifactRepository cacheArtifacts,
    TenantArtifactAccessRepository tenantAccess,
    TokenRepository tokens,
    AuditRepository audit,
    IBlobStore blobs,
    UpstreamClient upstream,
    UpstreamRegistryResolver registries,
    AllowlistService allowlist,
    BlocklistRepository blocklist,
    BlockGateService blockGate,
    VulnerabilityRepository vulns,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    ProxyFetchService proxyFetch,
    Dependably.Protocol.Provenance.NuGetProvenanceVerifier provenance,
    TimeProvider time,
    ILogger<NuGetFlatContainerHandler> logger)
{
    public async Task<IActionResult> FlatcontainerVersionsAsync(
        HttpContext httpContext, string orgId, string id, CancellationToken ct)
    {
        // The id flows into the upstream flatcontainer URL — reject traversal-shaped values
        // before any lookup or upstream call, mirroring the push-side validation.
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

        // Pre-load vuln signals for all local versions (uploaded + proxy cached) in one
        // batch query so block-gate filtering in CollectLocalVersions avoids per-version I/O.
        var localVersions = pkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await LoadCombinedVersionsAsync(orgId, pkg.Id, normalizedId, ct);
        var signals = await LoadCombinedVulnSignalsAsync(localVersions, ct);
        var now = time.GetUtcNow();

        var versionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectLocalVersions(localVersions, versionSet, settings!, signals, now);

        // Merge upstream regardless of pkg.IsProxy — a name with uploaded versions is still a
        // namespace that can hold proxy-fetched versions. Gate on passthrough + claims, not on
        // whether anyone has ever published into this name.
        if (settings!.ProxyPassthroughEffective
            && !await reserved.IsReservedAsync(orgId, "nuget", normalizedId, ct)
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct))
        {
            await MergeUpstreamVersionsAsync(httpContext, orgId, id, versionSet, ct);
        }
        else
        {
            httpContext.Response.Headers["X-Upstream-Status"] = "skipped";
        }

        return versionSet.Count == 0 ? new NotFoundResult() : new JsonResult(new { versions = versionSet.Order() });
    }

    // Adds non-yanked, non-blocked local version strings to versionSet. Accepts pre-loaded
    // versions and signals to avoid redundant DB round-trips when the caller already has them.
    private static void CollectLocalVersions(
        IReadOnlyList<PackageVersion> versions, HashSet<string> versionSet,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        foreach (var v in versions.Where(v => !v.Yanked
            && !BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now)))
        {
            versionSet.Add(v.Version);
        }
    }

    // Fetch the upstream version list and merge. Short timeout so slow upstream responses don't
    // hang clients after they have what they need. Sets X-Upstream-Status header (ok|error|timeout)
    // and logs at warning level when the merge fails so operators can see silent fallbacks.
    private async Task MergeUpstreamVersionsAsync(
        HttpContext httpContext, string orgId, string id, HashSet<string> versionSet, CancellationToken ct)
    {
        // Walk the org's configured upstreams in priority order; the first that returns a usable
        // version list wins and we stop. No configured upstream ⇒ proxying is disabled for nuget,
        // so the loop is skipped and the status reflects the unreachable/empty outcome.
        var bases = await registries.ResolveAsync(orgId, "nuget", ct);
        foreach (var source in bases)
        {
            string url = $"{source.Url}/flatcontainer/{id.ToLowerInvariant()}/index.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                // Single-flight: collapses N concurrent NuGet list requests onto one
                // upstream call for the same flatcontainer index.
                var resp = await upstream.GetOrFetchMetadataAsync(url, source.AuthorizationHeader, linkedCts.Token);
                if (!resp.IsSuccessStatusCode)
                {
                    httpContext.Response.Headers["X-Upstream-Status"] = "error";
                    // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                    logger.LogWarning("NuGet upstream version-list fetch failed: {Status} for {Url}", resp.StatusCode, url);
                    continue;
                }

                using var doc = JsonDocument.Parse(resp.Body);
                if (!doc.RootElement.TryGetProperty("versions", out var versionsElem))
                {
                    httpContext.Response.Headers["X-Upstream-Status"] = "error";
                    // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                    logger.LogWarning("NuGet upstream version-list response missing 'versions' property for {Url}", url);
                    continue;
                }
                versionSet.UnionWith(
                    versionsElem.EnumerateArray()
                        .Select(v => v.GetString())
                        .OfType<string>());
                httpContext.Response.Headers["X-Upstream-Status"] = "ok";
                return;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                httpContext.Response.Headers["X-Upstream-Status"] = "timeout";
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning("NuGet upstream version-list fetch timed out for {Url}", url);
            }
            catch (Exception ex)
            {
                httpContext.Response.Headers["X-Upstream-Status"] = "error";
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                logger.LogWarning(ex, "NuGet upstream version-list fetch threw for {Url}", url);
            }
        }
    }

    public async Task<IActionResult> FlatcontainerDownloadAsync(
        HttpContext httpContext, string orgId, string id, string version, string file, CancellationToken ct)
    {
        // All three route values flow into the upstream flatcontainer URL — reject
        // traversal-shaped values before any lookup or upstream call, mirroring the
        // push-side validation.
        if (!AreUpstreamSafeNuGetSegments(id, version, file))
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        string normalizedId = id.ToLowerInvariant();
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // Route uploaded-origin versions (private builds) via package_versions. A package name
        // is a namespace that can hold mixed-origin versions; proxy rows are no longer stored
        // in package_versions and fall through to the global-plane cache-hit path below.
        if (pkg is not null)
        {
            var routed = await TryRouteToKnownVersionAsync(
                httpContext, pkg, version, file, new NuGetDownloadContext(orgId, token, settings!), ct);
            if (routed is not null)
            {
                return routed;
            }
        }

        // Proxy cache-hit: an already-cached proxy artifact is served from the global plane before
        // the allowlist / blocklist gates. The AnonymousPull gate applies to cache-hit serves too —
        // anonymous clients must authenticate when the org requires it. The Proxy-tab passthrough
        // settings govern whether anonymous clients may trigger an upstream fetch on a miss,
        // handled in FetchFromUpstreamAsync below. The per-version policy block-gate is still
        // re-evaluated on every hit.
        var proxyCacheHit = await TryServeProxyCacheHitAsync(
            httpContext, orgId, normalizedId, version, file, token, settings!, ct);
        if (proxyCacheHit is not null)
        {
            return proxyCacheHit;
        }

        // Miss → upstream fetch path. The anonymous-pull / allowlist / blocklist / passthrough
        // gates apply here because a miss would trigger an outbound fetch.
        return await FetchFromUpstreamAsync(httpContext, orgId, id, normalizedId, version, file, token, settings!, ct);
    }

    // Attempts to serve an already-cached proxy artifact from the global plane. Returns
    // the IActionResult to send (including block-gate denials) when a cache_artifact row
    // exists, or null when the artifact is not cached and the caller should fall through
    // to the upstream fetch path.
    // Cohesive proxy-cache serve helper; all params are required for coordinate lookup, block-gate, and serve.
#pragma warning disable S107
    private async Task<IActionResult?> TryServeProxyCacheHitAsync(
        HttpContext httpContext, string orgId, string normalizedId, string version, string file,
        TokenRecord? token, OrgSettings settings, CancellationToken ct)
#pragma warning restore S107
    {
        string normalizedVersion = NuGetNormalization.NormalizeVersion(version);
        var caFacts = await cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "nuget", normalizedId, normalizedVersion, file, ct);
        if (caFacts is null)
        {
            return null;
        }

        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string? sourceIpCa = httpContext.GetNormalizedRemoteIp();
        return await blockGate.EvaluateAsync(
                BuildProxyBlockGateRequest(orgId, caFacts, token, settings, sourceIpCa), ct)
            == BlockDecision.Blocked
            ? new StatusCodeResult(StatusCodes.Status403Forbidden)
            : await TryServeProxyCachedNupkgAsync(httpContext, caFacts, file, orgId, token, sourceIpCa, ct);
    }

    // Evaluates the anonymous-pull / allowlist / blocklist / passthrough gates for a cache miss
    // and delegates to the upstream fetch when all gates pass. Returns 401/403/404 when a
    // gate denies access, or the proxied artifact on success.
    // Cohesive upstream-fetch helper; id + normalizedId + version + file each carry distinct semantics.
#pragma warning disable S107
    private async Task<IActionResult> FetchFromUpstreamAsync(
        HttpContext httpContext, string orgId, string id, string normalizedId, string version, string file,
        TokenRecord? token, OrgSettings settings, CancellationToken ct)
#pragma warning restore S107
    {
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string purlCheck = $"pkg:nuget/{normalizedId}";
        if (settings.AllowlistMode && !await allowlist.IsAllowedAsync(orgId, purlCheck, ct))
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        if (await blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await audit.LogActivityAsync(orgId, "nuget", purlCheck, "blocked", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        if (!settings.ProxyPassthroughEffective)
        {
            return new NotFoundResult();
        }

        // Claim state and reserved namespaces gate the proxy fetch. local_only (or air-gap
        // implicit local_only) and reserved names disable proxy serving with the same
        // silent 404.
        return await reserved.IsReservedAsync(orgId, "nuget", normalizedId, ct)
            || !await claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct)
            ? new NotFoundResult()
            : await ProxyFetchNupkgAsync(httpContext, id, version, file,
                new NuGetDownloadContext(orgId, token, settings), ct);
    }

    public async Task<IActionResult> FlatcontainerHeadAsync(
        HttpContext httpContext, string orgId, string id, string version, string file, CancellationToken ct)
    {
        if (!AreUpstreamSafeNuGetSegments(id, version, file))
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        string normalizedId = id.ToLowerInvariant();
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);
        string normalizedVersion = NuGetNormalization.NormalizeVersion(version);

        // Uploaded-origin lookup first: proxy rows are served from the global plane below.
        if (pkg is not null)
        {
            var pkgVersion = await packages.GetVersionAsync(pkg.Id, normalizedVersion, ct);
            if (pkgVersion?.Origin == "uploaded")
            {
                return await HeadUploadedVersionAsync(httpContext, orgId, pkgVersion, token, settings, ct);
            }
        }

        return await HeadProxyCachedVersionAsync(
            httpContext, orgId, normalizedId, normalizedVersion, file, token, settings!, ct);
    }

    // Returns HEAD headers for an uploaded-origin .nupkg. When AnonymousPull is disabled a
    // token is required; runs the block gate; returns 401/403/404 when a gate denies access.
    private async Task<IActionResult> HeadUploadedVersionAsync(
        HttpContext httpContext, string orgId, PackageVersion pkgVersion,
        TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        if (settings is null || (!settings.AnonymousPull && token is null))
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string? srcIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "nuget", pkgVersion, token, settings, srcIp), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        string uploadedBlobKey = BlobKeys.StoreKey(pkgVersion.BlobKey);
        if (!await blobs.ExistsAsync(uploadedBlobKey, ct))
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        httpContext.Response.ContentType = "application/octet-stream";
        httpContext.Response.Headers["Content-Length"] = pkgVersion.SizeBytes.ToString();
        if (pkgVersion.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        return new OkResult();
    }

    // Returns HEAD headers for a proxy-cached artifact from the global plane. Enforces the
    // AnonymousPull gate, then runs the block gate; returns 401/403/404 when denied or absent.
    // Cohesive HEAD serve helper; all params are required for auth, block-gate, and blob lookup.
#pragma warning disable S107
    private async Task<IActionResult> HeadProxyCachedVersionAsync(
        HttpContext httpContext, string orgId, string normalizedId, string normalizedVersion,
        string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
#pragma warning restore S107
    {
        // Proxy cache-hit path: check the global plane.
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var caFacts = await cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "nuget", normalizedId, normalizedVersion, file, ct);
        if (caFacts is null)
        {
            return new NotFoundResult();
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BuildProxyBlockGateRequest(orgId, caFacts, token, settings, sourceIp), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        // blobkey-ok: proxy blob key from cache_artifact; no filename suffix needed for HEAD.
        string blobKey = BlobKeys.StoreKey(caFacts.BlobKey);
        if (!await blobs.ExistsAsync(blobKey, ct))
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        if (caFacts.Purl is not null)
        {
            httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(caFacts.Purl);
        }
        httpContext.Response.ContentType = "application/octet-stream";
        httpContext.Response.Headers["Content-Length"] = caFacts.SizeBytes.ToString();
        if (!string.IsNullOrEmpty(caFacts.ContentHash))
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{caFacts.ContentHash}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        return new OkResult();
    }

    // Per-version origin routing: returns a hosted (uploaded-origin) version, or null when the
    // caller should fall through to the global-plane proxy path or the upstream proxy-fetch path.
    private async Task<IActionResult?> TryRouteToKnownVersionAsync(
        HttpContext httpContext, Package pkg, string version, string file,
        NuGetDownloadContext ctx, CancellationToken ct)
    {
        string normalizedVersion = NuGetNormalization.NormalizeVersion(version);
        var pkgVersion = await packages.GetVersionAsync(pkg.Id, normalizedVersion, ct);
        // Proxy-origin rows are no longer written to package_versions; fall through to the
        // global-plane lookup in FlatcontainerDownloadAsync.
        return pkgVersion?.Origin == "uploaded"
            ? await ServeHostedVersionAsync(httpContext, ctx.OrgId, pkgVersion, file, ctx.Token, ctx.Settings, ct)
            : null;
    }

    private async Task<IActionResult> ServeHostedVersionAsync(
        HttpContext httpContext, string orgId,
        PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // When AnonymousPull is disabled, a token is required for hosted downloads.
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "nuget", pkgVersion, token, settings, sourceIp), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        var stream = await blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null)
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        if (pkgVersion.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        await packages.IncrementDownloadCountAsync(pkgVersion.Id, ct);
        return new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    // Builds a BlockGateRequest for a proxy artifact from global-plane serve facts.
    private static BlockGateRequest BuildProxyBlockGateRequest(
        string orgId, CacheArtifactServeFacts caFacts, TokenRecord? token,
        OrgSettings settings, string? sourceIp) =>
        new(orgId, "nuget", caFacts.Purl ?? string.Empty, string.Empty,
            caFacts.ManualBlockState, caFacts.VulnCheckedAt,
            token?.UserId, settings.MaxOsvScoreTolerance, sourceIp,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            PublishedAt: caFacts.PublishedAt,
            ActorKind: token?.ActorKind,
            Deprecated: caFacts.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            Origin: "proxy",
            HasInstallScript: caFacts.HasInstallScript,
            InstallScriptKind: caFacts.InstallScriptKind,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            ProvenanceStatus: caFacts.ProvenanceStatus,
            CacheArtifactId: caFacts.Id);

    // Serves a proxy NuGet artifact from the global-plane cache. Each NuGet file type
    // (.nupkg, .nuspec, .sha512) is stored as a separate cache_artifact row keyed by
    // filename, so the GET coordinate already selects the exact blob. Returns null when
    // the blob is not yet in the store (the caller falls through to the upstream proxy fetch).
    private async Task<IActionResult?> TryServeProxyCachedNupkgAsync(
        HttpContext httpContext, CacheArtifactServeFacts caFacts, string file, string orgId,
        TokenRecord? token, string? sourceIp, CancellationToken ct)
    {
        // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey maps to the cache tier.
        var stream = await blobs.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
        if (stream is null)
        {
            return null;
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        if (caFacts.Purl is not null)
        {
            httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(caFacts.Purl);
        }
        if (!string.IsNullOrEmpty(caFacts.ContentHash))
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{caFacts.ContentHash}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        if (caFacts.Purl is not null)
        {
            await audit.LogActivityAsync(orgId, "nuget", caFacts.Purl, "download", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        }
        // Increment per-tenant download count on the global plane.
        await tenantAccess.UpsertStateAsync(orgId, caFacts.Id, time.GetUtcNow(), ct);
        return new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    private async Task<IActionResult> ProxyFetchNupkgAsync(
        HttpContext httpContext, string id, string version, string file,
        NuGetDownloadContext ctx, CancellationToken ct)
    {
        string orgId = ctx.OrgId;
        var token = ctx.Token;
        var settings = ctx.Settings;

        // Resolve the org's configured upstreams in priority order. An empty list means
        // proxying is disabled for nuget — a download miss is a 404.
        var bases = await registries.ResolveAsync(orgId, "nuget", ct);
        if (bases.Count == 0)
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "MISS";
        try
        {
            var fetched = await FetchNupkgFromUpstreamsAsync(bases, id, version, file, orgId, ct);
            if (fetched is null)
            {
                return new NotFoundResult();
            }

            var (fetchResult, upstreamSource) = fetched.Value;

            string normalizedId = id.ToLowerInvariant();
            string normalizedVersion = NuGetNormalization.NormalizeVersion(version);
            string proxyKey = fetchResult.BlobKey;
            string sha = fetchResult.Sha256Hex;
            long sizeBytes = fetchResult.SizeBytes;

            // Resolve canonical-case ID for the PURL from the cached blob. The blob was
            // already written by the streaming MISS path so a single blob-store open is enough.
            string canonicalId = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
                blobs, file, proxyKey, normalizedId, ct);
            string purl = PurlNormalizer.NuGet(canonicalId, normalizedVersion);

            var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
                upstream, upstreamSource, normalizedId, normalizedVersion, ct);

            // The streaming MISS path already wrote the blob and computed the SHA-256 inline —
            // no large byte[] allocation needed. BlobHandle wraps the result so ProxyFetchService
            // can open a fresh blob-store stream for licence extraction or checksum re-verification.
            var blob = new BlobHandle(proxyKey, sha, sizeBytes,
                async openCt => await blobs.GetAsync(proxyKey, openCt)
                    ?? Stream.Null);

            // Verify the .nupkg signature against org-pinned trust anchors when the tenant
            // enabled it. Runs only for proxy-origin .nupkg files (the signature lives in the
            // package ZIP, not the sidecar .nuspec/.sha512); off-policy or an org without
            // configured anchors short-circuits to NotApplicable (NULL status, never blocks).
            var prov = await ResolveProvenanceAsync(settings, orgId, file, blob, ct);

            // deepcode ignore PT,LogForging: ProxyFetchService stores under BlobKeys.Proxy(sha256),
            // which validates a 64-char lowercase hex — path traversal cannot escape that key. All
            // structured logs use Serilog RenderedCompactJsonFormatter (CRLF-safe).
            var result = await proxyFetch.RecordAndScanAsync(
                NuGetNupkgProxyHelper.BuildNuGetProxyFetchRequest(
                    orgId, normalizedId, normalizedVersion, purl, file, blob,
                    upstreamSource.Url, token, settings, meta, httpContext.GetNormalizedRemoteIp(), prov), ct);

            if (result.Decision == BlockDecision.Blocked)
            {
                return new StatusCodeResult(StatusCodes.Status403Forbidden);
            }

            // Stream the cached blob back to the client (response memory is one read
            // buffer, not the whole artefact).
            var blobStream = await blobs.GetAsync(result.BlobKey, ct);
            return blobStream is null
                ? new NotFoundResult()
                : new FileStreamResult(blobStream, "application/octet-stream") { FileDownloadName = file };
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch (ChecksumException) { return new StatusCodeResult(StatusCodes.Status502BadGateway); }
        catch (UpstreamResponseTooLargeException) { return new StatusCodeResult(StatusCodes.Status502BadGateway); }
        catch (UpstreamFetchFailedException) { throw; }
        catch { return new NotFoundResult(); }
    }

    // Caps the in-memory buffer the signature verifier allocates to seek the .nupkg ZIP central
    // directory. Generous (the upstream streaming fetch already bounds artefact size); a package
    // above this cap verifies as Failed rather than allocating without bound.
    private const long NuGetSignatureVerifyCapBytes = 256L * 1024 * 1024;

    // Runs NuGet .nupkg signature verification for a proxy-origin version when the tenant enabled
    // it. Only .nupkg files carry a .signature.p7s — sidecar files (.nuspec/.sha512) and an
    // off-policy setting or an org with no configured anchors short-circuit to NotApplicable
    // (NULL status, never blocks). The package bytes come from the freshly-staged cache blob
    // via the BlobHandle.
    private async Task<Dependably.Protocol.Provenance.ProvenanceResult> ResolveProvenanceAsync(
        OrgSettings settings, string orgId, string file, BlobHandle blob, CancellationToken ct)
    {
        if (settings.VerifyNuGetSignatures == "off"
            || !file.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
            || !await provenance.IsConfiguredForAsync(orgId, ct))
        {
            return Dependably.Protocol.Provenance.ProvenanceResult.NotApplicable;
        }

        await using var stream = await blob.OpenAsync(ct);
        return await provenance.VerifyForOrgAsync(orgId, stream, NuGetSignatureVerifyCapBytes, ct);
    }

    // Walks upstreams in priority order; streams and stages the first successful flatcontainer
    // artifact to disk, hashing inline. Memory usage is bounded by the staging buffer
    // regardless of artifact size. Returns (UpstreamFetchResult, upstreamBase) on success,
    // or null when no upstream returns a success response. Single-flight: concurrent
    // first-fetches of the same coordinate share one upstream call.
    private async Task<(UpstreamFetchResult FetchResult, UpstreamSource Source)?> FetchNupkgFromUpstreamsAsync(
        IReadOnlyList<UpstreamSource> bases, string id, string version, string file, string orgId, CancellationToken ct)
    {
        foreach (var candidate in bases)
        {
            string candidateUrl = $"{candidate.Url}/flatcontainer/{id.ToLowerInvariant()}/{version}/{file}";
            try
            {
                // Streams upstream → staging file (hashing inline) → blob store.
                // No upstream checksum is known for flatcontainer URLs; the ingest-time
                // SHA-256 computed inline is the canonical reference.
                var fetchResult = await upstream.FetchAndCacheByUrlAsync(
                    candidateUrl, null, "nuget", orgId, candidate.AuthorizationHeader, ct);
                return (fetchResult, candidate);
            }
            // Only transport-level failures advance to the next upstream; checksum, size-cap,
            // SSRF, and air-gap failures propagate to the caller.
            catch (HttpRequestException) { /* try next upstream */ }
        }

        return null;
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
    // objects projected from global-plane proxy cache entries. NuGet flatcontainer lists all
    // cached versions for a package id; proxy entries whose version already appears in uploaded
    // versions are deduplicated.
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

        // Each .nupkg, .nuspec, and .sha512 file for a version produces a separate
        // cache_artifact row. Deduplicate by version (case-insensitive) so the version
        // list only carries one entry per version string.
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

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

// Tenant + caller context for NuGet download operations. Bundles the three per-request
// values (org id, resolved token, settings snapshot) so private helpers stay within the
// S107 parameter limit.
internal sealed record NuGetDownloadContext(string OrgId, TokenRecord? Token, OrgSettings Settings);
