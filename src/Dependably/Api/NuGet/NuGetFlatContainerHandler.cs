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
/// version is never listed or served. Proxy-fetch helpers are in <see cref="NuGetNupkgProxyHelper"/>.
/// </summary>
public sealed class NuGetFlatContainerHandler(
    OrgRepository orgs,
    PackageRepository packages,
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

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string normalizedId = id.ToLowerInvariant();
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // Pre-load vuln signals for all local versions in one batch query so block-gate
        // filtering in CollectLocalVersions avoids per-version I/O.
        var localVersions = pkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await packages.GetVersionsAsync(pkg.Id, ct);
        var signals = await LoadVulnSignalsAsync(localVersions, ct);
        var now = time.GetUtcNow();

        var versionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectLocalVersions(localVersions, versionSet, settings!, signals, now);

        // Merge upstream regardless of pkg.IsProxy — a name with uploaded versions is still a
        // namespace that can hold proxy-fetched versions. Gate on passthrough + claims, not on
        // whether anyone has ever published into this name.
        if (settings.ProxyPassthroughEffective
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
        foreach (string upstreamBase in bases)
        {
            string url = $"{upstreamBase}/flatcontainer/{id.ToLowerInvariant()}/index.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                // Single-flight: collapses N concurrent NuGet list requests onto one
                // upstream call for the same flatcontainer index.
                var resp = await upstream.GetOrFetchMetadataAsync(url, linkedCts.Token);
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

        // Route by the specific version's origin (per-version state), not by the package-level
        // is_proxy flag. A package name is a namespace that can hold mixed-origin versions:
        // some uploaded private builds and some proxy-fetched public versions can coexist.
        if (pkg is not null)
        {
            var routed = await TryRouteToKnownVersionAsync(
                httpContext, pkg, version, file, new NuGetDownloadContext(orgId, token, settings!), ct);
            if (routed is not null)
            {
                return routed;
            }
        }

        if (!settings!.AnonymousPull && token is null)
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
                new NuGetDownloadContext(orgId, token, settings!), ct);
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

        if (pkg is null)
        {
            // No local record — could be a proxy cache-miss; return 404 for HEAD.
            return new NotFoundResult();
        }

        string normalizedVersion = NuGetNormalization.NormalizeVersion(version);
        var pkgVersion = await packages.GetVersionAsync(pkg.Id, normalizedVersion, ct);
        if (pkgVersion is null)
        {
            return new NotFoundResult();
        }

        // Auth gate: hosted versions require a token; proxy follows AnonymousPull.
        if (pkgVersion.Origin == "uploaded")
        {
            if (token is null)
            {
                httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return new UnauthorizedResult();
            }
        }
        else if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "nuget", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token?.UserId, settings!.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated,
                    BlockMaliciousMode: settings.BlockMalicious,
                    BlockKevMode: settings.BlockKev,
                    MaxEpssTolerance: settings.MaxEpssTolerance), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        // For proxy versions, confirm the blob key corresponds to the requested file.
        if (pkgVersion.Origin == "proxy" &&
            !pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
        {
            return new NotFoundResult();
        }

        // Confirm the blob is present without opening a stream.
        string blobKey = BlobKeys.StoreKey(pkgVersion.BlobKey);
        bool exists = await blobs.ExistsAsync(blobKey, ct);
        if (!exists)
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

    // Per-version origin routing: returns a hosted version, a cached proxy version, or null
    // when the caller should fall through to the proxy-fetch path (no matching version row,
    // or cached proxy blob is for a different file type than requested).
    private async Task<IActionResult?> TryRouteToKnownVersionAsync(
        HttpContext httpContext, Package pkg, string version, string file,
        NuGetDownloadContext ctx, CancellationToken ct)
    {
        string normalizedVersion = NuGetNormalization.NormalizeVersion(version);
        var pkgVersion = await packages.GetVersionAsync(pkg.Id, normalizedVersion, ct);
        return pkgVersion is null
            ? null
            : pkgVersion.Origin == "uploaded"
            ? await ServeHostedVersionAsync(httpContext, ctx.OrgId, pkgVersion, file, ctx.Token, ctx.Settings, ct)
            : pkgVersion.Origin == "proxy" ? await TryServeCachedProxyVersionAsync(httpContext, ctx.OrgId, pkgVersion, file, ctx.Token, ctx.Settings, ct) : null;
    }

    private async Task<IActionResult> ServeHostedVersionAsync(
        HttpContext httpContext, string orgId,
        PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // Version exists and is privately hosted — token is required to download.
        if (token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "nuget", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated,
                    BlockMaliciousMode: settings.BlockMalicious,
                    BlockKevMode: settings.BlockKev,
                    MaxEpssTolerance: settings.MaxEpssTolerance), ct)
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
        await audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "download", token.UserId,
            actorKind: token.ActorKind, sourceIp: sourceIp, ct: ct);
        await packages.IncrementDownloadCountAsync(pkgVersion.Id, ct);
        return new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    // For proxy versions: serve from cache only when the cached blob is for the exact requested file.
    // Each file type (nupkg, nuspec, sha512) has a distinct sha256 and blob. Serving the wrong blob
    // (e.g., nupkg bytes when the client requests the .sha512 hash) causes integrity verification to fail.
    // Returns 403 if blocked, the file IActionResult if cached, or null if cache miss → caller proxies.
    private async Task<IActionResult?> TryServeCachedProxyVersionAsync(
        HttpContext httpContext, string orgId,
        PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "nuget", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token?.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated,
                    BlockMaliciousMode: settings.BlockMalicious,
                    BlockKevMode: settings.BlockKev,
                    MaxEpssTolerance: settings.MaxEpssTolerance), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var stream = await blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null)
        {
            return null;
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

            var (fetchResult, upstreamBase) = fetched.Value;

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
                upstream, upstreamBase, normalizedId, normalizedVersion, ct);

            // The streaming MISS path already wrote the blob and computed the SHA-256 inline —
            // no large byte[] allocation needed. BlobHandle wraps the result so ProxyFetchService
            // can open a fresh blob-store stream for licence extraction or checksum re-verification.
            var blob = new BlobHandle(proxyKey, sha, sizeBytes,
                async openCt => await blobs.GetAsync(proxyKey, openCt)
                    ?? Stream.Null);

            // deepcode ignore PT,LogForging: ProxyFetchService stores under BlobKeys.Proxy(sha256),
            // which validates a 64-char lowercase hex — path traversal cannot escape that key. All
            // structured logs use Serilog RenderedCompactJsonFormatter (CRLF-safe).
            var result = await proxyFetch.RecordAndScanAsync(
                NuGetNupkgProxyHelper.BuildNuGetProxyFetchRequest(
                    orgId, normalizedId, normalizedVersion, purl, file, blob,
                    upstreamBase, token, settings, meta, httpContext.GetNormalizedRemoteIp()), ct);

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

    // Walks upstreams in priority order; streams and stages the first successful flatcontainer
    // artifact to disk, hashing inline. Memory usage is bounded by the staging buffer
    // regardless of artifact size. Returns (UpstreamFetchResult, upstreamBase) on success,
    // or null when no upstream returns a success response. Single-flight: concurrent
    // first-fetches of the same coordinate share one upstream call.
    private async Task<(UpstreamFetchResult FetchResult, string UpstreamBase)?> FetchNupkgFromUpstreamsAsync(
        IReadOnlyList<string> bases, string id, string version, string file, string orgId, CancellationToken ct)
    {
        foreach (string candidateBase in bases)
        {
            string candidateUrl = $"{candidateBase}/flatcontainer/{id.ToLowerInvariant()}/{version}/{file}";
            try
            {
                // Streams upstream → staging file (hashing inline) → blob store.
                // No upstream checksum is known for flatcontainer URLs; the ingest-time
                // SHA-256 computed inline is the canonical reference.
                var fetchResult = await upstream.FetchAndCacheByUrlAsync(
                    candidateUrl, null, "nuget", orgId, ct);
                return (fetchResult, candidateBase);
            }
            // Only transport-level failures advance to the next upstream; checksum, size-cap,
            // SSRF, and air-gap failures propagate to the caller.
            catch (HttpRequestException) { /* try next upstream */ }
        }

        return null;
    }

    // Loads vuln gate signals for a version list in one batch query. Returns an empty dict when
    // all versions lack advisory links.
    private Task<IReadOnlyDictionary<string, VulnGateSignals>> LoadVulnSignalsAsync(
        IReadOnlyList<PackageVersion> versions, CancellationToken ct) =>
        versions.Count == 0
            ? Task.FromResult<IReadOnlyDictionary<string, VulnGateSignals>>(new Dictionary<string, VulnGateSignals>())
            : vulns.GetGateSignalsBatchAsync(versions.Select(v => v.Id).ToList(), ct);

    private static bool AreUpstreamSafeNuGetSegments(params string[] values)
        => Array.TrueForAll(values, v => PathSafeValidator.ValidateUpstreamSegment(v, "segment").IsValid);

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

// Tenant + caller context for NuGet download operations. Bundles the three per-request
// values (org id, resolved token, settings snapshot) so private helpers stay within the
// S107 parameter limit.
internal sealed record NuGetDownloadContext(string OrgId, TokenRecord? Token, OrgSettings Settings);
