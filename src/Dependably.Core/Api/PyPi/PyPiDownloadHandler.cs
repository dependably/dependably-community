using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Handles HEAD /packages/{file} and GET /packages/{file}: auth gate, block-gate evaluation,
/// cached-blob serving, and delegation to <see cref="PyPiProxyFetcher"/> for cache-miss proxy.
/// Serve routing: uploaded versions use <c>package_versions</c>; proxy cache-hits use the
/// global plane (<c>cache_artifact</c> + <c>tenant_artifact_access</c>).
/// </summary>
public sealed class PyPiDownloadHandler(
    OrgRepository orgs,
    PackageRepository packages,
    PackageVersionFilesRepository versionFiles,
    CacheArtifactRepository cacheArtifacts,
    TenantArtifactAccessRepository tenantAccess,
    TokenRepository tokens,
    AuditRepository audit,
    IBlobStore blobs,
    BlockGateService blockGate,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    UpstreamRegistryResolver registries,
    PyPiProxyFetcher proxyFetcher,
    TimeProvider time)
{
    /// <summary>
    /// HEAD /packages/{file} — returns headers (size, checksum, content-type) without opening
    /// the blob stream. Enforces the same auth and block gates as GET but uses
    /// <see cref="IBlobStore.ExistsAsync"/> instead of <see cref="IBlobStore.GetAsync"/>, so no
    /// network stream is opened for S3/Azure-backed stores. Returns 404 on proxy cache-miss
    /// (the client would receive a 404 on GET too until the blob is fetched and cached).
    /// <paramref name="expectedSha256"/> is optional — set only by the CDN-shaped alias in
    /// <see cref="HeadPackageByDigestAsync"/> — and is compared to the on-record checksum only
    /// AFTER the same auth gate every other caller goes through first (see
    /// <see cref="HeadUploadedPackageAsync"/>/<see cref="HeadProxyCachedPackageAsync"/>), so an
    /// unauthenticated caller learns nothing about whether a digest matches.
    /// </summary>
    public async Task<IActionResult> HeadPackageAsync(
        HttpContext httpContext, string orgId, string file, CancellationToken ct, string? expectedSha256 = null)
    {
        if (!PathSafeValidator.ValidateUpstreamSegment(file, "file").IsValid)
        {
            return new NotFoundResult();
        }

        var (filenameSuccess, parsedPurlName, parsedVersion) = PyPiArtifactValidator.TryParseFilename(file);
        if (!filenameSuccess)
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        // Uploaded-only lookup: proxy versions are served via the global plane below. The
        // per-file table resolves any distribution file of the version (wheel or sdist),
        // not just the version row's primary artifact.
        var fileHit = await versionFiles.FindFileWithVersionAsync(orgId, "pypi", file, ct);

        return fileHit is not null
            ? await HeadUploadedPackageAsync(httpContext, orgId, fileHit.Value.Version, fileHit.Value.File, token, settings, expectedSha256, ct)
            : await HeadProxyCachedPackageAsync(
                httpContext, orgId, parsedPurlName!, parsedVersion!, file, token, settings!, expectedSha256, ct);
    }

    // Returns HEAD headers for an uploaded-origin PyPI artifact. When AnonymousPull is
    // disabled, a token is required; when a token is present, ReadMetadata is required.
    // Blob facts (key, size, checksum) come from the requested FILE record; the gate facts
    // (block state, purl) come from its owning version.
    // Cohesive HEAD serve helper; expectedSha256 is the optional CDN-alias digest check.
#pragma warning disable S107
    private async Task<IActionResult> HeadUploadedPackageAsync(
        HttpContext httpContext, string orgId, PackageVersion v, PackageVersionFile fileRec,
        TokenRecord? token, OrgSettings? settings, string? expectedSha256, CancellationToken ct)
#pragma warning restore S107
    {
        var authErr = RequireUploadedAuth(httpContext, token, settings);
        if (authErr is not null)
        {
            return authErr;
        }

        // Digest check runs only after the auth gate above, so a mismatch (and a match) are
        // both invisible to a caller who hasn't already cleared RequireUploadedAuth.
        if (expectedSha256 is not null
            && !string.Equals(fileRec.ChecksumSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return new NotFoundResult();
        }

        string? srcIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "pypi", v, token, settings, srcIp), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        string blobKeyUploaded = BlobKeys.StoreKey(fileRec.BlobKey);
        if (!await blobs.ExistsAsync(blobKeyUploaded, ct))
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = HeaderSanitizer.Sanitize(v.Purl);
        httpContext.Response.ContentType = "application/octet-stream";
        httpContext.Response.Headers["Content-Length"] = fileRec.SizeBytes.ToString();
        if (fileRec.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{fileRec.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        return new OkResult();
    }

    // Returns HEAD headers for a proxy-cached PyPI artifact from the global plane. Enforces
    // the AnonymousPull gate, then runs the block gate; returns 401/403/404 when denied or absent.
    // Cohesive HEAD serve helper; expectedSha256 is the optional CDN-alias digest check.
#pragma warning disable S107
    private async Task<IActionResult> HeadProxyCachedPackageAsync(
        HttpContext httpContext, string orgId, string parsedPurlName, string parsedVersion,
        string file, TokenRecord? token, OrgSettings settings, string? expectedSha256, CancellationToken ct)
#pragma warning restore S107
    {
        // Proxy cache-hit path: look up via the global plane.
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var caFacts = await cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "pypi", parsedPurlName, parsedVersion, file, ct);

        if (caFacts is null)
        {
            return new NotFoundResult();
        }

        // Digest check runs only after the AnonymousPull gate above, so a mismatch (and a
        // match) are both invisible to a caller who hasn't already cleared it.
        if (expectedSha256 is not null
            && !string.Equals(caFacts.ContentHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return new NotFoundResult();
        }

        // Re-check the claim on every cache-hit serve, not just on the miss/upstream-fetch
        // path. A surviving cache_artifact row (an in-flight fetch that raced a local_only
        // transition's purge, or air-gap mode's implicit local_only, which never purges) must
        // not be served just because the row still exists — same silent 404 as the miss path
        // so probing can't distinguish "never cached" from "cached but now local_only".
        if (!await claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", parsedPurlName, ct))
        {
            return new NotFoundResult();
        }

        string? sourceIpHead = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(orgId, "pypi", caFacts, token, settings, sourceIpHead), ct)
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
            httpContext.Response.Headers["X-Dependably-PURL"] = HeaderSanitizer.Sanitize(caFacts.Purl);
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

    /// <summary>
    /// HEAD /packages/{h1}/{h2}/{sha256}/{file} — CDN-shaped alias of <see cref="HeadPackageAsync"/>.
    /// <see cref="IsConsistentCdnDigest"/> is pure computation on the route segments (touches no
    /// data, no auth), so it runs before delegation; the digest itself is threaded through as
    /// <paramref name="sha256"/> and compared only after <see cref="HeadPackageAsync"/>'s own auth
    /// gate — see <see cref="DownloadPackageByDigestAsync"/> for why that ordering matters.
    /// </summary>
    public Task<IActionResult> HeadPackageByDigestAsync(
        HttpContext httpContext, string orgId, string h1, string h2, string sha256, string file, CancellationToken ct)
        => !IsConsistentCdnDigest(h1, h2, sha256)
            ? Task.FromResult<IActionResult>(new NotFoundResult())
            : HeadPackageAsync(httpContext, orgId, file, ct, sha256);

    /// <summary>
    /// GET /packages/{h1}/{h2}/{sha256}/{file} — CDN-shaped alias of <see cref="DownloadPackageAsync"/>.
    /// h1/h2/sha256 never drive a filesystem or blob-store path and are never composed into an
    /// outbound URL — only <paramref name="file"/> does that, exactly as on the flat route.
    /// <see cref="IsConsistentCdnDigest"/> is pure computation on the route segments — no data
    /// access, no auth implication — so it runs here, before delegation. The route's regex
    /// constraints already reject anything that isn't exactly 2/2/64 hex characters before this
    /// method is ever invoked; <see cref="IsConsistentCdnDigest"/> repeats the hex/length check in
    /// application code (defense in depth, independently unit-testable without depending on
    /// ASP.NET routing behaviour) and additionally requires h1/h2 to actually be sha256's own
    /// leading four characters — the same decomposition
    /// <see cref="PyPiProxyFetcher.ResolveProxyUpstreamUrlAsync"/> uses to build the outbound CDN
    /// URL, so a garbled shard prefix is rejected as not a real CDN URL.
    /// <para/>
    /// The digest itself is NOT compared here. It is threaded through as <paramref name="sha256"/>
    /// into <see cref="DownloadPackageAsync"/>, which runs completely unchanged, and is checked
    /// against the on-record checksum only at the points that method already has one in hand
    /// (<see cref="TryServeUploadedPackageAsync"/>, <see cref="TryServeProxyCacheHitAsync"/>) —
    /// both strictly AFTER that method's own auth gate. A digest peek run before delegation, like
    /// this method's own <see cref="IsConsistentCdnDigest"/> check, would let an unauthenticated
    /// caller distinguish "digest matches" (falls through to the auth gate, 401) from "digest does
    /// not match" (404 immediately) — a pre-auth oracle for cache contents on an instance with
    /// AnonymousPull disabled. Comparing only past the gate makes the two outcomes identical to
    /// anyone who hasn't already cleared it. On a genuine cache miss nothing is on record yet, so
    /// the digest goes unchecked; <see cref="PyPiProxyFetcher"/>'s existing known-checksum
    /// verification (from the version's stored hash or the upstream simple index's
    /// <c>#sha256=</c> fragment) still runs on the fetch path unchanged.
    /// </summary>
    public Task<IActionResult> DownloadPackageByDigestAsync(
        HttpContext httpContext, string orgId, string h1, string h2, string sha256, string file, CancellationToken ct)
        => !IsConsistentCdnDigest(h1, h2, sha256)
            ? Task.FromResult<IActionResult>(new NotFoundResult())
            : DownloadPackageAsync(httpContext, orgId, file, ct, sha256);

    // True only when sha256 is a 64-character hex digest and h1/h2 are literally its own leading
    // four characters — independent of the route's regex constraints, so this rejects a
    // traversal-shaped or malformed digest segment even if invoked directly. Pure computation on
    // the route segments only — no data access, so it carries no pre-auth disclosure risk.
    private static bool IsConsistentCdnDigest(string h1, string h2, string sha256) =>
        sha256.Length == PyPiConstants.CdnSha256Length
        && sha256.All(Uri.IsHexDigit)
        && string.Equals(sha256[..PyPiConstants.CdnPrefixLength], h1, StringComparison.OrdinalIgnoreCase)
        && string.Equals(sha256[PyPiConstants.CdnSecondSegmentStart..PyPiConstants.CdnSecondSegmentEnd], h2, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// GET /packages/{file} — blob download with proxy cache (tenant-implicit from host).
    /// <paramref name="expectedSha256"/> is optional — set only by the CDN-shaped alias in
    /// <see cref="DownloadPackageByDigestAsync"/> — and is compared to the on-record checksum
    /// only AFTER the same auth gate every other caller goes through first (see
    /// <see cref="TryServeUploadedPackageAsync"/>/<see cref="TryServeProxyCacheHitAsync"/>), so an
    /// unauthenticated caller learns nothing about whether a digest matches.
    /// </summary>
    public async Task<IActionResult> DownloadPackageAsync(
        HttpContext httpContext, string orgId, string file, CancellationToken ct, string? expectedSha256 = null)
    {
        // The filename flows into upstream URLs (files.pythonhosted.org path, simple-index
        // resolution) — reject traversal-shaped values before any DB / upstream work,
        // mirroring the upload-side validation.
        if (!PathSafeValidator.ValidateUpstreamSegment(file, "file").IsValid)
        {
            return new NotFoundResult();
        }

        // Parse name + version up front. PEP 503/440-aware; rejects mis-shaped requests
        // before any DB / upstream work so corrupt filenames can't reach the recorders.
        var (filenameSuccess, parsedPurlName, parsedVersion) = PyPiArtifactValidator.TryParseFilename(file);
        if (!filenameSuccess)
        {
            return new NotFoundResult();
        }

        var parsed = new PyPiFilename(parsedPurlName!, parsedVersion!);

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        string? sourceIp = httpContext.GetNormalizedRemoteIp();

        // Uploaded-only lookup first: proxy rows are no longer in package_versions. The
        // per-file table resolves any distribution file of a version (wheel or sdist), not
        // just the version row's primary artifact.
        var fileHit = await versionFiles.FindFileWithVersionAsync(orgId, "pypi", file, ct);

        if (fileHit is not null)
        {
            var uploadedResult = await TryServeUploadedPackageAsync(
                httpContext, orgId, fileHit.Value, file, token, settings, sourceIp, expectedSha256, ct);
            if (uploadedResult is not null)
            {
                return uploadedResult;
            }
        }
        else
        {
            // No uploaded row. Check the global-plane proxy cache before going to upstream.
            var proxyCacheResult = await TryServeProxyCacheHitAsync(
                httpContext, orgId, parsedPurlName!, parsedVersion!, file, token, settings!, sourceIp, expectedSha256, ct);
            if (proxyCacheResult is not null)
            {
                return proxyCacheResult;
            }
        }

        return await FetchFromUpstreamAsync(
            httpContext, orgId, file, parsed,
            fileHit is { } fh ? (fh.Package, fh.Version) : null,
            token, settings!, sourceIp, ct);
    }

    // Serves an uploaded-origin PyPI artifact if auth and block gates pass. Returns an
    // IActionResult (including 401/403 gate denials or a file stream) when the uploaded file
    // record is found and the blob is in the store, or null when the blob is missing (falls
    // through to upstream).
    // Cohesive uploaded-serve helper; hit tuple + sourceIp + expectedSha256 + ct each carry
    // distinct roles. expectedSha256 (the CDN-alias digest check) is compared only after
    // RequireUploadedAuth — see DownloadPackageByDigestAsync for why that ordering matters.
#pragma warning disable S107
    private async Task<IActionResult?> TryServeUploadedPackageAsync(
        HttpContext httpContext, string orgId,
        (Package Package, PackageVersion Version, PackageVersionFile File) hit, string file,
        TokenRecord? token, OrgSettings? settings, string? sourceIp, string? expectedSha256, CancellationToken ct)
#pragma warning restore S107
    {
        var authErr = RequireUploadedAuth(httpContext, token, settings);
        if (authErr is not null)
        {
            return authErr;
        }

        if (expectedSha256 is not null
            && !string.Equals(hit.File.ChecksumSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return new NotFoundResult();
        }

        var v = hit.Version;
        return await blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "pypi", v, token, settings, sourceIp), ct)
            == BlockDecision.Blocked
            ? new StatusCodeResult(StatusCodes.Status403Forbidden)
            : await TryServeCachedBlobAsync(httpContext, hit, file, orgId, token, sourceIp, ct);
    }

    // Checks the global-plane proxy cache for a PyPI artifact. Returns an IActionResult
    // (including a claim/block-gate denial or a file stream) when a cache_artifact row exists
    // and the blob is in the store, or null when absent (falls through to upstream).
    // Cohesive proxy-cache serve helper; sourceIp is separate from HttpContext for testability.
    // expectedSha256 (the CDN-alias digest check) is compared only after the AnonymousPull gate
    // just below — see DownloadPackageByDigestAsync for why that ordering matters.
#pragma warning disable S107
    private async Task<IActionResult?> TryServeProxyCacheHitAsync(
        HttpContext httpContext, string orgId, string parsedPurlName, string parsedVersion,
        string file, TokenRecord? token, OrgSettings settings, string? sourceIp, string? expectedSha256, CancellationToken ct)
#pragma warning restore S107
    {
        // No uploaded row. Check the global-plane proxy cache before going to upstream.
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var caFacts = await cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "pypi", parsedPurlName, parsedVersion, file, ct);

        if (caFacts is null)
        {
            return null;
        }

        if (expectedSha256 is not null
            && !string.Equals(caFacts.ContentHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return new NotFoundResult();
        }

        // Re-check the claim on every cache-hit serve, not just on the miss/upstream-fetch
        // path in FetchFromUpstreamAsync below. A surviving cache_artifact row (an in-flight
        // fetch that raced a local_only transition's purge, or air-gap mode's implicit
        // local_only, which never purges) must not be served just because the row still
        // exists — same silent 404 the miss path returns for a local_only/reserved name.
        if (!await claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", parsedPurlName, ct))
        {
            return new NotFoundResult();
        }

        // Ternary form satisfies IDE0046: last guard before a single return expression.
        return await (await blockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(orgId, "pypi", caFacts, token, settings, sourceIp), ct)
            == BlockDecision.Blocked
            ? Task.FromResult<IActionResult?>(new StatusCodeResult(StatusCodes.Status403Forbidden))
            : TryServeProxyCachedBlobAsync(httpContext, caFacts, file, orgId, token, sourceIp, ct));
    }

    // Proxies a PyPI artifact from upstream on a cache miss. Evaluates the allowlist/blocklist,
    // passthrough, and claim gates before triggering the outbound fetch.
    // Cohesive upstream-fetch helper; pkgVersions + parsed each carry distinct resolution state.
#pragma warning disable S107
    private async Task<IActionResult> FetchFromUpstreamAsync(
        HttpContext httpContext, string orgId, string file, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions,
        TokenRecord? token, OrgSettings settings, string? sourceIp, CancellationToken ct)
#pragma warning restore S107
    {
        // Cache miss — proxy from upstream.
        httpContext.Response.Headers["X-Cache"] = "MISS";
        var bases = await registries.ResolveAsync(orgId, "pypi", ct);
        var resolved = await proxyFetcher.ResolveProxyUpstreamUrlAsync(file, parsed, pkgVersions, bases, ct);
        if (resolved is null)
        {
            return new NotFoundResult();
        }

        var gateError = await proxyFetcher.CheckProxyAllowlistBlocklistAsync(orgId, parsed, token, settings, sourceIp, ct);
        if (gateError is not null)
        {
            return gateError;
        }

        if (!settings.ProxyPassthroughEffective)
        {
            return new NotFoundResult();
        }

        // Claim state and reserved namespaces gate the proxy fetch. local_only (including
        // air-gap implicit local_only) and reserved names disable proxy serving with the
        // same silent 404.
        string purlNameForClaim = pkgVersions?.Package.PurlName ?? parsed.PurlName;
        return await reserved.IsReservedAsync(orgId, "pypi", purlNameForClaim, ct)
            || !await claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlNameForClaim, ct)
            ? new NotFoundResult()
            : await proxyFetcher.FetchAndCacheUpstreamAsync(
                httpContext,
                new PyPiProxyDownload(file, resolved.Value.Url, resolved.Value.Sha256Hex, parsed, pkgVersions, resolved.Value.AuthorizationHeader),
                new ProxyContext(orgId, token?.UserId, token?.ActorKind, settings, sourceIp),
                ct);
    }

    // Auth gate for uploaded-origin versions: when AnonymousPull is disabled (or settings is
    // null, fail-closed), a token is required. When a token is present, ReadMetadata is required.
    private static IActionResult? RequireUploadedAuth(HttpContext httpContext, TokenRecord? token, OrgSettings? settings)
    {
        if ((settings is null || !settings.AnonymousPull) && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }
        return token is not null && !token.HasCapability(Capabilities.ReadMetadata) ? new ForbidResult() : (IActionResult?)null;
    }

    private async Task<IActionResult?> TryServeCachedBlobAsync(
        HttpContext httpContext,
        (Package Package, PackageVersion Version, PackageVersionFile File) hit, string file, string orgId,
        TokenRecord? token, string? sourceIp, CancellationToken ct)
    {
        // Blob facts come from the requested FILE record (wheel and sdist of one release are
        // distinct blobs with distinct checksums); version facts cover purl + counters.
        // 304 short-circuit: check the client's cached copy before opening the blob stream.
        if (hit.File.ChecksumSha256 is not null)
        {
            string uploadedEtag = $"\"sha256:{hit.File.ChecksumSha256}\"";
            if (ConditionalRequestHelper.IfNoneMatchHits(httpContext.Request.Headers, uploadedEtag))
            {
                httpContext.Response.Headers.ETag = uploadedEtag;
                httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
                return new StatusCodeResult(StatusCodes.Status304NotModified);
            }
        }

        var blob = await blobs.GetAsync(BlobKeys.StoreKey(hit.File.BlobKey), ct);
        if (blob is null)
        {
            return null;
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = HeaderSanitizer.Sanitize(hit.Version.Purl);
        if (hit.File.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{hit.File.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await audit.LogActivityAsync(orgId, "pypi", hit.Version.Purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        await packages.IncrementDownloadCountAsync(hit.Version.Id, ct);
        return new FileStreamResult(blob, "application/octet-stream") { FileDownloadName = file };
    }

    private async Task<IActionResult?> TryServeProxyCachedBlobAsync(
        HttpContext httpContext,
        CacheArtifactServeFacts caFacts, string file, string orgId,
        TokenRecord? token, string? sourceIp, CancellationToken ct)
    {
        // 304 short-circuit: check the client's cached copy before opening the blob stream.
        if (!string.IsNullOrEmpty(caFacts.ContentHash))
        {
            string cachedEtag = $"\"sha256:{caFacts.ContentHash}\"";
            if (ConditionalRequestHelper.IfNoneMatchHits(httpContext.Request.Headers, cachedEtag))
            {
                httpContext.Response.Headers.ETag = cachedEtag;
                httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
                return new StatusCodeResult(StatusCodes.Status304NotModified);
            }
        }

        // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey maps to the cache tier.
        var blob = await blobs.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
        if (blob is null)
        {
            return null;
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        if (caFacts.Purl is not null)
        {
            httpContext.Response.Headers["X-Dependably-PURL"] = HeaderSanitizer.Sanitize(caFacts.Purl);
        }
        if (!string.IsNullOrEmpty(caFacts.ContentHash))
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{caFacts.ContentHash}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        if (caFacts.Purl is not null)
        {
            await audit.LogActivityAsync(orgId, "pypi", caFacts.Purl, "download", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        }
        // Increment per-tenant download count on the global plane. Enqueued off the request
        // path — the row already exists (seeded durably at first-fetch).
        await tenantAccess.RecordDownloadHitAsync(orgId, caFacts.Id, time.GetUtcNow(), ct);
        return new FileStreamResult(blob, "application/octet-stream") { FileDownloadName = file };
    }
}
