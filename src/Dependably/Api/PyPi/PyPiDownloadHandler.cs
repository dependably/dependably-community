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
    /// </summary>
    public async Task<IActionResult> HeadPackageAsync(
        HttpContext httpContext, string orgId, string file, CancellationToken ct)
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

        // Uploaded-only lookup: proxy versions are served via the global plane below.
        var pkgVersions = await packages.FindVersionByBlobKeySuffixAsync(orgId, "pypi", file, ct: ct);

        return pkgVersions is not null
            ? await HeadUploadedPackageAsync(httpContext, orgId, pkgVersions.Value.Version, token, settings, ct)
            : await HeadProxyCachedPackageAsync(
                httpContext, orgId, parsedPurlName!, parsedVersion!, file, token, settings!, ct);
    }

    // Returns HEAD headers for an uploaded-origin PyPI artifact. Requires a valid token;
    // runs the block gate; returns 401/403/404 when denied or absent.
    private async Task<IActionResult> HeadUploadedPackageAsync(
        HttpContext httpContext, string orgId, PackageVersion v,
        TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        // Uploaded version found — auth required.
        var authErr = RequireUploadedAuth(httpContext, token);
        if (authErr is not null)
        {
            return authErr;
        }

        string? srcIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "pypi", v, token, settings, srcIp), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        string blobKeyUploaded = BlobKeys.StoreKey(v.BlobKey);
        if (!await blobs.ExistsAsync(blobKeyUploaded, ct))
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(v.Purl);
        httpContext.Response.ContentType = "application/octet-stream";
        httpContext.Response.Headers["Content-Length"] = v.SizeBytes.ToString();
        if (v.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{v.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        return new OkResult();
    }

    // Returns HEAD headers for a proxy-cached PyPI artifact from the global plane. Enforces
    // the AnonymousPull gate, then runs the block gate; returns 401/403/404 when denied or absent.
    // Cohesive HEAD serve helper; all params are required for auth, block-gate, and blob lookup.
#pragma warning disable S107
    private async Task<IActionResult> HeadProxyCachedPackageAsync(
        HttpContext httpContext, string orgId, string parsedPurlName, string parsedVersion,
        string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
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

        string? sourceIpHead = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                BuildProxyBlockGateRequest(orgId, caFacts, token, settings, sourceIpHead), ct)
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

    /// <summary>GET /packages/{file} — blob download with proxy cache (tenant-implicit from host)</summary>
    public async Task<IActionResult> DownloadPackageAsync(
        HttpContext httpContext, string orgId, string file, CancellationToken ct)
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

        // Uploaded-only lookup first: proxy rows are no longer in package_versions.
        var pkgVersions = await packages.FindVersionByBlobKeySuffixAsync(orgId, "pypi", file, ct: ct);

        if (pkgVersions is not null)
        {
            var uploadedResult = await TryServeUploadedPackageAsync(
                httpContext, orgId, pkgVersions.Value, file, token, settings, sourceIp, ct);
            if (uploadedResult is not null)
            {
                return uploadedResult;
            }
        }
        else
        {
            // No uploaded row. Check the global-plane proxy cache before going to upstream.
            var proxyCacheResult = await TryServeProxyCacheHitAsync(
                httpContext, orgId, parsedPurlName!, parsedVersion!, file, token, settings!, sourceIp, ct);
            if (proxyCacheResult is not null)
            {
                return proxyCacheResult;
            }
        }

        return await FetchFromUpstreamAsync(
            httpContext, orgId, file, parsed, pkgVersions, token, settings!, sourceIp, ct);
    }

    // Serves an uploaded-origin PyPI artifact if auth and block gates pass. Returns an
    // IActionResult (including 401/403 gate denials or a file stream) when the uploaded row is
    // found and the blob is in the store, or null when the blob is missing (falls through to upstream).
    // Cohesive uploaded-serve helper; pkgVer tuple + sourceIp + ct each carry distinct roles.
#pragma warning disable S107
    private async Task<IActionResult?> TryServeUploadedPackageAsync(
        HttpContext httpContext, string orgId,
        (Package Package, PackageVersion Version) pkgVer, string file,
        TokenRecord? token, OrgSettings? settings, string? sourceIp, CancellationToken ct)
#pragma warning restore S107
    {
        // Uploaded version found — auth required.
        var authErr = RequireUploadedAuth(httpContext, token);
        if (authErr is not null)
        {
            return authErr;
        }

        var v = pkgVer.Version;
        return await blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "pypi", v, token, settings, sourceIp), ct)
            == BlockDecision.Blocked
            ? new StatusCodeResult(StatusCodes.Status403Forbidden)
            : await TryServeCachedBlobAsync(httpContext, pkgVer, file, orgId, token, sourceIp, ct);
    }

    // Checks the global-plane proxy cache for a PyPI artifact. Returns an IActionResult
    // (including a block-gate denial or a file stream) when a cache_artifact row exists and
    // the blob is in the store, or null when absent (falls through to upstream).
    // Cohesive proxy-cache serve helper; sourceIp is separate from HttpContext for testability.
#pragma warning disable S107
    private async Task<IActionResult?> TryServeProxyCacheHitAsync(
        HttpContext httpContext, string orgId, string parsedPurlName, string parsedVersion,
        string file, TokenRecord? token, OrgSettings settings, string? sourceIp, CancellationToken ct)
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

        // Ternary form satisfies IDE0046: last guard before a single return expression.
        return await (await blockGate.EvaluateAsync(
                BuildProxyBlockGateRequest(orgId, caFacts, token, settings, sourceIp), ct)
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
                new PyPiProxyDownload(file, resolved.Value.Url, resolved.Value.Sha256Hex, parsed, pkgVersions),
                new ProxyContext(orgId, token?.UserId, token?.ActorKind, settings, sourceIp),
                ct);
    }

    // Auth gate for uploaded-origin versions: token required, ReadMetadata capability required.
    private static IActionResult? RequireUploadedAuth(HttpContext httpContext, TokenRecord? token)
    {
        if (token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }
        return !token.HasCapability(Capabilities.ReadMetadata) ? new ForbidResult() : (IActionResult?)null;
    }

    // Builds a BlockGateRequest for a proxy artifact from global-plane serve facts.
    private static BlockGateRequest BuildProxyBlockGateRequest(
        string orgId, CacheArtifactServeFacts caFacts, TokenRecord? token,
        OrgSettings settings, string? sourceIp) =>
        new(orgId, "pypi", caFacts.Purl ?? string.Empty, string.Empty,
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

    private async Task<IActionResult?> TryServeCachedBlobAsync(
        HttpContext httpContext,
        (Package Package, PackageVersion Version) pkgVer, string file, string orgId,
        TokenRecord? token, string? sourceIp, CancellationToken ct)
    {
        var blob = await blobs.GetAsync(BlobKeys.StoreKey(pkgVer.Version.BlobKey), ct);
        if (blob is null)
        {
            return null;
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVer.Version.Purl);
        if (pkgVer.Version.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{pkgVer.Version.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await audit.LogActivityAsync(orgId, "pypi", pkgVer.Version.Purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        await packages.IncrementDownloadCountAsync(pkgVer.Version.Id, ct);
        return new FileStreamResult(blob, "application/octet-stream") { FileDownloadName = file };
    }

    private async Task<IActionResult?> TryServeProxyCachedBlobAsync(
        HttpContext httpContext,
        CacheArtifactServeFacts caFacts, string file, string orgId,
        TokenRecord? token, string? sourceIp, CancellationToken ct)
    {
        // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey maps to the cache tier.
        var blob = await blobs.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
        if (blob is null)
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
            await audit.LogActivityAsync(orgId, "pypi", caFacts.Purl, "download", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        }
        // Increment per-tenant download count on the global plane.
        await tenantAccess.UpsertStateAsync(orgId, caFacts.Id, time.GetUtcNow(), ct);
        return new FileStreamResult(blob, "application/octet-stream") { FileDownloadName = file };
    }

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}
