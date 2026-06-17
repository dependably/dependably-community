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
/// </summary>
public sealed class PyPiDownloadHandler(
    OrgRepository orgs,
    PackageRepository packages,
    TokenRepository tokens,
    AuditRepository audit,
    IBlobStore blobs,
    BlockGateService blockGate,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    UpstreamRegistryResolver registries,
    PyPiProxyFetcher proxyFetcher)
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

        if (!PyPiArtifactValidator.TryParseFilename(file).Success)
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        var pkgVersions = await packages.FindVersionByBlobKeySuffixAsync(orgId, "pypi", file, ct);

        var authError = CheckDownloadAuth(httpContext, pkgVersions, token, settings!);
        if (authError is not null)
        {
            return authError;
        }

        if (pkgVersions is null)
        {
            return new NotFoundResult();
        }

        var v = pkgVersions.Value.Version;
        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "pypi", v.Purl, v.Id,
                    v.ManualBlockState, v.VulnCheckedAt,
                    token?.UserId, settings!.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: v.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: v.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated,
                    BlockMaliciousMode: settings.BlockMalicious,
                    BlockKevMode: settings.BlockKev,
                    MaxEpssTolerance: settings.MaxEpssTolerance), ct)
            == BlockDecision.Blocked)
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        // Confirm the blob is present without opening a stream.
        string blobKey = BlobKeys.StoreKey(v.BlobKey);
        bool exists = await blobs.ExistsAsync(blobKey, ct);
        if (!exists)
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
        var pkgVersions = await packages.FindVersionByBlobKeySuffixAsync(orgId, "pypi", file, ct);

        var authError = CheckDownloadAuth(httpContext, pkgVersions, token, settings!);
        if (authError is not null)
        {
            return authError;
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (pkgVersions is not null)
        {
            var v = pkgVersions.Value.Version;
            if (await blockGate.EvaluateAsync(
                    new BlockGateRequest(orgId, "pypi", v.Purl, v.Id,
                        v.ManualBlockState, v.VulnCheckedAt,
                        token?.UserId, settings!.MaxOsvScoreTolerance, sourceIp,
                        MinReleaseAgeHours: settings.MinReleaseAgeHours,
                        PublishedAt: v.PublishedAt,
                        ActorKind: token?.ActorKind,
                        Deprecated: v.Deprecated,
                        BlockDeprecatedMode: settings.BlockDeprecated,
                        BlockMaliciousMode: settings.BlockMalicious,
                        BlockKevMode: settings.BlockKev,
                        MaxEpssTolerance: settings.MaxEpssTolerance), ct)
                == BlockDecision.Blocked)
            {
                return new StatusCodeResult(StatusCodes.Status403Forbidden);
            }

            var cached = await TryServeCachedBlobAsync(httpContext, pkgVersions.Value, file, orgId, token, sourceIp, ct);
            if (cached is not null)
            {
                return cached;
            }
        }

        // Cache miss — proxy from upstream. No configured upstream for pypi ⇒ proxying is
        // disabled for this ecosystem, so a miss is a 404 (mirrors ProxyPassthroughEnabled=false).
        httpContext.Response.Headers["X-Cache"] = "MISS";
        var bases = await registries.ResolveAsync(orgId, "pypi", ct);
        var resolved = await proxyFetcher.ResolveProxyUpstreamUrlAsync(file, parsed, pkgVersions, bases, ct);
        if (resolved is null)
        {
            return new NotFoundResult();
        }

        var gateError = await proxyFetcher.CheckProxyAllowlistBlocklistAsync(orgId, parsed, token, settings!, sourceIp, ct);
        if (gateError is not null)
        {
            return gateError;
        }

        if (!settings!.ProxyPassthroughEffective)
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
                new ProxyContext(orgId, token?.UserId, token?.ActorKind, settings!, sourceIp),
                ct);
    }

    private static IActionResult? CheckDownloadAuth(
        HttpContext httpContext,
        (Package Package, PackageVersion Version)? pkgVersions,
        TokenRecord? token, OrgSettings settings)
    {
        // Route by per-version origin, not the package-level is_proxy flag. A package name
        // can host mixed-origin versions; an uploaded version requires auth even if other
        // versions on the same name are proxy-cached.
        if (pkgVersions is not null && pkgVersions.Value.Version.Origin == "uploaded")
        {
            if (token is null)
            {
                httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return new UnauthorizedResult();
            }
            return !token.HasCapability(Capabilities.ReadMetadata) ? new ForbidResult() : (IActionResult?)null;
        }
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return new UnauthorizedResult();
        }
        return null;
    }

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

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}
