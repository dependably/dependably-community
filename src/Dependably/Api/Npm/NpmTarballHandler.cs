using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Handles npm tarball download endpoints (GET and HEAD) for both the rewritten
/// <c>/npm/tarballs/…</c> paths and the conventional <c>/npm/{pkg}/-/{file}</c> paths.
/// Routes by per-version origin; proxy cache-miss fetches are single-flighted via
/// <see cref="ProxyFetchService"/>.
/// </summary>
public sealed class NpmTarballHandler(
    OrgRepository orgs,
    PackageRepository packages,
    TokenRepository tokens,
    AuditRepository audit,
    IBlobStore blobs,
    UpstreamClient upstream,
    AllowlistService allowlist,
    BlocklistRepository blocklist,
    BlockGateService blockGate,
    ClaimResolver claimResolver,
    ReservedNamespaceService reserved,
    ProxyFetchService proxyFetch,
    UpstreamRegistryResolver registries)
{
    public Task<IActionResult> GetTarballAsync(
        HttpContext httpContext, string orgId, string pkg, string file, CancellationToken ct)
    {
        string fullName = NpmSharedHelpers.DecodeNpmName(pkg);
        string shortName = fullName.Contains('/') ? fullName[(fullName.LastIndexOf('/') + 1)..] : fullName;
        return GetTarballImplAsync(httpContext, orgId, fullName, shortName, file, ct);
    }

    public Task<IActionResult> GetScopedTarballAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string file, CancellationToken ct)
        => GetTarballImplAsync(httpContext, orgId, fullName: "@" + scope + "/" + pkg, shortName: pkg, file, ct);

    public Task<IActionResult> GetTarballConventionalAsync(
        HttpContext httpContext, string orgId, string pkg, string file, CancellationToken ct)
        => GetTarballAsync(httpContext, orgId, pkg, file, ct);

    public Task<IActionResult> GetScopedTarballConventionalAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string file, CancellationToken ct)
        => GetScopedTarballAsync(httpContext, orgId, scope, pkg, file, ct);

    public Task<IActionResult> HeadTarballAsync(
        HttpContext httpContext, string orgId, string pkg, string file, CancellationToken ct)
    {
        string fullName = NpmSharedHelpers.DecodeNpmName(pkg);
        string shortName = fullName.Contains('/') ? fullName[(fullName.LastIndexOf('/') + 1)..] : fullName;
        return HeadTarballImplAsync(httpContext, orgId, fullName, shortName, file, ct);
    }

    public Task<IActionResult> HeadScopedTarballAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string file, CancellationToken ct)
        => HeadTarballImplAsync(httpContext, orgId, fullName: "@" + scope + "/" + pkg, shortName: pkg, file, ct);

    public Task<IActionResult> HeadTarballConventionalAsync(
        HttpContext httpContext, string orgId, string pkg, string file, CancellationToken ct)
        => HeadTarballAsync(httpContext, orgId, pkg, file, ct);

    public Task<IActionResult> HeadScopedTarballConventionalAsync(
        HttpContext httpContext, string orgId, string scope, string pkg, string file, CancellationToken ct)
        => HeadScopedTarballAsync(httpContext, orgId, scope, pkg, file, ct);

    /// <summary>
    /// Returns headers (size, checksum, content-type) for an npm tarball without opening the
    /// blob stream. Enforces the same auth and block gates as <see cref="GetTarballImplAsync"/>.
    /// Returns 404 when the version is not cached locally; the client can issue a GET to fetch
    /// and cache the tarball from upstream.
    /// </summary>
    private async Task<IActionResult> HeadTarballImplAsync(
        HttpContext httpContext, string orgId, string fullName, string shortName, string file, CancellationToken ct)
    {
        if (!NpmSharedHelpers.IsUpstreamSafeNpmName(fullName) ||
            !PathSafeValidator.ValidateUpstreamSegment(file, "file").IsValid)
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);
        var pkgVersion = await LookupVersionByFilenameAsync(orgId, fullName, shortName, file, ct);

        if (pkgVersion is null)
        {
            // No local record — treat as a proxy cache-miss; return 404.
            return new NotFoundResult();
        }

        // Auth gate mirrors GET: hosted requires a token; proxy follows AnonymousPull.
        var authResult = await CheckTarballOriginGateAsync(httpContext, new TarballLookup(orgId, fullName, file, pkgVersion), token, settings, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
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

        // Confirm the blob is present without opening a stream.
        string blobKey = BlobKeys.StoreKey(pkgVersion.BlobKey);
        bool exists = await blobs.ExistsAsync(blobKey, ct);
        if (!exists)
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "HIT";
        httpContext.Response.Headers["X-Dependably-PURL"] = NpmSharedHelpers.SanitizeHeader(pkgVersion.Purl);
        httpContext.Response.ContentType = "application/octet-stream";
        httpContext.Response.Headers["Content-Length"] = pkgVersion.SizeBytes.ToString();
        if (pkgVersion.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        return new OkResult();
    }

    // Identifies the tarball being served: org scope, npm package name, filename, and the
    // resolved version record. Bundled to keep CheckTarballOriginGateAsync under S107.
    private sealed record TarballLookup(
        string OrgId, string FullName, string File, PackageVersion Version);

    // Checks the per-origin auth gate for a tarball request: uploaded versions require a
    // token with ReadArtifact; proxy versions run the shared proxy gate (allowlist/blocklist).
    // Also validates that the blob key matches the requested filename — a mismatch means the
    // DB row exists but the file segment doesn't match (e.g. old rename artefact). Returns a
    // non-null IActionResult when the gate denies access or the filename check fails.
    private async Task<IActionResult?> CheckTarballOriginGateAsync(
        HttpContext httpContext, TarballLookup lookup,
        TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        if (lookup.Version.Origin == "uploaded")
        {
            if (token is null)
            {
                httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
                return new UnauthorizedResult();
            }
            if (!token.HasCapability(Capabilities.ReadArtifact))
            {
                return new ForbidResult();
            }
        }
        else
        {
            // Proxy version — run the same gates as GET: auth, allowlist, blocklist.
            var gate = await CheckProxyGatesAsync(httpContext, lookup.OrgId, lookup.FullName, token, settings!, ct);
            if (gate is not null)
            {
                return gate;
            }
        }

        // Filename mismatch: the DB row exists but the file segment in the URL doesn't match
        // the stored blob key — treat as 404 to avoid leaking a neighbouring file path.
        return !lookup.Version.BlobKey.EndsWith("/" + lookup.File, StringComparison.OrdinalIgnoreCase)
            ? new NotFoundResult()
            : null;
    }

    private async Task<IActionResult> GetTarballImplAsync(
        HttpContext httpContext, string orgId, string fullName, string shortName, string file, CancellationToken ct)
    {
        // Name and filename flow into the upstream proxy URL ({base}/{fullName}/-/{file}) —
        // reject traversal-shaped values before any lookup or upstream call, mirroring the
        // upload-side validation.
        if (!NpmSharedHelpers.IsUpstreamSafeNpmName(fullName) ||
            !PathSafeValidator.ValidateUpstreamSegment(file, "file").IsValid)
        {
            return new NotFoundResult();
        }

        var settings = await orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens behave as anonymous (respecting AnonymousPull).
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        // Route by per-version origin, not packages.is_proxy. Extract version from the tarball
        // filename ({shortName}-{version}.tgz) and branch on that row's origin.
        var pkgVersion = await LookupVersionByFilenameAsync(orgId, fullName, shortName, file, ct);

        if (pkgVersion is not null && pkgVersion.Origin == "uploaded")
        {
            return await ServeHostedTarballVersionAsync(httpContext, orgId, pkgVersion, file, token, settings!, ct);
        }

        if (pkgVersion is not null && pkgVersion.Origin == "proxy")
        {
            var cached = await ServeCachedProxyTarballAsync(httpContext, orgId, pkgVersion, file, token, settings!, ct);
            if (cached is not null)
            {
                return cached;
            }
            // Same version row exists but the cached blob doesn't match the requested file — fall through.
        }

        var gate = await CheckProxyGatesAsync(httpContext, orgId, fullName, token, settings!, ct);
        if (gate is not null)
        {
            return gate;
        }

        // Claim state and reserved namespaces gate the proxy fetch — both reject with the
        // same silent 404 so probing cannot map which internal names exist.
        return await reserved.IsReservedAsync(orgId, "npm", fullName, ct)
            || !await claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", fullName, ct)
            ? new NotFoundResult()
            : await ProxyFetchAndCacheAsync(httpContext, new NpmTarballKey(orgId, fullName, shortName, file), token, settings!, ct);
    }

    // Looks up the package version record whose tarball filename matches the request.
    private async Task<PackageVersion?> LookupVersionByFilenameAsync(
        string orgId, string fullName, string shortName, string file, CancellationToken ct)
    {
        var pkgRecord = await packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);
        string? versionFromFilename = NpmSharedHelpers.ExtractVersionFromTarballFilename(shortName, file);
        return pkgRecord is null || versionFromFilename is null
            ? null
            : await packages.GetVersionAsync(pkgRecord.Id, versionFromFilename, ct);
    }

    // Evaluates allowlist, blocklist, and proxy-passthrough gates for the proxy fetch path.
    // Returns null when all gates pass; returns the blocking IActionResult otherwise.
    private async Task<IActionResult?> CheckProxyGatesAsync(
        HttpContext httpContext, string orgId, string fullName,
        TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        string purlCheck = PurlNormalizer.Npm(fullName, "0.0.0").Split('@')[0]; // name-only PURL
        if (settings.AllowlistMode && !await allowlist.IsAllowedAsync(orgId, purlCheck, ct))
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        if (await blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await audit.LogActivityAsync(orgId, "npm", purlCheck, "blocked", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: httpContext.GetNormalizedRemoteIp(), ct: ct);
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        return !settings.ProxyPassthroughEffective ? new NotFoundResult() : null;
    }

    private async Task<IActionResult> ServeHostedTarballVersionAsync(
        HttpContext httpContext, string orgId, PackageVersion pkgVersion, string file,
        TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }
        if (!token.HasCapability(Capabilities.ReadArtifact))
        {
            return new ForbidResult();
        }

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
        {
            return new NotFoundResult();
        }

        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
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
        httpContext.Response.Headers["X-Dependably-PURL"] = NpmSharedHelpers.SanitizeHeader(pkgVersion.Purl);
        if (pkgVersion.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await audit.LogActivityAsync(orgId, "npm", pkgVersion.Purl, "download", token.UserId,
            actorKind: token.ActorKind, sourceIp: sourceIp, ct: ct);
        await packages.IncrementDownloadCountAsync(pkgVersion.Id, ct);
        return new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    private async Task<IActionResult?> ServeCachedProxyTarballAsync(
        HttpContext httpContext, string orgId, PackageVersion pkgVersion, string file,
        TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        string? sourceIp = httpContext.GetNormalizedRemoteIp();
        if (await blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
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
        httpContext.Response.Headers["X-Dependably-PURL"] = NpmSharedHelpers.SanitizeHeader(pkgVersion.Purl);
        if (pkgVersion.ChecksumSha256 is not null)
        {
            httpContext.Response.Headers.ETag = $"\"sha256:{pkgVersion.ChecksumSha256}\"";
            httpContext.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await audit.LogActivityAsync(orgId, "npm", pkgVersion.Purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        await packages.IncrementDownloadCountAsync(pkgVersion.Id, ct);
        return new FileStreamResult(stream, "application/octet-stream") { FileDownloadName = file };
    }

    // Identifies a proxied npm tarball request: org scope, full package name, short name,
    // and filename. Bundled to keep ProxyFetchAndCacheAsync under S107.
    private sealed record NpmTarballKey(
        string OrgId, string FullName, string ShortName, string File);

    private async Task<IActionResult> ProxyFetchAndCacheAsync(
        HttpContext httpContext, NpmTarballKey key,
        TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // Walk the org's configured upstreams in priority order. No configured upstream ⇒
        // proxying is disabled for npm, so a miss is a 404 (mirrors ProxyPassthroughEnabled=false).
        var bases = await registries.ResolveAsync(key.OrgId, "npm", ct);
        if (bases.Count == 0)
        {
            return new NotFoundResult();
        }

        httpContext.Response.Headers["X-Cache"] = "MISS";

        try
        {
            var fetched = await FetchTarballFromUpstreamsAsync(bases, key.FullName, key.File, key.OrgId, ct);
            if (fetched is null)
            {
                return new NotFoundResult();
            }

            var (fetchResult, upstreamBase, upstreamUrl) = fetched.Value;

            string baseName = key.File.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? key.File[..^4] : key.File;
            string version = baseName.Length > key.ShortName.Length + 1 ? baseName[(key.ShortName.Length + 1)..] : "unknown";
            string purl = PurlNormalizer.Npm(key.FullName, version);

            var meta = await TryFetchNpmFirstFetchMetadataAsync(upstreamBase, key.FullName, version, ct);

            // The streaming MISS path already wrote the blob and computed the SHA-256 inline —
            // no large byte[] allocation needed. Wrap the result in a BlobHandle so
            // ProxyFetchService can open a fresh blob-store stream for licence extraction
            // or non-SHA-256 checksum re-verification without buffering.
            string proxyKey = fetchResult.BlobKey;
            string sha = fetchResult.Sha256Hex;
            long sizeBytes = fetchResult.SizeBytes;
            var blob = new BlobHandle(proxyKey, sha, sizeBytes,
                async openCt => await blobs.GetAsync(proxyKey, openCt)
                    ?? Stream.Null);

            // deepcode ignore PT,LogForging: ProxyFetchService stores under BlobKeys.Proxy(sha256),
            // which validates a 64-char lowercase hex — path traversal cannot escape that key. All
            // structured logs use Serilog RenderedCompactJsonFormatter (CRLF-safe).
            var result = await proxyFetch.RecordAndScanAsync(
                BuildNpmProxyFetchRequest(httpContext, key.OrgId, key.FullName, version, purl, key.File, blob, upstreamUrl, token, settings, meta), ct);

            if (result.Decision == BlockDecision.Blocked)
            {
                return new StatusCodeResult(StatusCodes.Status403Forbidden);
            }

            // Stream the cached blob back to the client (response memory is one read
            // buffer, not the whole artefact).
            var blobStream = await blobs.GetAsync(result.BlobKey, ct);
            return blobStream is null
                ? new NotFoundResult()
                : new FileStreamResult(blobStream, "application/octet-stream") { FileDownloadName = key.File };
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch (ChecksumException)
        {
            // Upstream bytes didn't match upstream-supplied integrity — refuse the response
            // rather than serve poison. ProxyFetchService already audited + emitted the metric.
            return new StatusCodeResult(StatusCodes.Status502BadGateway);
        }
        catch (UpstreamResponseTooLargeException)
        {
            // Upstream body crossed the streaming cap — a malformed or hostile upstream.
            return new StatusCodeResult(StatusCodes.Status502BadGateway);
        }
        catch (UpstreamFetchFailedException)
        {
            // Transient upstream exhausted retries — propagate so the middleware maps it to a
            // retryable 503/502 instead of a hard 403/404 that aborts the install.
            throw;
        }
        catch
        {
            return new NotFoundResult();
        }
    }

    // Walks upstreams in priority order; streams and stages the first successful tarball
    // to disk, hashing inline. Memory usage is bounded by the staging buffer regardless of
    // artifact size. Returns (UpstreamFetchResult, upstreamBase, upstreamUrl) on success,
    // or null when no upstream returns a success response. Single-flight: concurrent
    // first-fetches of the same tarball coordinate share one upstream call.
    private async Task<(UpstreamFetchResult FetchResult, string UpstreamBase, string UpstreamUrl)?> FetchTarballFromUpstreamsAsync(
        IReadOnlyList<string> bases, string fullName, string file, string orgId, CancellationToken ct)
    {
        foreach (string candidateBase in bases)
        {
            string candidateUrl = $"{candidateBase}/{fullName}/-/{file}";
            try
            {
                // Streams upstream → staging file (hashing inline) → blob store.
                // No upstream checksum is known at request time; the ingest-time SHA-256
                // computed inline is the canonical reference and is verified by the
                // upstream-declared hash in ProxyFetchService after staging.
                var fetchResult = await upstream.FetchAndCacheByUrlAsync(
                    candidateUrl, null, "npm", orgId, ct);
                return (fetchResult, candidateBase, candidateUrl);
            }
            catch (HttpRequestException)
            {
                // Unreachable upstream — try the next one. Checksum, size-cap, SSRF, and
                // air-gap failures are not HttpRequestExceptions; they propagate to the
                // caller instead of falling through to the next upstream.
            }
        }

        return null;
    }

    // Builds the ProxyFetchRequest record for an npm tarball, including integrity metadata
    // from the upstream packument. npm publishes integrity as an SRI string ("sha512-{b64}") —
    // stored verbatim; null when upstream only sent shasum or no integrity at all.
    // The parameters are the assembly inputs of the ProxyFetchRequest record itself; grouping
    // them into an intermediate type would add indirection without cohesion.
#pragma warning disable S107
    private static ProxyFetchRequest BuildNpmProxyFetchRequest(
        HttpContext httpContext, string orgId, string fullName, string version, string purl, string file,
        BlobHandle blob, string upstreamUrl, TokenRecord? token, OrgSettings settings,
        NpmFirstFetchMetadata meta)
#pragma warning restore S107
    {
        var (integrityValue, integrityAlgo) = meta.IntegritySri is not null
            ? (meta.IntegritySri, "sha512-sri")
            : ((string?)null, (string?)null);

        return new ProxyFetchRequest(
            OrgId: orgId, Ecosystem: "npm",
            PackageName: fullName, PurlName: fullName,
            Version: version, Purl: purl, File: file, Blob: blob,
            ExtractLicenses: LicenseExtractor.FromNpmTarballPackageJson,
            UserId: token?.UserId,
            ActorKind: token?.ActorKind,
            SourceIp: httpContext.GetNormalizedRemoteIp(),
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            CacheAccess: new CacheAccess(orgId, "npm", fullName, version, file,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: upstreamUrl),
            PublishedAt: meta.PublishedAt,
            UpstreamChecksum: meta.Checksum,
            Sha1Hex: meta.Sha1Hex,
            UpstreamIntegrityValue: integrityValue,
            UpstreamIntegrityAlgorithm: integrityAlgo,
            Deprecated: meta.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance);
    }

    /// <summary>
    /// Fetches the npm packument once on proxy first-fetch and extracts everything we care
    /// about: the per-version published timestamp, an upstream integrity spec for fail-fast
    /// verification (<c>dist.integrity</c> SRI sha512 preferred, <c>dist.shasum</c> SHA-1
    /// fallback), the raw <c>dist.shasum</c> hex so the packument we re-emit later can carry
    /// the correct SHA-1, and the verbatim SRI string for the version detail UI. Fail-soft:
    /// any error returns a record full of nulls and the caller proceeds without verification
    /// or capture.
    /// </summary>
    private async Task<NpmFirstFetchMetadata> TryFetchNpmFirstFetchMetadataAsync(
        string upstreamBase, string fullName, string version, CancellationToken ct)
    {
        try
        {
            // Route through single-flighted metadata fetch — TryFetchNpmFirstFetchMetadataAsync
            // is called inline with the tarball-fetch handler, so a stampede on the tarball
            // path otherwise drives a duplicate stampede on the packument URL too.
            var resp = await upstream.GetOrFetchMetadataAsync($"{upstreamBase}/{fullName}", ct);
            if (!resp.IsSuccessStatusCode)
            {
                return NpmFirstFetchMetadata.Empty;
            }

            string json = resp.BodyAsString();
            var node = System.Text.Json.Nodes.JsonNode.Parse(json);

            DateTimeOffset? publishedAt = null;
            string? timeStr = node?["time"]?[version]?.GetValue<string>();
            if (DateTimeOffset.TryParse(timeStr, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
            {
                publishedAt = ts;
            }

            var versionNode = node?["versions"]?[version];
            var dist = versionNode?["dist"];
            string? integrity = dist?["integrity"]?.GetValue<string>();
            string? shasum = dist?["shasum"]?.GetValue<string>();
            var checksum = ChecksumVerifier.ParseNpmIntegrity(integrity, shasum);

            // Only surface the integrity string when it's actually the SHA-512 SRI form; older
            // packages might carry a non-SRI value in this field, in which case the UI label
            // ("SHA-512 SRI") would lie. Anything else stays NULL.
            string? integritySri = integrity is not null
                && integrity.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase)
                ? integrity : null;

            string? deprecated = LicenseExtractor.FromNpmPackumentVersion(versionNode).Deprecated;

            return new NpmFirstFetchMetadata(publishedAt, checksum, shasum, integritySri, deprecated);
        }
        catch { return NpmFirstFetchMetadata.Empty; }
    }

    private readonly record struct NpmFirstFetchMetadata(
        DateTimeOffset? PublishedAt,
        ChecksumSpec? Checksum,
        string? Sha1Hex,
        string? IntegritySri,
        string? Deprecated)
    {
        public static NpmFirstFetchMetadata Empty => new(null, null, null, null, null);
    }
}
