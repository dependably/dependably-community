using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Proxy-fetch infrastructure for the PyPI download path: resolves upstream URLs via the
/// simple-index, fetches and caches blobs, records first-fetch metadata, and runs the
/// block gate after recording. Extracted from <see cref="PyPiDownloadHandler"/> so each
/// class stays under the S1200 coupling limit.
/// </summary>
public sealed class PyPiProxyFetcher(
    AuditRepository audit,
    IBlobStore blobs,
    UpstreamClient upstream,
    AllowlistService allowlist,
    BlocklistRepository blocklist,
    CacheAccessRecorder cacheRecorder,
    ProxyFetchService proxyFetch,
    UpstreamRegistryResolver registries,
    ILogger<PyPiProxyFetcher> logger)
{
    public async Task<IActionResult?> CheckProxyAllowlistBlocklistAsync(
        string orgId, PyPiFilename parsed,
        TokenRecord? token, OrgSettings settings, string? sourceIp, CancellationToken ct)
    {
        string purlCheck = $"pkg:pypi/{parsed.PurlName}";
        if (settings.AllowlistMode && !await allowlist.IsAllowedAsync(orgId, purlCheck, ct))
        {
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        if (await blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await audit.LogActivityAsync(orgId, "pypi", purlCheck, "blocked", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }
        return null;
    }

    public async Task<IActionResult> FetchAndCacheUpstreamAsync(
        HttpContext httpContext, PyPiProxyDownload download, ProxyContext gate, CancellationToken ct)
    {
        string file = download.File;
        string upstreamUrl = download.UpstreamUrl;
        string? upstreamSha256 = download.UpstreamSha256;
        var parsed = download.Parsed;
        var pkgVersions = download.PkgVersions;

        try
        {
            // Verification preference: previously-stored hash > upstream-supplied (#sha256=).
            // Both are SHA-256; we pass whichever we have into UpstreamClient so it can verify
            // before caching and throw ChecksumException → 502 on mismatch.
            string? knownSha = pkgVersions?.Version.ChecksumSha256 ?? upstreamSha256;
            var fetched = await DownloadAndCacheAsync(upstreamUrl, knownSha, gate.OrgId, ct);
            if (fetched is null)
            {
                return new NotFoundResult();
            }

            httpContext.Response.Headers["X-Cache"] = fetched.IsHit ? "HIT" : "MISS";
            if (pkgVersions is not null)
            {
                httpContext.Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersions.Value.Version.Purl);
            }

            // Record into cache_artifact + tenant_artifact_access on every fetch path
            // (hit and miss). Best-effort — recorder swallows failures.
            string purlName = pkgVersions?.Package.PurlName ?? parsed.PurlName;
            string version = pkgVersions?.Version.Version ?? parsed.Version;
            await cacheRecorder.RecordAccessAsync(new CacheAccess(
                gate.OrgId, "pypi", purlName, version, file,
                fetched.Blob.Sha256Hex, fetched.Blob.SizeBytes, fetched.Blob.BlobKey, upstreamUrl), ct);

            if (!fetched.IsHit && pkgVersions is null)
            {
                var firstFetchBlock = await RecordAndScanFirstFetchAsync(file, parsed, fetched.Blob, upstreamSha256, gate, ct);
                if (firstFetchBlock is not null)
                {
                    return firstFetchBlock;
                }
            }

            // The blob is already cached (either pre-existing for HIT, or freshly written
            // by UpstreamClient / DownloadAndCacheAsync for MISS). Open a fresh stream for
            // the response so memory stays bounded regardless of artefact size + concurrency.
            var proxyStream = await fetched.Blob.OpenAsync(ct);
            return new FileStreamResult(proxyStream, "application/octet-stream") { FileDownloadName = file };
        }
        catch (ChecksumException)
        {
            return new StatusCodeResult(StatusCodes.Status502BadGateway);
        }
        catch (UpstreamResponseTooLargeException)
        {
            // Upstream body crossed the read cap (streamed or buffered) — a malformed or
            // hostile upstream, refused rather than served.
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

    /// <summary>
    /// Resolves the upstream download URL and the SHA-256 hash for a given file. If the
    /// stored version already has a checksum, files.pythonhosted.org CDN path is used
    /// directly. Otherwise, the configured upstreams' simple indices are queried in
    /// priority order.
    /// </summary>
    public async Task<(string Url, string? Sha256Hex)?> ResolveProxyUpstreamUrlAsync(
        string file, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions,
        IReadOnlyList<string> bases, CancellationToken ct)
    {
        // No configured upstream ⇒ proxying disabled for pypi; resolve nothing.
        if (bases.Count == 0)
        {
            return null;
        }

        string? sha256 = pkgVersions?.Version.ChecksumSha256;
        if (sha256 is not null)
        {
            string cdnUrl = $"https://files.pythonhosted.org/packages" +
                $"/{sha256[..PyPiConstants.CdnPrefixLength]}" +
                $"/{sha256[PyPiConstants.CdnSecondSegmentStart..PyPiConstants.CdnSecondSegmentEnd]}" +
                $"/{sha256}/{file}";
            return (cdnUrl, sha256);
        }

        // Walk upstreams in priority order; the first whose simple index resolves the file wins.
        foreach (string upstreamBase in bases)
        {
            var resolved = await ResolveUpstreamPyPiUrlAsync(upstreamBase, parsed.PurlName, file, ct);
            if (resolved is not null)
            {
                return (resolved.Value.Url, resolved.Value.Sha256Hex);
            }
        }
        return null;
    }

    /// <summary>
    /// Downloads <paramref name="upstreamUrl"/> into the proxy cache and returns a
    /// <see cref="BlobHandle"/> describing the stored artefact.
    /// <list type="bullet">
    ///   <item><b>Known-sha path:</b> routes through
    ///         <see cref="UpstreamClient.GetOrFetchStreamAsync"/> which hash-and-stages the
    ///         body to disk — no full-artefact byte[] is ever materialised.</item>
    ///   <item><b>Unknown-sha cold-start:</b> still buffers via
    ///         <see cref="UpstreamClient.GetOrFetchMetadataAsync"/> because the cache key
    ///         only exists after hashing. The byte[] residue is bounded to this path and
    ///         wrapped in a <see cref="BlobHandle"/> so all downstream code is
    ///         stream-shaped.</item>
    /// </list>
    /// </summary>
    // deepcode ignore PT,LogForging: blob put uses BlobKeys.Proxy(sha) which validates
    // 64-char lowercase hex; Serilog uses RenderedCompactJsonFormatter (CRLF-safe).
    private async Task<PyPiFetchOutcome?> DownloadAndCacheAsync(
        string upstreamUrl, string? knownSha256, string orgId, CancellationToken ct)
    {
        if (knownSha256 is not null)
        {
            // Known checksum — verify and use content-addressed cache. The streaming
            // variant returns a stream we immediately dispose: subsequent consumers
            // (license extraction, response body) open a fresh blob-store stream via
            // the BlobHandle. SizeBytes is read from the seekable stream's Length when
            // available (LocalBlobStore → FileStream); remote backends that hand back
            // a non-seekable network stream leave SizeBytes at 0, which the cache_artifact
            // recorder tolerates (best-effort, not load-bearing for the proxy fetch).
            string blobKey = BlobKeys.Proxy(knownSha256);
            // deepcode ignore LogForging: blobKey is BlobKeys.Proxy of a 64-char hex SHA-256 (no user input); upstreamUrl is operator-configured; Serilog structured rendering prevents log injection.
            var (stream, isHit) = await upstream.GetOrFetchStreamAsync(
                blobKey, upstreamUrl, new ChecksumSpec(ChecksumAlgorithm.Sha256, knownSha256),
                "pypi", orgId, ct: ct);
            long size = 0;
            await using (stream.ConfigureAwait(false))
            {
                if (stream.CanSeek)
                {
                    size = stream.Length;
                }
            }
            var blob = new BlobHandle(blobKey, knownSha256, size,
                async openCt => await blobs.GetAsync(blobKey, openCt)
                    ?? throw new InvalidOperationException(
                        $"Blob {blobKey} vanished between PutAsync and GetAsync."));
            return new PyPiFetchOutcome(blob, isHit);
        }

        // Unknown checksum — fetch, compute, cache, wrap in a BlobHandle. Route through
        // single-flighted metadata fetch so a stampede of concurrent CI clients
        // pulling an unchecked-sha coordinate triggers just one upstream call.
        //
        // PyPi cold-start residue of the proxy-fetch: the SHA isn't known up front so the
        // content-addressed hash-and-stage pipeline can't route this request. Wrapping the
        // byte[] in a BlobHandle keeps the residue localized — ProxyFetchService,
        // ProxyVersionRecorder, and LicenseExtractor never see a byte[].
        // Artifact bytes flow through the buffered path here, so the cap is the artifact
        // limit, not the (much smaller) default metadata limit.
        var resp = await upstream.GetOrFetchMetadataAsync(
            upstreamUrl, UpstreamClient.MaxUpstreamResponseBytes, ct);
        if (!resp.IsSuccessStatusCode)
        {
            return null;
        }

        byte[] bytes = resp.Body;
        string sha = ChecksumVerifier.ComputeSha256Hex(bytes);
        string proxyKey = BlobKeys.Proxy(sha);
        if (!await blobs.ExistsAsync(proxyKey, ct))
        {
            await blobs.PutAsync(proxyKey, new MemoryStream(bytes), ct);
        }

        var coldBlob = new BlobHandle(proxyKey, sha, bytes.LongLength,
            async openCt => await blobs.GetAsync(proxyKey, openCt)
                ?? (Stream)new MemoryStream(bytes, writable: false));
        return new PyPiFetchOutcome(coldBlob, IsHit: false);
    }

    // deepcode ignore PT,LogForging: bytes are cached under BlobKeys.Proxy(sha) which validates
    // 64-char lowercase hex; Serilog uses RenderedCompactJsonFormatter (CRLF-safe).
    private async Task<IActionResult?> RecordAndScanFirstFetchAsync(
        string file, PyPiFilename parsed, BlobHandle blob, string? upstreamSha256,
        ProxyContext gate, CancellationToken ct)
    {
        string purl = PurlNormalizer.PyPi(parsed.PurlName, parsed.Version);
        // Use the highest-priority configured upstream for the supplementary JSON metadata fetch.
        var bases = await registries.ResolveAsync(gate.OrgId, "pypi", ct);
        var jsonMeta = bases.Count == 0
            ? PyPiJsonMetadata.Empty
            : await TryFetchPyPiJsonMetadataAsync(bases[0], parsed.PurlName, parsed.Version, file, ct);

        // Prefer the simple-index #sha256= fragment (it's already verified against the bytes
        // by UpstreamClient on the way in). Fall back to the JSON API's digests.sha256 when
        // upstream's simple page didn't carry a fragment.
        string? integrityValue = upstreamSha256 ?? jsonMeta.Sha256Hex;
        string? integrityAlgo = integrityValue is not null ? "sha256" : null;

        // deepcode ignore LogForging: file is a PyPI filename parsed and validated by PyPiFilename.TryParse before this method is called; Serilog structured rendering prevents log injection.
        var result = await proxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: gate.OrgId, Ecosystem: "pypi",
            PackageName: parsed.PurlName, PurlName: parsed.PurlName,
            Version: parsed.Version, Purl: purl, File: file, Blob: blob,
            ExtractLicenses: stream => LicenseExtractor.FromPyPiPackageBytes(stream, file),
            UserId: gate.UserId,
            ActorKind: gate.ActorKind,
            SourceIp: gate.SourceIp,
            MaxOsvScoreTolerance: gate.Settings.MaxOsvScoreTolerance,
            MinReleaseAgeHours: gate.Settings.MinReleaseAgeHours,
            // PyPI records cache_access separately in FetchAndCacheUpstreamAsync (covers
            // both hit and miss paths); skip here to avoid the double-write.
            CacheAccess: null,
            PublishedAt: jsonMeta.PublishedAt,
            UpstreamIntegrityValue: integrityValue,
            UpstreamIntegrityAlgorithm: integrityAlgo,
            Deprecated: jsonMeta.Deprecated,
            BlockDeprecatedMode: gate.Settings.BlockDeprecated,
            BlockMaliciousMode: gate.Settings.BlockMalicious,
            BlockKevMode: gate.Settings.BlockKev,
            MaxEpssTolerance: gate.Settings.MaxEpssTolerance), ct);
        return result.Decision == BlockDecision.Blocked ? new StatusCodeResult(StatusCodes.Status403Forbidden) : null;
    }

    /// <summary>
    /// Calls PyPI's per-version JSON API and picks the <c>urls[]</c> entry matching the file
    /// we're about to record: returns its <c>upload_time_iso_8601</c> for <c>published_at</c>
    /// and its <c>digests.sha256</c> as a fallback upstream integrity value. The Simple API
    /// is HTML-only and carries no timestamps, so the JSON API is an extra request — fail-soft,
    /// never blocks the underlying artefact fetch.
    /// </summary>
    private async Task<PyPiJsonMetadata> TryFetchPyPiJsonMetadataAsync(
        string upstreamBase, string purlName, string version, string file, CancellationToken ct)
    {
        try
        {
            string url = $"{upstreamBase}/pypi/{purlName}/{version}/json";
            // Routes through single-flighted metadata fetch so an artefact stampede
            // doesn't also stampede this endpoint.
            var resp = await upstream.GetOrFetchMetadataAsync(url, ct);
            return resp.IsSuccessStatusCode
                ? PyPiUpstreamJsonParser.ParseUrlsArrayForFile(resp.Body, file)
                : PyPiJsonMetadata.Empty;
        }
        catch { return PyPiJsonMetadata.Empty; }
    }

    /// <summary>
    /// Fetches the upstream simple index for a package and extracts the actual download URL for a
    /// specific file, plus the <c>#sha256=</c> fragment if PEP 503 supplied one. The fragment
    /// drives fail-fast verification on first fetch — passed through as <c>knownSha256</c> to
    /// <see cref="UpstreamClient.GetOrFetchAsync"/> which throws <see cref="ChecksumException"/>
    /// on mismatch before any blob is cached. Returns null when the file isn't in the index.
    /// </summary>
    private async Task<(string Url, string? Sha256Hex)?> ResolveUpstreamPyPiUrlAsync(
        string upstreamBase, string pkgName, string filename, CancellationToken ct)
    {
        try
        {
            // This simple-index fetch fires inline with every PyPI file-download path,
            // so concurrent CI fan-out would otherwise stampede here too. Route through
            // single-flight.
            var resp = await upstream.GetOrFetchMetadataAsync($"{upstreamBase}/simple/{pkgName}/", ct);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            string html = resp.BodyAsString();
            // Group 1 = URL up to but not including the fragment; group 3 = the hex SHA-256
            // when a #sha256=... fragment is present. Older mirrors / non-PEP-503 indices
            // may omit the fragment; in that case group 3 is empty and we fall through with
            // a null hash (the request still succeeds, just without first-fetch verification).
            var match = Regex.Match(
                html,
                $@"href=""(https?://[^""#]*/{Regex.Escape(filename)})(#sha256=([0-9a-fA-F]{{64}}))?""",
                RegexOptions.None, PyPiConstants.RegexTimeout);
            if (!match.Success)
            {
                return null;
            }

            string url = match.Groups[1].Value;
            string? sha = match.Groups[3].Success ? match.Groups[3].Value.ToLowerInvariant() : null;
            return (url, sha);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or RegexMatchTimeoutException)
        {
            logger.LogWarning(
                ex,
                "Upstream simple-index fetch failed for {PackageName}: {ExceptionType} trace={TraceId}",
                pkgName,
                ex.GetType().Name,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return null;
        }
    }

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}
