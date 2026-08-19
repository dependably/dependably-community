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
/// simple-index, fetches and caches blobs, and delegates the post-fetch half to
/// <see cref="ProxyFetchService"/>, which records first-fetch metadata and runs the block gate
/// both before recording (the first-fetch arms, so a refused artefact never enters the
/// catalogue) and after (the arms that read the recorded facts). Extracted from
/// <see cref="PyPiDownloadHandler"/> so each class stays under the S1200 coupling limit.
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
    Dependably.Protocol.Provenance.PyPiProvenanceVerifier provenance,
    ILogger<PyPiProxyFetcher> logger)
{
    public async Task<IActionResult?> CheckProxyAllowlistBlocklistAsync(
        string orgId, PyPiFilename parsed,
        TokenRecord? token, OrgSettings settings, string? sourceIp, CancellationToken ct)
    {
        string purlCheck = PurlNormalizer.NameOnly("pypi", parsed.PurlName);
        if (settings.AllowlistMode && !await allowlist.IsAllowedAsync(orgId, purlCheck, ct))
        {
            // Recorded for the same reason the blocklist arm below is: an allowlist miss is an
            // operator's own configuration refusing a request, and it previously produced a bare
            // 403 with no activity row — invisible in the feed the operator would check first.
            await audit.LogActivityAsync(orgId, "pypi", purlCheck, "blocked", token?.AuditActorId,
                actorLabel: token?.AuditActorLabel, actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
            return new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        if (await blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await audit.LogActivityAsync(orgId, "pypi", purlCheck, "blocked", token?.AuditActorId, actorLabel: token?.AuditActorLabel,
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
            var fetched = await DownloadAndCacheAsync(upstreamUrl, knownSha, gate.OrgId, download.AuthorizationHeader, ct);
            if (fetched is null)
            {
                return new NotFoundResult();
            }

            httpContext.Response.Headers["X-Cache"] = fetched.IsHit ? "HIT" : "MISS";
            if (pkgVersions is not null)
            {
                httpContext.Response.Headers["X-Dependably-PURL"] = HeaderSanitizer.Sanitize(pkgVersions.Value.Version.Purl);
            }

            // The cache-access record for this fetch into cache_artifact + tenant_artifact_access.
            // The name is normalized to the canonical PURL name inside the shared pipeline; the blob
            // fields come from what we just staged.
            string purlName = pkgVersions?.Package.PurlName ?? parsed.PurlName;
            string version = pkgVersions?.Version.Version ?? parsed.Version;
            var cacheAccess = new CacheAccess(
                gate.OrgId, "pypi", purlName, version, file,
                fetched.Blob.Sha256Hex, fetched.Blob.SizeBytes, fetched.Blob.BlobKey, upstreamUrl,
                // The hash is this request's own over the bytes it just staged and verified,
                // whether or not the content-addressed blob store already held them, so this is a
                // fetch for binding purposes on both the hit and miss branches below.
                CacheAccessOrigin.FirstFetch);

            if (pkgVersions is null)
            {
                // This org's first fetch of the coordinate: reaching here means it holds neither an
                // uploaded version nor a proxy cache row (the caller's per-org GetServeFactsByCoordinate
                // hit-check already returned null). Hand the record to the shared pipeline so the
                // artefact is adopted only AFTER its first-fetch gates pass — a version blocked by
                // deprecation/provenance must leave no cache_artifact / tenant_artifact_access row,
                // matching npm/NuGet/Maven. This must NOT key on fetched.IsHit: that is the GLOBAL
                // content-addressed blob-store hit, so an org first-fetching bytes another tenant
                // already cached would otherwise adopt with no gate at all.
                var firstFetchArgs = new FirstFetchArgs(file, parsed, upstreamSha256, cacheAccess, upstreamUrl, httpContext);
                var firstFetchBlock = await RecordAndScanFirstFetchAsync(firstFetchArgs, fetched.Blob, gate, ct);
                if (firstFetchBlock is not null)
                {
                    return firstFetchBlock;
                }
            }
            else
            {
                // The coordinate already has an uploaded version for this org (a mixed hosted/proxied
                // name whose uploaded serve fell through to a proxied file): record access up front, a
                // last_accessed_at / download-count touch — the org already holds the name.
                await cacheRecorder.RecordAccessAsync(cacheAccess, ct);
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
        catch (ProxyCatalogueUnavailableException)
        {
            // The artefact could not be recorded on the cache plane, so it could not be scanned or
            // gated — and an artefact the registry cannot vouch for is not served. 503, never 404:
            // the artefact exists upstream, we just could not admit it. The bytes are staged, so the
            // client's retry is cheap.
            return new StatusCodeResult(StatusCodes.Status503ServiceUnavailable);
        }
        catch (UpstreamFetchFailedException)
        {
            // Transient upstream exhausted retries — propagate so the middleware maps it to a
            // retryable 503/502 instead of a hard 403/404 that aborts the install.
            throw;
        }
        catch (System.Data.Common.DbException)
        {
            // A metadata-store failure (DB locked, disk full, corrupt) during first-fetch recording
            // is infrastructure, not a missing artefact. RecordAndScanAsync's global-plane writes
            // (proxy version row, first_fetch activity) are direct DB writes not wrapped by
            // CacheAccessRecorder's swallow-to-null, so a raw provider exception reaches here.
            // Rethrow so the middleware maps it to a 5xx — never the blanket 404 below, which would
            // make pip report a real package as nonexistent. Matches npm/NuGet.
            throw;
        }
        catch (OperationCanceledException)
        {
            // Client disconnect / shutdown — propagate cancellation rather than masking it as a 404.
            throw;
        }
        catch (HttpRequestException)
        {
            // A genuine upstream not-found: UpstreamClient surfaces non-transient upstream
            // statuses (404/410) as HttpRequestException. The artefact truly does not exist
            // upstream, so the client sees 404 — distinct from the unclassified 502 below.
            return new NotFoundResult();
        }
        catch (Exception ex)
        {
            // An unclassified failure (blob-store I/O error, a bug in first-fetch metadata or
            // provenance resolution, malformed upstream data, etc.) — none of the carved-out
            // cases above matched. Log it so the operator has a diagnostic trail, and answer
            // 502 rather than the blanket 404 that would make pip report a real package as
            // nonexistent and fail the install outright, since a 404 is not retried.
            logger.LogWarning(ex,
                "Unclassified failure during PyPI proxy fetch/cache for {PurlName}/{File}: {ExceptionType} trace={TraceId}",
                parsed.PurlName, file, ex.GetType().Name,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return new StatusCodeResult(StatusCodes.Status502BadGateway);
        }
    }

    /// <summary>
    /// Resolves the upstream download URL and the SHA-256 hash for a given file. If the
    /// stored version already has a checksum, files.pythonhosted.org CDN path is used
    /// directly. Otherwise, the configured upstreams' simple indices are queried in
    /// priority order.
    /// </summary>
    public async Task<(string Url, string? Sha256Hex, string? AuthorizationHeader)?> ResolveProxyUpstreamUrlAsync(
        string file, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions,
        IReadOnlyList<UpstreamSource> bases, CancellationToken ct)
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
            // CDN shortcut hits files.pythonhosted.org directly — never attach an upstream's auth
            // header here, or a private upstream token would leak to a different (public) host.
            return (cdnUrl, sha256, null);
        }

        // Walk upstreams in priority order; the first whose simple index resolves the file wins.
        // The matched upstream's auth header rides along, but ONLY when the resolved href stayed
        // on the upstream's own host. A PEP 503 simple index may name an absolute href to any
        // host (see ResolvePyPiHref's doc comment) — a hostile or merely mirror-like upstream
        // (Artifactory-style proxies commonly link straight to files.pythonhosted.org) can name a
        // third-party host in its own response. Attaching this upstream's stored credential there
        // would leak it to a host the org never configured, mirroring the CDN-shortcut guard above.
        foreach (var source in bases)
        {
            var resolved = await ResolveUpstreamPyPiUrlAsync(source, parsed.PurlName, file, ct);
            if (resolved is not null)
            {
                string? authorizationHeader = UpstreamHostPin.IsSameHost(source.Url, resolved.Value.Url)
                    ? source.AuthorizationHeader
                    : null;
                return (resolved.Value.Url, resolved.Value.Sha256Hex, authorizationHeader);
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
    ///   <item><b>Unknown-sha cold-start:</b> routes through
    ///         <see cref="UpstreamClient.FetchAndCacheByUrlAsync"/> which hash-and-stages the
    ///         body to a disk temp file (SHA-256 computed inline), stores it under the
    ///         content-addressed key, and wraps the result in a <see cref="BlobHandle"/> — no
    ///         full-artefact byte[] is ever materialised.</item>
    /// </list>
    /// </summary>
    // blob put uses BlobKeys.Proxy(sha) which validates
    // 64-char lowercase hex; Serilog uses RenderedCompactJsonFormatter (CRLF-safe).
    private async Task<PyPiFetchOutcome?> DownloadAndCacheAsync(
        string upstreamUrl, string? knownSha256, string orgId, string? authorizationHeader, CancellationToken ct)
    {
        if (knownSha256 is not null)
        {
            // Known checksum — verify and use content-addressed cache. The streaming
            // variant returns a stream we immediately dispose: subsequent consumers
            // (license extraction, response body) open a fresh blob-store stream via
            // the BlobHandle. SizeBytes is read from the seekable stream's Length when
            // available (LocalBlobStore → FileStream); remote backends that hand back
            // a non-seekable network stream leave SizeBytes at 0. That 0 means "not measured",
            // not "zero bytes": CacheAccessRecorder.BindingFor declines to bind a non-positive
            // size for exactly that reason, so it cannot shadow the coordinate's recorded size
            // and be served as this tenant's HEAD Content-Length.
            string blobKey = BlobKeys.Proxy(knownSha256);
            // blobKey is BlobKeys.Proxy of a 64-char hex SHA-256 (no user input); upstreamUrl is operator-configured; Serilog structured rendering prevents log injection.
            var (stream, isHit) = await upstream.GetOrFetchStreamAsync(
                blobKey, upstreamUrl, new ChecksumSpec(ChecksumAlgorithm.Sha256, knownSha256),
                "pypi", orgId, ct: ct, authorizationHeader: authorizationHeader);
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

        // Unknown checksum — the content-addressed cache key only exists after hashing, so route
        // through the hash-and-stage disk pipeline. FetchAndCacheByUrlAsync streams the body to a
        // staging temp file (SHA-256 computed inline via HashingFileStream), stores it under
        // BlobKeys.Proxy(sha), and single-flights concurrent first-fetches of the same URL. No
        // full-artefact byte[] is ever materialised — memory stays bounded by the staging buffer
        // regardless of wheel size or concurrency. A genuine upstream 404 surfaces as an
        // HttpRequestException (mapped to 404 by the caller); a transient exhaustion surfaces as
        // UpstreamFetchFailedException (mapped to a retryable 503).
        var fetched = await upstream.FetchAndCacheByUrlAsync(
            upstreamUrl, checksumSpec: null, "pypi", orgId, authorizationHeader, ct);

        var coldBlob = new BlobHandle(fetched.BlobKey, fetched.Sha256Hex, fetched.SizeBytes,
            async openCt => await blobs.GetAsync(fetched.BlobKey, openCt)
                ?? throw new InvalidOperationException(
                    $"Blob {fetched.BlobKey} vanished between PutAsync and GetAsync."));
        return new PyPiFetchOutcome(coldBlob, IsHit: false);
    }

    // Groups the first-fetch bookkeeping (filename, parsed identity, upstream-supplied
    // checksum/URL, and the not-yet-recorded cache-access record) that RecordAndScanFirstFetchAsync
    // threads through to the shared proxy pipeline, which adopts it only after its gates pass.
    private sealed record FirstFetchArgs(
        string File, PyPiFilename Parsed, string? UpstreamSha256, CacheAccess CacheAccess, string UpstreamUrl,
        // Carried so a first-fetch refusal can name the arm that produced it on the response.
        HttpContext HttpContext);

    // bytes are cached under BlobKeys.Proxy(sha) which validates
    // 64-char lowercase hex; Serilog uses RenderedCompactJsonFormatter (CRLF-safe).
    private async Task<IActionResult?> RecordAndScanFirstFetchAsync(
        FirstFetchArgs args, BlobHandle blob, ProxyContext gate, CancellationToken ct)
    {
        string file = args.File;
        var parsed = args.Parsed;
        string purl = PurlNormalizer.PyPi(parsed.PurlName, parsed.Version);
        // Use the highest-priority configured upstream for the supplementary JSON metadata fetch.
        var bases = await registries.ResolveAsync(gate.OrgId, "pypi", ct);
        var jsonMeta = bases.Count == 0
            ? PyPiJsonMetadata.Empty
            : await TryFetchPyPiJsonMetadataAsync(bases[0], parsed.PurlName, parsed.Version, file, ct);

        // Prefer the simple-index #sha256= fragment (it's already verified against the bytes
        // by UpstreamClient on the way in). Fall back to the JSON API's digests.sha256 when
        // upstream's simple page didn't carry a fragment.
        string? integrityValue = args.UpstreamSha256 ?? jsonMeta.Sha256Hex;
        string? integrityAlgo = integrityValue is not null ? "sha256" : null;

        // PEP 740 attestation verification for proxy-origin files when the tenant enabled it. The
        // verifier binds the attestation's in-toto subject digest to the SHA-256 dependably just
        // computed (blob.Sha256Hex), so a mismatched attestation fails closed. Off-policy or an
        // unconfigured verifier short-circuits to NotApplicable (NULL status, never blocks).
        var prov = await ResolveProvenanceAsync(file, blob.Sha256Hex, jsonMeta, gate, ct);

        // file is a PyPI filename parsed and validated by PyPiFilename.TryParse before this method is called; Serilog structured rendering prevents log injection.
        var result = await proxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: gate.OrgId, Ecosystem: "pypi",
            PackageName: parsed.PurlName, PurlName: parsed.PurlName,
            Version: parsed.Version, Purl: purl, File: file, Blob: blob,
            ExtractLicenses: stream => LicenseExtractor.FromPyPiPackageBytes(stream, file),
            AuditActorId: gate.AuditActorId, AuditActorLabel: gate.AuditActorLabel,
            ActorKind: gate.ActorKind,
            SourceIp: gate.SourceIp,
            MaxOsvScoreTolerance: gate.Settings.MaxOsvScoreTolerance,
            MinReleaseAgeHours: gate.Settings.MinReleaseAgeHours,
            // Hand the cache-access record to the shared pipeline so it adopts the artefact only
            // after its first-fetch gates pass (RecordCacheAccessAsync runs after
            // EvaluateFirstFetchGatesAsync). A blocked version therefore leaves no cache_artifact /
            // tenant_artifact_access row, and the record still routes to the global plane.
            CacheAccess: args.CacheAccess,
            PreRecordedCacheArtifactId: null,
            PublishedAt: jsonMeta.PublishedAt,
            UpstreamIntegrityValue: integrityValue,
            UpstreamIntegrityAlgorithm: integrityAlgo,
            Deprecated: jsonMeta.Deprecated,
            BlockDeprecatedMode: gate.Settings.BlockDeprecated,
            BlockMaliciousMode: gate.Settings.BlockMalicious,
            BlockKevMode: gate.Settings.BlockKev,
            BlockRevokedMode: gate.Settings.BlockRevoked,
            MaxEpssTolerance: gate.Settings.MaxEpssTolerance,
            BlockInstallScriptsMode: gate.Settings.BlockInstallScripts,
            ProvenanceStatus: Dependably.Protocol.Provenance.ProvenanceStatuses.ToColumn(prov.Status),
            ProvenanceSigner: prov.Signer,
            VerifyProvenanceMode: gate.Settings.VerifyPyPiAttestations,
            UpstreamUrl: args.UpstreamUrl,
            LicenseEnforcementMode: gate.Settings.LicenseEnforcementMode), ct);
        return result.Decision == BlockDecision.Blocked
            ? BlockRefusalResult.Forbidden(args.HttpContext, new BlockOutcome(result.Decision, result.Arm))
            : null;
    }

    // Runs PEP 740 attestation verification for a proxy-origin PyPI file when the tenant enabled it
    // and the org has per-org sigstore_root + trusted_publisher anchors configured. Fetches the
    // file's provenance document from the URL the JSON API surfaced; an off policy, an unconfigured
    // org, or a missing provenance URL short-circuits to NotApplicable / Unsigned without throwing.
    // The verifier never throws — a malformed bundle maps to Failed so the gate can fail closed.
    private async Task<Dependably.Protocol.Provenance.ProvenanceResult> ResolveProvenanceAsync(
        string file, string fileSha256Hex, PyPiJsonMetadata jsonMeta, ProxyContext gate, CancellationToken ct)
    {
        if (gate.Settings.VerifyPyPiAttestations == "off")
        {
            return Dependably.Protocol.Provenance.ProvenanceResult.NotApplicable;
        }

        // Resolve per-org trust material. If not configured (no sigstore_root + trusted_publisher),
        // short-circuit to NotApplicable — fail-closed: the verify policy requires anchors.
        var trust = await provenance.GetTrustMaterialAsync(gate.OrgId, ct);
        if (!trust.IsConfigured)
        {
            return Dependably.Protocol.Provenance.ProvenanceResult.NotApplicable;
        }

        string? provenanceJson = await TryFetchProvenanceDocumentAsync(jsonMeta.ProvenanceUrl, ct);
        return provenance.VerifyAttestation(file, fileSha256Hex, provenanceJson, trust);
    }

    // Fetches the PEP 740 provenance document from the upstream-supplied URL. Routed through the
    // single-flighted metadata fetch so a stampede doesn't hammer the provenance endpoint. Returns
    // null (→ Unsigned) when no URL was published or the fetch fails — fail-soft, like the JSON
    // metadata fetch; the verifier maps a null document to Unsigned, which the block gate refuses
    // under a 'block' policy.
    private async Task<string?> TryFetchProvenanceDocumentAsync(string? provenanceUrl, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(provenanceUrl))
        {
            return null;
        }

        try
        {
            var resp = await upstream.GetOrFetchMetadataAsync(provenanceUrl, ct: ct);
            return resp.IsSuccessStatusCode ? resp.BodyAsString() : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            logger.LogWarning(
                ex,
                "PyPI provenance-document fetch failed: {ExceptionType} trace={TraceId}",
                ex.GetType().Name,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return null;
        }
    }

    /// <summary>
    /// Calls PyPI's per-version JSON API and picks the <c>urls[]</c> entry matching the file
    /// we're about to record: returns its <c>upload_time_iso_8601</c> for <c>published_at</c>
    /// and its <c>digests.sha256</c> as a fallback upstream integrity value. The Simple API
    /// is HTML-only and carries no timestamps, so the JSON API is an extra request — fail-soft,
    /// never blocks the underlying artefact fetch.
    /// </summary>
    private async Task<PyPiJsonMetadata> TryFetchPyPiJsonMetadataAsync(
        UpstreamSource source, string purlName, string version, string file, CancellationToken ct)
    {
        try
        {
            string url = $"{source.Url}/pypi/{purlName}/{version}/json";
            // Routes through single-flighted metadata fetch so an artefact stampede
            // doesn't also stampede this endpoint.
            var resp = await upstream.GetOrFetchMetadataAsync(url, source.AuthorizationHeader, ct);
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
    /// <see cref="UpstreamClient.GetOrFetchStreamAsync"/> which throws <see cref="ChecksumException"/>
    /// on mismatch before any blob is cached. Returns null when the file isn't in the index.
    ///
    /// Hrefs may be absolute (public PyPI: <c>https://files.pythonhosted.org/...</c>) or
    /// root-relative (another dependably upstream emits <c>/packages/{file}</c>); both forms are
    /// resolved against the simple-index request URI so chaining through a private dependably works.
    /// </summary>
    private async Task<(string Url, string? Sha256Hex)?> ResolveUpstreamPyPiUrlAsync(
        UpstreamSource source, string pkgName, string filename, CancellationToken ct)
    {
        string simpleIndexUrl = $"{source.Url}/simple/{pkgName}/";
        try
        {
            // This simple-index fetch fires inline with every PyPI file-download path,
            // so concurrent CI fan-out would otherwise stampede here too. Route through
            // single-flight.
            // Same Accept as the index render, so both consumers of this URL keep sharing one
            // single-flight slot and one cache entry instead of splitting into two variants.
            var resp = await upstream.GetOrFetchMetadataAsync(
                simpleIndexUrl,
                UpstreamClient.MaxMetadataResponseBytes,
                source.AuthorizationHeader,
                PyPiSimpleIndexHelper.UpstreamAccept,
                ct);
            return resp.IsSuccessStatusCode
                ? ResolvePyPiUrl(simpleIndexUrl, resp.ContentType, resp.BodyAsString(), filename)
                : null;
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

    /// <summary>
    /// Extracts the download URL and optional SHA-256 for <paramref name="filename"/> from an
    /// upstream simple-index document in either representation, resolving a relative URL against
    /// <paramref name="simpleIndexUrl"/>. Returns null when the file isn't in the index or its
    /// URL can't be resolved.
    ///
    /// The PEP 691 branch reads <c>url</c> and <c>hashes.sha256</c> as fields, which is both
    /// cheaper and safer than the HTML branch's regex over an attacker-controlled body; the HTML
    /// branch remains for upstreams that answer PEP 503 regardless of the Accept sent.
    /// </summary>
    internal static (string Url, string? Sha256Hex)? ResolvePyPiUrl(
        string simpleIndexUrl, string? contentType, string body, string filename)
    {
        if (contentType is null
            || !contentType.Contains(PyPiSimpleIndexHelper.JsonContentType, StringComparison.OrdinalIgnoreCase))
        {
            return ResolvePyPiHref(simpleIndexUrl, body, filename);
        }

        var entry = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson(body)
            .FirstOrDefault(e => string.Equals(e.Filename, filename, StringComparison.OrdinalIgnoreCase));
        return entry?.Url is { Length: > 0 } url
            && Uri.TryCreate(new Uri(simpleIndexUrl), url, out var resolved)
                ? (resolved.ToString(), entry.Sha256?.ToLowerInvariant())
                : null;
    }

    /// <summary>
    /// Extracts the download URL (and optional <c>#sha256=</c> fragment) for <paramref name="filename"/>
    /// from a PEP 503 simple-index document, resolving the href against
    /// <paramref name="simpleIndexUrl"/>. Hrefs may be absolute (public PyPI →
    /// <c>https://files.pythonhosted.org/...</c>) or root-relative (another dependably upstream →
    /// <c>/packages/{file}</c>); both resolve to an absolute URL. Returns null when the file isn't
    /// in the index or the href can't be resolved.
    /// </summary>
    internal static (string Url, string? Sha256Hex)? ResolvePyPiHref(
        string simpleIndexUrl, string html, string filename)
    {
        // Group 1 captures the href (absolute or root-relative) up to but not including the
        // fragment, and group 3 captures the hex SHA-256 when a #sha256=... fragment is
        // present. Older mirrors and non-PEP-503 indices may omit the fragment, in which case
        // group 3 is empty and this falls through with a null hash. The href is matched
        // loosely, anything ending in /{filename}, and then resolved against the simple-index
        // URI, so a private dependably upstream emitting root-relative hrefs chains correctly.
        var match = Regex.Match(
            html,
            $@"href=""([^""#]*/{Regex.Escape(filename)})(#sha256=([0-9a-fA-F]{{64}}))?""",
            RegexOptions.None, PyPiConstants.RegexTimeout);
        if (!match.Success || !Uri.TryCreate(new Uri(simpleIndexUrl), match.Groups[1].Value, out var absolute))
        {
            return null;
        }

        string? sha = match.Groups[3].Success ? match.Groups[3].Value.ToLowerInvariant() : null;
        return (absolute.ToString(), sha);
    }
}
