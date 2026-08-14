using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Serve/proxy surface for <see cref="RpmController"/>: package download (hosted, global-plane
/// cache-hit, and proxy first-fetch), repodata (passthrough, merged, and locally-built), and the
/// upstream GPG key endpoint. Split from the publish/upload half purely to stay under the
/// file-length compliance gate — both halves are one controller, gated and rate-limited together.
/// </summary>
public sealed partial class RpmController
{
    // ── Download ──────────────────────────────────────────────────────────────

    /// <summary>GET /rpm/packages/{file} — download an RPM by NEVRA filename.</summary>
    [HttpGet("/rpm/packages/{file}")]
    [HttpHead("/rpm/packages/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Download(string file, CancellationToken ct)
    {
        // ValidateUpstreamSegment (not Validate): the filename is composed into the upstream
        // proxy URL on a cache miss. ASP.NET decodes a route value once, so a double-encoded
        // "%252e%252e%252f" arrives here as the literal "%2e%2e%2f" — no literal '..' or '/',
        // so it clears every base rule — and .NET's Uri carries the "%2e%2e%2f" through to the
        // upstream, which decodes it back to "../". The '%' ban rejects it before any fetch.
        var pathCheck = PathSafeValidator.ValidateUpstreamSegment(file, "file");
        if (!pathCheck.IsValid)
        {
            return BadRequest(pathCheck.Message);
        }

        if (!file.EndsWith(".rpm", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("RPM filename must end with .rpm.");
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Uploaded RPMs are served from the package_versions path.
        var versionMatch = await _svc.Packages.FindVersionByBlobKeySuffixAsync(orgId, "rpm", file, uploadedOnly: true, ct: ct);

        if (versionMatch is not null)
        {
            return await ServePackageFromCacheAsync(orgId, file, versionMatch.Value, token, settings, ct);
        }

        // Global-plane lookup for proxy RPMs stored in cache_artifact.
        // Parse the NEVRA filename to extract the name and version for the coordinate lookup.
        // Name is lowercased to match the normalized value stored in cache_artifact.name.
        var nevra = ParseNevra(file);
        if (nevra is not null)
        {
            var globalCa = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
                orgId, "rpm", nevra.Value.Name.ToLowerInvariant(), $"{nevra.Value.Version}-{nevra.Value.Release}", file, ct);
            if (globalCa is not null)
            {
                return await ServeGlobalPlaneRpmAsync(orgId, file, globalCa, token, settings, ct);
            }
        }

        // Cache MISS — attempt upstream proxy if configured.
        if (_svc.Proxy is null || _svc.UpstreamClient is null)
        {
            return NotFound();
        }

        if (settings is null || !settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        // Per-org upstream: top-priority configured rpm registry. Empty ⇒ proxying disabled.
        // RPM upstreams are anonymous-only (the per-upstream auth feature covers the language
        // ecosystems; RPM mirrors are public distro repos), so only the base URL is threaded.
        var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
        return bases.Count == 0 ? NotFound() : await ProxyDownloadAsync(orgId, bases[0].Url, file, token, settings, ct);
    }

    private async Task<IActionResult> ServePackageFromCacheAsync(
        string orgId, string file,
        (Package Package, PackageVersion Version) versionMatch,
        TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        // Block gate runs before any bytes are served, so an operator-blocked (or OSV-flagged)
        // uploaded RPM stops serving from the cache path, not just at never-before-fetched time.
        if (await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "rpm", versionMatch.Version, token, settings,
                    HttpContext.GetNormalizedRemoteIp()), ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // 304 short-circuit: check the client's cached copy before opening the blob stream.
        string? uploadedEtag = versionMatch.Version.ChecksumSha256 is not null
            ? $"\"sha256:{versionMatch.Version.ChecksumSha256}\""
            : null;
        if (uploadedEtag is not null && ConditionalRequestHelper.IfNoneMatchHits(Request.Headers, uploadedEtag))
        {
            Response.Headers.ETag = uploadedEtag;
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
            return StatusCode(StatusCodes.Status304NotModified);
        }

        string blobKey = BlobKeys.StoreKey(versionMatch.Version.BlobKey);
        var hitStore = versionMatch.Version.Origin == "proxy"
            ? _svc.BlobStore.Cache
            : _svc.BlobStore.Registry;
        var stream = await hitStore.GetAsync(blobKey, ct);
        if (stream is null)
        {
            return NotFound();
        }

        Response.Headers["X-Cache"] = "HIT";
        if (uploadedEtag is not null)
        {
            Response.Headers.ETag = uploadedEtag;
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        await _svc.Audit.LogActivityAsync(orgId, "rpm", versionMatch.Version.Purl, "download",
            token?.UserId, actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _svc.Packages.IncrementDownloadCountAsync(versionMatch.Version.Id, ct);
        return File(stream, "application/x-rpm", file);
    }

    /// <summary>
    /// Evaluates the block gate for a proxy RPM against its global-plane (<c>cache_artifact</c>)
    /// facts. Both the cache-hit serve and the first-fetch serve call this with facts read from the
    /// same projection, so the two paths cannot drift into asymmetric enforcement: whatever refuses
    /// the second download refuses the first one too.
    /// </summary>
    private Task<BlockDecision> EvaluateGlobalPlaneGateAsync(
        string orgId, CacheArtifactServeFacts caFacts, TokenRecord? token,
        OrgSettings? settings, CancellationToken ct)
        => _svc.BlockGate.EvaluateAsync(
            BlockGateRequest.ForProxyCacheFacts(
                orgId, "rpm", caFacts, token, settings, HttpContext.GetNormalizedRemoteIp()), ct);

    // Serves a proxy RPM that was recorded in the global plane (cache_artifact) after the P3b flip.
    // The per-tenant download count is bumped via tenant_artifact_access (RecordDownloadHitAsync).
    private async Task<IActionResult> ServeGlobalPlaneRpmAsync(
        string orgId, string file, CacheArtifactServeFacts caFacts, TokenRecord? token,
        OrgSettings? settings, CancellationToken ct)
    {
        // Block gate runs before any bytes are served, so a manual block / OSV finding on a
        // proxy-cached RPM takes effect on every subsequent download, not just first-fetch.
        if (await EvaluateGlobalPlaneGateAsync(orgId, caFacts, token, settings, ct)
            == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // 304 short-circuit: check the client's cached copy before opening the blob stream.
        string? cachedEtag = !string.IsNullOrEmpty(caFacts.ContentHash)
            ? $"\"sha256:{caFacts.ContentHash}\""
            : null;
        if (cachedEtag is not null && ConditionalRequestHelper.IfNoneMatchHits(Request.Headers, cachedEtag))
        {
            Response.Headers.ETag = cachedEtag;
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
            return StatusCode(StatusCodes.Status304NotModified);
        }

        // blobkey-ok: proxy blob key from cache_artifact; BlobKeys.StoreKey routes to cache tier.
        var stream = await _svc.BlobStore.Cache.GetAsync(BlobKeys.StoreKey(caFacts.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        Response.Headers["X-Cache"] = "HIT";
        if (cachedEtag is not null)
        {
            Response.Headers.ETag = cachedEtag;
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }

        string purl = caFacts.Purl ?? string.Empty;
        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "download",
            token?.UserId, actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        // Increment per-tenant download count on the global plane. Enqueued off the request
        // path — the row already exists (seeded durably at first-fetch).
        await _svc.TenantAccess.RecordDownloadHitAsync(orgId, caFacts.Id, _svc.Time.GetUtcNow(), ct);
        return File(stream, "application/x-rpm", file);
    }

    // Bound on how much of a staged RPM the signature verifier will read. Generous (the blob is
    // already staged and bounded by the upstream size limit); the verifier streams the covered
    // region in fixed-size chunks, so this caps work and not resident memory. A package that runs
    // past it is reported unverifiable, never verified.
    private const long RpmSignatureVerifyCapBytes = 256L * 1024 * 1024;

    private async Task<IActionResult> ProxyDownloadAsync(
        string orgId, string upstreamBase, string file, TokenRecord? token,
        OrgSettings? settings, CancellationToken ct)
    {
        // 1. Negative cache — keyed on the org's resolved upstream base + filename so one org's
        //    404 cannot answer another org whose upstream host does have the package.
        if (await _svc.Proxy!.IsNegativelyCachedAsync(upstreamBase, file, ct))
        {
            return NotFound();
        }

        // 2. Resolve package URL from primary.xml.gz
        var resolution = await TryResolveUpstreamPackageAsync(orgId, upstreamBase, file, ct);
        if (resolution is null)
        {
            await _svc.Proxy.RecordNegativeAsync(upstreamBase, file, ct);
            return NotFound();
        }

        // 3. Parse NEVRA from filename
        var nevra = ParseNevra(file);
        if (nevra is null)
        {
            return NotFound();
        }

        var (name, epoch, rpmVersion, release, arch) = nevra.Value;
        string ver = $"{rpmVersion}-{release}";
        string purl = PurlNormalizer.Rpm(name, rpmVersion, release, arch, epoch);
        string blobStoreKey = BlobKeys.Proxy(resolution.Sha256);

        // 4. Fetch from upstream via UpstreamClient (checksum-verified, cached on Cache tier)
        // RPM resolves no per-org upstream credential today — every repodata/package fetch is
        // anonymous. The host-pin still gates the attach point: a <primary.xml> <location href>
        // may be absolute to any host, so if a future per-org RPM credential is threaded in here,
        // it can only ever ride to a fetch whose host matches the configured upstream — never to
        // whatever third-party host the upstream's own repodata named.
        string? rpmUpstreamCredential = null;
        string? authorizationHeader = UpstreamHostPin.IsSameHost(upstreamBase, resolution.PackageUrl)
            ? rpmUpstreamCredential
            : null;

        Stream body;
        bool isHit;
        try
        {
            (body, isHit) = await _svc.UpstreamClient!.GetOrFetchStreamAsync(
                blobStoreKey, resolution.PackageUrl,
                new ChecksumSpec(ChecksumAlgorithm.Sha256, resolution.Sha256),
                "rpm", orgId, purl, ct: ct, authorizationHeader: authorizationHeader);
        }
        catch (ChecksumException)
        {
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream checksum mismatch; package not served.");
        }

        // 5. Verify per-package RPM signature against the per-org trust ring when the tenant has
        // verification enabled.
        var provResult = await VerifyRpmProxySignatureAsync(orgId, settings, blobStoreKey, ct);

        // 6. Persist DB row (cache_artifact + rpm_metadata) on first fetch
        string dbBlobKey = $"proxy/{resolution.Sha256}/{file}"; // StoreKey strips the filename suffix
        long contentLength = await ResolveProxyContentLengthAsync(body, blobStoreKey, ct);

        string? cacheArtifactId = await CacheProxyPackageAsync(
            new ProxyCachePackage(orgId, file, resolution, nevra.Value, ver, purl, dbBlobKey, contentLength,
                provResult),
            ct);

        // 7. Block gate — the same gate the cache-hit path runs, evaluated on the facts just
        // written, before any byte of the artifact reaches the client. Without this the first
        // requester (the machine actually installing the package) is the one client a 'block'
        // policy never protects.
        var gate = await EvaluateFirstFetchGateAsync(
            new RpmFirstFetchGateTarget(orgId, file, resolution.Name, purl, cacheArtifactId), token, settings, ct);
        if (gate is not null)
        {
            // The staged blob is deliberately kept, and RPM is the one proxy ecosystem where that
            // is right. Go/Cargo/apk discard theirs on a refusal because their blob keys are
            // org-scoped and their hit path probes the blob store, so a leftover blob would answer
            // every later request with no row to gate against. RPM keys proxy blobs by content
            // hash and shares them across tenants — discarding one would break other tenants'
            // rows — and it does not need to: the serve path above resolves a cache_artifact row
            // first, so a missing row is already a MISS that re-fetches and re-records. Only the
            // response is refused.
            await body.DisposeAsync();
            return gate;
        }

        Response.Headers["X-Cache"] = isHit ? "HIT" : "MISS";
        await _svc.Audit.LogActivityAsync(orgId, "rpm", purl, "download",
            token?.UserId, actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        // Keyed by the cache_artifact id just recorded, matching the cache-hit path above. The
        // purl is not a unique key on the cache plane — one RPM purl can span several filenames —
        // so a purl-keyed bump would count this download against all of them and refresh their
        // last_used, perturbing LRU eviction order. Null only when the row could not be recorded,
        // in which case there is nothing to count against.
        if (cacheArtifactId is not null)
        {
            await _svc.TenantAccess.RecordDownloadHitAsync(
                orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);
        }

        return File(body, "application/x-rpm", file);
    }

    // Step 5 of ProxyDownloadAsync: verifies the just-staged proxy blob's signature against the
    // org's trust ring when verification is enabled and configured. The blob was already staged
    // by GetOrFetchStreamAsync, so this opens a fresh stream from the cache tier rather than
    // buffering twice. NotApplicable (off/not-configured) leaves the status NULL (never blocks);
    // a staged blob that has since disappeared from the cache tier reports Failed rather than
    // silently skipping verification.
    private async Task<Dependably.Protocol.Provenance.ProvenanceResult> VerifyRpmProxySignatureAsync(
        string orgId, OrgSettings? settings, string blobStoreKey, CancellationToken ct)
    {
        if (settings?.VerifyRpmSignatures == "off" || !await _svc.RpmProvenance.IsConfiguredForAsync(orgId, ct))
        {
            return Dependably.Protocol.Provenance.ProvenanceResult.NotApplicable;
        }

        var blobStream = await _svc.BlobStore.Cache.GetAsync(blobStoreKey, ct);
        if (blobStream is null)
        {
            return Dependably.Protocol.Provenance.ProvenanceResult.Failed;
        }

        await using (blobStream.ConfigureAwait(false))
        {
            return await _svc.RpmProvenance.VerifyPackageAsync(orgId, blobStream, RpmSignatureVerifyCapBytes, ct);
        }
    }

    // Step 6 of ProxyDownloadAsync: body.Length is only usable when the stream is seekable
    // (S3/Azure network streams are not). GetRangeAsync issues a cheap metadata-only lookup
    // against the same cache key and returns the true blob length without buffering, so
    // size_bytes is exact regardless of backend or artifact size (kept as long — a >2 GiB RPM is
    // plausible for driver/firmware/CUDA packages and must not narrow-wrap).
    private async Task<long> ResolveProxyContentLengthAsync(Stream body, string blobStoreKey, CancellationToken ct)
    {
        if (body.CanSeek)
        {
            return body.Length;
        }

        await using var sizeProbe = await _svc.BlobStore.Cache.GetRangeAsync(blobStoreKey, 0, 0, ct);
        return sizeProbe?.TotalLength ?? 0;
    }

    /// <summary>
    /// First-fetch enforcement for a proxy RPM: scans the freshly recorded artifact so the
    /// vulnerability arms have findings to read, then evaluates the block gate against the
    /// persisted <c>cache_artifact</c> facts. Returns the refusal result to send, or null when the
    /// artifact is servable.
    ///
    /// Fails closed on a missing catalogue row: every gate arm reads that row, so an artifact that
    /// is not in the cache plane cannot be gated and is refused rather than served ungated. The
    /// bytes are already staged and have not reached the client, so refusing costs a retry.
    /// </summary>
    /// <summary>
    /// The just-recorded proxy artifact's identity, threaded from <see cref="ProxyDownloadAsync"/>
    /// into <see cref="EvaluateFirstFetchGateAsync"/> unchanged.
    /// </summary>
    private readonly record struct RpmFirstFetchGateTarget(
        string OrgId, string File, string RpmName, string Purl, string? CacheArtifactId);

    private async Task<IActionResult?> EvaluateFirstFetchGateAsync(
        RpmFirstFetchGateTarget target, TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        var (orgId, file, rpmName, purl, cacheArtifactId) = target;
        if (cacheArtifactId is null)
        {
            Logger.LogWarning(
                "RPM proxy: cache plane recorded no row for {Filename}; refusing to serve ungated.",
                file);
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                "Artifact catalogue unavailable; package not served.");
        }

        await _svc.Scanner.ScanCacheArtifactAsync(
            purl, cacheArtifactId, "rpm", rpmName.ToLowerInvariant(), ct);

        // Re-read through the same projection the cache-hit path uses, after the scan, so the gate
        // sees vuln_checked_at and every fact the second request would see.
        var caFacts = await _svc.CacheArtifacts.GetServeFactsByIdAsync(orgId, cacheArtifactId, ct);
        if (caFacts is null)
        {
            Logger.LogWarning(
                "RPM proxy: recorded artifact for {Filename} is not readable from the cache plane; " +
                "refusing to serve ungated.", file);
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                "Artifact catalogue unavailable; package not served.");
        }

        return await EvaluateGlobalPlaneGateAsync(orgId, caFacts, token, settings, ct)
            == BlockDecision.Blocked
            ? StatusCode(StatusCodes.Status403Forbidden)
            : null;
    }

    private async Task<PackageResolution?> TryResolveUpstreamPackageAsync(string orgId, string upstreamBase, string file, CancellationToken ct)
    {
        try
        {
            return await _svc.Proxy!.ResolvePackageUrlAsync(orgId, upstreamBase, file, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            // Serilog RenderedCompactJsonFormatter JSON-encodes {Filename}, neutralising newline/control-char injection.
            Logger.LogWarning(ex,
                "RPM proxy: ResolvePackageUrlAsync failed for {Filename}: {ExceptionType}",
                file, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// GET /rpm/Packages/{bucket}/{file} — download an RPM by the *nested*
    /// path that upstream repodata advertises in its <c>&lt;location href&gt;</c>
    /// (e.g. <c>Packages/t/tree-2.1.0-5.fc40.x86_64.rpm</c>).
    /// </summary>
    /// <remarks>
    /// In passthrough mode the proxy forwards upstream's <c>primary.xml</c> verbatim —
    /// its hashes are sealed by <c>repomd.xml</c>, so the location hrefs cannot be
    /// rewritten to the flat <c>/rpm/packages/{file}</c> form without breaking dnf's
    /// metadata integrity check. dnf therefore composes <c>baseurl + href</c> and
    /// requests the nested path. This route maps that request to the same
    /// flat-filename download flow (the proxy resolves packages by NEVRA filename,
    /// not by mirror layout) — <paramref name="bucket"/> (the Fedora/EPEL first-letter
    /// directory) is ignored. The fixed two-segment shape keeps it distinct from the
    /// single-segment flat route, so there is no ambiguous-route conflict.
    /// </remarks>
    [HttpGet("/rpm/Packages/{bucket}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> DownloadNested(string bucket, string file, CancellationToken ct)
        => Download(file, ct);

    // ── Repodata ──────────────────────────────────────────────────────────────

    /// <summary>GET /rpm/repodata/{file} — repomd.xml or compressed XML docs.</summary>
    [HttpGet("/rpm/repodata/{file}")]
    [HttpHead("/rpm/repodata/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Repodata(string file, CancellationToken ct)
    {
        // ValidateUpstreamSegment (not Validate): the filename is embedded verbatim in the
        // composed upstream URL "{upstreamBase}/repodata/{file}". IsHashPrefixedFilename only
        // constrains the leading 64 hex characters and the dash, so a percent-encoded traversal
        // in the tail would reach the fetch untouched. The '%' ban stops it at the boundary — no
        // legitimate repodata name (repomd.xml, repomd.xml.asc, {sha256}-primary.xml.gz)
        // contains a '%'.
        var pathCheck = PathSafeValidator.ValidateUpstreamSegment(file, "file");
        if (!pathCheck.IsValid)
        {
            return BadRequest(pathCheck.Message);
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Proxy modes (passthrough / merged) delegate to upstream before local generation; both
        // fall through to local on a null result (unrecognised filename / upstream 404).
        var proxied = await TryServeRepodataFromProxyAsync(orgId, settings!, file, ct);
        return proxied ?? await ServeRepodataLocallyAsync(orgId, file, ct);
    }

    /// <summary>
    /// Serves repodata from the configured RPM proxy when proxying is effective for the org.
    /// Passthrough mode forwards upstream's repomd/compressed docs verbatim; merged mode serves a
    /// combined local ∪ upstream index. Effective engagement = org passthrough effective
    /// (air-gap-aware) AND ≥1 rpm registry; the top-priority registry (bases[0]) is the whole-repo
    /// source. Returns null when proxying is not effective, no rpm registry is configured, or the
    /// upstream result is null — the caller then falls back to local generation.
    /// </summary>
    private async Task<IActionResult?> TryServeRepodataFromProxyAsync(string orgId, OrgSettings settings, string file, CancellationToken ct)
    {
        if (!settings.ProxyPassthroughEffective)
        {
            return null;
        }

        if (IsRpmPassthroughEffective(settings))
        {
            var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
            return bases.Count > 0 ? await TryServeRepodataFromUpstreamAsync(bases[0].Url, file, ct) : null;
        }

        // Effective merged mode: serve a combined local ∪ upstream index.
        var mergedBases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
        return mergedBases.Count > 0 ? await TryServeMergedRepodataAsync(orgId, mergedBases[0].Url, file, ct) : null;
    }

    // Resolves the effective RPM upstream mode for an org and reports whether passthrough is in
    // force. The per-org rpm_upstream_mode is an override, not a floor: an explicit org value
    // (set via PUT /api/v1/rpm-upstream-mode) wins over the instance Rpm:UpstreamMode env value in
    // EITHER direction — an org can opt into 'merged' on a passthrough instance, or opt out to
    // 'passthrough' on a merged instance. A null org setting (never configured, or explicitly
    // cleared back to inherit) falls back to the env value. A garbage/unset env value normalizes
    // to the documented 'passthrough' default (mirrors IRpmUpstreamProxy.IsMergedModeSelected).
    private bool IsRpmPassthroughEffective(OrgSettings? settings)
    {
        string envMode = _svc.Proxy is { IsMergedModeSelected: true } ? "merged" : "passthrough";
        string effectiveMode = settings?.RpmUpstreamMode ?? envMode;
        return !string.Equals(effectiveMode, "merged", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Serves <c>repomd.xml</c>, <c>primary.xml.gz</c>, and <c>filelists.xml.gz</c> as a merge
    /// of the tenant's locally published RPMs and the upstream repo's packages. The gzipped
    /// documents are memoised per org (short TTL, evicted on upload) so the <c>repomd.xml</c>
    /// request and the follow-up document requests return byte-identical content — otherwise the
    /// SHA-256 checksums the repomd seals would not match what dnf downloads.
    ///
    /// Upstream non-primary repomd entries (other, group, modules, updateinfo, …) with
    /// hash-prefixed (content-addressed) hrefs are passed through verbatim in the merged repomd;
    /// entries with plain hrefs are dropped at build time (see <see cref="BuildMergedRepodataAsync"/>)
    /// because this dispatch cannot proxy them. When dnf follows an advertised hash-prefixed href,
    /// the request arrives here as a hash-prefixed filename and is proxied upstream via
    /// <see cref="TryServeRepodataFromUpstreamAsync"/> (the same caching + checksum path
    /// passthrough mode uses) — so every href the merged repomd advertises resolves here.
    ///
    /// Group (comps) and module (modulemd) metadata: Dependably does not generate comps or
    /// modulemd documents for locally published RPMs. Group definitions and module streams are
    /// authored independently of RPM packages and require operator-supplied metadata outside
    /// the scope of the artifact registry. Upstream group/module entries with hash-prefixed
    /// hrefs are forwarded verbatim (including locally published packages that happen to match
    /// a group defined upstream), but locally published packages absent from the upstream
    /// repo's group/module documents do not appear in any comps or modulemd. Plain-named group
    /// entries (e.g. <c>comps.xml.gz</c>) are dropped from the merged repomd so no unreachable
    /// href is advertised — dnf treats absent supplemental metadata as non-fatal.
    /// <c>dnf install</c> and direct package installs work for all published RPMs; <c>dnf group
    /// install</c> and modular stream installs work only for packages with upstream definitions.
    ///
    /// Returns null when the upstream primary can't be fetched (caller then falls back to local-only),
    /// or when a hash-prefixed upstream fetch also returns null (caller 404s).
    /// </summary>
    private async Task<IActionResult?> TryServeMergedRepodataAsync(string orgId, string upstreamBase, string file, CancellationToken ct)
    {
        bool isRepomd = file.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase);
        bool isPrimary = file.Equals("primary.xml.gz", StringComparison.OrdinalIgnoreCase);
        bool isFilelists = file.Equals("filelists.xml.gz", StringComparison.OrdinalIgnoreCase);

        // Hash-prefixed filenames are upstream non-primary blobs (other, updateinfo, group, modules,
        // etc.) advertised in the merged repomd. Proxy them through the upstream fetch path so they
        // are reachable — the same caching + checksum verification used by passthrough mode applies.
        if (!isRepomd && !isPrimary && !isFilelists)
        {
            return RpmUpstreamProxy.IsHashPrefixedFilename(file)
                ? await TryServeRepodataFromUpstreamAsync(upstreamBase, file, ct)
                : null;
        }

        var merged = await BuildMergedRepodataAsync(orgId, upstreamBase, ct);
        if (merged is null)
        {
            return null;
        }

        if (isPrimary)
        {
            return File(merged.PrimaryGz, "application/x-gzip", "primary.xml.gz");
        }

        if (isFilelists)
        {
            return File(merged.FilelistsGz, "application/x-gzip", "filelists.xml.gz");
        }

        // repomd.xml: local primary + filelists entries sealed by their checksums, plus upstream's
        // hash-prefixed non-primary entries (other, group, modules, updateinfo) forwarded verbatim.
        // Plain-named upstream entries (e.g. comps.xml.gz from classic createrepo) were dropped at
        // build time because they are not content-addressed and cannot be proxied here.
        // No locally-generated comps/modulemd is produced — group and module metadata is upstream-only.
        string repomd = RpmRepodataService.BuildRepomd(
            merged.PrimaryGz,
            _svc.Time.GetUtcNow(),
            merged.FilelistsGz,
            otherGz: null,
            extraEntries: merged.UpstreamNonPrimaryEntries);
        return File(System.Text.Encoding.UTF8.GetBytes(repomd), "application/xml", "repomd.xml");
    }

    /// <summary>
    /// Builds (and caches) the gzipped combined documents for merged mode. Returns null when the
    /// upstream primary can't be fetched/verified so the caller degrades to local-only.
    /// </summary>
    private async Task<MergedRepodataCache?> BuildMergedRepodataAsync(string orgId, string upstreamBase, CancellationToken ct)
    {
        var cacheKey = new RpmMergedRepodataKey(orgId);
        if (_svc.MergedRepodataCache.TryGet(cacheKey, out var cached) && cached is not null)
        {
            return cached;
        }

        byte[]? upstreamPrimaryGz;
        try
        {
            upstreamPrimaryGz = await _svc.Proxy!.GetUpstreamPrimaryXmlGzAsync(orgId, upstreamBase, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex,
                "RPM merged mode: upstream primary fetch failed for {UpstreamBase}: {ExceptionType}",
                upstreamBase, ex.GetType().Name);
            return null;
        }
        if (upstreamPrimaryGz is null)
        {
            return null;
        }

        // Fetch upstream filelists for merging; a missing upstream filelists is non-fatal —
        // local filelists is still generated and served.
        byte[]? upstreamFilelistsGz = null;
        try
        {
            upstreamFilelistsGz = await _svc.Proxy!.GetUpstreamFilelistsXmlGzAsync(orgId, upstreamBase, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex,
                "RPM merged mode: upstream filelists fetch failed for {UpstreamBase}: {ExceptionType}",
                upstreamBase, ex.GetType().Name);
        }

        // Fetch upstream non-primary repomd entries to pass through verbatim.
        IReadOnlyList<System.Xml.Linq.XElement> upstreamExtras = Array.Empty<System.Xml.Linq.XElement>();
        try
        {
            upstreamExtras = await _svc.Proxy!.GetUpstreamNonPrimaryRepomdEntriesAsync(orgId, upstreamBase, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex,
                "RPM merged mode: upstream repomd entry fetch failed for {UpstreamBase}: {ExceptionType}",
                upstreamBase, ex.GetType().Name);
        }

        // Build merged primary. Builds gzip bytes directly (no intermediate string/byte[]) —
        // see RpmRepodataService.BuildMergedPrimaryGzAsync.
        byte[] primaryGz = await _svc.Repodata.BuildMergedPrimaryGzAsync(orgId, upstreamPrimaryGz, ct);

        // Build merged filelists: local entries from stored files_json merged with upstream entries.
        byte[] filelistsGz;
        if (upstreamFilelistsGz is not null)
        {
            filelistsGz = await _svc.Repodata.BuildMergedFilelistsGzAsync(orgId, upstreamFilelistsGz, ct);
        }
        else
        {
            string localFilelists = await _svc.Repodata.BuildFilelistsAsync(orgId, ct);
            filelistsGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(localFilelists));
        }

        // Filter upstream extras down to entries the merged repo can actually serve. The
        // upstream filelists entry is dropped because a merged local+upstream filelists is
        // generated above — advertising upstream's as well would make dnf parse two
        // conflicting filelists documents. Entries whose advertised href is not hash-prefixed
        // are also dropped: the repodata dispatch only proxies content-addressed
        // (64-hex-prefixed) filenames upstream, so a plain-named entry (e.g. an
        // uncompressed comps group file from classic createrepo) would 404 when dnf
        // follows it. dnf treats absent supplemental metadata as non-fatal, so dropping the
        // entry degrades gracefully instead of advertising an unreachable href.
        var filteredExtras = upstreamExtras
            .Where(e => (string?)e.Attribute("type") != "filelists")
            .Where(HasProxyableHref)
            .ToArray();

        var result = new MergedRepodataCache(primaryGz, filelistsGz, filteredExtras);
        _svc.MergedRepodataCache.Set(cacheKey, result, MergedRepodataTtl, primaryGz.Length + filelistsGz.Length);
        return result;
    }

    /// <summary>
    /// True when an upstream repomd <c>&lt;data&gt;</c> entry's advertised
    /// <c>&lt;location href&gt;</c> names a hash-prefixed (content-addressed) file — the only
    /// upstream repodata filenames the merged-mode dispatch can proxy. Entries failing this
    /// check are excluded from the merged repomd so every advertised href resolves.
    /// </summary>
    private static bool HasProxyableHref(System.Xml.Linq.XElement entry)
    {
        // The repomd XML namespace identifier — an opaque match string, never fetched over the network.
#pragma warning disable S5332
        System.Xml.Linq.XNamespace ns = "http://linux.duke.edu/metadata/repo";
#pragma warning restore S5332
        string? href = (string?)entry.Element(ns + "location")?.Attribute("href");
        if (href is null)
        {
            return false;
        }

        string filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;
        return RpmUpstreamProxy.IsHashPrefixedFilename(filename);
    }

    // Keep the repomd/primary/filelists tuple consistent across a single dnf sync while
    // still picking up new upstream content within a minute — matches the repomd passthrough TTL.
    private static readonly TimeSpan MergedRepodataTtl = TimeSpan.FromSeconds(60);

    private async Task<IActionResult?> TryServeRepodataFromUpstreamAsync(string upstreamBase, string file, CancellationToken ct)
    {
        string? ifNoneMatch = Request.Headers.IfNoneMatch.FirstOrDefault();
        string? ifModifiedSince = Request.Headers.IfModifiedSince.FirstOrDefault();

        RepodataResult? upstreamResult;
        try
        {
            upstreamResult = await _svc.Proxy!.GetRepodataAsync(upstreamBase, file, ifNoneMatch, ifModifiedSince, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            // Serilog RenderedCompactJsonFormatter JSON-encodes {Filename}, neutralising newline/control-char injection.
            Logger.LogWarning(ex,
                "RPM proxy: GetRepodataAsync failed for {Filename}: {ExceptionType}",
                file, ex.GetType().Name);
            return null;
        }

        if (upstreamResult is null)
        {
            return null;
        }

        if (upstreamResult.NotModified)
        {
            return StatusCode(StatusCodes.Status304NotModified);
        }

        if (upstreamResult.ETag is not null)
        {
            Response.Headers.ETag = upstreamResult.ETag;
        }

        if (upstreamResult.LastModified is not null)
        {
            Response.Headers.LastModified = upstreamResult.LastModified;
        }

        // Honor range requests for hash-prefixed (zchunk-capable) metadata files.
        if (RpmUpstreamProxy.IsHashPrefixedFilename(file) && Request.Headers.Range.Count > 0)
        {
            Response.Headers.AcceptRanges = "bytes";
        }

        return File(upstreamResult.Body, upstreamResult.ContentType);
    }

    // Short TTL keeps the local repodata fresh while amortising per-request builds over
    // a dnf metadata refresh burst. Eviction on upload provides immediate consistency.
    private static readonly TimeSpan LocalRepodataTtl = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Serves locally generated repodata when no upstream proxy is active (no configured rpm
    /// registry, or proxy passthrough disabled). Generates and serves <c>repomd.xml</c>,
    /// <c>primary.xml.gz</c>, <c>filelists.xml.gz</c>, and <c>other.xml.gz</c> from the
    /// locally published RPMs stored in the database.
    ///
    /// Group (comps) and module (modulemd) documents are not generated in local or hosted mode.
    /// Group definitions and module streams are authored independently of RPM packages; the
    /// registry stores only the package artifact and its header metadata. Any request for
    /// <c>comps.xml.gz</c>, <c>modules.yaml</c>, or similar supplemental metadata returns
    /// 404 — no empty or malformed document is served. <c>dnf install</c> works for all
    /// published packages; <c>dnf group install</c> and modular workflows require upstream
    /// group/module definitions that Dependably does not produce.
    /// </summary>
    private async Task<IActionResult> ServeRepodataLocallyAsync(string orgId, string file, CancellationToken ct)
    {
        if (file.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase))
        {
            // repomd.xml seals the SHA-256 checksums of primary/filelists/other — the three
            // compressed documents must be byte-identical to what was used to compute those
            // checksums. Fetch or rebuild each from the same per-document cache entries so
            // concurrent repomd.xml and primary.xml.gz requests always agree.
            byte[] primaryGz = await GetOrRebuildLocalDocAsync(orgId, "primary",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildPrimaryAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            byte[] filelistsGz = await GetOrRebuildLocalDocAsync(orgId, "filelists",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildFilelistsAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            byte[] otherGz = await GetOrRebuildLocalDocAsync(orgId, "other",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildOtherAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            string repomd = RpmRepodataService.BuildRepomd(primaryGz, _svc.Time.GetUtcNow(), filelistsGz, otherGz);
            return File(System.Text.Encoding.UTF8.GetBytes(repomd), "application/xml", "repomd.xml");
        }
        if (file.Equals("primary.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            byte[] gz = await GetOrRebuildLocalDocAsync(orgId, "primary",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildPrimaryAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            return File(gz, "application/x-gzip", "primary.xml.gz");
        }
        if (file.Equals("filelists.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            byte[] gz = await GetOrRebuildLocalDocAsync(orgId, "filelists",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildFilelistsAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            return File(gz, "application/x-gzip", "filelists.xml.gz");
        }
        if (file.Equals("other.xml.gz", StringComparison.OrdinalIgnoreCase))
        {
            byte[] gz = await GetOrRebuildLocalDocAsync(orgId, "other",
                async rebuildCt =>
                {
                    string xml = await _svc.Repodata.BuildOtherAsync(orgId, rebuildCt);
                    return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));
                }, ct);
            return File(gz, "application/x-gzip", "other.xml.gz");
        }

        return NotFound();
    }

    // Retrieves the gzip-compressed document bytes from the per-document cache, or rebuilds
    // them under single-flight (concurrent callers for the same key share one rebuild). The
    // rebuild lambda always produces bytes (RPM documents are unconditionally generated from
    // stored rows), so the nullable result is converted to non-null by the call site.
    private async Task<byte[]> GetOrRebuildLocalDocAsync(
        string orgId, string docType,
        Func<CancellationToken, Task<byte[]>> build,
        CancellationToken ct)
    {
        var key = new RpmLocalRepodataKey(orgId, docType);
        // The lambda always returns non-null bytes; null-forgiving is safe here because
        // the RPM build methods always produce a complete XML document even for an empty repo.
        return (await _svc.LocalRepodataCache.GetOrRebuildAsync(
            key, LocalRepodataTtl,
            async rebuildCt => await build(rebuildCt),
            ct))!;
    }

    // ── GPG key ───────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /rpm/repodata/RPM-GPG-KEY or /rpm/repodata/repomd.xml.key — upstream GPG key.
    /// Both routes alias the same handler so <c>dnf</c> succeeds regardless of which path
    /// the upstream <c>.repo</c> file specifies for <c>gpgkey=</c>.
    /// </summary>
    [HttpGet("/rpm/repodata/RPM-GPG-KEY")]
    [HttpGet("/rpm/repodata/repomd.xml.key")]
    [HttpHead("/rpm/repodata/RPM-GPG-KEY")]
    [HttpHead("/rpm/repodata/repomd.xml.key")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GpgKey(CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        // Pin: when the org has an RPM PGP trust anchor configured, serve THAT operator-pinned key
        // rather than a key fetched from the same upstream that served the packages. Relaying the
        // upstream key unpinned makes a client's gpgcheck=1 self-referential — dnf would verify
        // package signatures against a key the attacker who served the packages also supplied. This
        // runs regardless of proxy state: the pinned key is the operator's own, not upstream's.
        if (_svc.TrustStore is not null)
        {
            var anchors = await _svc.TrustStore.ListAsync(orgId, "rpm", ct);
            string pinned = string.Join('\n', anchors
                .Where(a => string.Equals(a.AnchorKind, "pgp", StringComparison.Ordinal)
                            && !string.IsNullOrWhiteSpace(a.Material))
                .Select(a => a.Material.Trim()));
            if (pinned.Length > 0)
            {
                return File(System.Text.Encoding.UTF8.GetBytes(pinned), "application/pgp-keys");
            }
        }

        // No pinned anchor: fall back to relaying the upstream key (only when proxying is enabled).
        if (_svc.Proxy is null)
        {
            return NotFound();
        }

        // Per-org upstream: top-priority configured rpm registry. Empty ⇒ proxying disabled.
        var bases = await _svc.Registries.ResolveAsync(orgId, "rpm", ct);
        if (bases.Count == 0)
        {
            return NotFound();
        }

        byte[]? key;
        try
        {
            key = await _svc.Proxy.GetGpgKeyAsync(bases[0].Url, ct);
        }
        catch (Exception ex) when (ex is not AirGappedException)
        {
            Logger.LogWarning(ex, "RPM proxy: GetGpgKeyAsync failed: {ExceptionType}", ex.GetType().Name);
            return NotFound();
        }

        return key is null ? NotFound() : File(key, "application/pgp-keys");
    }
}
