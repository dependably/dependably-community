using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>Sparse-index serving, crate download/proxy, and the shared request/response
/// helpers for <see cref="CargoController"/>.</summary>
public sealed partial class CargoController
{
    // ── Catch-all dispatcher ─────────────────────────────────────────────────

    /// <summary>
    /// GET /cargo/{**path} — dispatches to either the sparse index or the crate download
    /// handler based on the path shape.
    /// Download paths match <c>api/v1/crates/{name}/{version}/download</c>.
    /// All other paths are treated as sparse index file lookups.
    /// </summary>
    [HttpGet("/cargo/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetCatchAll(string path, CancellationToken ct)
    {
        // Download: api/v1/crates/{name}/{version}/download
        const string downloadPrefix = "api/v1/crates/";
        const string downloadSuffix = "/download";
        if (path.StartsWith(downloadPrefix, StringComparison.OrdinalIgnoreCase)
            && path.EndsWith(downloadSuffix, StringComparison.OrdinalIgnoreCase))
        {
            string inner = path[downloadPrefix.Length..^downloadSuffix.Length];
            int lastSlash = inner.LastIndexOf('/');
            if (lastSlash > 0)
            {
                string name = inner[..lastSlash];
                string version = inner[(lastSlash + 1)..];
                return await GetCrateAsync(name, version, ct);
            }
        }

        // Sparse index: the name is the last segment of the path
        int nameSlash = path.LastIndexOf('/');
        if (nameSlash >= 0)
        {
            string name = path[(nameSlash + 1)..];
            return await GetIndexAsync(name, ct);
        }

        return NotFound();
    }

    // ── Sparse index ─────────────────────────────────────────────────────────

    /// <summary>
    /// Serves the sparse index file for a crate. The response is a newline-delimited JSON
    /// document — one JSON object per version line, exactly as described by the Cargo sparse
    /// registry spec. Local versions shadow upstream versions on version collision.
    /// </summary>
    private async Task<IActionResult> GetIndexAsync(string name, CancellationToken ct)
    {
        if (!PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        // Collect local index lines for this crate.
        var localLines = await _cargoMeta.GetIndexLinesAsync(orgId, name, ct);

        // A reserved crate name — or a hosted name that ClaimResolver resolves to local_only
        // (explicit claim or the implicit hosted-name shadowing guard) — skips the upstream merge
        // so only locally-published versions are advertised, closing the dependency-confusion
        // window. The claim check mirrors what npm/pypi/nuget index reads consult; the
        // reserved-namespace check stays as the additional operator-curated control.
        bool upstreamAllowed = settings.ProxyPassthroughEffective
            && !await _reserved.IsReservedAsync(orgId, "cargo", name, ct)
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "cargo", name, ct);
        var upstreamLines = upstreamAllowed
            ? await CollectUpstreamIndexLinesAsync(orgId, name, ParseLocalVersions(localLines), ct)
            : new List<string>();

        if (localLines.Count == 0 && upstreamLines.Count == 0)
        {
            return NotFound();
        }

        var allLines = new List<string>(localLines.Count + upstreamLines.Count);
        allLines.AddRange(localLines);
        allLines.AddRange(upstreamLines);

        string body = string.Join('\n', allLines);

        // The index body is built from local + upstream index lines for a fixed version set —
        // no timestamps — so the strong ETag is naturally stable across polls for an unchanged
        // crate. Cargo polls index files frequently; honouring If-None-Match returns 304 and
        // cuts bandwidth on the common no-change poll.
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        string etag = ComputeETagFromBytes(bodyBytes);
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            Response.Headers.ETag = etag;
            return StatusCode(StatusCodes.Status304NotModified);
        }
        Response.Headers.ETag = etag;
        // Proxy-merged responses may include upstream lines that change as the upstream
        // publishes; short TTL so additions propagate. Local-only responses (passthrough off)
        // change only on local publish; a longer TTL is appropriate.
        Response.Headers.CacheControl = upstreamLines.Count > 0
            ? "private, max-age=60"
            : "private, max-age=300";
        return Content(body, "text/plain");
    }

    /// <summary>
    /// Computes a strong ETag over the response body. Mirrors the Maven metadata ETag shape:
    /// SHA-256 of the bytes, truncated to 16 hex chars, quoted.
    /// </summary>
    private static string ComputeETagFromBytes(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }

    /// <summary>
    /// Parses the local version set from the local index lines so upstream versions can be
    /// shadowed on collision.
    /// </summary>
    private static HashSet<string> ParseLocalVersions(IReadOnlyList<string> localLines)
    {
        var localVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in localLines)
        {
            string? vers = ParseVersionFromIndexLine(line);
            if (vers is not null)
            {
                localVersions.Add(vers);
            }
        }
        return localVersions;
    }

    /// <summary>
    /// Fetches the sparse index for a crate from the configured upstreams in priority order,
    /// returning the lines from the first upstream that responds. Lines whose version already
    /// exists locally are excluded so local versions shadow upstream on collision.
    /// </summary>
    private async Task<List<string>> CollectUpstreamIndexLinesAsync(
        string orgId, string name, HashSet<string> localVersions, CancellationToken ct)
    {
        var upstreamLines = new List<string>();
        var upstreamUrls = await _registries.ResolveAsync(orgId, "cargo", ct);
        foreach (var source in upstreamUrls)
        {
            string? fetched = await FetchUpstreamIndexAsync(source.Url, name, ct, source.AuthorizationHeader);
            if (fetched is null)
            {
                continue;
            }

            // Only include upstream lines for versions not already in local store.
            foreach (string line in fetched.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                string? vers = ParseVersionFromIndexLine(line);
                if (vers is not null && !localVersions.Contains(vers))
                {
                    upstreamLines.Add(line);
                }
            }
            break;
        }
        return upstreamLines;
    }

    // ── Crate download ───────────────────────────────────────────────────────

    /// <summary>
    /// Serves a .crate file. Checks the blob store first (cache hit); on a miss, fetches
    /// from the upstream download URL, stores the bytes, and serves them. The SHA-256 of
    /// the downloaded bytes is captured and stored on the package_versions row.
    /// </summary>
    private async Task<IActionResult> GetCrateAsync(string name, string version, CancellationToken ct)
    {
        if (!PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }
        if (!PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid version.", Status = StatusCodes.Status400BadRequest });
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        // A hosted (published) crate stores its blob under the publish pipeline's hosted key
        // (BlobKeys.Hosted), recorded on the package_versions row; a proxied crate stores under
        // the content-addressed BlobKeys.Cargo key. Prefer the stored row key so both shapes
        // resolve, falling back to the reconstructed Cargo key for any row that predates the
        // hosted-publish path. A yanked version is still downloadable — yank hides a version
        // from resolution, it does not delete the artefact.
        string blobKey = await ResolveLocalBlobKeyAsync(orgId, name, version, ct)
            ?? BlobKeys.Cargo(orgId, name, version);
        string storeKey = BlobKeys.StoreKey(blobKey);

        // Cache hit path.
        if (await _blobs.ExistsAsync(storeKey, ct))
        {
            // Block gate runs before the cached bytes are served, so an operator block (or OSV
            // finding) on a crate takes effect on every subsequent download, not only on a
            // never-before-fetched version. Proxy crates carry their policy state on the global
            // plane (cache_artifact); hosted crates on their package_versions row.
            if (await IsCrateBlockedAsync(orgId, name, version, token, settings, ct))
            {
                return StatusCode(StatusCodes.Status403Forbidden);
            }

            var cachedStream = await _blobs.GetAsync(storeKey, ct);
            if (cachedStream is not null)
            {
                // deepcode ignore LogForging: name and version are validated by PathSafeValidator.ValidateUpstreamSegment
                // before reaching this path; Serilog renders structured parameters, not concatenated strings.
                _logger.LogDebug(
                    "Cargo cache hit: {Name} {Version} for org {OrgId}.", name, version, orgId);
                // A cached blob may be a hosted (published) crate or a proxied one; only
                // proxied accesses belong in the shared cache index. Gate on the version's
                // origin so hosted crates stay out of cache_artifact / tenant_artifact_access.
                await RecordProxiedCacheHitAsync(orgId, name, version, storeKey, ct);
                return File(cachedStream, "application/octet-stream", $"{name}-{version}.crate");
            }
        }

        // Cache miss — proxy fetch. A reserved crate name, or a name ClaimResolver resolves to
        // local_only (explicit claim or the implicit hosted-name shadowing guard), refuses the
        // upstream fetch, so an unpublished shadowed coordinate 404s instead of pulling from
        // crates.io. The claim check closes the dependency-confusion window on hosted crates
        // automatically; the reserved-namespace check stays as the additional pre-publication control.
        if (!settings.ProxyPassthroughEffective
            || await _reserved.IsReservedAsync(orgId, "cargo", name, ct)
            || !await _claimResolver.IsProxyFetchAllowedAsync(orgId, "cargo", name, ct))
        {
            return NotFound();
        }

        var upstreamSources = await _registries.ResolveAsync(orgId, "cargo", ct);
        return upstreamSources.Count == 0
            ? NotFound()
            : await ProxyCrateFromUpstreamAsync(orgId, name, version, blobKey, upstreamSources, ct);
    }

    // Walks the configured upstream URLs in priority order, fetching the crate from the first
    // that responds. On a checksum mismatch the walk stops immediately (supply-chain integrity
    // failure). On transient errors (network, SSRF, size), the next upstream is tried.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Functional Snyk // deepcode ignore suppression marker, not commented-out code.")]
    private async Task<IActionResult> ProxyCrateFromUpstreamAsync(
        string orgId, string name, string version, string blobKey,
        IReadOnlyList<UpstreamSource> upstreamSources, CancellationToken ct)
    {
        foreach (var source in upstreamSources)
        {
            string upstreamBase = source.Url;
            string? authorizationHeader = source.AuthorizationHeader;
            string downloadUrl = BuildCrateDownloadUrl(upstreamBase, name, version);
            var checksumSpec = await ResolveUpstreamChecksumSpecAsync(upstreamBase, name, version, ct, authorizationHeader);

            UpstreamFetchResult fetchResult;
            try
            {
                // Route through UpstreamClient: size-capped, SSRF-checked, checksum-verified
                // (when the index advertises a cksum), and dedup-protected. The blob is
                // stored under the org-scoped Cargo key so subsequent ExistsAsync calls hit
                // the cache path above. The result carries the SHA-256 the streamed stage
                // already computed (and the byte count), so the crate is never buffered into
                // memory here and its digest is not recomputed — it is served straight from
                // the just-staged blob below.
                // deepcode ignore PT,LogForging: name and version are validated by PathSafeValidator.ValidateUpstreamSegment above;
                // blobKey comes from BlobKeys.Cargo (no traversal possible); Serilog uses structured rendering.
                fetchResult = await _upstream.GetOrFetchToBlobKeyAsync(
                    blobKey, downloadUrl, checksumSpec, "cargo", orgId, ct: ct, authorizationHeader: authorizationHeader);
            }
            catch (ChecksumException)
            {
                // Index-advertised checksum and downloaded bytes disagree — a supply-chain
                // integrity failure. Fail loudly; the mismatch deserves operator attention.
                // deepcode ignore LogForging: name and version pass PathSafeValidator; downloadUrl is constructed from validated segments; Serilog structured rendering prevents log injection.
                _logger.LogWarning(
                    "Cargo crate checksum mismatch for {Name} {Version} from {Url}: index cksum does not match downloaded bytes.",
                    name, version, downloadUrl);
                return StatusCode(StatusCodes.Status502BadGateway, new ProblemDetails
                {
                    Detail = "Upstream crate failed checksum verification against its index entry.",
                    Status = StatusCodes.Status502BadGateway,
                });
            }
            catch (Exception ex) when (
                ex is HttpRequestException
                    or SsrfBlockedException
                    or UpstreamResponseTooLargeException
                    or TaskCanceledException
                    or OperationCanceledException)
            {
                // deepcode ignore LogForging: name and version pass PathSafeValidator; downloadUrl is constructed from
                // validated segments; ExceptionType is a type name, not user input; Serilog structured rendering prevents log injection.
                _logger.LogWarning(
                    "Cargo upstream crate fetch failed for {Name} {Version} from {Url}: {ExceptionType}",
                    name, version, downloadUrl, ex.GetType().Name);
                continue;
            }

            string sha256Hex = fetchResult.Sha256Hex;
            long sizeBytes = fetchResult.SizeBytes;

            // Resolve the index line to store alongside the cache_artifact row so the
            // sparse-index renderer can serve it without a package_versions row.
            string? upstreamIndexText = await FetchUpstreamIndexAsync(upstreamBase, name, ct, authorizationHeader);
            string indexLine = BuildProxyIndexLine(name, version, sha256Hex, upstreamIndexText);

            await RecordProxiedVersionAsync(orgId, name, ct);

            // Record the proxy first-fetch into the shared cache index so the eviction
            // pipeline and vulnerability-response query can see it. Best-effort — the
            // recorder swallows its own failures.
            string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
                new CacheAccess(orgId, "cargo", name, version, $"{name}-{version}.crate",
                    sha256Hex, sizeBytes, blobKey, downloadUrl), ct);
            if (cacheArtifactId is not null)
            {
                // Dual-write per-tenant download state and global supply-chain facts.
                await _tenantAccess.UpsertStateAsync(orgId, cacheArtifactId, _time.GetUtcNow(), ct);
                await _cacheArtifacts.UpdateGlobalFactsAsync(
                    cacheArtifactId,
                    purl: PurlNormalizer.Cargo(name, version),
                    checksumSha1: null,
                    publishedAt: null,
                    deprecated: null,
                    hasInstallScript: false,
                    installScriptKind: null,
                    provenanceStatus: null,
                    provenanceSigner: null,
                    upstreamIntegrityValue: sha256Hex,
                    upstreamIntegrityAlgorithm: "sha256",
                    ct);

                // Write the sparse-index line against the global cache_artifact row so the
                // index renderer serves it without a package_versions row.
                await _cargoMeta.UpsertIndexLineForCacheArtifactAsync(cacheArtifactId, indexLine, ct);

                // The sparse-index line carries no license field, so the only proxy-side
                // license signal is the crate's own Cargo.toml. Best-effort: extraction never
                // fails or delays the serve path below.
                await TryExtractAndStoreCargoLicenseAsync(cacheArtifactId, blobKey, orgId, name, version, ct);
            }

            // deepcode ignore LogForging: name and version pass PathSafeValidator; sha256Hex is a hex digest from the upstream fetch result; Serilog structured rendering prevents log injection.
            _logger.LogInformation(
                "Cargo proxy first-fetch: {Name} {Version} ({Bytes} bytes, sha256={Sha256}) for org {OrgId}.",
                name, version, sizeBytes, sha256Hex[..ETagHexPrefixLength], orgId);

            // Serve straight from the just-staged blob so the crate is streamed to the response
            // rather than held in memory. StoreKey(blobKey) is the Cargo key unchanged.
            var crateStream = await _blobs.GetAsync(BlobKeys.StoreKey(blobKey), ct);
            return crateStream is null
                ? NotFound()
                : File(crateStream, "application/octet-stream", $"{name}-{version}.crate");
        }

        return NotFound();
    }

    /// <summary>
    /// Reads the just-cached <c>.crate</c> blob back and pulls its <c>[package].license</c>
    /// key out of the bundled <c>Cargo.toml</c>, writing any SPDX result to the global
    /// <c>cache_artifact</c> license plane. The sparse index carries no license field, so this
    /// is the only proxy-side license signal available. Failure at any step (blob read,
    /// decompress, parse) is swallowed and logged at Warning — extraction never fails or
    /// delays the crate that has already been staged for serving.
    /// </summary>
    private async Task TryExtractAndStoreCargoLicenseAsync(
        string cacheArtifactId, string blobKey, string orgId, string name, string version, CancellationToken ct)
    {
        try
        {
            var stream = await _blobs.GetAsync(BlobKeys.StoreKey(blobKey), ct);
            if (stream is null)
            {
                return;
            }

            var extracted = LicenseExtractor.FromCrateTarball(stream);
            if (extracted.Spdx.Count > 0)
            {
                await _licenses.SetLicensesForCacheArtifactAsync(cacheArtifactId, extracted.Spdx, "upstream", ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // deepcode ignore LogForging: name and version pass PathSafeValidator; ExceptionType is a type name; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo license extraction failed for {Name} {Version} (org {OrgId}): {ExceptionType}",
                name, version, orgId, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Returns the stored <c>blob_key</c> for a local crate version (proxy or hosted), or null
    /// when no local row exists. Checks the hosted/legacy-proxy <c>package_versions</c> path
    /// first; falls back to the global plane (<c>cache_artifact</c>) for proxy crates recorded
    /// after the P3b flip. Tenant-scoped via the JOIN on <c>packages.org_id</c> (PV path) and
    /// via <c>tenant_artifact_access</c> (global-plane path).
    /// </summary>
    private async Task<string?> ResolveLocalBlobKeyAsync(
        string orgId, string name, string version, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Tenant gate: packages.org_id = @orgId confines the lookup to the requesting org.
        string? pvKey = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.blob_key
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'cargo'
              AND p.name = @name
              AND pv.version = @version
            """,
            new { orgId, name, version });

        if (pvKey is not null)
        {
            return pvKey;
        }

        // Global-plane lookup for proxy crates recorded after the P3b flip.
        string filename = $"{name}-{version}.crate";
        var ca = await _cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "cargo", name, version, filename, ct);
        return ca?.BlobKey;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves a Cargo auth token scoped to the given org. Cargo sends the token as a bare
    /// value in the Authorization header (no scheme prefix) — e.g. <c>Authorization: mytoken</c>
    /// — in addition to the standard <c>Authorization: Bearer mytoken</c> form.
    /// This helper tries Bearer/Basic first via the org-scoped extension, then falls back to
    /// treating the whole header value as a raw token and verifying org membership.
    /// Cross-org tokens are coerced to null so AnonymousPull governs cross-tenant requests
    /// consistently with the other ecosystems.
    /// </summary>
    private async Task<TokenRecord?> ResolveCargoTokenAsync(string orgId, CancellationToken ct)
    {
        // Standard Bearer / Basic resolution — org-scoped: cross-tenant tokens become null.
        var resolved = await Request.ResolveTokenAsync(_tokens, orgId, ct);
        if (resolved is not null)
        {
            return resolved;
        }

        // Cargo-specific: bare token with no scheme prefix.
        string? auth = Request.Headers.Authorization.FirstOrDefault();
        if (auth is null || auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                         || auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string raw = auth.Trim();
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        var bareToken = await _tokens.ResolveAsync(raw, ct);
        // Reject tokens that belong to a different org — same coerce-to-null behaviour as
        // the org-scoped overload so AnonymousPull governs cross-tenant requests.
        return bareToken?.OrgId == orgId ? bareToken : null;
    }

    /// <summary>
    /// Fetches the sparse index file for a crate from the upstream registry via
    /// <see cref="UpstreamClient"/>. Returns the raw text content (newline-delimited JSON
    /// lines) on success, null on 404 or error. Routes through UpstreamClient to enforce
    /// the size cap and SSRF allowlist on metadata responses.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Functional Snyk // deepcode ignore suppression marker, not commented-out code.")]
    private async Task<string?> FetchUpstreamIndexAsync(
        string upstreamBase, string name, CancellationToken ct, string? authorizationHeader = null)
    {
        string indexPath = IndexPath(name);
        string url = $"{upstreamBase}/{indexPath}";
        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(url, authorizationHeader, ct);
            return response.IsSuccessStatusCode
                ? response.BodyAsString()
                : null;
        }
        catch (Exception ex) when (
            ex is HttpRequestException
                or SsrfBlockedException
                or UpstreamResponseTooLargeException
                or TaskCanceledException
                or OperationCanceledException)
        {
            // deepcode ignore LogForging: name passes PathSafeValidator; url comes from operator-configured upstream registry;
            // ExceptionType is a type name; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo upstream index fetch failed for {Name} from {Url}: {ExceptionType}",
                name, url, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// Constructs the upstream crate download URL. For the crates.io sparse index
    /// (<c>index.crates.io</c>), the download base is <c>static.crates.io/crates</c>.
    /// For other sparse registries, <c>/api/v1/crates</c> is appended to the upstream base.
    /// </summary>
    private static string BuildCrateDownloadUrl(string upstreamBase, string name, string version)
    {
        string downloadBase = upstreamBase.Contains("index.crates.io", StringComparison.OrdinalIgnoreCase)
            ? "https://static.crates.io/crates"
            : $"{upstreamBase}/api/v1/crates";
        return $"{downloadBase}/{name}/{version}/download";
    }

    /// <summary>
    /// Records a proxied Cargo version in the global cache plane. Ensures the per-tenant
    /// <c>packages</c> row exists for discoverability; the per-version data lives in
    /// <c>cache_artifact</c> + <c>tenant_artifact_access</c>. No <c>package_versions</c> row
    /// is inserted for proxy artifacts — the global plane is authoritative for proxy versions.
    /// The sparse-index line is written to <c>cargo_metadata</c> keyed by
    /// <c>cache_artifact_id</c> so the index renderer finds it on the global-plane read path.
    /// </summary>
    private async Task RecordProxiedVersionAsync(
        string orgId, string name, CancellationToken ct)
    {
        // Ensure per-tenant packages row so the crate appears in this org's search / sparse index.
        await _packages.GetOrCreateAsync(orgId, "cargo", name, name, isProxy: true, ct);
    }

    /// <summary>
    /// On a cache hit, records the access into the shared cache index — but only when the
    /// cached version was proxied. Hosted (published) crates are durable registry artefacts
    /// and never belong in <c>cache_artifact</c> / <c>tenant_artifact_access</c>. Checks the
    /// legacy <c>package_versions</c> row first; falls back to the global plane
    /// (<c>cache_artifact</c>) for proxy crates recorded after the P3b flip. A lookup that
    /// finds no proxied row is a no-op; the recorder swallows any recording failure itself.
    /// </summary>
    private async Task RecordProxiedCacheHitAsync(
        string orgId, string name, string version, string blobKey, CancellationToken ct)
    {
        ProxiedVersionRow? row;
        try
        {
            await using var conn = await _db.OpenAsync(ct);
            row = await conn.QuerySingleOrDefaultAsync<ProxiedVersionRow>(
                """
                SELECT pv.origin AS Origin,
                       pv.checksum_sha256 AS ChecksumSha256,
                       pv.size_bytes AS SizeBytes
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId
                  AND p.ecosystem = 'cargo'
                  AND p.purl_name = @name
                  AND pv.version = @version
                """,
                new { orgId, name, version });
        }
        catch (Exception ex)
        {
            // The bytes already streamed to the client; this index lookup is best-effort.
            // deepcode ignore LogForging: name and version pass PathSafeValidator; ExceptionType is a type name; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo cache-hit recording lookup failed for {Name} {Version} (org {OrgId}): {ExceptionType}",
                name, version, orgId, ex.GetType().Name);
            return;
        }

        if (row is not null && !string.Equals(row.Origin, "proxy", StringComparison.Ordinal))
        {
            // Hosted crate — not a proxy artifact; do not record in cache_artifact.
            return;
        }

        string contentHash;
        long sizeBytes;
        if (row is not null)
        {
            contentHash = row.ChecksumSha256 ?? "";
            sizeBytes = row.SizeBytes;
        }
        else
        {
            // Global-plane proxy (no package_versions row) — resolve checksum and size from
            // cache_artifact so the recorder gets accurate metadata on cache hits.
            string filename = $"{name}-{version}.crate";
            var ca = await _cacheArtifacts.GetServeFactsByCoordinateAsync(
                orgId, "cargo", name, version, filename, ct);
            if (ca is null)
            {
                // Neither a package_versions row nor a cache_artifact row — hosted crate without
                // a PV row, or the data was evicted. Do not record; nothing to attribute.
                return;
            }
            contentHash = ca.ContentHash;
            sizeBytes = ca.SizeBytes;
        }

        // upstream_url is left null on a hit: the originating upstream is not known here and
        // the row already carries it from the first-fetch insert.
        string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, "cargo", name, version, $"{name}-{version}.crate",
                contentHash, sizeBytes, blobKey, null), ct);
        // On cache hits, increment the per-tenant download counter; global facts are already
        // populated from first-fetch and do not need to be re-written. Enqueued off the request
        // path — the row already exists.
        if (cacheArtifactId is not null)
        {
            await _tenantAccess.RecordDownloadHitAsync(orgId, cacheArtifactId, _time.GetUtcNow(), ct);
        }
    }

    // Evaluates the block gate for a cache-hit crate download. A proxy crate carries its policy
    // signals on the global plane (cache_artifact + tenant_artifact_access); a hosted crate on
    // its package_versions row. When neither exists (nothing to attribute), the download is
    // allowed — there is no block state to enforce.
    private async Task<bool> IsCrateBlockedAsync(
        string orgId, string name, string version, TokenRecord? token, OrgSettings? settings, CancellationToken ct)
    {
        string? sourceIp = HttpContext.GetNormalizedRemoteIp();

        var caFacts = await _cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "cargo", name, version, $"{name}-{version}.crate", ct);
        if (caFacts is not null)
        {
            return await _blockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token, settings, sourceIp), ct)
                == BlockDecision.Blocked;
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "cargo", name, ct);
        if (pkg is null)
        {
            return false;
        }
        var hostedVersion = await _packages.GetVersionAsync(pkg.Id, version, ct);
        return hostedVersion is not null
            && await _blockGate.EvaluateAsync(
                BlockGateRequest.For(orgId, "cargo", hostedVersion, token, settings, sourceIp), ct)
                == BlockDecision.Blocked;
    }

    private sealed record ProxiedVersionRow(string Origin, string? ChecksumSha256, long SizeBytes);

    /// <summary>Parses the <c>vers</c> field from a Cargo index JSON line.</summary>
    private static string? ParseVersionFromIndexLine(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            return doc.RootElement.TryGetProperty("vers", out var v) ? v.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the index-advertised SHA-256 for a crate version by reading the upstream
    /// sparse index file (served from the metadata cache when warm) and extracting the
    /// matching line's <c>cksum</c>. Returns null when the index is unreachable, the
    /// version has no line, or the cksum is not a 64-char hex digest — the download then
    /// proceeds unverified, exactly as a registry that omits cksum would behave.
    /// </summary>
    private async Task<ChecksumSpec?> ResolveUpstreamChecksumSpecAsync(
        string upstreamBase, string name, string version, CancellationToken ct, string? authorizationHeader = null)
    {
        string? indexText = await FetchUpstreamIndexAsync(upstreamBase, name, ct, authorizationHeader);
        if (indexText is null)
        {
            return null;
        }

        string? cksum = ParseCksumForVersion(indexText, version);
        if (cksum is null)
        {
            return null;
        }

        if (cksum.Length != Sha256HexLength || !cksum.All(Uri.IsHexDigit))
        {
            // deepcode ignore LogForging: name and version pass PathSafeValidator; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo index cksum for {Name} {Version} is not a SHA-256 hex digest; downloading unverified.",
                name, version);
            return null;
        }

        return new ChecksumSpec(ChecksumAlgorithm.Sha256, cksum.ToLowerInvariant());
    }

    /// <summary>Extracts the <c>cksum</c> field of the index line whose <c>vers</c> matches.</summary>
    private static string? ParseCksumForVersion(string indexText, string version)
    {
        foreach (string line in indexText.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (doc.RootElement.TryGetProperty("vers", out var v)
                    && v.GetString() == version
                    && doc.RootElement.TryGetProperty("cksum", out var c))
                {
                    return c.GetString();
                }
            }
            catch (JsonException)
            {
                // Malformed line — skip; other lines may still match.
            }
        }

        return null;
    }

    private static string ComputeSha256Hex(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Builds a sparse-index JSON line for a proxied crate. When the upstream index text is
    /// available and contains a line for the version, that line is returned verbatim (so the
    /// full dependency/feature graph is preserved). Otherwise a minimal line is synthesised
    /// from the known name, version, and computed SHA-256 so the crate remains resolvable
    /// without the full upstream metadata.
    /// </summary>
    private static string BuildProxyIndexLine(
        string name, string version, string sha256Hex, string? upstreamIndexText)
    {
        string? matchedLine = upstreamIndexText?
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(line => MatchesUpstreamIndexVersion(line, version));
        if (matchedLine is not null)
        {
            return matchedLine;
        }

        // Minimal line when upstream index is unavailable or does not contain the version.
        var minimal = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = name,
            ["vers"] = version,
            ["deps"] = new System.Text.Json.Nodes.JsonArray(),
            ["cksum"] = sha256Hex,
            ["features"] = new System.Text.Json.Nodes.JsonObject(),
            ["yanked"] = false,
        };
        return minimal.ToJsonString(CargoPublishJsonContext.CompactOptions);
    }

    // True when a sparse-index line is valid JSON whose "vers" field equals the target version.
    // Malformed lines are treated as non-matching (skipped).
    private static bool MatchesUpstreamIndexVersion(string line, string version)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(line);
            return doc.RootElement.TryGetProperty("vers", out var v) && v.GetString() == version;
        }
        catch (System.Text.Json.JsonException)
        {
            // Malformed line — skip.
            return false;
        }
    }

    /// <summary>
    /// Reads the request body fully, bounded by <paramref name="cap"/>. Returns null when the
    /// body exceeds the cap (the caller maps this to 413), so an oversized upload is rejected
    /// without materialising more than the cap's worth of bytes.
    /// </summary>
    private async Task<byte[]?> ReadBodyBoundedAsync(long cap, CancellationToken ct)
    {
        var limited = new LimitedReadStream(Request.Body, cap, "cargo publish frame");
        try
        {
            using var ms = new MemoryStream();
            await limited.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>
    /// Validates a Cargo crate name: 1–64 characters, ASCII alphanumeric plus '-' and '_'.
    /// The Cargo spec compares names case-insensitively and treats '-'/'_' as interchangeable;
    /// names land verbatim in path positions (index path, blob key), so the charset is locked
    /// down here on top of the traversal/control-char guard in PathSafeValidator.
    /// </summary>
    private static bool IsValidCrateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxCrateNameLength)
        {
            return false;
        }
        foreach (char c in name)
        {
            bool ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z')
                or (>= '0' and <= '9') or '-' or '_';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Returns the stored index line with its <c>yanked</c> flag set to
    /// <paramref name="yanked"/>. Parses the line as JSON and flips the one property, leaving
    /// every other field untouched. A line that no longer parses (corrupted at rest) is rebuilt
    /// from the known name/version/cksum with an empty dependency/feature set so the index stays
    /// well-formed rather than serving a broken line.
    /// </summary>
    private static string RewriteYankedFlag(
        string storedLine, string name, string version, string? cksum, bool yanked)
    {
        try
        {
            if (JsonNode.Parse(storedLine) is JsonObject obj)
            {
                obj["yanked"] = yanked;
                return obj.ToJsonString(CargoPublishJsonContext.CompactOptions);
            }
        }
        catch (JsonException)
        {
            // Fall through to the minimal rebuild below.
        }

        var rebuilt = new JsonObject
        {
            ["name"] = name,
            ["vers"] = version,
            ["deps"] = new JsonArray(),
            ["cksum"] = cksum ?? "",
            ["features"] = new JsonObject(),
            ["yanked"] = yanked,
        };
        return rebuilt.ToJsonString(CargoPublishJsonContext.CompactOptions);
    }

    private static ObjectResult Forbidden(string detail)
        => new(new ProblemDetails { Detail = detail, Status = StatusCodes.Status403Forbidden })
        { StatusCode = StatusCodes.Status403Forbidden };

    private static ObjectResult Payload413(string detail)
        => new(new ProblemDetails { Detail = detail, Status = StatusCodes.Status413PayloadTooLarge })
        { StatusCode = StatusCodes.Status413PayloadTooLarge };
}
