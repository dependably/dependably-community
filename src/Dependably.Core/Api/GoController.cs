using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Go module proxy surface — implements the GOPROXY protocol so <c>go get</c> and module-aware
/// tooling can resolve and download Go modules via Dependably.
///
/// Routes: <c>/go/{module}/@v/list</c>, <c>/go/{module}/@v/{version}.info</c>,
/// <c>/go/{module}/@v/{version}.mod</c>, <c>/go/{module}/@v/{version}.zip</c>,
/// <c>/go/{module}/@latest</c>.
///
/// Bang-encoding: the Go module proxy protocol encodes uppercase letters in module paths as
/// <c>!</c> + lowercase (e.g. <c>github.com/!azure/...</c> means <c>github.com/Azure/...</c>).
/// Decoding happens at the route boundary; re-encoding is applied when constructing upstream
/// URLs so the upstream proxy sees the canonical form.
///
/// Proxy-only surface: all requests go through the upstream cache-miss path
/// (<see cref="UpstreamClient.GetOrFetchStreamAsync"/>). There is no hosted-push path for Go
/// modules — only proxy reading is supported.
/// </summary>
[ApiController]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075",
    Justification = "Default Go upstream URL is a well-known public registry. Override via Go:Upstream.")]
public sealed class GoController : OrgScopedControllerBase
{
    private readonly GoControllerServices _svc;

    public GoController(GoControllerServices svc) => _svc = svc;

    // ── Bang-encoding helpers ────────────────────────────────────────────────

    /// <summary>
    /// Decodes Go module proxy bang-encoding: <c>!x</c> → <c>X</c>.
    /// Sequences <c>!{char}</c> where <c>char</c> is a lowercase ASCII letter are replaced
    /// with the corresponding uppercase letter. All other characters are passed through unchanged.
    /// </summary>
    internal static string DecodeBangEncoding(string s)
    {
        if (!s.Contains('!'))
        {
            return s;
        }

        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '!' && i + 1 < s.Length && s[i + 1] >= 'a' && s[i + 1] <= 'z')
            {
                sb.Append(char.ToUpperInvariant(s[i + 1]));
                i++;
            }
            else
            {
                sb.Append(s[i]);
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Encodes a Go module path into bang-encoding form for upstream URLs:
    /// each uppercase ASCII letter becomes <c>!</c> + lowercase.
    /// </summary>
    internal static string EncodeBangEncoding(string s)
    {
        if (!s.Any(char.IsAsciiLetterUpper))
        {
            return s;
        }

        var sb = new StringBuilder(s.Length + 4);
        foreach (char c in s)
        {
            if (char.IsAsciiLetterUpper(c))
            {
                sb.Append('!');
                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    // ── Route entry point ────────────────────────────────────────────────────

    /// <summary>
    /// GET /go/{**path} — catch-all route for all Go module proxy requests.
    /// The path is parsed at runtime to distinguish list, info, mod, zip, and @latest.
    /// </summary>
    [HttpGet("/go/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> HandleGoRequest(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return NotFound();
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);

        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // sumdb passthrough: the go client discovers the proxy proxies the checksum database
        // via /go/sumdb/{name}/supported, then fetches lookup/tile/latest paths verbatim. The
        // client verifies the transparency-log signatures itself, so bytes pass through untouched.
        if (path.StartsWith("sumdb/", StringComparison.OrdinalIgnoreCase))
        {
            return await ServeSumDbAsync(orgId, path["sumdb/".Length..], settings, ct);
        }

        // Classify the request by examining the last two path segments.
        // Patterns:
        //   {module}/@latest                  → @latest
        //   {module}/@v/list                  → list
        //   {module}/@v/{encoded-version}.info → version info JSON
        //   {module}/@v/{encoded-version}.mod  → go.mod file
        //   {module}/@v/{encoded-version}.zip  → module zip
        return await DispatchAsync(path, orgId, settings, token, ct);
    }

    private async Task<IActionResult> DispatchAsync(
        string path, string orgId, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // @latest: {module}/@latest
        if (path.EndsWith("/@latest", StringComparison.OrdinalIgnoreCase))
        {
            string encodedModule = path[..^"/@latest".Length];
            string module = DecodeBangEncoding(encodedModule);
            return await ServeLatestAsync(orgId, module, settings, ct);
        }

        // @v/list: {module}/@v/list
        if (path.EndsWith("/@v/list", StringComparison.OrdinalIgnoreCase))
        {
            string encodedModule = path[..^"/@v/list".Length];
            string module = DecodeBangEncoding(encodedModule);
            return await ServeVersionListAsync(orgId, module, ct);
        }

        // @v/{version}.{ext}: find the last /@v/ segment
        int atVIdx = path.LastIndexOf("/@v/", StringComparison.OrdinalIgnoreCase);
        if (atVIdx < 0)
        {
            return BadRequest("Invalid Go module proxy path.");
        }

        string encodedModulePart = path[..atVIdx];
        string versionFile = path[(atVIdx + "/@v/".Length)..];
        string modulePath = DecodeBangEncoding(encodedModulePart);

        // versionFile is "{encoded-version}.{ext}"
        int dotIdx = versionFile.LastIndexOf('.');
        if (dotIdx <= 0)
        {
            return BadRequest("Invalid Go module proxy path: missing extension.");
        }

        string encodedVersion = versionFile[..dotIdx];
        string ext = versionFile[(dotIdx + 1)..].ToLowerInvariant();
        string version = DecodeBangEncoding(encodedVersion);

        return !IsValidGoExt(ext)
            ? BadRequest($"Unsupported Go module proxy extension: {ext}")
            : await ServeArtifactAsync(orgId, modulePath, version, ext, settings, token, ct);
    }

    // ── sumdb passthrough ──────────────────────────────────────────────────────

    /// <summary>
    /// Serves the Go checksum-database passthrough surface (GOPROXY spec, "Serving modules
    /// privately"). <paramref name="rest"/> is the path after <c>sumdb/</c>:
    /// <c>{sumdb-name}/supported</c> or <c>{sumdb-name}/{lookup|tile|latest...}</c>.
    ///
    /// Only the single operator-configured sumdb (<c>Go:SumDb</c>, default
    /// <c>sum.golang.org</c>) is proxied — a request naming any other sumdb returns 404 so the
    /// go client falls back to verifying directly. The upstream host is config-derived, never
    /// taken from the client path, so an attacker cannot steer the fetch at an arbitrary host.
    /// </summary>
    private async Task<IActionResult> ServeSumDbAsync(
        string orgId, string rest, OrgSettings? settings, CancellationToken ct)
    {
        int slashIdx = rest.IndexOf('/');
        if (slashIdx <= 0)
        {
            return NotFound();
        }

        string requestedName = rest[..slashIdx];
        string sumDbPath = rest[(slashIdx + 1)..];

        var (configuredName, upstreamBase) = ResolveSumDb();
        if (!string.Equals(requestedName, configuredName, StringComparison.OrdinalIgnoreCase))
        {
            // Per spec, an unsupported sumdb name returns 404 from /supported (the client then
            // falls back to verifying the checksum database directly) and 404 for any other path.
            return NotFound();
        }

        // /supported is the capability probe: a 200 with an empty body tells the client the
        // proxy serves this sumdb. No upstream call — the answer is purely "do we proxy it".
        if (string.Equals(sumDbPath, "supported", StringComparison.Ordinal))
        {
            return Ok();
        }

        // Air-gap / proxy-passthrough gate, identical to the module proxy paths: gated off → 404.
        if (settings is not null && !settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        // The residual sumdb path is composed into the upstream URL. Validate each segment the
        // same way module paths are validated (reject traversal, control chars, percent-encoding)
        // before it reaches the upstream request.
        foreach (string seg in sumDbPath.Split('/'))
        {
            var r = PathSafeValidator.ValidateUpstreamSegment(seg, "sumdb");
            if (!r.IsValid)
            {
                return BadRequest($"Invalid sumdb path: {r.Message}");
            }
        }

        string upstreamUrl = $"{upstreamBase}/{sumDbPath}";
        try
        {
            // Verbatim proxy via the shared metadata path: it caches (tiles are immutable),
            // dedups concurrent fetches, and size-caps. Status, bytes, and Content-Type pass
            // through untouched so the client verifies the transparency-log signatures itself.
            var resp = await _svc.Upstream.GetOrFetchMetadataAsync(upstreamUrl, ct: ct);
            string contentType = resp.ContentType ?? "text/plain; charset=utf-8";
            // Verbatim passthrough: the upstream status and bytes are returned untouched so the
            // client verifies the transparency-log signatures itself. Writing the body directly
            // (rather than File(...)) lets a non-200 upstream status — e.g. a 404 lookup for an
            // unknown module — survive instead of being coerced to 200 by an IActionResult.
            Response.StatusCode = resp.StatusCode;
            Response.ContentType = contentType;
            await Response.Body.WriteAsync(resp.Body, ct);
            return new EmptyResult();
        }
        catch (UpstreamResponseTooLargeException)
        {
            _svc.Logger.LogWarning(
                "Upstream sumdb response too large fetching {SumDbPath} for org {OrgId}",
                sumDbPath, orgId);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream sumdb response exceeded size limit.");
        }
        catch (Exception ex) when (ex is HttpRequestException or SsrfBlockedException)
        {
            _svc.Logger.LogWarning(
                ex,
                "Upstream sumdb fetch failed for {SumDbPath} (org {OrgId}): {ExceptionType}",
                sumDbPath, orgId, ex.GetType().Name);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream sumdb fetch failed.");
        }
    }

    /// <summary>
    /// Resolves the operator-configured checksum database into (name, upstream-base-URL).
    /// <c>Go:SumDb</c> accepts a bare host (<c>sum.golang.org</c> → <c>https://sum.golang.org</c>)
    /// or a full URL (used as its own origin, host taken as the name) so deployments can point at
    /// a mirror. The default is the public <c>sum.golang.org</c>.
    /// </summary>
    private (string Name, string UpstreamBase) ResolveSumDb()
    {
        string? raw = _svc.Configuration["Go:SumDb"];
        string configured = string.IsNullOrWhiteSpace(raw) ? "sum.golang.org" : raw.Trim();

        if (configured.Contains("://", StringComparison.Ordinal)
            && Uri.TryCreate(configured, UriKind.Absolute, out var uri))
        {
            string baseUrl = uri.GetLeftPart(UriPartial.Authority);
            return (uri.Host, baseUrl);
        }

        return (configured, $"https://{configured}");
    }

    // ── Artifact serving ─────────────────────────────────────────────────────

    private async Task<IActionResult> ServeArtifactAsync(
        string orgId, string module, string version, string ext,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        if (ValidateModulePath(module) is { } moduleError)
        {
            return BadRequest($"Invalid module path: {moduleError}");
        }

        if (UpstreamSegmentError(version) is { } versionError)
        {
            return BadRequest($"Invalid version: {versionError}");
        }

        string blobKey = BlobKeys.Go(orgId, module, version, ext);

        // Cache HIT — serve from blob store.
        var cached = await _svc.Blobs.GetAsync(blobKey, ct);
        if (cached is not null)
        {
            // Block gate runs before the cached bytes are served. Only the .zip (the module code)
            // is recorded on the global plane, so it is the artefact an operator block / OSV
            // finding attaches to; a blocked module stops serving on every subsequent download,
            // not only at never-before-fetched time. The .info / .mod metadata sidecars carry no
            // cache_artifact row and no block state, so they fall through unblocked.
            if (ext == "zip"
                && await IsGoZipBlockedAsync(orgId, module, version, settings, token, ct))
            {
                return StatusCode(StatusCodes.Status403Forbidden);
            }

            Response.Headers["X-Cache"] = "HIT";
            if (ext == "zip")
            {
                // The .zip is the primary cached artefact; record the hit so the eviction
                // pipeline and vulnerability-response query see this tenant's access.
                await RecordZipCacheAccessAsync(orgId, module, version, blobKey, upstreamUrl: null, ct);
            }
            return File(cached, ContentTypeFor(ext));
        }

        // Cache MISS — refuse the upstream fetch when proxying is off (ProxyPassthroughEffective
        // combines ProxyPassthroughEnabled and AirGapped) or the module path is reserved. A
        // reserved namespace follows local_only semantics: it never pulls from upstream.
        bool proxyOff = settings is not null && !settings.ProxyPassthroughEffective;
        return proxyOff || await _svc.Reserved.IsReservedAsync(orgId, "golang", module, ct)
            ? NotFound()
            : await ServeArtifactFromUpstreamsAsync(orgId, module, version, ext, token, ct);
    }

    /// <summary>
    /// Cache-miss path: tries each configured upstream in priority order, stores the fetched
    /// blob, records the version for .zip artifacts, and serves the bytes. A 404 from one
    /// upstream falls through to the next; other upstream failures map to 502.
    /// </summary>
    private async Task<IActionResult> ServeArtifactFromUpstreamsAsync(
        string orgId, string module, string version, string ext,
        TokenRecord? token, CancellationToken ct)
    {
        var upstreamBases = await _svc.Registries.ResolveAsync(orgId, "golang", ct);
        if (upstreamBases.Count == 0)
        {
            return NotFound();
        }

        string blobKey = BlobKeys.Go(orgId, module, version, ext);

        // Build the upstream URL using bang-encoded module path + version (as proxy.golang.org expects).
        string encodedModule = EncodeBangEncoding(module);
        string encodedVersion = EncodeBangEncoding(version);
        string upstreamPath = $"{encodedModule}/@v/{encodedVersion}.{ext}";

        var attempt = new GoFetchAttempt(orgId, module, version, ext, blobKey, upstreamPath);
        foreach (var source in upstreamBases)
        {
            var result = await TryFetchFromSourceAsync(attempt, token, source, ct);
            if (result is not null)
            {
                return result;
            }
        }

        return NotFound();
    }

    /// <summary>
    /// One resolved fetch coordinate — the raw artifact identity plus the blob key and upstream
    /// path path already derived from it — threaded unchanged through the upstream-source retry
    /// loop in <see cref="ServeArtifactFromUpstreamsAsync"/>.
    /// </summary>
    private readonly record struct GoFetchAttempt(
        string OrgId, string Module, string Version, string Ext, string BlobKey, string UpstreamPath);

    /// <summary>
    /// Attempts the fetch against a single upstream source. Returns the response to serve to the
    /// client (success or a mapped failure status), or <c>null</c> when this source 404'd and the
    /// caller should fall through to the next one.
    /// </summary>
    private async Task<IActionResult?> TryFetchFromSourceAsync(
        GoFetchAttempt attempt, TokenRecord? token, UpstreamSource source, CancellationToken ct)
    {
        var (orgId, module, version, ext, blobKey, upstreamPath) = attempt;
        string upstreamUrl = $"{source.Url}/{upstreamPath}";
        try
        {
            var (stream, isHit) = await _svc.Upstream.GetOrFetchStreamAsync(
                blobKey,
                upstreamUrl,
                checksumSpec: null,
                ecosystem: "golang",
                orgId: orgId,
                purl: PurlNormalizer.Golang(module, version),
                ct: ct,
                authorizationHeader: source.AuthorizationHeader);

            _ = isHit; // cache-hit is already handled above; this is always a miss path

            if (ext == "zip")
            {
                // Record the version in the catalogue for the .zip (primary artifact).
                await RecordVersionAsync(orgId, module, ct);
                // Record the proxy fetch into the shared cache index so the eviction pipeline
                // and vulnerability-response query can see it. Throws
                // ProxyCatalogueUnavailableException when the cache plane cannot take the row —
                // caught below and answered 503 rather than serving an ungateable .zip.
                string cacheArtifactId = await RecordZipFirstFetchOrRefuseAsync(
                    orgId, module, version, blobKey, upstreamUrl, stream, ct);

                // Go modules carry no license metadata in .info/.mod, so the module's own
                // LICENSE-file text is the only proxy-side signal. Best-effort: extraction
                // never fails or delays the response streamed below.
                await TryExtractAndStoreGoLicenseAsync(cacheArtifactId, blobKey, orgId, module, version, ct);
            }

            await _svc.Audit.LogActivityAsync(
                orgId, "golang", PurlNormalizer.Golang(module, version),
                ext == "zip" ? "first_fetch" : "download",
                token?.AuditActorId, actorLabel: token?.AuditActorLabel,
                actorKind: token?.ActorKind,
                sourceIp: HttpContext.GetNormalizedRemoteIp(),
                ct: ct);

            Response.Headers["X-Cache"] = "MISS";
            return File(stream, ContentTypeFor(ext));
        }
        catch (ChecksumException)
        {
            _svc.Logger.LogWarning(
                "Checksum mismatch fetching golang {Module}@{Version}.{Ext} from {UpstreamBase}",
                module, version, ext, source.Url);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream checksum verification failed.");
        }
        catch (UpstreamResponseTooLargeException)
        {
            _svc.Logger.LogWarning(
                "Upstream response too large fetching golang {Module}@{Version}.{Ext} from {UpstreamBase}",
                module, version, ext, source.Url);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream response exceeded size limit.");
        }
        catch (ProxyCatalogueUnavailableException)
        {
            // The .zip could not be recorded on the cache plane, so it could not be gated — and
            // an artefact the registry cannot vouch for is not served. 503, never 404: the
            // module exists upstream, we just could not admit it. Not a per-upstream failure,
            // so the walk stops here instead of retrying the next source.
            _svc.Logger.LogWarning(
                "Cache plane unavailable recording golang {Module}@{Version}.zip for org {OrgId}; refusing the fetch.",
                module, version, orgId);
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                "Module could not be recorded on the cache plane; retry.");
        }
        catch (HttpRequestException ex)
        {
            // 404 from upstream means not found at this registry; try the next one.
            if (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            _svc.Logger.LogWarning(
                ex,
                "HTTP error fetching golang {Module}@{Version}.{Ext} from {UpstreamBase}: {ExceptionType}",
                module, version, ext, source.Url, ex.GetType().Name);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream fetch failed.");
        }
    }

    /// <summary>
    /// One path segment safe to bang-encode into the upstream proxy URL. Uses the '%'-banning
    /// ValidateUpstreamSegment (not Validate): the module/version are composed into the upstream
    /// URL via EncodeBangEncoding, which passes '%' through untouched, and the {**path} catch-all
    /// leaves %2F/%2E undecoded — so a percent-encoded traversal would otherwise reach the
    /// upstream and be decoded to '../' there, invisible to the host-only SSRF guard. Returns the
    /// failing rule's message, or null when the segment is safe.
    /// </summary>
    internal static string? UpstreamSegmentError(string value)
    {
        var r = PathSafeValidator.ValidateUpstreamSegment(value, "segment");
        return r.IsValid ? null : r.Message;
    }

    /// <summary>
    /// Validates each segment of a Go module path. Go module paths contain '/' so each
    /// segment is validated individually (split on '/'), the same way Maven validates its
    /// multi-part coordinates. Returns the first invalid segment's message, null when the
    /// whole path is valid.
    /// </summary>
    internal static string? ValidateModulePath(string module)
    {
        foreach (string seg in module.Split('/'))
        {
            if (UpstreamSegmentError(seg) is { } error)
            {
                return error;
            }
        }
        return null;
    }

    // ── @v/list ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns a newline-separated list of locally-cached versions for the module.
    /// Only versions recorded in the catalogue (package_versions) are returned.
    /// </summary>
    private async Task<IActionResult> ServeVersionListAsync(string orgId, string module, CancellationToken ct)
    {
        if (ValidateModulePath(module) is { } moduleError)
        {
            return BadRequest($"Invalid module path: {moduleError}");
        }

        var versions = await _svc.Packages.ListVersionsForGoModuleAsync(orgId, module, ct);
        string body = string.Join('\n', versions);
        return Content(body, "text/plain; charset=utf-8");
    }

    // ── @latest ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns JSON with the latest cached version for the module.
    /// If no version is cached locally, proxies upstream with a bounded read (32 KB cap)
    /// and single-flight dedup so concurrent @latest requests share one upstream call.
    /// </summary>
    private async Task<IActionResult> ServeLatestAsync(
        string orgId, string module, OrgSettings? settings, CancellationToken ct)
    {
        if (ValidateModulePath(module) is { } moduleError)
        {
            return BadRequest($"Invalid module path: {moduleError}");
        }

        // Return the latest locally-cached version if we have one.
        var latest = await _svc.Packages.GetLatestGoVersionAsync(orgId, module, ct);
        if (latest is not null)
        {
            return Content(
                JsonSerializer.Serialize(new GoVersionInfo(latest.Version, latest.CreatedAt)),
                "application/json");
        }

        // Proxy upstream @latest — refused when proxying is off or the module path is reserved
        // (local_only semantics). A locally-cached latest was already returned above.
        if ((settings is not null && !settings.ProxyPassthroughEffective)
            || await _svc.Reserved.IsReservedAsync(orgId, "golang", module, ct))
        {
            return NotFound();
        }

        var upstreamBases = await _svc.Registries.ResolveAsync(orgId, "golang", ct);
        if (upstreamBases.Count == 0)
        {
            return NotFound();
        }

        string encodedModule = EncodeBangEncoding(module);
        foreach (var source in upstreamBases)
        {
            string? json = await FetchLatestFromUpstreamAsync(orgId, module, encodedModule, source.Url, ct, source.AuthorizationHeader);
            if (json is not null)
            {
                return Content(json, "application/json");
            }
        }

        return NotFound();
    }

    // Single-flight @latest fetch for one upstream base. Returns the JSON string on success,
    // null when the upstream returns 404 or a too-large body, and logs + returns null on
    // HttpRequestException so the caller continues to the next upstream.
    private async Task<string?> FetchLatestFromUpstreamAsync(
        string orgId, string module, string encodedModule, string upstreamBase, CancellationToken ct,
        string? authorizationHeader = null)
    {
        string upstreamUrl = $"{upstreamBase}/{encodedModule}/@latest";
        string inflightKey = $"{orgId}:{module}:{upstreamBase}";
        try
        {
            // Single-flight: collapse concurrent @latest fetches for the same coordinate
            // onto one upstream call. CancellationToken.None ensures a disconnecting caller
            // does not cancel the shared Lazy and fault every other waiter.
            var lazy = _svc.LatestCoordinator.InFlight.GetOrAdd(
                inflightKey,
                _ => new Lazy<Task<string?>>(
                    () => FetchLatestJsonAsync(upstreamUrl, _svc.HttpClientFactory, _svc.Logger, module, upstreamBase, authorizationHeader, CancellationToken.None)));

            // Removes exactly this (key, lazy) pair once the shared fetch genuinely completes —
            // success or failure — never when this caller's WaitAsync(ct) below merely detaches
            // early. Attaching per-caller (instead of once at registration) is safe: TryRemove is
            // idempotent, so joiners' redundant continuations are no-ops.
            InFlightCoordination.ScheduleRemoval(_svc.LatestCoordinator.InFlight, inflightKey, lazy);

            return await lazy.Value.WaitAsync(ct);
        }
        catch (HttpRequestException ex)
        {
            _svc.Logger.LogWarning(
                ex,
                "HTTP error fetching golang {Module} @latest from {UpstreamBase}: {ExceptionType}",
                module, upstreamBase, ex.GetType().Name);
            return null;
        }
    }

    // Performs the bounded upstream @latest fetch. Returns the JSON string on success,
    // null on 404, or throws HttpRequestException on other HTTP errors.
    // Called exclusively from the Lazy<Task> body — always with CancellationToken.None.
    private static async Task<string?> FetchLatestJsonAsync(
        string upstreamUrl,
        IHttpClientFactory httpClientFactory,
        ILogger<GoController> logger,
        string module,
        string upstreamBase,
        string? authorizationHeader,
        CancellationToken ct)
    {
        using var httpClient = httpClientFactory.CreateClient("upstream");
        using var request = new HttpRequestMessage(HttpMethod.Get, upstreamUrl);
        if (authorizationHeader is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        using var resp = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode)
        {
            return resp.StatusCode == System.Net.HttpStatusCode.NotFound
                ? null
                : throw new HttpRequestException(
                    $"Upstream @latest returned {(int)resp.StatusCode}",
                    inner: null,
                    statusCode: resp.StatusCode);
        }

        const int MaxLatestResponseBytes = 32 * 1024;
        using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var reader = new StreamReader(stream);
        StringBuilder sb = new();
        char[] buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer, ct)) > 0)
        {
            sb.Append(buffer, 0, read);
            if (sb.Length > MaxLatestResponseBytes)
            {
                // module is validated by ValidateModulePath in ServeLatestAsync before this helper is called;
                // upstreamBase is operator-configured; Serilog renders structured parameters, not concatenated strings.
                logger.LogWarning(
                    "Upstream @latest response too large for golang {Module} from {UpstreamBase}",
                    module, upstreamBase);
                return null;
            }
        }

        return sb.ToString();
    }

    // ── Package catalogue recording ──────────────────────────────────────────

    // Records a Go module .zip first-fetch. Ensures the per-tenant packages row exists so the
    // module appears in this org's @v/list and @latest responses; the per-version data lives in
    // the global cache plane (cache_artifact + tenant_artifact_access). No package_versions row
    // is inserted for proxy .zips — the global plane is authoritative for proxy versions.
    private async Task RecordVersionAsync(
        string orgId, string module, CancellationToken ct)
    {
        await _svc.Packages.GetOrCreateAsync(orgId, "golang", module, module, isProxy: true, ct);
    }

    /// <summary>
    /// Records a .zip access into the shared cache index (<c>cache_artifact</c> +
    /// <c>tenant_artifact_access</c>). Go modules are proxy-only, so every cached .zip is a
    /// proxy artefact and is always recorded. The checksum and size come from the
    /// <c>package_versions</c> row (org-scoped via the join on <c>packages</c>), matching the
    /// Cargo lookup shape. A missing row records empty/zero bytes-metadata — the coordinate
    /// and blob key are what the eviction pipeline keys on. Returns the recorded
    /// <c>cache_artifact</c> id, or null when the recorder declined after its retry.
    ///
    /// A null return means different things to the two callers. On a cache HIT it is best-effort:
    /// the row the serve path already gated against exists, and only this access tick is lost, so
    /// the bytes still serve. On a first fetch it means the artefact was never admitted to the
    /// cache plane at all — <see cref="RecordZipFirstFetchOrRefuseAsync"/> turns that into a 503.
    /// </summary>
    private async Task<string?> RecordZipCacheAccessAsync(
        string orgId, string module, string version, string blobKey, string? upstreamUrl, CancellationToken ct)
    {
        var (contentHash, sizeBytes) = await ResolveZipContentMetadataAsync(orgId, module, version, ct);

        string filename = $"{version}.zip";
        string? cacheArtifactId = await _svc.CacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, "golang", module, version, filename,
                contentHash, sizeBytes, blobKey, upstreamUrl,
                // A .zip first fetch is Unidentified because this path never hashes the bytes it
                // staged — ResolveZipContentMetadataAsync reads an index, and on a genuine first
                // fetch there is nothing to read. That is safe here and only here: BlobKeys.Go
                // embeds the org, so the bytes behind this key are reachable by no other tenant
                // whatever the shared coordinate row says. A hit carries no new evidence at all.
                upstreamUrl is not null
                    ? CacheAccessOrigin.FirstFetchUnidentified
                    : CacheAccessOrigin.CacheHit), ct);
        if (cacheArtifactId is not null)
        {
            // Increment per-tenant download counter and write global supply-chain facts.
            // First-fetch (upstreamUrl set) must be durable before the row's global facts are
            // written below, so it stays synchronous; a cache hit only bumps the counter and is
            // enqueued off the request path — the row already exists.
            if (upstreamUrl is not null)
            {
                await _svc.TenantAccess.UpsertStateAsync(orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);

                // Only write global facts on first-fetch (when upstreamUrl is non-null).
                // Cache-hit calls pass null to signal the artifact row already carries them.
                await _svc.CacheArtifacts.UpdateGlobalFactsAsync(
                    cacheArtifactId,
                    purl: PurlNormalizer.Golang(module, version),
                    checksumSha1: null,
                    publishedAt: null,
                    deprecated: null,
                    hasInstallScript: false,
                    installScriptKind: null,
                    provenanceStatus: null,
                    provenanceSigner: null,
                    upstreamIntegrityValue: contentHash.Length > 0 ? contentHash : null,
                    upstreamIntegrityAlgorithm: contentHash.Length > 0 ? "sha256" : null,
                    ct: ct);
            }
            else
            {
                await _svc.TenantAccess.RecordDownloadHitAsync(orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);
            }
        }

        return cacheArtifactId;
    }

    /// <summary>
    /// First-fetch wrapper around <see cref="RecordZipCacheAccessAsync"/> that enforces the
    /// fail-closed cache-plane contract: a .zip the cache plane could not take a row for is one the
    /// registry cannot scan, gate, or reclaim, so it is refused rather than served ungated.
    ///
    /// The staged blob is discarded along with the refusal. The content-addressed ecosystems
    /// (npm/PyPI/NuGet/Maven) get this for free — their cache-hit lookup is row-driven, so no row
    /// means the next request re-enters the fetch path and re-refuses. A Go .zip is keyed by its
    /// module coordinate and found by probing the blob store, so a staged-but-unrecorded blob would
    /// answer every later request from cache with no row to gate against — a permanent bypass, not
    /// a deferred one. Dropping it restores the same "no row ⇒ miss ⇒ re-fetch ⇒ re-record"
    /// invariant, at the cost of re-downloading once the plane is back.
    /// </summary>
    /// <exception cref="ProxyCatalogueUnavailableException">The recorder returned no row.</exception>
    private async Task<string> RecordZipFirstFetchOrRefuseAsync(
        string orgId, string module, string version, string blobKey, string upstreamUrl,
        Stream staged, CancellationToken ct)
    {
        string? cacheArtifactId = await RecordZipCacheAccessAsync(orgId, module, version, blobKey, upstreamUrl, ct);
        if (cacheArtifactId is not null)
        {
            return cacheArtifactId;
        }

        // Release the caller's handle on the staged blob before deleting it — the response is
        // never written, and an open handle blocks the delete on stores that lock by handle.
        await staged.DisposeAsync();
        await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(blobKey), ct);
        throw new ProxyCatalogueUnavailableException("golang", module, version);
    }

    /// <summary>
    /// Reads the just-cached module <c>.zip</c> blob back and classifies its bundled LICENSE-file
    /// text against the bundled SPDX corpus, writing any match to the global
    /// <c>cache_artifact</c> license plane. Go modules carry no declared license metadata, so
    /// LICENSE-text classification is the only proxy-side signal available. Failure at any step
    /// (blob read, decompress, classify) is swallowed and logged at Warning — extraction never
    /// fails or delays the response for the artefact that has already been staged for serving.
    /// </summary>
    private async Task TryExtractAndStoreGoLicenseAsync(
        string cacheArtifactId, string blobKey, string orgId, string module, string version, CancellationToken ct)
    {
        try
        {
            var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(blobKey), ct);
            if (stream is null)
            {
                return;
            }

            var extracted = LicenseExtractor.FromGoModuleZip(stream, module, version);
            if (extracted.Spdx.Count > 0)
            {
                await _svc.Licenses.SetLicensesForCacheArtifactAsync(cacheArtifactId, extracted.Spdx, "upstream", ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _svc.Logger.LogWarning(
                "Go license extraction failed for {Module}@{Version} (org {OrgId}): {ExceptionType}",
                module, version, orgId, ex.GetType().Name);
        }
    }

    // Resolves the checksum + size for a Go .zip: the package_versions row first (hosted or
    // pre-P3b proxy rows), falling back to the global cache_artifact plane for proxy .zips
    // recorded after the P3b flip. Best-effort — a lookup failure is logged and swallowed
    // (empty/zero metadata) so serving is never broken by an index-recording error.
    private async Task<(string ContentHash, long SizeBytes)> ResolveZipContentMetadataAsync(
        string orgId, string module, string version, CancellationToken ct)
    {
        try
        {
            await using var conn = await _svc.Db.OpenAsync(ct);
            var row = await Dapper.SqlMapper.QuerySingleOrDefaultAsync<GoVersionBytesRow>(conn,
                // plane-ok: PV-plane .zip metadata first; global-plane proxy .zips resolve via the sibling cache_artifact SELECT below.
                """
                SELECT pv.checksum_sha256 AS ChecksumSha256,
                       pv.size_bytes AS SizeBytes
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId
                  AND p.ecosystem = 'golang'
                  AND p.purl_name = @module
                  AND pv.version = @version
                """,
                new { orgId, module, version });
            if (row is not null)
            {
                return (row.ChecksumSha256 ?? "", row.SizeBytes);
            }

            // Global-plane lookup for proxy .zips recorded after the P3b flip: resolve
            // checksum and size from cache_artifact so the recorder gets accurate metadata.
            // xtenant: cache_artifact is global; org_id filter on tenant_artifact_access.
            var caRow = await Dapper.SqlMapper.QuerySingleOrDefaultAsync<GoZipCacheRow>(conn,
                """
                SELECT ca.content_hash AS ContentHash, ca.size_bytes AS SizeBytes
                FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
                WHERE ca.ecosystem = 'golang'
                  AND ca.name = @module
                  AND ca.version = @version
                LIMIT 1
                """,
                new { orgId, module, version });
            return caRow is not null && caRow.ContentHash is not null
                ? (caRow.ContentHash, caRow.SizeBytes)
                : ("", 0);
        }
        catch (Exception ex)
        {
            // The bytes already streamed to the client; this index lookup is best-effort.
            _svc.Logger.LogWarning(
                "Go cache-access recording lookup failed for {Module}@{Version} (org {OrgId}): {ExceptionType}",
                module, version, orgId, ex.GetType().Name);
            return ("", 0);
        }
    }

    // Evaluates the block gate for a cache-hit Go .zip download from the global plane. Returns
    // false (allow) when no cache_artifact row exists for the coordinate — there is no block
    // state to enforce.
    private async Task<bool> IsGoZipBlockedAsync(
        string orgId, string module, string version, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        var caFacts = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, "golang", module, version, $"{version}.zip", ct);
        return caFacts is not null
            && await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(
                    orgId, "golang", caFacts, token, settings, HttpContext.GetNormalizedRemoteIp()), ct)
                == BlockDecision.Blocked;
    }

    // Integer columns bind as long, and [ExplicitConstructor] is what lets one signature serve
    // both providers — SQLite reports INTEGER as Int64, Postgres as Int32, and Dapper's default
    // positional-record binding demands an exact CLR match. See
    // DapperPositionalRecordComplianceTests.
    [method: Dapper.ExplicitConstructor]
    private sealed record GoVersionBytesRow(string? ChecksumSha256, long SizeBytes);

    // Holds content hash and size resolved from the global cache plane for proxy .zip metadata.
    [method: Dapper.ExplicitConstructor]
    private sealed record GoZipCacheRow(string? ContentHash, long SizeBytes);

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string ContentTypeFor(string ext) => ext switch
    {
        "info" => "application/json",
        "mod" => "text/plain; charset=utf-8",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    };

    private static bool IsValidGoExt(string ext) => ext is "info" or "mod" or "zip";

    // ── Info JSON shape ──────────────────────────────────────────────────────

    private sealed record GoVersionInfo(string Version, DateTimeOffset Time);
}

/// <summary>
/// Singleton coordinator that deduplicates concurrent upstream @latest fetches.
/// Scoped to the application lifetime so the dictionary survives across requests.
/// </summary>
public sealed class GoLatestFetchCoordinator
{
    /// <summary>
    /// In-flight @latest fetch tasks keyed by <c>{orgId}:{module}:{upstreamBase}</c>.
    /// Entries are removed via <see cref="InFlightCoordination.ScheduleRemoval{TResult}"/> once
    /// the registering entry's shared task completes — not by an individual caller detaching.
    /// </summary>
    public ConcurrentDictionary<string, Lazy<Task<string?>>> InFlight { get; } = new();
}

/// <summary>Scoped DI bundle for the Go module proxy controller.</summary>
public sealed record GoControllerServices(
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    UpstreamRegistryResolver Registries,
    IHttpClientFactory HttpClientFactory,
    IMetadataStore Db,
    CacheAccessRecorder CacheRecorder,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    TimeProvider Time,
    IConfiguration Configuration,
    ILogger<GoController> Logger,
    GoLatestFetchCoordinator LatestCoordinator,
    ReservedNamespaceService Reserved,
    BlockGateService BlockGate,
    LicenseRepository Licenses);
