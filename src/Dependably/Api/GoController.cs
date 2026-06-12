using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Dependably.Infrastructure;
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
/// modules in MR1 — only proxy reading is supported.
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

        // sumdb passthrough is not implemented in this version.
        if (path.StartsWith("sumdb/", StringComparison.OrdinalIgnoreCase))
        {
            return NotFound("sumdb passthrough not yet implemented");
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);

        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
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

    // ── Artifact serving ─────────────────────────────────────────────────────

    private async Task<IActionResult> ServeArtifactAsync(
        string orgId, string module, string version, string ext,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        var invalidModule = ValidateModulePath(module);
        if (invalidModule is not null)
        {
            return invalidModule;
        }

        var versionResult = PathSafeValidator.Validate(version, "version");
        if (!versionResult.IsValid)
        {
            return BadRequest($"Invalid version: {versionResult.Message}");
        }

        string blobKey = BlobKeys.Go(orgId, module, version, ext);

        // Cache HIT — serve from blob store.
        var cached = await _svc.Blobs.GetAsync(blobKey, ct);
        if (cached is not null)
        {
            Response.Headers["X-Cache"] = "HIT";
            return File(cached, ContentTypeFor(ext));
        }

        // Cache MISS — check proxy settings (ProxyPassthroughEffective combines
        // ProxyPassthroughEnabled and AirGapped into a single gate).
        return settings is not null && !settings.ProxyPassthroughEffective
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

        foreach (string upstreamBase in upstreamBases)
        {
            string upstreamUrl = $"{upstreamBase}/{upstreamPath}";
            try
            {
                var (stream, isHit) = await _svc.Upstream.GetOrFetchStreamAsync(
                    blobKey,
                    upstreamUrl,
                    checksumSpec: null,
                    ecosystem: "golang",
                    orgId: orgId,
                    purl: PurlNormalizer.Golang(module, version),
                    ct: ct);

                _ = isHit; // cache-hit is already handled above; this is always a miss path

                if (ext == "zip")
                {
                    // Record the version in the catalogue for the .zip (primary artifact).
                    await RecordVersionAsync(orgId, module, version, blobKey, token, ct);
                }

                await _svc.Audit.LogActivityAsync(
                    orgId, "golang", PurlNormalizer.Golang(module, version),
                    ext == "zip" ? "first_fetch" : "download",
                    token?.UserId,
                    sourceIp: HttpContext.GetNormalizedRemoteIp(),
                    ct: ct);

                Response.Headers["X-Cache"] = "MISS";
                return File(stream, ContentTypeFor(ext));
            }
            catch (ChecksumException)
            {
                _svc.Logger.LogWarning(
                    "Checksum mismatch fetching golang {Module}@{Version}.{Ext} from {UpstreamBase}",
                    module, version, ext, upstreamBase);
                return StatusCode(502, "Upstream checksum verification failed.");
            }
            catch (UpstreamResponseTooLargeException)
            {
                _svc.Logger.LogWarning(
                    "Upstream response too large fetching golang {Module}@{Version}.{Ext} from {UpstreamBase}",
                    module, version, ext, upstreamBase);
                return StatusCode(502, "Upstream response exceeded size limit.");
            }
            catch (HttpRequestException ex)
            {
                // 404 from upstream means not found at this registry; try the next one.
                if (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    continue;
                }

                _svc.Logger.LogWarning(
                    ex,
                    "HTTP error fetching golang {Module}@{Version}.{Ext} from {UpstreamBase}: {ExceptionType}",
                    module, version, ext, upstreamBase, ex.GetType().Name);
                return StatusCode(502, "Upstream fetch failed.");
            }
        }

        return NotFound();
    }

    /// <summary>
    /// Validates each segment of a Go module path. Go module paths contain '/' so each
    /// segment is validated individually (split on '/'), the same way Maven validates its
    /// multi-part coordinates. Returns a 400 result on the first invalid segment, null when
    /// the whole path is valid.
    /// </summary>
    private BadRequestObjectResult? ValidateModulePath(string module)
    {
        foreach (string seg in module.Split('/'))
        {
            var r = PathSafeValidator.Validate(seg, "module");
            if (!r.IsValid)
            {
                return BadRequest($"Invalid module path: {r.Message}");
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
        var invalidModule = ValidateModulePath(module);
        if (invalidModule is not null)
        {
            return invalidModule;
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
        var invalidModule = ValidateModulePath(module);
        if (invalidModule is not null)
        {
            return invalidModule;
        }

        // Return the latest locally-cached version if we have one.
        var latest = await _svc.Packages.GetLatestGoVersionAsync(orgId, module, ct);
        if (latest is not null)
        {
            return Content(
                JsonSerializer.Serialize(new GoVersionInfo(latest.Version, latest.CreatedAt)),
                "application/json");
        }

        // Proxy upstream @latest.
        if (settings is not null && !settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        var upstreamBases = await _svc.Registries.ResolveAsync(orgId, "golang", ct);
        if (upstreamBases.Count == 0)
        {
            return NotFound();
        }

        string encodedModule = EncodeBangEncoding(module);
        foreach (string upstreamBase in upstreamBases)
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
                        () => FetchLatestJsonAsync(upstreamUrl, _svc.HttpClientFactory, _svc.Logger, module, upstreamBase, CancellationToken.None)));
                try
                {
                    string? json = await lazy.Value.WaitAsync(ct);
                    if (json is null)
                    {
                        continue;
                    }
                    return Content(json, "application/json");
                }
                finally
                {
                    _svc.LatestCoordinator.InFlight.TryRemove(inflightKey, out _);
                }
            }
            catch (HttpRequestException ex)
            {
                _svc.Logger.LogWarning(
                    ex,
                    "HTTP error fetching golang {Module} @latest from {UpstreamBase}: {ExceptionType}",
                    module, upstreamBase, ex.GetType().Name);
                continue;
            }
        }

        return NotFound();
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
        CancellationToken ct)
    {
        using var httpClient = httpClientFactory.CreateClient("upstream");
        using var resp = await httpClient.GetAsync(upstreamUrl, HttpCompletionOption.ResponseHeadersRead, ct);
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
                logger.LogWarning(
                    "Upstream @latest response too large for golang {Module} from {UpstreamBase}",
                    module, upstreamBase);
                return null;
            }
        }

        return sb.ToString();
    }

    // ── Package catalogue recording ──────────────────────────────────────────

    private async Task RecordVersionAsync(
        string orgId, string module, string version, string blobKey, TokenRecord? token, CancellationToken ct)
    {
        string purl = PurlNormalizer.Golang(module, version);
        await _svc.Packages.GetOrCreateGoVersionAsync(orgId, module, version, purl, blobKey, token?.UserId, ct);
    }

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
    /// Entries are removed by the caller's finally block once the task resolves.
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
    ILogger<GoController> Logger,
    GoLatestFetchCoordinator LatestCoordinator);
