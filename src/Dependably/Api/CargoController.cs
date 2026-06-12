using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Cargo sparse registry surface. Implements the Rust sparse registry protocol at
/// <c>/cargo/</c>:
/// <list type="bullet">
///   <item><c>GET /cargo/config.json</c> — registry configuration document</item>
///   <item><c>GET /cargo/{**path}</c> — sparse index file or crate download dispatch</item>
/// </list>
/// The sparse index path layout follows the Cargo specification:
/// 1-char names live at <c>1/{name}</c>, 2-char at <c>2/{name}</c>,
/// 3-char at <c>3/{c}/{name}</c>, and 4+-char at <c>{ab}/{cd}/{name}</c>
/// where <c>ab</c> and <c>cd</c> are the first and second pairs of the name.
/// </summary>
[ApiController]
public sealed class CargoController : OrgScopedControllerBase
{
    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly TokenRepository _tokens;
    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly UpstreamRegistryResolver _registries;
    private readonly CargoMetadataRepository _cargoMeta;
    private readonly IPublicUrlBuilder _urls;
    private readonly UpstreamClient _upstream;
    private readonly ILogger<CargoController> _logger;

    // Dependency-injection constructor; the parameter list is the controller's declared
    // dependency set and grouping it into an aggregate would hide dependencies without
    // adding cohesion.
#pragma warning disable S107
    public CargoController(
        OrgRepository orgs,
        PackageRepository packages,
        TokenRepository tokens,
        IMetadataStore db,
        IBlobStore blobs,
        UpstreamRegistryResolver registries,
        CargoMetadataRepository cargoMeta,
        IPublicUrlBuilder urls,
        UpstreamClient upstream,
        ILogger<CargoController> logger)
#pragma warning restore S107
    {
        _orgs = orgs;
        _packages = packages;
        _tokens = tokens;
        _db = db;
        _blobs = blobs;
        _registries = registries;
        _cargoMeta = cargoMeta;
        _urls = urls;
        _upstream = upstream;
        _logger = logger;
    }

    // ── Sparse index path computation ────────────────────────────────────────

    /// <summary>
    /// Returns the index sub-path for a crate name per the Cargo sparse registry spec.
    /// The result is the relative path under the registry root (no leading slash).
    /// </summary>
    internal static string IndexPath(string name)
    {
        return name.Length switch
        {
            1 => $"1/{name}",
            2 => $"2/{name}",
            3 => $"3/{name[0]}/{name}",
            _ => $"{name[..2]}/{name[2..4]}/{name}",
        };
    }

    // ── config.json ──────────────────────────────────────────────────────────

    /// <summary>
    /// GET /cargo/config.json — Cargo registry configuration document.
    /// The <c>dl</c> field is the download URL template; Cargo appends
    /// <c>{crate}/{version}/download</c> to form the full download URL.
    /// The <c>api</c> field points to the registry API base for publish/yank.
    /// </summary>
    [HttpGet("/cargo/config.json")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetConfig(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        string baseUrl = _urls.BaseUrl(HttpContext);
        var config = new
        {
            dl = $"{baseUrl}/cargo/api/v1/crates",
            api = $"{baseUrl}/cargo",
        };

        return new JsonResult(config);
    }

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
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = 400 });
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

        var upstreamLines = settings.ProxyPassthroughEffective
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
        return Content(body, "text/plain");
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
        foreach (string upstreamBase in upstreamUrls)
        {
            string? fetched = await FetchUpstreamIndexAsync(upstreamBase, name, ct);
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
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = 400 });
        }
        if (!PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid version.", Status = 400 });
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        string blobKey = BlobKeys.Cargo(orgId, name, version);

        // Cache hit path.
        if (await _blobs.ExistsAsync(blobKey, ct))
        {
            var cachedStream = await _blobs.GetAsync(blobKey, ct);
            if (cachedStream is not null)
            {
                // deepcode ignore LogForging: name and version are validated by PathSafeValidator.ValidateUpstreamSegment before reaching this path; Serilog renders structured parameters, not concatenated strings.
                _logger.LogDebug(
                    "Cargo cache hit: {Name} {Version} for org {OrgId}.", name, version, orgId);
                return File(cachedStream, "application/octet-stream", $"{name}-{version}.crate");
            }
        }

        // Cache miss — proxy fetch.
        if (!settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        var upstreamUrls = await _registries.ResolveAsync(orgId, "cargo", ct);
        if (upstreamUrls.Count == 0)
        {
            return NotFound();
        }

        foreach (string upstreamBase in upstreamUrls)
        {
            string downloadUrl = BuildCrateDownloadUrl(upstreamBase, name, version);
            Stream crateStream;
            try
            {
                // Route through UpstreamClient: size-capped, SSRF-checked, and
                // dedup-protected. The blob is stored under the org-scoped Cargo key so
                // subsequent ExistsAsync calls hit the cache path above.
                // deepcode ignore PT,LogForging: name and version are validated by PathSafeValidator.ValidateUpstreamSegment above; blobKey comes from BlobKeys.Cargo (no traversal possible); Serilog uses structured rendering.
                (crateStream, _) = await _upstream.GetOrFetchStreamAsync(
                    blobKey, downloadUrl, checksumSpec: null, "cargo", orgId, ct: ct);
            }
            catch (Exception ex) when (
                ex is HttpRequestException
                    or SsrfBlockedException
                    or UpstreamResponseTooLargeException
                    or TaskCanceledException
                    or OperationCanceledException)
            {
                // deepcode ignore LogForging: name and version pass PathSafeValidator; downloadUrl is constructed from validated segments; ExceptionType is a type name, not user input; Serilog structured rendering prevents log injection.
                _logger.LogWarning(
                    "Cargo upstream crate fetch failed for {Name} {Version} from {Url}: {ExceptionType}",
                    name, version, downloadUrl, ex.GetType().Name);
                continue;
            }

            // Buffer the stored blob once to compute SHA-256 and size for the DB record,
            // then serve the bytes directly. This is the first-fetch path so a single
            // in-memory buffer is acceptable; subsequent requests stream from the blob store.
            byte[] crateBytes;
            await using (crateStream)
            {
                using var ms = new MemoryStream();
                await crateStream.CopyToAsync(ms, ct);
                crateBytes = ms.ToArray();
            }

            string sha256Hex = ComputeSha256Hex(crateBytes);
            await RecordProxiedVersionAsync(orgId, name, version, blobKey, sha256Hex, crateBytes.Length, ct);

            // deepcode ignore LogForging: name and version pass PathSafeValidator; sha256Hex is a hex digest from ComputeSha256Hex; Serilog structured rendering prevents log injection.
            _logger.LogInformation(
                "Cargo proxy first-fetch: {Name} {Version} ({Bytes} bytes, sha256={Sha256}) for org {OrgId}.",
                name, version, crateBytes.Length, sha256Hex[..16], orgId);

            return File(crateBytes, "application/octet-stream", $"{name}-{version}.crate");
        }

        return NotFound();
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
    private async Task<string?> FetchUpstreamIndexAsync(
        string upstreamBase, string name, CancellationToken ct)
    {
        string indexPath = IndexPath(name);
        string url = $"{upstreamBase}/{indexPath}";
        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(url, ct);
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
            // deepcode ignore LogForging: name passes PathSafeValidator; url comes from operator-configured upstream registry; ExceptionType is a type name; Serilog structured rendering prevents log injection.
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
    /// Records a proxied Cargo version in the packages/package_versions tables. Uses the
    /// standard GetOrCreate pattern so re-fetches are idempotent. Skips insertion when
    /// the version already exists (the blob was refreshed but the DB row is authoritative).
    /// </summary>
    private async Task RecordProxiedVersionAsync(
        string orgId, string name, string version,
        string blobKey, string sha256Hex, long sizeBytes,
        CancellationToken ct)
    {
        string purl = PurlNormalizer.Cargo(name, version);

        var pkg = await _packages.GetOrCreateAsync(orgId, "cargo", name, name, isProxy: true, ct);

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: package_id is derived from pkg.Id which is already org-scoped above.
        int existing = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = pkg.Id, version });

        if (existing > 0)
        {
            return;
        }

        string filename = $"{name}-{version}.crate";
        // xtenant: package_id is derived from pkg.Id which is already org-scoped by GetOrCreateAsync above.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes,
                 checksum_sha256, first_fetch, origin)
            VALUES
                (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes,
                 @sha256, 1, 'proxy')
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pkgId = pkg.Id,
                version,
                purl,
                blobKey,
                filename,
                sizeBytes,
                sha256 = sha256Hex,
            });
    }

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

    private static string ComputeSha256Hex(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
