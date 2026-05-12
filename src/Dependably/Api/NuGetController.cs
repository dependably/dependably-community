using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using NuGet.Versioning;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

[ApiController]
public partial class NuGetController : ControllerBase
{
    // Known Microsoft nuspec namespaces
    private static readonly HashSet<string> KnownNuspecNamespaces = [
        "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"
    ];

    [GeneratedRegex(@"^[A-Za-z0-9_\-\.]+$")]
    private static partial Regex NuGetIdRegex();

    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly TokenRepository _tokens;
    private readonly AuditRepository _audit;
    private readonly IBlobStore _blobs;
    private readonly UpstreamClient _upstream;
    private readonly AllowlistService _allowlist;
    private readonly BlocklistRepository _blocklist;
    private readonly IConfiguration _config;
    private readonly IMetadataStore _db;
    private readonly Dependably.Infrastructure.VulnerabilityScanService _scanner;
    private readonly VulnerabilityRepository _vulns;
    private readonly LicenseRepository _licenses;
    private readonly IPublicUrlBuilder _urls;
    private readonly PublishGate _publishGate;
    private readonly Dependably.Infrastructure.Publish.IPackagePublishService _publish;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ClaimResolver _claimResolver;

    public NuGetController(NuGetControllerServices svc)
    {
        _orgs = svc.Orgs;
        _packages = svc.Packages;
        _tokens = svc.Tokens;
        _audit = svc.Audit;
        _blobs = svc.Blobs;
        _upstream = svc.Upstream;
        _allowlist = svc.Allowlist;
        _blocklist = svc.Blocklist;
        _config = svc.Config;
        _db = svc.Db;
        _scanner = svc.Scanner;
        _vulns = svc.Vulns;
        _licenses = svc.Licenses;
        _urls = svc.Urls;
        _publishGate = svc.PublishGate;
        _publish = svc.Publish;
        _cacheRecorder = svc.CacheRecorder;
        _claimResolver = svc.ClaimResolver;
    }

    // ── Service index ────────────────────────────────────────────────────────

    /// <summary>GET /o/{org}/nuget/v3/index.json and /o/{org}/nuget/index.json — NuGet v3 service index</summary>
    [HttpGet("/nuget/v3/index.json")]
    [HttpGet("/nuget/index.json")]
    public async Task<IActionResult> ServiceIndex(CancellationToken ct)
    {
        var baseUrl = BaseUrl();

        static Dictionary<string, string> R(string id, string type) =>
            new() { ["@id"] = id, ["@type"] = type };

        return new JsonResult(new
        {
            version = "3.0.0",
            resources = new[]
            {
                R($"{baseUrl}/query",        "SearchQueryService"),
                R($"{baseUrl}/registration", "RegistrationsBaseUrl"),
                R($"{baseUrl}/flatcontainer","PackageBaseAddress/3.0.0"),
                R($"{baseUrl}/publish",      "PackagePublish/2.0.0"),
                R($"{baseUrl}/symbols",      "SymbolPackagePublish/4.9.0")
            }
        });
    }

    // ── Search ───────────────────────────────────────────────────────────────

    /// <summary>GET /o/{org}/nuget/query — NuGet search endpoint</summary>
    [HttpGet("/nuget/query")]
    public async Task<IActionResult> Search([FromQuery] string? q, [FromQuery] int skip = 0, [FromQuery] int take = 20, CancellationToken ct = default)
    {
        var orgId = CurrentTenantId();

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var allPkgs = await _packages.ListAsync(orgId, "nuget", ct);
        var filtered = string.IsNullOrWhiteSpace(q)
            ? allPkgs
            : allPkgs.Where(p => p.Name.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();

        var baseUrl = BaseUrl();
        var results = new List<object>();

        foreach (var pkg in filtered.Skip(skip).Take(take))
        {
            var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
            var latestVersion = versions.Where(v => !v.Yanked).MaxBy(v => v.CreatedAt);
            if (latestVersion is null) continue;

            results.Add(new
            {
                id = pkg.Name,
                version = latestVersion.Version,
                versions = versions.Where(v => !v.Yanked).Select(v => new { version = v.Version }),
                registration = $"{baseUrl}/registration/{pkg.Name.ToLowerInvariant()}/"
            });
        }

        return new JsonResult(new { totalHits = results.Count, data = results });
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /// <summary>GET /o/{org}/nuget/registration/{id}/ — registration index</summary>
    [HttpGet("/nuget/registration/{id}/")]
    public async Task<IActionResult> RegistrationIndex(string id, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);

        if (pkg is null) return await ProxyNuGetRegistration(id, settings, token, ct);

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var baseUrl = BaseUrl();

        var leaves = versions.Where(v => !v.Yanked).Select(v => new
        {
            @id = $"{baseUrl}/registration/{id.ToLowerInvariant()}/{v.Version}.json",
            catalogEntry = new
            {
                id = pkg.Name,
                version = v.Version,
                listed = true,
                packageContent = $"{baseUrl}/flatcontainer/{id.ToLowerInvariant()}/{v.Version}/{id.ToLowerInvariant()}.{v.Version}.nupkg"
            }
        }).ToList();

        return new JsonResult(new
        {
            @id = $"{baseUrl}/registration/{id.ToLowerInvariant()}/",
            items = new[]
            {
                new
                {
                    @id = $"{baseUrl}/registration/{id.ToLowerInvariant()}/index.json",
                    items = leaves
                }
            }
        });
    }

    private async Task<IActionResult> ProxyNuGetRegistration(string id, OrgSettings settings, TokenRecord? token, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null) return Unauthorized();

        var upstreamBase = _config["NuGet:Upstream"] ?? "https://api.nuget.org/v3";
        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            // Use registration3 (uncompressed JSON) to avoid gzip decompression issues
            using var resp = await _upstream.GetMetadataAsync($"{upstreamBase}/registration3/{id.ToLowerInvariant()}/index.json", linkedCts.Token);
            if (!resp.IsSuccessStatusCode) return NotFound();
            var content = await resp.Content.ReadAsStringAsync(linkedCts.Token);
            return Content(content, "application/json");
        }
        catch { return StatusCode(502); }
    }

    // ── Flatcontainer / download ─────────────────────────────────────────────

    /// <summary>GET /o/{org}/nuget/flatcontainer/{id}/index.json — version list</summary>
    [HttpGet("/nuget/flatcontainer/{id}/index.json")]
    public async Task<IActionResult> FlatcontainerVersions(string id, CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);

        var versionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await CollectLocalVersionsAsync(pkg, versionSet, ct);
        if (pkg is null || pkg.IsProxy)
            await MergeUpstreamVersionsAsync(id, versionSet, ct);

        if (versionSet.Count == 0) return NotFound();
        return new JsonResult(new { versions = versionSet.Order() });
    }

    private async Task CollectLocalVersionsAsync(Package? pkg, HashSet<string> versionSet, CancellationToken ct)
    {
        if (pkg is null) return;
        var local = await _packages.GetVersionsAsync(pkg.Id, ct);
        foreach (var v in local.Where(v => !v.Yanked)) versionSet.Add(v.Version);
    }

    // For proxy packages (or unknown packages), fetch the upstream version list and merge.
    // Short timeout so slow upstream responses don't hang clients after they have what they need.
    // Upstream unreachable / slow → fall back to local set.
    private async Task MergeUpstreamVersionsAsync(string id, HashSet<string> versionSet, CancellationToken ct)
    {
        var upstreamBase = _config["NuGet:Upstream"] ?? "https://api.nuget.org/v3";
        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            using var resp = await _upstream.GetMetadataAsync(
                $"{upstreamBase}/flatcontainer/{id.ToLowerInvariant()}/index.json", linkedCts.Token);
            if (!resp.IsSuccessStatusCode) return;

            var content = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(content);
            if (!doc.RootElement.TryGetProperty("versions", out var versionsElem)) return;
            foreach (var v in versionsElem.EnumerateArray())
            {
                var ver = v.GetString();
                if (ver is not null) versionSet.Add(ver);
            }
        }
        catch { /* upstream unreachable — fall back to local versions */ }
    }

    /// <summary>GET /o/{org}/nuget/flatcontainer/{id}/{version}/{file} — package download</summary>
    [HttpGet("/nuget/flatcontainer/{id}/{version}/{file}")]
    public async Task<IActionResult> Flatcontainer(string id, string version, string file, CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);

        if (pkg is { IsProxy: false })
            return await ServeHostedNupkgAsync(orgId, pkg, version, file, token, settings!, ct);

        if (pkg is { IsProxy: true })
        {
            var proxyResult = await TryServeProxyCachedNupkgAsync(orgId, pkg, version, file, token, settings!, ct);
            if (proxyResult is not null) return proxyResult;
        }

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var purlCheck = $"pkg:nuget/{id.ToLowerInvariant()}";
        if (settings?.AllowlistMode == true && !await _allowlist.IsAllowedAsync(orgId, "nuget", purlCheck, ct))
            return StatusCode(403);
        if (await _blocklist.IsBlockedAsync(orgId, "nuget", purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "nuget", purlCheck, "blocked", token?.UserId, ct: ct);
            return StatusCode(403);
        }

        if (!settings!.ProxyPassthroughEnabled) return NotFound();

        // #47: claim state gates the proxy fetch. local_only (or air-gap implicit local_only)
        // disables proxy serving for that name.
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", id.ToLowerInvariant(), ct))
            return NotFound();

        return await ProxyFetchNupkgAsync(orgId, id, version, file, token, settings!, ct);
    }

    private async Task<IActionResult> ServeHostedNupkgAsync(
        string orgId, Package pkg, string version, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }
        var pkgVersion = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (pkgVersion is null) return NotFound();

        var blockResult = await CheckNuGetBlockGateAsync(
            new BlockProbe(pkgVersion.Purl, pkgVersion.Id, pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt),
            new BlockGateContext(orgId, token.UserId, settings), ct);
        if (blockResult is not null) return blockResult;

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null) return NotFound();

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        await _audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "download", token.UserId, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    // For proxy packages: serve from cache only when the cached blob is for the exact requested file.
    // Each file type (nupkg, nuspec, sha512) has a distinct sha256 and blob. Serving the wrong blob
    // (e.g., nupkg bytes when the client requests the .sha512 hash) causes integrity verification to fail.
    // Returns 403 if blocked, the file IActionResult if cached, or null if cache miss → caller proxies.
    private async Task<IActionResult?> TryServeProxyCachedNupkgAsync(
        string orgId, Package pkg, string version, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var normalizedVersion = NormalizeNuGetVersion(version);
        var pkgVersion = await _packages.GetVersionAsync(pkg.Id, normalizedVersion, ct);

        if (pkgVersion is not null)
        {
            var blockResult = await CheckNuGetBlockGateAsync(
                new BlockProbe(pkgVersion.Purl, pkgVersion.Id, pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt),
                new BlockGateContext(orgId, token?.UserId, settings), ct);
            if (blockResult is not null) return blockResult;
        }

        if (pkgVersion is null || !pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
            return null;

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null) return null;

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        await _audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "download", token?.UserId, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    private static string NormalizeNuGetVersion(string version) =>
        NuGet.Versioning.NuGetVersion.TryParse(version, out var nv)
            ? nv.ToNormalizedString().ToLowerInvariant()
            : version.ToLowerInvariant();

    // Returns 403 IActionResult if blocked (manual or OSV score over tolerance), else null.
    private async Task<IActionResult?> CheckNuGetBlockGateAsync(
        BlockProbe probe, BlockGateContext gate, CancellationToken ct)
    {
        if (probe.ManualState == "blocked")
        {
            await _audit.LogActivityAsync(gate.OrgId, "nuget", probe.Purl, "blocked_manual", gate.UserId, ct: ct);
            return StatusCode(403);
        }
        if (probe.ManualState == "allowed" || probe.VulnCheckedAt is null) return null;

        var maxScore = await _vulns.GetMaxScoreForVersionAsync(probe.VersionId, ct);
        if (!maxScore.HasValue || maxScore.Value <= gate.Settings.MaxOsvScoreTolerance) return null;

        await _audit.LogActivityAsync(gate.OrgId, "nuget", probe.Purl, "blocked_vuln_score", gate.UserId,
            detail: $"{{\"max_score\":{maxScore.Value},\"tolerance\":{gate.Settings.MaxOsvScoreTolerance}}}",
            ct: ct);
        return StatusCode(403);
    }

    private sealed record BlockProbe(string Purl, string VersionId, string? ManualState, DateTimeOffset? VulnCheckedAt);
    private sealed record BlockGateContext(string OrgId, string? UserId, OrgSettings Settings);

    private async Task<IActionResult> ProxyFetchNupkgAsync(
        string orgId, string id, string version, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var upstreamBase = _config["NuGet:Upstream"] ?? "https://api.nuget.org/v3";
        Response.Headers["X-Cache"] = "MISS";
        try
        {
            using var resp = await _upstream.GetMetadataAsync(
                $"{upstreamBase}/flatcontainer/{id.ToLowerInvariant()}/{version}/{file}", ct);
            if (!resp.IsSuccessStatusCode) return NotFound();
            var bytes = await resp.Content.ReadAsByteArrayAsync(ct);

            var sha256 = ChecksumVerifier.ComputeSha256Hex(bytes);
            var blobKey = BlobKeys.Proxy(sha256);
            if (!await _blobs.ExistsAsync(blobKey, ct))
                await _blobs.PutAsync(blobKey, new MemoryStream(bytes), ct);

            var normalizedId = id.ToLowerInvariant();
            var normalizedVersion = NormalizeNuGetVersion(version);
            var canonicalId = ResolveCanonicalNuGetId(file, bytes, normalizedId);
            var purl = PurlNormalizer.NuGet(canonicalId, normalizedVersion);

            // #48: record into cache_artifact + tenant_artifact_access. Best-effort.
            await _cacheRecorder.RecordAccessAsync(new CacheAccess(
                orgId, "nuget", normalizedId, normalizedVersion, file, sha256, bytes.Length,
                blobKey, $"{upstreamBase}/flatcontainer/{normalizedId}/{normalizedVersion}/{file}"), ct);

            var scanVersionId = await RecordOrLookupNuGetVersionAsync(
                normalizedId, normalizedVersion, purl,
                new ProxyPayload(sha256, file, bytes),
                new ProxyTenantContext(orgId, token), ct);

            if (scanVersionId is not null)
            {
                await _scanner.ScanVersionAsync(purl, scanVersionId, "nuget", normalizedId, orgId, ct: ct);
                var existing = await _packages.GetVersionByIdAsync(scanVersionId, ct);
                var blockResult = await CheckNuGetBlockGateAsync(
                    new BlockProbe(purl, scanVersionId, existing?.ManualBlockState, DateTimeOffset.UtcNow),
                    new BlockGateContext(orgId, token?.UserId, settings), ct);
                if (blockResult is not null) return blockResult;
            }

            return File(bytes, "application/octet-stream", file);
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch { return NotFound(); }
    }

    // NuGet client URLs use lowercase IDs, but OSV PURL lookups are case-sensitive.
    // Extract the canonical-case ID from the downloaded content so the PURL matches OSV.
    private static string ResolveCanonicalNuGetId(string file, byte[] bytes, string normalizedId)
    {
        if (file.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var doc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(bytes));
                var ns = doc.Root?.Name.NamespaceName ?? "";
                XNamespace xns = ns;
                var parsedId = doc.Root?.Element(xns + "metadata")?.Element(xns + "id")?.Value?.Trim();
                if (!string.IsNullOrEmpty(parsedId)) return parsedId;
            }
            catch { /* malformed nuspec — fall back to lowercase */ }
        }
        else if (file.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
        {
            var (parseResult, nuspecId, _) = ParseNupkg(bytes, isSymbol: false);
            if (parseResult.IsValid && !string.IsNullOrEmpty(nuspecId)) return nuspecId;
        }
        return normalizedId;
    }

    private async Task<string?> RecordOrLookupNuGetVersionAsync(
        string normalizedId, string normalizedVersion, string purl,
        ProxyPayload payload, ProxyTenantContext tenant, CancellationToken ct)
    {
        try
        {
            var record = await _packages.GetOrCreateAsync(tenant.OrgId, "nuget", normalizedId, normalizedId, isProxy: true, ct);
            var dbBlobKey = $"{BlobKeys.Proxy(payload.Sha256)}/{payload.File}";
            var newVer = await _packages.CreateVersionAsync(
                new NewPackageVersion(record.Id, normalizedVersion, purl, dbBlobKey, payload.Bytes.Length, payload.Sha256, FirstFetch: true), ct);
            await _audit.LogActivityAsync(tenant.OrgId, "nuget", purl, "first_fetch", tenant.Token?.UserId, ct: ct);

            // License from the .nuspec inside the cached .nupkg. Other file types (.nuspec sidecar / .sha512)
            // don't carry the package archive, so skip those.
            if (payload.File.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
            {
                var extracted = LicenseExtractor.FromNuspec(payload.Bytes);
                if (extracted.Spdx.Count > 0)
                    await _licenses.SetLicensesAsync(newVer.Id, extracted.Spdx, "upstream", ct);
            }
            return newVer.Id;
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            var existingPkg = await _packages.GetByPurlNameAsync(tenant.OrgId, "nuget", normalizedId, ct);
            if (existingPkg is null) return null;
            var existingVer = await _packages.GetVersionAsync(existingPkg.Id, normalizedVersion, ct);
            return existingVer?.Id;
        }
    }

    private sealed record ProxyPayload(string Sha256, string File, byte[] Bytes);
    private sealed record ProxyTenantContext(string OrgId, TokenRecord? Token);

    // ── Push ─────────────────────────────────────────────────────────────────

    /// <summary>PUT /o/{org}/nuget/publish — push a .nupkg</summary>
    [HttpPut("/nuget/publish")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNuget)]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> Push(CancellationToken ct)
        => PushPackage(isSymbol: false, ct);

    /// <summary>PUT /o/{org}/nuget/symbols — push a .snupkg</summary>
    [HttpPut("/nuget/symbols")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNuget)]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> PushSymbols(CancellationToken ct)
        => PushPackage(isSymbol: true, ct);

    private async Task<IActionResult> PushPackage(bool isSymbol, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        var (token, authError) = await ResolveNuGetPushTokenAsync(orgId, ct);
        if (authError is not null) return authError;

        var (bytes, readError) = await ReadPushBodyAsync(ct);
        if (readError is not null) return readError;

        var (parseResult, nuspecId, nuspecVersion) = ParseNupkg(bytes!, isSymbol);
        if (!parseResult.IsValid)
            return UnprocessableEntity(new ProblemDetails { Detail = parseResult.Message, Status = 422 });

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var limit = settings?.MaxUploadBytesNuGet ?? settings?.MaxUploadBytes ?? long.MaxValue;
        var pushCtx = new NuGetPushContext(orgId, token!, settings, limit);
        var publishResult = await PublishNuspecAsync(
            pushCtx, nuspecId!, nuspecVersion!, isSymbol, bytes!, ct);
        return publishResult;
    }

    /// <summary>
    /// Publish-side context for NuGet push: tenant id, resolved token, the org's settings
    /// row (nullable for fresh tenants), and the resolved size cap. Bundling these into a
    /// record keeps <see cref="PublishNuspecAsync"/>'s parameter list at 6 instead of 9.
    /// </summary>
    private sealed record NuGetPushContext(
        string OrgId, TokenRecord Token, OrgSettings? Settings, long Limit);

    /// <summary>
    /// Cross-tenant guard + token resolution for NuGet push. [Authorize] +
    /// [RequireCapability] on the action method already enforce auth + capability;
    /// this method's only remaining job is to assert the resolved token's tenant
    /// matches the request's tenant and to surface the WWW-Authenticate header on
    /// rejection. Returns the resolved token on success or an IActionResult on
    /// rejection.
    /// </summary>
    private async Task<(TokenRecord? token, IActionResult? error)> ResolveNuGetPushTokenAsync(
        string orgId, CancellationToken ct)
    {
        var apiKey = Request.Headers["X-NuGet-ApiKey"].FirstOrDefault();
        TokenRecord? token = null;
        if (apiKey is not null) token = await _tokens.ResolveAsync(apiKey, ct);

        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return (null, Unauthorized());
        }
        return (token, null);
    }

    /// <summary>
    /// Reads the multipart body's first file into memory. Returns (bytes, null) on success
    /// or (null, error) on shape mismatch.
    /// </summary>
    private async Task<(byte[]? bytes, IActionResult? error)> ReadPushBodyAsync(CancellationToken ct)
    {
        if (!Request.HasFormContentType)
            return (null, BadRequest("Expected multipart/form-data."));

        var form = await Request.ReadFormAsync(ct);
        var file = form.Files.Count > 0 ? form.Files[0] : null;
        if (file is null)
            return (null, UnprocessableEntity(new ProblemDetails { Detail = "No file in request.", Status = 422 }));

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms, ct);
        return (ms.ToArray(), null);
    }

    /// <summary>
    /// Path-safety + size + claim-gate validation, build the PublishRequest, dispatch to
    /// PackagePublishService, and emit the licence rows on success. The final mile of the
    /// push flow lives here so PushPackage stays a thin orchestrator.
    /// </summary>
    private async Task<IActionResult> PublishNuspecAsync(
        NuGetPushContext ctx, string nuspecId, string nuspecVersion,
        bool isSymbol, byte[] bytes, CancellationToken ct)
    {
        var idCheck = PathSafeValidator.Validate(nuspecId, "id");
        if (!idCheck.IsValid) return UnprocessableEntity(new ProblemDetails { Detail = idCheck.Message, Status = 422 });

        var verCheck = PathSafeValidator.Validate(nuspecVersion, "version");
        if (!verCheck.IsValid) return UnprocessableEntity(new ProblemDetails { Detail = verCheck.Message, Status = 422 });

        var claimReject = await _publishGate.CheckAsync(ctx.OrgId, "nuget", nuspecId.ToLowerInvariant(), ct);
        if (claimReject is not null) return claimReject;

        if (bytes.Length > ctx.Limit)
            return StatusCode(413, new ProblemDetails { Detail = "Upload exceeds NuGet size limit.", Status = 413 });

        var normalizedVersion = PurlNormalizer.NormalizeNuGetVersionString(nuspecVersion);
        var purlName = nuspecId.ToLowerInvariant();
        var ext = isSymbol ? "snupkg" : "nupkg";
        var filename = $"{purlName}.{normalizedVersion.ToLowerInvariant()}.{ext}";

        var filenameCheck = PathSafeValidator.Validate(filename, "filename");
        if (!filenameCheck.IsValid)
            return UnprocessableEntity(new ProblemDetails { Detail = filenameCheck.Message, Status = 422 });

        var claim = await _claimResolver.ResolveAsync(ctx.OrgId, "nuget", purlName, ct);
        var publishResult = await _publish.StoreAndRecordAsync(new Dependably.Infrastructure.Publish.PublishRequest
        {
            OrgId = ctx.OrgId,
            Ecosystem = "nuget",
            Name = nuspecId,
            PurlName = purlName,
            Version = normalizedVersion,
            Filename = filename,
            Purl = PurlNormalizer.NuGet(nuspecId, normalizedVersion),
            ArtifactBytes = bytes,
            Origin = "uploaded",
            SizeCap = ctx.Limit,
            ActorUserId = ctx.Token.UserId,
            AuditAction = "push",
            AllowOverwrite = ctx.Settings?.AllowVersionOverwrite ?? false,
            ClaimState = claim.State,
        }, ct);

        if (publishResult is Dependably.Infrastructure.Publish.PublishResult.Rejected rej)
        {
            return rej.Code == "version_exists"
                ? Conflict(new ProblemDetails { Detail = $"Version {normalizedVersion} already exists.", Status = 409 })
                : StatusCode(rej.HttpStatus, new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus });
        }

        // License from the .nuspec inside the .nupkg. Deprecation lives in registration
        // metadata, not the nuspec — never available at push time, only on proxy fetches
        // with a registration leaf.
        var versionId = ((Dependably.Infrastructure.Publish.PublishResult.Accepted)publishResult).VersionId;
        var extracted = LicenseExtractor.FromNuspec(bytes);
        if (extracted.Spdx.Count > 0)
            await _licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);

        return StatusCode(201);
    }

    // ── Unlist ───────────────────────────────────────────────────────────────

    /// <summary>DELETE /o/{org}/nuget/publish/{id}/{version} — unlist (not hard-delete)</summary>
    [HttpDelete("/nuget/publish/{id}/{version}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.YankNuget)]
    public async Task<IActionResult> Unlist(string id, string version, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        // [Authorize] + [RequireCapability(YankNuget)] enforce auth + capability above.
        // Resolve the token here only for the cross-tenant guard.
        var apiKey = Request.Headers["X-NuGet-ApiKey"].FirstOrDefault();
        TokenRecord? token = null;
        if (apiKey is not null) token = await _tokens.ResolveAsync(apiKey, ct);

        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);
        if (pkg is null) return NotFound();

        var pkgVersion = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (pkgVersion is null) return NotFound();

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE package_versions SET yanked = 1 WHERE id = @id",
            new { id = pkgVersion.Id });

        return NoContent();
    }

    // ── Symbol download ──────────────────────────────────────────────────────

    /// <summary>GET /o/{org}/nuget/symbols/{id}/{version}/{file}</summary>
    [HttpGet("/nuget/symbols/{id}/{version}/{file}")]
    public async Task<IActionResult> GetSymbols(string id, string version, string file, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", id.ToLowerInvariant(), ct);
        if (pkg is null) return NotFound();

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var normalizedSymbolVersion = NuGet.Versioning.NuGetVersion.TryParse(version, out var snv)
            ? snv.ToNormalizedString() : version;
        var match = versions.FirstOrDefault(v => v.Version == normalizedSymbolVersion && v.BlobKey.EndsWith(".snupkg"));
        if (match is null) return NotFound();

        var stream = await _blobs.GetAsync(match.BlobKey, ct);
        if (stream is null) return NotFound();

        return File(stream, "application/octet-stream", file);
    }

    // ── Validation helpers ────────────────────────────────────────────────────

    private static (ValidationResult, string? id, string? version) ParseNupkg(byte[] bytes, bool isSymbol)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);

            if (isSymbol)
            {
                var hasPdb = zip.Entries.Any(e => e.Name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase));
                if (!hasPdb)
                    return (ValidationResult.Fail("content", ".snupkg must contain at least one .pdb file"), null, null);
            }

            var nuspecEntry = zip.Entries.FirstOrDefault(e =>
                e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains('/'));

            if (nuspecEntry is null)
                return (ValidationResult.Fail("content", "No .nuspec found at ZIP root"), null, null);

            using var nuspecStream = nuspecEntry.Open();
            var doc = XDocument.Load(nuspecStream);
            var ns = doc.Root?.Name.NamespaceName ?? "";

            if (!KnownNuspecNamespaces.Contains(ns))
                return (ValidationResult.Fail("content", $"Unknown nuspec namespace: {ns}"), null, null);

            XNamespace xns = ns;
            var metadata = doc.Root?.Element(xns + "metadata");
            var id = metadata?.Element(xns + "id")?.Value?.Trim();
            var version = metadata?.Element(xns + "version")?.Value?.Trim();
            var description = metadata?.Element(xns + "description")?.Value?.Trim();
            var authors = metadata?.Element(xns + "authors")?.Value?.Trim();

            if (string.IsNullOrEmpty(id) || id.Length > 100)
                return (ValidationResult.Fail("id", "id must be 1-100 characters"), null, null);

            if (!NuGetIdRegex().IsMatch(id))
                return (ValidationResult.Fail("id", "id contains invalid characters"), null, null);

            if (!NuGetVersion.TryParse(version, out _))
                return (ValidationResult.Fail("version", $"Invalid NuGet version: {version}"), null, null);

            if (string.IsNullOrEmpty(description))
                return (ValidationResult.Fail("description", "description is required"), null, null);

            if (string.IsNullOrEmpty(authors))
                return (ValidationResult.Fail("authors", "authors is required"), null, null);

            return (ValidationResult.Ok(), id, version);
        }
        catch (Exception ex)
        {
            return (ValidationResult.Fail("content", $"Invalid ZIP/OPC: {ex.Message}"), null, null);
        }
    }

    /// <summary>
    /// NuGet base URL for service-index links. Tenant-implicit: every request is already on
    /// the tenant's host (multi mode) or the single-tenant install. <c>BASE_URL</c>'s scheme is
    /// authoritative when set (e.g. https behind a TLS-terminating proxy).
    /// </summary>
    private string BaseUrl() => _urls.Absolute(HttpContext, "/nuget");

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

// DI-injected dependency aggregate for NuGetController. Single param avoids S107.
public sealed record NuGetControllerServices(
    OrgRepository Orgs,
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    AllowlistService Allowlist,
    BlocklistRepository Blocklist,
    IConfiguration Config,
    IMetadataStore Db,
    Dependably.Infrastructure.VulnerabilityScanService Scanner,
    VulnerabilityRepository Vulns,
    LicenseRepository Licenses,
    IPublicUrlBuilder Urls,
    PublishGate PublishGate,
    Dependably.Infrastructure.Publish.IPackagePublishService Publish,
    CacheAccessRecorder CacheRecorder,
    ClaimResolver ClaimResolver);
