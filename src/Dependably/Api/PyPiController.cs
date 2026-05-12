using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

[ApiController]
public partial class PyPiController : ControllerBase
{
    // PEP 508 name regex
    [GeneratedRegex(@"^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?$")]
    private static partial Regex Pep508NameRegex();

    // PEP 440 version: permissive check — must start with a digit
    [GeneratedRegex(@"^\d[\w\.\!\+\-]*$")]
    private static partial Regex Pep440VersionRegex();

    private static readonly HashSet<string> ValidMetadataVersions =
        ["1.0", "1.1", "1.2", "2.0", "2.1", "2.2", "2.3"];

    // Bounded regex evaluation — guards against ReDoS on user-supplied/upstream HTML inputs.
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly TokenRepository _tokens;
    private readonly AuditRepository _audit;
    private readonly IBlobStore _blobs;
    private readonly UpstreamClient _upstream;
    private readonly AllowlistService _allowlist;
    private readonly BlocklistRepository _blocklist;
    private readonly IConfiguration _config;
    private readonly Dependably.Infrastructure.VulnerabilityScanService _scanner;
    private readonly VulnerabilityRepository _vulns;
    private readonly LicenseRepository _licenses;
    private readonly PublishGate _publishGate;
    private readonly Dependably.Infrastructure.Publish.IPackagePublishService _publish;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ClaimResolver _claimResolver;

    public PyPiController(PyPiControllerServices svc)
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
        _scanner = svc.Scanner;
        _vulns = svc.Vulns;
        _licenses = svc.Licenses;
        _publishGate = svc.PublishGate;
        _publish = svc.Publish;
        _cacheRecorder = svc.CacheRecorder;
        _claimResolver = svc.ClaimResolver;
    }

    // ── Read endpoints (#8) ─────────────────────────────────────────────────

    /// <summary>GET /o/{org}/simple/ — PEP 503 package listing</summary>
    [HttpGet("/simple/")]
    public async Task<IActionResult> SimpleIndex(CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var pkgs = await _packages.ListAsync(orgId, "pypi", ct);

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head><title>Simple Index</title></head><body>");
        sb.AppendLine("<h1>Simple Index</h1>");
        foreach (var name in pkgs.Select(pkg => pkg.PurlName))
        {
            var simpleHref = OrgPath($"simple/{name}/");
            sb.AppendLine($"<a href=\"{simpleHref}\">{name}</a><br/>");
        }
        sb.AppendLine("</body></html>");

        return Content(sb.ToString(), "text/html; charset=utf-8");
    }

    /// <summary>GET /simple/{package}/ — PEP 503/592 version listing</summary>
    [HttpGet("/simple/{package}/")]
    public async Task<IActionResult> PackageIndex(string package, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);

        var purlName = NormalizePyPiName(package);
        var pkg = await _packages.GetByPurlNameAsync(orgId, "pypi", purlName, ct);

        if (pkg is null || pkg.IsProxy)
        {
            // For proxy packages (known or not yet seen), always proxy the upstream simple index
            // so pip can discover all available versions, not just locally-cached ones.
            return await ProxyUpstreamSimpleIndex(purlName, settings!, token, ct);
        }

        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {pkg.PurlName}</title></head><body>");
        sb.AppendLine($"<h1>Links for {pkg.PurlName}</h1>");

        foreach (var v in versions)
        {
            var filename = v.BlobKey.Split('/').Last();
            var href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null) href += $"#sha256={v.ChecksumSha256}";

            var yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\"" : "";

            sb.AppendLine($"<a href=\"{href}\"{yankAttr}>{filename}</a><br/>");
        }

        sb.AppendLine("</body></html>");
        return Content(sb.ToString(), "text/html; charset=utf-8");
    }

    private async Task<IActionResult> ProxyUpstreamSimpleIndex(
        string purlName, OrgSettings settings,
        TokenRecord? token, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var upstreamBase = _config["PyPI:Upstream"] ?? "https://pypi.org";
        try
        {
            using var response = await _upstream.GetMetadataAsync($"{upstreamBase}/simple/{purlName}/", ct);
            if (!response.IsSuccessStatusCode)
                return NotFound();

            var html = await response.Content.ReadAsStringAsync(ct);

            // Strip PEP 658/714 metadata attributes: we don't proxy .metadata files,
            // so removing these makes pip fall back to downloading the wheel/sdist directly.
            html = Regex.Replace(html, @"\s*data-(?:dist-info-metadata|core-metadata)=""[^""]*""", "", RegexOptions.None, RegexTimeout);

            // Rewrite upstream download URLs to route through our proxy.
            // PyPI CDN URLs are content-addressed (filename is in link text, not URL path).
            // The attribute pattern (?:[^>"']*(?:"[^"]*"|'[^']*')?)* handles quoted values
            // that contain ">" (e.g. data-requires-python=">=3.6") without stopping early.
            html = Regex.Replace(
                html,
                @"<a\b((?:[^>""']*(?:""[^""]*""|'[^']*')?)*)>([^<]+)</a>",
                m =>
                {
                    var attrs = m.Groups[1].Value;
                    var filename = m.Groups[2].Value.Trim();
                    var hrefMatch = Regex.Match(attrs, @"href=""(https?://[^""#]+)(#[^""]*)?""", RegexOptions.None, RegexTimeout);
                    if (!hrefMatch.Success) return m.Value; // not an upstream link, leave alone
                    var fragment = hrefMatch.Groups[2].Value; // "#sha256=..." or ""
                    return $"<a href=\"{OrgPath($"packages/{filename}{fragment}")}\">{filename}</a>";
                },
                RegexOptions.None,
                RegexTimeout);

            return Content(html, "text/html; charset=utf-8");
        }
        catch
        {
            return StatusCode(502);
        }
    }

    /// <summary>GET /packages/{file} — blob download with proxy cache (tenant-implicit from host)</summary>
    [HttpGet("/packages/{file}")]
    public async Task<IActionResult> DownloadPackage(string file, CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        var pkgVersions = await FindVersionByFilename(orgId, file, ct);

        var authError = CheckDownloadAuth(pkgVersions, token, settings!);
        if (authError is not null) return authError;

        if (pkgVersions is not null)
        {
            var v = pkgVersions.Value.Version;
            var blockResult = await CheckPyPiBlockGateAsync(
                new BlockProbe(v.Purl, v.Id, v.ManualBlockState, v.VulnCheckedAt),
                new BlockGateContext(orgId, token?.UserId, settings!), ct);
            if (blockResult is not null) return blockResult;

            var cached = await TryServeCachedBlobAsync(pkgVersions.Value, file, orgId, token, ct);
            if (cached is not null) return cached;
        }

        // Cache miss — proxy from upstream
        Response.Headers["X-Cache"] = "MISS";
        var upstreamUrl = await ResolveProxyUpstreamUrlAsync(file, pkgVersions, ct);
        if (upstreamUrl is null) return NotFound();

        var gateError = await CheckProxyAllowlistBlocklistAsync(orgId, file, token, settings!, ct);
        if (gateError is not null) return gateError;

        if (!settings!.ProxyPassthroughEnabled) return NotFound();

        // #47: claim state gates the proxy fetch. local_only (including air-gap implicit
        // local_only) disables proxy serving for that name.
        var purlNameForClaim = pkgVersions is not null
            ? pkgVersions.Value.Package.PurlName
            : NormalizePyPiName(file.Split('-')[0]);
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlNameForClaim, ct))
            return NotFound();

        return await FetchAndCacheUpstreamAsync(file, upstreamUrl, pkgVersions,
            new BlockGateContext(orgId, token?.UserId, settings!),
            token, ct);
    }

    private IActionResult? CheckDownloadAuth((Package Package, PackageVersion Version)? pkgVersions, TokenRecord? token, OrgSettings settings)
    {
        if (pkgVersions is not null && !pkgVersions.Value.Package.IsProxy)
        {
            // Hosted package — always require auth
            if (token is null)
            {
                Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return Unauthorized();
            }
            if (!token.HasCapability(Capabilities.ReadMetadata)) return Forbid();
            return null;
        }
        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }
        return null;
    }

    // Returns 403 IActionResult if the version is blocked (manual or OSV score over tolerance), else null.
    private async Task<IActionResult?> CheckPyPiBlockGateAsync(
        BlockProbe probe, BlockGateContext gate, CancellationToken ct)
    {
        if (probe.ManualState == "blocked")
        {
            await _audit.LogActivityAsync(gate.OrgId, "pypi", probe.Purl, "blocked_manual", gate.UserId, ct: ct);
            return StatusCode(403);
        }
        if (probe.ManualState == "allowed" || probe.VulnCheckedAt is null) return null;

        var maxScore = await _vulns.GetMaxScoreForVersionAsync(probe.VersionId, ct);
        if (!maxScore.HasValue || maxScore.Value <= gate.Settings.MaxOsvScoreTolerance) return null;

        await _audit.LogActivityAsync(gate.OrgId, "pypi", probe.Purl, "blocked_vuln_score", gate.UserId,
            detail: $"{{\"max_score\":{maxScore.Value},\"tolerance\":{gate.Settings.MaxOsvScoreTolerance}}}",
            ct: ct);
        return StatusCode(403);
    }

    private sealed record BlockProbe(string Purl, string VersionId, string? ManualState, DateTimeOffset? VulnCheckedAt);
    private sealed record BlockGateContext(string OrgId, string? UserId, OrgSettings Settings);
    private sealed record ProxyPayload(string Sha256, string File, byte[] Bytes);
    private sealed record ProxyTenantContext(string OrgId, TokenRecord? Token);

    private async Task<IActionResult?> TryServeCachedBlobAsync(
        (Package Package, PackageVersion Version) pkgVer, string file, string orgId, TokenRecord? token, CancellationToken ct)
    {
        var blob = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVer.Version.BlobKey), ct);
        if (blob is null) return null;

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVer.Version.Purl);
        await _audit.LogActivityAsync(orgId, "pypi", pkgVer.Version.Purl, "download", token?.UserId, ct: ct);
        return File(blob, "application/octet-stream", file);
    }

    // If we have a known sha256, files.pythonhosted.org uses the sha256 as a path prefix.
    // Otherwise, look it up in the upstream simple index. Returns null on lookup failure.
    private async Task<string?> ResolveProxyUpstreamUrlAsync(string file, (Package Package, PackageVersion Version)? pkgVersions, CancellationToken ct)
    {
        var sha256 = pkgVersions?.Version.ChecksumSha256;
        if (sha256 is not null)
            return $"https://files.pythonhosted.org/packages/{sha256[..2]}/{sha256[2..4]}/{sha256}/{file}";

        var upstreamBase = _config["PyPI:Upstream"] ?? "https://pypi.org";
        var pkgName = NormalizePyPiName(file.Split('-')[0]);
        var url = await ResolveUpstreamPyPiUrlAsync(upstreamBase, pkgName, file, ct);
        return string.IsNullOrEmpty(url) ? null : url;
    }

    private async Task<IActionResult?> CheckProxyAllowlistBlocklistAsync(string orgId, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var purlCheck = $"pkg:pypi/{NormalizePyPiName(file.Split('-')[0])}";
        if (settings.AllowlistMode && !await _allowlist.IsAllowedAsync(orgId, "pypi", purlCheck, ct))
            return StatusCode(403);
        if (await _blocklist.IsBlockedAsync(orgId, "pypi", purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "pypi", purlCheck, "blocked", token?.UserId, ct: ct);
            return StatusCode(403);
        }
        return null;
    }

    private async Task<IActionResult> FetchAndCacheUpstreamAsync(
        string file, string upstreamUrl, (Package Package, PackageVersion Version)? pkgVersions,
        BlockGateContext gate, TokenRecord? token, CancellationToken ct)
    {
        try
        {
            var (bytes, computedSha256, isHit) = await DownloadAndCacheAsync(upstreamUrl, pkgVersions?.Version.ChecksumSha256, gate.OrgId, ct);
            if (bytes is null) return NotFound();

            Response.Headers["X-Cache"] = isHit ? "HIT" : "MISS";
            if (pkgVersions is not null)
                Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersions.Value.Version.Purl);

            // #48: record into cache_artifact + tenant_artifact_access on every fetch path
            // (hit and miss). Best-effort — recorder swallows failures.
            var purlName = pkgVersions is not null
                ? pkgVersions.Value.Package.PurlName
                : NormalizePyPiName(file.Split('-')[0]);
            var version = pkgVersions?.Version.Version ?? ExtractPyPiVersion(file);
            await _cacheRecorder.RecordAccessAsync(new Dependably.Infrastructure.CacheAccess(
                gate.OrgId, "pypi", purlName, version, file,
                computedSha256, bytes.Length, BlobKeys.Proxy(computedSha256), upstreamUrl), ct);

            if (!isHit && pkgVersions is null)
            {
                var firstFetchBlock = await RecordAndScanFirstFetchAsync(file, bytes, computedSha256, gate, token, ct);
                if (firstFetchBlock is not null) return firstFetchBlock;
            }

            return File(bytes, "application/octet-stream", file);
        }
        catch (ChecksumException)
        {
            return StatusCode(502);
        }
        catch
        {
            return NotFound();
        }
    }

    private async Task<(byte[]? Bytes, string ComputedSha, bool IsHit)> DownloadAndCacheAsync(
        string upstreamUrl, string? knownSha256, string orgId, CancellationToken ct)
    {
        if (knownSha256 is not null)
        {
            // Known checksum — verify and use content-addressed cache
            var blobKey = BlobKeys.Proxy(knownSha256);
            var (bytes, isHit) = await _upstream.GetOrFetchAsync(
                blobKey, upstreamUrl, new ChecksumSpec(ChecksumAlgorithm.Sha256, knownSha256),
                "pypi", orgId, ct: ct);
            return (bytes, knownSha256, isHit);
        }

        // Unknown checksum — fetch, compute, and cache
        using var resp = await _upstream.GetMetadataAsync(upstreamUrl, ct);
        if (!resp.IsSuccessStatusCode) return (null, "", false);
        var fetched = await resp.Content.ReadAsByteArrayAsync(ct);
        var sha = ChecksumVerifier.ComputeSha256Hex(fetched);
        var proxyKey = BlobKeys.Proxy(sha);
        if (!await _blobs.ExistsAsync(proxyKey, ct))
            await _blobs.PutAsync(proxyKey, new MemoryStream(fetched), ct);
        return (fetched, sha, false);
    }

    private async Task<IActionResult?> RecordAndScanFirstFetchAsync(
        string file, byte[] bytes, string computedSha256,
        BlockGateContext gate, TokenRecord? token, CancellationToken ct)
    {
        var purlName = NormalizePyPiName(file.Split('-')[0]);
        var version = ExtractPyPiVersion(file);
        var purl = PurlNormalizer.PyPi(purlName, version);
        var scanVersionId = await RecordOrLookupPyPiVersionAsync(
            purlName, version, purl,
            new ProxyPayload(computedSha256, file, bytes),
            new ProxyTenantContext(gate.OrgId, token), ct);
        if (scanVersionId is null) return null;

        // Synchronous scan so the OSV gate can fire on the very first fetch.
        await _scanner.ScanVersionAsync(purl, scanVersionId, "pypi", purlName, gate.OrgId, ct: ct);
        var existing = await _packages.GetVersionByIdAsync(scanVersionId, ct);
        return await CheckPyPiBlockGateAsync(
            new BlockProbe(purl, scanVersionId, existing?.ManualBlockState, DateTimeOffset.UtcNow),
            gate, ct);
    }

    private async Task<string?> RecordOrLookupPyPiVersionAsync(
        string purlName, string version, string purl,
        ProxyPayload payload, ProxyTenantContext tenant, CancellationToken ct)
    {
        try
        {
            var pkg = await _packages.GetOrCreateAsync(tenant.OrgId, "pypi", purlName, purlName, isProxy: true, ct);
            // Store filename in blob key suffix so the simple index can recover it.
            // Actual blob storage uses BlobKeys.Proxy(sha256); the /filename suffix is metadata-only.
            var dbBlobKey = $"{BlobKeys.Proxy(payload.Sha256)}/{payload.File}";
            var newVer = await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, version, purl, dbBlobKey, payload.Bytes.Length, payload.Sha256, FirstFetch: true), ct);
            await _audit.LogActivityAsync(tenant.OrgId, "pypi", purl, "first_fetch", tenant.Token?.UserId, ct: ct);

            var extracted = LicenseExtractor.FromPyPiPackageBytes(payload.Bytes, payload.File);
            if (extracted.Spdx.Count > 0)
                await _licenses.SetLicensesAsync(newVer.Id, extracted.Spdx, "upstream", ct);

            return newVer.Id;
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            // Concurrent first fetch already recorded this version — look it up so we can still gate.
            var pkg = await _packages.GetByPurlNameAsync(tenant.OrgId, "pypi", purlName, ct);
            if (pkg is null) return null;
            var existing = await _packages.GetVersionAsync(pkg.Id, version, ct);
            return existing?.Id;
        }
    }

    /// <summary>
    /// Proxy DB blob keys embed the filename as a suffix: "proxy/{sha256}/{filename}".
    /// Blob store keys are content-addressed: "proxy/{sha256}".
    private static string ExtractPyPiVersion(string filename)
    {
        var name = filename;
        if (name.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)) name = name[..^7];
        else if (name.EndsWith(".tar.bz2", StringComparison.OrdinalIgnoreCase)) name = name[..^8];
        else if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        else if (name.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        var parts = name.Split('-');
        return parts.Length >= 2 ? parts[1] : "unknown";
    }

    /// <summary>
    /// Fetches the upstream simple index for a package and extracts the actual download URL for a specific file.
    /// Returns null if the file is not found in the upstream index.
    /// </summary>
    private async Task<string?> ResolveUpstreamPyPiUrlAsync(string upstreamBase, string pkgName, string filename, CancellationToken ct)
    {
        try
        {
            using var resp = await _upstream.GetMetadataAsync($"{upstreamBase}/simple/{pkgName}/", ct);
            if (!resp.IsSuccessStatusCode) return null;
            var html = await resp.Content.ReadAsStringAsync(ct);
            // Find href containing this filename (strip fragment for comparison)
            var match = Regex.Match(html, $@"href=""(https?://[^""#]*/{Regex.Escape(filename)})(#[^""]*)?""", RegexOptions.None, RegexTimeout);
            return match.Success ? match.Groups[1].Value : null;
        }
        catch
        {
            return null;
        }
    }

    private Task<(Package Package, PackageVersion Version)?> FindVersionByFilename(
        string orgId, string filename, CancellationToken ct)
        => _packages.FindVersionByBlobKeySuffixAsync(orgId, "pypi", filename, ct);

    // ── Upload endpoint (#9) ────────────────────────────────────────────────

    /// <summary>POST /pypi/legacy/ — twine-compatible upload (tenant-implicit from host)</summary>
    [HttpPost("/pypi/legacy/")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishPypi)]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; per-tenant limit checked below
    public async Task<IActionResult> Upload(CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        var authError = await CheckUploadAuthAsync(orgId, ct);
        if (authError is not null) return authError;
        var token = (await Request.ResolveTokenAsync(_tokens, ct))!;

        if (!Request.HasFormContentType) return BadRequest("Expected multipart/form-data.");
        var form = await Request.ReadFormAsync(ct);

        var (name, version, sha256Digest, file, formError) = ValidateUploadForm(form);
        if (formError is not null) return formError;

        var pathError = ValidatePathSafety(name!, version!, file!.FileName);
        if (pathError is not null) return pathError;

        var claimReject = await _publishGate.CheckAsync(orgId, "pypi", name!.ToLowerInvariant(), ct);
        if (claimReject is not null) return claimReject;

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms, ct);
        var fileBytes = ms.ToArray();

        var sizeError = await CheckPyPiUploadSizeAsync(orgId, fileBytes.Length, ct);
        if (sizeError is not null) return sizeError;

        var hashError = VerifyDigests(fileBytes, sha256Digest!, form["md5_digest"].FirstOrDefault(), out var actualSha256);
        if (hashError is not null) return hashError;

        var fileTypeError = ValidateFileTypeContents(form["filetype"].FirstOrDefault() ?? "", fileBytes, name!, file.FileName);
        if (fileTypeError is not null) return fileTypeError;

        return await StoreAndRecordUploadAsync(
            new PyPiUpload(name!, version!, file.FileName, fileBytes, actualSha256),
            new ProxyTenantContext(orgId, token), ct);
    }

    private async Task<IActionResult?> CheckUploadAuthAsync(string orgId, CancellationToken ct)
    {
        // [Authorize] + [RequireCapability(Capabilities.PublishPypi)] on the action method
        // already enforce auth + capability; this method's only remaining job is the
        // cross-tenant guard (token.OrgId vs requested orgId) and surfacing the
        // WWW-Authenticate header on rejection.
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }
        return null;
    }

    private (string? Name, string? Version, string? Sha256, IFormFile? File, IActionResult? Error) ValidateUploadForm(IFormCollection form)
    {
        if (form[":action"].FirstOrDefault() != "file_upload")
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = ":action must be 'file_upload'", Status = 422 }));

        var metadataVersion = form["metadata_version"].FirstOrDefault();
        if (!ValidMetadataVersions.Contains(metadataVersion ?? ""))
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Invalid metadata_version: {metadataVersion}", Status = 422 }));

        var name = form["name"].FirstOrDefault() ?? "";
        var version = form["version"].FirstOrDefault() ?? "";
        var sha256Digest = form["sha256_digest"].FirstOrDefault() ?? "";

        if (!Pep508NameRegex().IsMatch(name))
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Invalid package name: {name}", Status = 422 }));
        if (!Pep440VersionRegex().IsMatch(version))
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Invalid version: {version}", Status = 422 }));
        if (string.IsNullOrEmpty(sha256Digest))
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = "sha256_digest is required", Status = 422 }));

        var file = form.Files.GetFile("content");
        if (file is null)
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = "File content is required", Status = 422 }));

        return (name, version, sha256Digest, file, null);
    }

    private UnprocessableEntityObjectResult? ValidatePathSafety(string name, string version, string filename)
    {
        foreach (var (value, kind) in new[] { (name, "name"), (version, "version"), (filename, "filename") })
        {
            var check = PathSafeValidator.Validate(value, kind);
            if (!check.IsValid)
                return UnprocessableEntity(new ProblemDetails { Detail = check.Message, Status = 422 });
        }
        return null;
    }

    private async Task<IActionResult?> CheckPyPiUploadSizeAsync(string orgId, long size, CancellationToken ct)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var instanceLimitStr = await _orgs.GetInstanceSettingAsync("max_upload_bytes_pypi", ct);
        var instanceLimit = instanceLimitStr is not null && long.TryParse(instanceLimitStr, out var parsedInstanceLimit)
            ? parsedInstanceLimit : long.MaxValue;
        var limit = settings?.MaxUploadBytesPyPi ?? settings?.MaxUploadBytes ?? instanceLimit;
        return size > limit
            ? StatusCode(413, new ProblemDetails { Detail = "Upload exceeds size limit.", Status = 413 })
            : null;
    }

    private UnprocessableEntityObjectResult? VerifyDigests(byte[] fileBytes, string sha256Digest, string? md5Digest, out string actualSha256)
    {
        actualSha256 = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();
        if (!string.Equals(actualSha256, sha256Digest, StringComparison.OrdinalIgnoreCase))
            return UnprocessableEntity(new ProblemDetails { Detail = "SHA-256 digest mismatch.", Status = 422 });
        if (string.IsNullOrEmpty(md5Digest)) return null;

        var actualMd5 = Convert.ToHexString(MD5.HashData(fileBytes)).ToLowerInvariant();
        return string.Equals(actualMd5, md5Digest, StringComparison.OrdinalIgnoreCase)
            ? null
            : UnprocessableEntity(new ProblemDetails { Detail = "MD5 digest mismatch.", Status = 422 });
    }

    private UnprocessableEntityObjectResult? ValidateFileTypeContents(string fileType, byte[] fileBytes, string name, string filename)
    {
        var result = fileType switch
        {
            "bdist_wheel" => ValidateWheel(fileBytes),
            "sdist"       => ValidateSdist(name, filename),
            _             => ValidationResult.Ok(),
        };
        return result.IsValid ? null : UnprocessableEntity(new ProblemDetails { Detail = result.Message, Status = 422 });
    }

    private async Task<IActionResult> StoreAndRecordUploadAsync(
        PyPiUpload upload, ProxyTenantContext tenant, CancellationToken ct)
    {
        var purlName = NormalizePyPiName(upload.Name);
        var purl = PurlNormalizer.PyPi(upload.Name, upload.Version);

        var orgSettings = await _orgs.GetSettingsAsync(tenant.OrgId, ct);
        var claim = await _claimResolver.ResolveAsync(tenant.OrgId, "pypi", purlName, ct);
        var result = await _publish.StoreAndRecordAsync(new Dependably.Infrastructure.Publish.PublishRequest
        {
            OrgId = tenant.OrgId,
            Ecosystem = "pypi",
            Name = upload.Name,
            PurlName = purlName,
            Version = upload.Version,
            Filename = upload.Filename,
            Purl = purl,
            ArtifactBytes = upload.FileBytes,
            Origin = "uploaded",
            SizeCap = long.MaxValue,        // size cap already enforced upstream by CheckPyPiUploadSizeAsync
            ActorUserId = tenant.Token?.UserId,
            AuditAction = "push",
            AllowOverwrite = orgSettings?.AllowVersionOverwrite ?? false,
            ClaimState = claim.State,
        }, ct);

        if (result is Dependably.Infrastructure.Publish.PublishResult.Rejected rej)
            return MapPyPiPublishRejection(rej, upload.Version);

        // Format-specific post-publish: license info comes from the wheel METADATA / sdist
        // PKG-INFO. Stays here because the extractor is PyPI-only.
        var versionId = ((Dependably.Infrastructure.Publish.PublishResult.Accepted)result).VersionId;
        var extracted = LicenseExtractor.FromPyPiPackageBytes(upload.FileBytes, upload.Filename);
        if (extracted.Spdx.Count > 0)
            await _licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);

        return Ok();
    }

    private IActionResult MapPyPiPublishRejection(Dependably.Infrastructure.Publish.PublishResult.Rejected rej, string version)
    {
        return rej.Code == "version_exists"
            ? Conflict(new ProblemDetails { Detail = $"Version {version} already exists.", Status = 409 })
            : StatusCode(rej.HttpStatus, new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus });
    }

    private sealed record PyPiUpload(string Name, string Version, string Filename, byte[] FileBytes, string ActualSha256);

    // ── Validation helpers ──────────────────────────────────────────────────

    private static ValidationResult ValidateWheel(byte[] bytes)
    {
        try
        {
            using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(bytes), System.IO.Compression.ZipArchiveMode.Read);
            var hasMetadata = zip.Entries.Any(e =>
                e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
            if (!hasMetadata)
                return ValidationResult.Fail("content", "Wheel is missing .dist-info/METADATA");
            return ValidationResult.Ok();
        }
        catch
        {
            return ValidationResult.Fail("content", "Wheel is not a valid ZIP file");
        }
    }

    private static ValidationResult ValidateSdist(string name, string filename)
    {
        if (!filename.EndsWith(".tar.gz") && !filename.EndsWith(".zip"))
            return ValidationResult.Fail("filename", "sdist must end in .tar.gz or .zip");

        // Basic check: filename should contain name-version
        var normalized = Regex.Replace(name, @"[-_.]+", "-", RegexOptions.None, RegexTimeout).ToLowerInvariant();
        if (!filename.StartsWith(normalized, StringComparison.OrdinalIgnoreCase))
            return ValidationResult.Fail("filename", "Filename does not match declared package name");

        return ValidationResult.Ok();
    }

    /// <summary>
    /// Tenant-implicit URL: every request is already on the tenant's host (multi mode) or
    /// the single-tenant install, so paths are host-relative. The legacy <c>/o/{slug}/</c>
    /// prefix is gone.
    /// </summary>
    private static string OrgPath(string rest) => "/" + rest;

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    private static string NormalizePyPiName(string name)
        => Regex.Replace(name, @"[-_.]+", "-", RegexOptions.None, RegexTimeout).ToLowerInvariant();

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

// DI-injected dependency aggregate for PyPiController. Single param avoids S107.
public sealed record PyPiControllerServices(
    OrgRepository Orgs,
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    AllowlistService Allowlist,
    BlocklistRepository Blocklist,
    IConfiguration Config,
    Dependably.Infrastructure.VulnerabilityScanService Scanner,
    VulnerabilityRepository Vulns,
    LicenseRepository Licenses,
    PublishGate PublishGate,
    Dependably.Infrastructure.Publish.IPackagePublishService Publish,
    CacheAccessRecorder CacheRecorder,
    ClaimResolver ClaimResolver);
