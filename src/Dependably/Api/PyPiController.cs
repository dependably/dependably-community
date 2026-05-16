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
    private readonly BlockGateService _blockGate;
    private readonly LicenseRepository _licenses;
    private readonly PublishGate _publishGate;
    private readonly Dependably.Infrastructure.Publish.IPackagePublishService _publish;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ClaimResolver _claimResolver;
    private readonly Dependably.Storage.ProxyFetchService _proxyFetch;

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
        _blockGate = svc.BlockGate;
        _licenses = svc.Licenses;
        _publishGate = svc.PublishGate;
        _publish = svc.Publish;
        _cacheRecorder = svc.CacheRecorder;
        _claimResolver = svc.ClaimResolver;
        _proxyFetch = svc.ProxyFetch;
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

        // Always merge upstream + local versions when passthrough + claims allow. Routing must
        // not gate on packages.is_proxy — a name with privately uploaded versions is still a
        // namespace that holds proxy-fetched versions; clients need to discover both.
        var passthroughAllowed = settings!.ProxyPassthroughEnabled
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlName, ct);

        if (passthroughAllowed)
            return await ProxyUpstreamSimpleIndex(purlName, pkg, settings, token, ct);

        // Passthrough disabled or name is claim-local — return only local versions.
        if (pkg is null) return NotFound();

        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        return RenderLocalSimpleIndex(pkg.PurlName, versions);
    }

    private ContentResult RenderLocalSimpleIndex(string purlName, IReadOnlyList<PackageVersion> versions)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {purlName}</title></head><body>");
        sb.AppendLine($"<h1>Links for {purlName}</h1>");
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
        string purlName, Package? localPkg, OrgSettings settings,
        TokenRecord? token, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Collect local versions up-front so a missing upstream still serves what we have.
        var localVersions = localPkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await _packages.GetVersionsAsync(localPkg.Id, ct);

        var upstreamBase = _config["PyPI:Upstream"] ?? "https://pypi.org";
        string? upstreamHtml = null;
        try
        {
            using var response = await _upstream.GetMetadataAsync($"{upstreamBase}/simple/{purlName}/", ct);
            if (response.IsSuccessStatusCode)
            {
                var html = await response.Content.ReadAsStringAsync(ct);
                html = Regex.Replace(html, @"\s*data-(?:dist-info-metadata|core-metadata)=""[^""]*""", "", RegexOptions.None, RegexTimeout);
                html = Regex.Replace(
                    html,
                    @"<a\b((?:[^>""']*(?:""[^""]*""|'[^']*')?)*)>([^<]+)</a>",
                    m =>
                    {
                        var attrs = m.Groups[1].Value;
                        var filename = m.Groups[2].Value.Trim();
                        var hrefMatch = Regex.Match(attrs, @"href=""(https?://[^""#]+)(#[^""]*)?""", RegexOptions.None, RegexTimeout);
                        if (!hrefMatch.Success) return m.Value;
                        var fragment = hrefMatch.Groups[2].Value;
                        return $"<a href=\"{OrgPath($"packages/{filename}{fragment}")}\">{filename}</a>";
                    },
                    RegexOptions.None,
                    RegexTimeout);
                upstreamHtml = html;
            }
        }
        catch
        {
            // Upstream unreachable — fall back to local-only when we have versions to serve.
        }

        if (upstreamHtml is null)
        {
            if (localVersions.Count == 0) return NotFound();
            return RenderLocalSimpleIndex(purlName, localVersions);
        }

        // Splice local-only filenames into the upstream index so mixed-origin namespaces
        // expose private versions alongside upstream. Filenames already present in the
        // upstream HTML are skipped to avoid duplicates.
        var merged = MergeLocalVersionsIntoUpstreamIndex(upstreamHtml, localVersions);
        return Content(merged, "text/html; charset=utf-8");
    }

    private static string MergeLocalVersionsIntoUpstreamIndex(string upstreamHtml, IReadOnlyList<PackageVersion> localVersions)
    {
        if (localVersions.Count == 0) return upstreamHtml;

        var sb = new StringBuilder();
        foreach (var v in localVersions)
        {
            var filename = v.BlobKey.Split('/').Last();
            if (upstreamHtml.Contains($">{filename}<", StringComparison.Ordinal)) continue;
            var href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null) href += $"#sha256={v.ChecksumSha256}";
            var yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\""
                : "";
            sb.Append($"<a href=\"{href}\"{yankAttr}>{filename}</a><br/>");
        }
        if (sb.Length == 0) return upstreamHtml;

        var bodyClose = upstreamHtml.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        return bodyClose < 0
            ? upstreamHtml + sb
            : upstreamHtml[..bodyClose] + sb + upstreamHtml[bodyClose..];
    }

    /// <summary>GET /packages/{file} — blob download with proxy cache (tenant-implicit from host)</summary>
    [HttpGet("/packages/{file}")]
    public async Task<IActionResult> DownloadPackage(string file, CancellationToken ct)
    {
        // Parse name + version up front. PEP 503/440-aware; rejects mis-shaped requests
        // before any DB / upstream work so corrupt filenames can't reach the recorders.
        if (!PyPiArtifactValidator.TryParseFilename(file, out var parsedPurlName, out var parsedVersion))
            return NotFound();
        var parsed = new PyPiFilename(parsedPurlName!, parsedVersion!);

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        var pkgVersions = await FindVersionByFilename(orgId, file, ct);

        var authError = CheckDownloadAuth(pkgVersions, token, settings!);
        if (authError is not null) return authError;

        var sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (pkgVersions is not null)
        {
            var v = pkgVersions.Value.Version;
            if (await _blockGate.EvaluateAsync(
                    new BlockGateRequest(orgId, "pypi", v.Purl, v.Id,
                        v.ManualBlockState, v.VulnCheckedAt,
                        token?.UserId, settings!.MaxOsvScoreTolerance, sourceIp), ct)
                == BlockDecision.Blocked) return StatusCode(403);

            var cached = await TryServeCachedBlobAsync(pkgVersions.Value, file, orgId, token, sourceIp, ct);
            if (cached is not null) return cached;
        }

        // Cache miss — proxy from upstream
        Response.Headers["X-Cache"] = "MISS";
        var upstreamUrl = await ResolveProxyUpstreamUrlAsync(file, parsed, pkgVersions, ct);
        if (upstreamUrl is null) return NotFound();

        var gateError = await CheckProxyAllowlistBlocklistAsync(orgId, parsed, token, settings!, sourceIp, ct);
        if (gateError is not null) return gateError;

        if (!settings!.ProxyPassthroughEnabled) return NotFound();

        // #47: claim state gates the proxy fetch. local_only (including air-gap implicit
        // local_only) disables proxy serving for that name.
        var purlNameForClaim = pkgVersions?.Package.PurlName ?? parsed.PurlName;
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlNameForClaim, ct))
            return NotFound();

        return await FetchAndCacheUpstreamAsync(file, upstreamUrl, parsed, pkgVersions,
            new ProxyContext(orgId, token?.UserId, settings!, sourceIp),
            token, ct);
    }

    private IActionResult? CheckDownloadAuth((Package Package, PackageVersion Version)? pkgVersions, TokenRecord? token, OrgSettings settings)
    {
        // Route by per-version origin, not the package-level is_proxy flag. A package name
        // can host mixed-origin versions; an uploaded version requires auth even if other
        // versions on the same name are proxy-cached.
        if (pkgVersions is not null && pkgVersions.Value.Version.Origin == "uploaded")
        {
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

    // Threading-only record for the PyPi proxy flow — carries the tenant + caller + settings tuple
    // through FetchAndCacheUpstreamAsync → RecordAndScanFirstFetchAsync so block-gate evaluation
    // at the tail of first-fetch can fire without re-reading settings.
    private sealed record ProxyContext(string OrgId, string? UserId, OrgSettings Settings, string? SourceIp = null);
    private sealed record ProxyTenantContext(string OrgId, TokenRecord? Token);
    private sealed record PyPiFilename(string PurlName, string Version);

    private async Task<IActionResult?> TryServeCachedBlobAsync(
        (Package Package, PackageVersion Version) pkgVer, string file, string orgId, TokenRecord? token,
        string? sourceIp, CancellationToken ct)
    {
        var blob = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVer.Version.BlobKey), ct);
        if (blob is null) return null;

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVer.Version.Purl);
        await _audit.LogActivityAsync(orgId, "pypi", pkgVer.Version.Purl, "download", token?.UserId,
            sourceIp: sourceIp, ct: ct);
        return File(blob, "application/octet-stream", file);
    }

    // If we have a known sha256, files.pythonhosted.org uses the sha256 as a path prefix.
    // Otherwise, look it up in the upstream simple index. Returns null on lookup failure.
    private async Task<string?> ResolveProxyUpstreamUrlAsync(string file, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions, CancellationToken ct)
    {
        var sha256 = pkgVersions?.Version.ChecksumSha256;
        if (sha256 is not null)
            return $"https://files.pythonhosted.org/packages/{sha256[..2]}/{sha256[2..4]}/{sha256}/{file}";

        var upstreamBase = _config["PyPI:Upstream"] ?? "https://pypi.org";
        var url = await ResolveUpstreamPyPiUrlAsync(upstreamBase, parsed.PurlName, file, ct);
        return string.IsNullOrEmpty(url) ? null : url;
    }

    private async Task<IActionResult?> CheckProxyAllowlistBlocklistAsync(string orgId, PyPiFilename parsed,
        TokenRecord? token, OrgSettings settings, string? sourceIp, CancellationToken ct)
    {
        var purlCheck = $"pkg:pypi/{parsed.PurlName}";
        if (settings.AllowlistMode && !await _allowlist.IsAllowedAsync(orgId, purlCheck, ct))
            return StatusCode(403);
        if (await _blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "pypi", purlCheck, "blocked", token?.UserId,
                sourceIp: sourceIp, ct: ct);
            return StatusCode(403);
        }
        return null;
    }

    private async Task<IActionResult> FetchAndCacheUpstreamAsync(
        string file, string upstreamUrl, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions,
        ProxyContext gate, TokenRecord? token, CancellationToken ct)
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
            var purlName = pkgVersions?.Package.PurlName ?? parsed.PurlName;
            var version = pkgVersions?.Version.Version ?? parsed.Version;
            await _cacheRecorder.RecordAccessAsync(new Dependably.Infrastructure.CacheAccess(
                gate.OrgId, "pypi", purlName, version, file,
                computedSha256, bytes.Length, BlobKeys.Proxy(computedSha256), upstreamUrl), ct);

            if (!isHit && pkgVersions is null)
            {
                var firstFetchBlock = await RecordAndScanFirstFetchAsync(file, parsed, bytes, computedSha256, gate, token, ct);
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
        string file, PyPiFilename parsed, byte[] bytes, string computedSha256,
        ProxyContext gate, TokenRecord? token, CancellationToken ct)
    {
        _ = computedSha256; // ProxyFetchService recomputes inside the trust boundary.
        var purl = PurlNormalizer.PyPi(parsed.PurlName, parsed.Version);
        var result = await _proxyFetch.RecordAndScanAsync(new Dependably.Storage.ProxyFetchRequest(
            OrgId: gate.OrgId, Ecosystem: "pypi",
            PackageName: parsed.PurlName, PurlName: parsed.PurlName,
            Version: parsed.Version, Purl: purl, File: file, Bytes: bytes,
            ExtractLicenses: bytes2 => LicenseExtractor.FromPyPiPackageBytes(bytes2, file),
            UserId: token?.UserId,
            SourceIp: gate.SourceIp,
            MaxOsvScoreTolerance: gate.Settings.MaxOsvScoreTolerance,
            // PyPI records cache_access separately in FetchAndCacheUpstreamAsync (covers
            // both hit and miss paths); skip here to avoid the double-write.
            CacheAccess: null), ct);
        return result.Decision == BlockDecision.Blocked ? StatusCode(403) : null;
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
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
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
    BlockGateService BlockGate,
    LicenseRepository Licenses,
    PublishGate PublishGate,
    Dependably.Infrastructure.Publish.IPackagePublishService Publish,
    CacheAccessRecorder CacheRecorder,
    ClaimResolver ClaimResolver,
    Dependably.Storage.ProxyFetchService ProxyFetch);
