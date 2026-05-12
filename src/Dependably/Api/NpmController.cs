using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

[ApiController]
public partial class NpmController : ControllerBase
{
    // npm name rules: lowercase, ≤214, URL-safe, no leading . or _
    [GeneratedRegex(@"^(?!node_modules$|favicon\.ico$)(?!\.|_)[a-z0-9][a-z0-9._\-]*$")]
    private static partial Regex NpmNameRegex();

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
    private readonly IPublicUrlBuilder _urls;
    private readonly IPackagePublishService _publish;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ClaimResolver _claimResolver;

    public NpmController(NpmControllerServices svc)
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
        _urls = svc.Urls;
        _publish = svc.Publish;
        _cacheRecorder = svc.CacheRecorder;
        _claimResolver = svc.ClaimResolver;
    }

    // ── Read endpoints (#10) ─────────────────────────────────────────────────

    /// <summary>GET /o/{org}/npm/{package} — CouchDB package metadata</summary>
    [HttpGet("/npm/{package}")]
    public Task<IActionResult> GetPackage(string package, CancellationToken ct)
        => GetPackageMetadata(DecodeNpmName(package), scope: null, ct);

    /// <summary>GET /o/{org}/npm/@{scope}/{package} — scoped package metadata</summary>
    [HttpGet("/npm/@{scope}/{package}")]
    public Task<IActionResult> GetScopedPackage(string scope, string package, CancellationToken ct)
        => GetPackageMetadata(package, scope: "@" + scope, ct);

    /// <summary>GET /o/{org}/npm/{package}/{version} — specific version metadata</summary>
    [HttpGet("/npm/{package}/{version}")]
    public async Task<IActionResult> GetVersion(string package, string version, CancellationToken ct)
    {
        var full = await GetPackageMetadata(package, null, ct);
        // Extract just the version object from the full metadata response
        if (full is JsonResult jr && jr.Value is JsonObject obj)
        {
            var versionData = obj["versions"]?[version];
            if (versionData is null) return NotFound();
            return new JsonResult(versionData);
        }
        return full;
    }

    private async Task<IActionResult> GetPackageMetadata(string package, string? scope, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);

        var fullName = scope is not null ? $"{scope}/{package}" : package;
        var purlName = fullName;

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", purlName, ct);

        if (pkg is not null && !pkg.IsProxy)
        {
            // Hosted package — require auth
            if (token is null)
            {
                Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
                return Unauthorized();
            }
        }
        else if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // Serve hosted metadata from DB
        if (pkg is not null && !pkg.IsProxy)
        {
            var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
            return new JsonResult(BuildNpmMetadata(pkg, versions));
        }

        // Proxy from upstream
        return await ProxyNpmMetadata(fullName, settings!, token, ct);
    }

    private async Task<IActionResult> ProxyNpmMetadata(
        string fullName, OrgSettings settings, TokenRecord? token, CancellationToken ct)
    {
        if (!settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        var upstreamBase = _config["Npm:Upstream"] ?? "https://registry.npmjs.org";
        try
        {
            using var response = await _upstream.GetMetadataAsync($"{upstreamBase}/{fullName}", ct);
            if (!response.IsSuccessStatusCode) return NotFound();

            var json = await response.Content.ReadAsStringAsync(ct);
            var metadata = JsonNode.Parse(json);
            if (metadata is null) return NotFound();

            var tarballBase = NpmTarballBase();
            RewriteTarballUrls(metadata, fullName, tarballBase);

            return new JsonResult(metadata);
        }
        catch
        {
            return StatusCode(502);
        }
    }

    /// <summary>
    /// Tarball download URL base. Tenant-implicit: every request is already on the tenant's host,
    /// so URLs are host-relative under <c>/npm/tarballs</c>.
    /// </summary>
    private string NpmTarballBase() => _urls.Absolute(HttpContext, "/npm/tarballs");

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    private static void RewriteTarballUrls(JsonNode metadata, string packageName, string tarballBase)
    {
        var versions = metadata["versions"]?.AsObject();
        if (versions is null) return;

        foreach (var (_, versionNode) in versions)
        {
            var dist = versionNode?["dist"];
            if (dist is null) continue;

            var tarball = dist["tarball"]?.GetValue<string>();
            if (tarball is null) continue;

            var filename = tarball.Split('/').Last();
            dist["tarball"] = $"{tarballBase}/{packageName}/{filename}";
        }
    }

    private JsonObject BuildNpmMetadata(Package pkg, IReadOnlyList<PackageVersion> versions)
    {
        var tarballBase = NpmTarballBase();
        var versionsObj = new JsonObject();
        string? latest = null;

        foreach (var v in versions.OrderByDescending(x => x.CreatedAt))
        {
            latest ??= v.Version;
            var filename = v.BlobKey.Split('/').Last();
            versionsObj[v.Version] = new JsonObject
            {
                ["name"] = pkg.Name,
                ["version"] = v.Version,
                ["dist"] = new JsonObject
                {
                    ["tarball"] = $"{tarballBase}/{pkg.Name}/{filename}",
                    ["shasum"] = v.ChecksumSha256 ?? ""
                }
            };
        }

        return new JsonObject
        {
            ["_id"] = pkg.Name,
            ["name"] = pkg.Name,
            ["dist-tags"] = new JsonObject { ["latest"] = latest },
            ["versions"] = versionsObj
        };
    }

    /// <summary>GET /o/{org}/npm/tarballs/{pkg}/{file} — tarball download</summary>
    [HttpGet("/npm/tarballs/{pkg}/{file}")]
    public Task<IActionResult> GetTarball(string pkg, string file, CancellationToken ct)
    {
        var fullName = DecodeNpmName(pkg);
        var shortName = fullName.Contains('/') ? fullName[(fullName.LastIndexOf('/') + 1)..] : fullName;
        return GetTarballImpl(fullName, shortName, file, ct);
    }

    /// <summary>GET /o/{org}/npm/tarballs/@{scope}/{pkg}/{file} — scoped package tarball download</summary>
    [HttpGet("/npm/tarballs/@{scope}/{pkg}/{file}")]
    public Task<IActionResult> GetScopedTarball(string scope, string pkg, string file, CancellationToken ct)
        => GetTarballImpl(fullName: "@" + scope + "/" + pkg, shortName: pkg, file, ct);

    private async Task<IActionResult> GetTarballImpl(
        string fullName, string shortName, string file, CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        var pkgRecord = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);

        if (pkgRecord is not null && !pkgRecord.IsProxy)
            return await ServeHostedTarballAsync(orgId, pkgRecord, file, token, settings!, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // Allowlist / blocklist check before fetching
        var purlCheck = PurlNormalizer.Npm(fullName, "0.0.0").Split('@')[0]; // name-only PURL
        if (settings?.AllowlistMode == true && !await _allowlist.IsAllowedAsync(orgId, "npm", purlCheck, ct))
            return StatusCode(403);
        if (await _blocklist.IsBlockedAsync(orgId, "npm", purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "npm", purlCheck, "blocked", token?.UserId, ct: ct);
            return StatusCode(403);
        }

        if (pkgRecord is { IsProxy: true })
        {
            var blockResult = await CheckExistingProxyVersionBlockAsync(pkgRecord, shortName, file, orgId, token, settings!, ct);
            if (blockResult is not null) return blockResult;
        }

        if (!settings!.ProxyPassthroughEnabled)
            return NotFound();

        // #47: claim state gates the proxy fetch. local_only (or air-gap implicit local_only)
        // disables proxy serving — the operator has reserved this name for local versions only.
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", fullName, ct))
            return NotFound();

        return await ProxyFetchAndCacheAsync(orgId, fullName, shortName, file, token, settings!, ct);
    }

    private async Task<IActionResult> ServeHostedTarballAsync(
        string orgId, Package pkgRecord, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }
        if (!token.HasCapability(Capabilities.ReadArtifact)) return Forbid();

        var versions = await _packages.GetVersionsAsync(pkgRecord.Id, ct);
        var match = versions.FirstOrDefault(v => v.BlobKey.EndsWith("/" + file));
        if (match is null) return NotFound();

        var blockResult = await CheckBlockGateAsync(
            new BlockProbe(match.Purl, match.Id, match.ManualBlockState, match.VulnCheckedAt),
            new BlockGateContext(orgId, token.UserId, settings), ct);
        if (blockResult is not null) return blockResult;

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(match.BlobKey), ct);
        if (stream is null) return NotFound();

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(match.Purl);
        await _audit.LogActivityAsync(orgId, "npm", match.Purl, "download", token.UserId, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    private async Task<IActionResult?> CheckExistingProxyVersionBlockAsync(
        Package pkgRecord, string shortName, string file, string orgId, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
        var proxyVersion = baseName.Length > shortName.Length + 1 ? baseName[(shortName.Length + 1)..] : null;
        if (proxyVersion is null) return null;

        var proxyVer = await _packages.GetVersionAsync(pkgRecord.Id, proxyVersion, ct);
        if (proxyVer is null) return null;

        return await CheckBlockGateAsync(
            new BlockProbe(proxyVer.Purl, proxyVer.Id, proxyVer.ManualBlockState, proxyVer.VulnCheckedAt),
            new BlockGateContext(orgId, token?.UserId, settings), ct);
    }

    // Returns 403 IActionResult if the version is blocked (manual or OSV score over tolerance), else null.
    private async Task<IActionResult?> CheckBlockGateAsync(
        BlockProbe probe, BlockGateContext gate, CancellationToken ct)
    {
        if (probe.ManualState == "blocked")
        {
            await _audit.LogActivityAsync(gate.OrgId, "npm", probe.Purl, "blocked_manual", gate.UserId, ct: ct);
            return StatusCode(403);
        }
        if (probe.ManualState == "allowed" || probe.VulnCheckedAt is null) return null;

        var maxScore = await _vulns.GetMaxScoreForVersionAsync(probe.VersionId, ct);
        if (!maxScore.HasValue || maxScore.Value <= gate.Settings.MaxOsvScoreTolerance) return null;

        await _audit.LogActivityAsync(gate.OrgId, "npm", probe.Purl, "blocked_vuln_score", gate.UserId,
            detail: $"{{\"max_score\":{maxScore.Value},\"tolerance\":{gate.Settings.MaxOsvScoreTolerance}}}",
            ct: ct);
        return StatusCode(403);
    }

    private sealed record BlockProbe(string Purl, string VersionId, string? ManualState, DateTimeOffset? VulnCheckedAt);
    private sealed record BlockGateContext(string OrgId, string? UserId, OrgSettings Settings);

    private async Task<IActionResult> ProxyFetchAndCacheAsync(
        string orgId, string fullName, string shortName, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var upstreamBase = _config["Npm:Upstream"] ?? "https://registry.npmjs.org";
        Response.Headers["X-Cache"] = "MISS";

        try
        {
            using var resp = await _upstream.GetMetadataAsync($"{upstreamBase}/{fullName}/-/{file}", ct);
            if (!resp.IsSuccessStatusCode) return NotFound();
            var bytes = await resp.Content.ReadAsByteArrayAsync(ct);

            var sha256 = ChecksumVerifier.ComputeSha256Hex(bytes);
            var blobKey = BlobKeys.Proxy(sha256);
            if (!await _blobs.ExistsAsync(blobKey, ct))
                await _blobs.PutAsync(blobKey, new MemoryStream(bytes), ct);

            var baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
            var version = baseName.Length > shortName.Length + 1 ? baseName[(shortName.Length + 1)..] : "unknown";
            var purl = PurlNormalizer.Npm(fullName, version);

            // #48: record into cache_artifact + tenant_artifact_access. Best-effort.
            await _cacheRecorder.RecordAccessAsync(new CacheAccess(
                orgId, "npm", fullName, version, file, sha256, bytes.Length,
                blobKey, $"{upstreamBase}/{fullName}/-/{file}"), ct);

            var scanVersionId = await RecordOrLookupProxyVersionAsync(
                fullName, version, purl,
                new ProxyPayload(sha256, file, bytes),
                new ProxyTenantContext(orgId, token), ct);

            if (scanVersionId is not null)
            {
                await _scanner.ScanVersionAsync(purl, scanVersionId, "npm", fullName, orgId, ct: ct);
                var existing = await _packages.GetVersionByIdAsync(scanVersionId, ct);
                var postScanBlock = await CheckBlockGateAsync(
                    new BlockProbe(purl, scanVersionId, existing?.ManualBlockState, DateTimeOffset.UtcNow),
                    new BlockGateContext(orgId, token?.UserId, settings), ct);
                if (postScanBlock is not null) return postScanBlock;
            }

            return File(bytes, "application/octet-stream", file);
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch
        {
            return NotFound();
        }
    }

    private async Task<string?> RecordOrLookupProxyVersionAsync(
        string fullName, string version, string purl,
        ProxyPayload payload, ProxyTenantContext tenant, CancellationToken ct)
    {
        try
        {
            var record = await _packages.GetOrCreateAsync(tenant.OrgId, "npm", fullName, fullName, isProxy: true, ct);
            var dbBlobKey = $"{BlobKeys.Proxy(payload.Sha256)}/{payload.File}";
            var newVer = await _packages.CreateVersionAsync(
                new NewPackageVersion(record.Id, version, purl, dbBlobKey, payload.Bytes.Length, payload.Sha256, FirstFetch: true), ct);
            await _audit.LogActivityAsync(tenant.OrgId, "npm", purl, "first_fetch", tenant.Token?.UserId, ct: ct);

            // License from the tarball's package.json. Deprecation only lives in the
            // packument (separate fetch), so it's intentionally not populated here.
            var extracted = LicenseExtractor.FromNpmTarballPackageJson(payload.Bytes);
            if (extracted.Spdx.Count > 0)
                await _licenses.SetLicensesAsync(newVer.Id, extracted.Spdx, "upstream", ct);

            return newVer.Id;
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            var pkg = await _packages.GetByPurlNameAsync(tenant.OrgId, "npm", fullName, ct);
            if (pkg is null) return null;
            var existing = await _packages.GetVersionAsync(pkg.Id, version, ct);
            return existing?.Id;
        }
    }

    private sealed record ProxyPayload(string Sha256, string File, byte[] Bytes);
    private sealed record ProxyTenantContext(string OrgId, TokenRecord? Token);


    // ── Publish endpoint (#11) ───────────────────────────────────────────────

    /// <summary>PUT /o/{org}/npm/{package} — npm publish</summary>
    [HttpPut("/npm/{package}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> Publish(string package, CancellationToken ct)
        => PublishPackage(package, scope: null, ct);

    /// <summary>PUT /o/{org}/npm/@{scope}/{package} — scoped npm publish</summary>
    [HttpPut("/npm/@{scope}/{package}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> PublishScoped(string scope, string package, CancellationToken ct)
        => PublishPackage(package, scope: "@" + scope, ct);

    private async Task<IActionResult> PublishPackage(string package, string? scope, CancellationToken ct)
    {
        var orgId = CurrentTenantId();

        // [Authorize] above already enforced auth + capability. We still resolve the token
        // for the cross-tenant guard (token.OrgId vs requested org) and to attribute the
        // audit row to the token owner (token.UserId). Both could be read off User claims
        // post-#55 — left as a follow-up to keep this migration tight.
        var token = await Request.ResolveTokenAsync(_tokens, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        // ── Format-specific extraction (lives here; shape is npm-only) ─────────
        var (body, parseError) = await ParsePublishBodyAsync(ct);
        if (parseError is not null) return parseError;

        var fullName = scope is not null ? $"{scope}/{package}" : package;
        var plainName = scope is not null ? package : fullName;

        var nameError = ValidatePackageName(body, fullName, plainName);
        if (nameError is not null) return nameError;

        var (attachmentKey, tarball, attachmentError) = ExtractAttachment(body);
        if (attachmentError is not null) return attachmentError;

        var (innerName, innerVersion, tarballError) = ValidateTarballAndExtractNameVersion(tarball!);
        if (tarballError is not null) return tarballError;

        var versions = body?["versions"]?.AsObject();
        var versionKey = versions?.First().Key;
        var matchError = ValidateBodyMatch(versionKey, innerName, innerVersion, fullName);
        if (matchError is not null) return matchError;

        var filename = attachmentKey!.Split('/').Last(); // e.g. package-1.0.0.tgz

        // Per-tenant + per-ecosystem upload size cap. The publish service enforces it again
        // as a safety net but we keep this lookup here so the existing UploadSizeLimitError
        // shape (413 with the same body the older code returned) is preserved verbatim.
        var sizeError = await CheckUploadSizeAsync(orgId, tarball!, ct);
        if (sizeError is not null) return sizeError;

        // ── Shared tail (path safety, claim gate, dedup, blob put, version, audit) ──
        var orgSettings = await _orgs.GetSettingsAsync(orgId, ct);
        var claim = await _claimResolver.ResolveAsync(orgId, "npm", fullName, ct);
        var result = await _publish.StoreAndRecordAsync(new PublishRequest
        {
            OrgId = orgId,
            Ecosystem = "npm",
            Name = fullName,
            PurlName = fullName,
            Version = versionKey!,
            Filename = filename,
            Purl = PurlNormalizer.Npm(fullName, versionKey!),
            ArtifactBytes = tarball!,
            Origin = "uploaded",
            SizeCap = long.MaxValue,           // already enforced above; service is defence-in-depth
            ActorUserId = token.UserId,
            AuditAction = "push",
            AllowOverwrite = orgSettings?.AllowVersionOverwrite ?? false,
            ClaimState = claim.State,
        }, ct);

        if (result is PublishResult.Rejected rej) return MapPublishRejection(rej, versionKey!);

        // License: read the tarball's package.json (canonical, and matches the proxy
        // first-fetch path at RecordOrLookupProxyVersionAsync). Fall back to the
        // packument when the tarball lacks a parseable package/package.json — many
        // publish clients don't include license in the packument's version object.
        // Deprecation only ever lives in the packument (npm deprecate writes there),
        // so it must always come from the packument extractor.
        var fromTarball = LicenseExtractor.FromNpmTarballPackageJson(tarball!);
        var fromPackument = LicenseExtractor.FromNpmPackumentVersion(versions?[versionKey!]);
        var spdx = fromTarball.Spdx.Count > 0 ? fromTarball.Spdx : fromPackument.Spdx;
        var versionId = ((PublishResult.Accepted)result).VersionId;
        if (spdx.Count > 0)
            await _licenses.SetLicensesAsync(versionId, spdx, "upstream", ct);
        if (fromPackument.Deprecated is not null)
            await _packages.UpdateDeprecatedAsync(versionId, fromPackument.Deprecated, ct);

        return Ok();
    }

    private ObjectResult MapPublishRejection(PublishResult.Rejected rej, string versionKey) => rej.Code switch
    {
        "version_exists" => Conflict(new ProblemDetails { Detail = $"Version {versionKey} already exists.", Status = 409 }),
        _ => StatusCode(rej.HttpStatus, new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus }),
    };

    private async Task<(JsonNode? Body, IActionResult? Error)> ParsePublishBodyAsync(CancellationToken ct)
    {
        try
        {
            using var reader = new StreamReader(Request.Body, Encoding.UTF8);
            var json = await reader.ReadToEndAsync(ct);
            return (JsonNode.Parse(json), null);
        }
        catch
        {
            return (null, UnprocessableEntity(new ProblemDetails { Detail = "Invalid JSON body.", Status = 422 }));
        }
    }

    private UnprocessableEntityObjectResult? ValidatePackageName(JsonNode? body, string fullName, string plainName)
    {
        var bodyName = body?["name"]?.GetValue<string>() ?? "";
        if (bodyName != fullName)
            return UnprocessableEntity(new ProblemDetails { Detail = "name in body does not match URL.", Status = 422 });
        if (plainName.Length > 214 || !NpmNameRegex().IsMatch(plainName))
            return UnprocessableEntity(new ProblemDetails { Detail = $"Invalid npm package name: {plainName}", Status = 422 });
        return null;
    }

    private (string? Key, byte[]? Tarball, IActionResult? Error) ExtractAttachment(JsonNode? body)
    {
        var attachments = body?["_attachments"]?.AsObject();
        if (attachments is null || attachments.Count != 1)
            return (null, null, UnprocessableEntity(new ProblemDetails { Detail = "_attachments must contain exactly one entry.", Status = 422 }));

        var (attachmentKey, attachmentNode) = attachments.First();
        var base64Data = attachmentNode?["data"]?.GetValue<string>();
        if (base64Data is null)
            return (null, null, UnprocessableEntity(new ProblemDetails { Detail = "_attachments.data is required.", Status = 422 }));

        byte[] tarball;
        try { tarball = Convert.FromBase64String(base64Data); }
        catch { return (null, null, UnprocessableEntity(new ProblemDetails { Detail = "Invalid base64 in _attachments.data.", Status = 422 })); }

        var declaredLength = attachmentNode?["length"]?.GetValue<long>() ?? -1;
        if (declaredLength >= 0 && tarball.Length != declaredLength)
            return (null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Attachment length mismatch: declared {declaredLength}, actual {tarball.Length}.", Status = 422 }));

        return (attachmentKey, tarball, null);
    }

    private async Task<IActionResult?> CheckUploadSizeAsync(string orgId, byte[] tarball, CancellationToken ct)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var limit = settings?.MaxUploadBytesNpm ?? settings?.MaxUploadBytes ?? long.MaxValue;
        return tarball.Length > limit
            ? StatusCode(413, new ProblemDetails { Detail = "Upload exceeds npm size limit.", Status = 413 })
            : null;
    }

    private (string? InnerName, string? InnerVersion, IActionResult? Error) ValidateTarballAndExtractNameVersion(byte[] tarball)
    {
        var tarValidation = ValidateTarball(tarball, out var innerName, out var innerVersion);
        return tarValidation.IsValid
            ? (innerName, innerVersion, null)
            : (null, null, UnprocessableEntity(new ProblemDetails { Detail = tarValidation.Message, Status = 422 }));
    }

    private UnprocessableEntityObjectResult? ValidateBodyMatch(string? versionKey, string? innerName, string? innerVersion, string fullName)
    {
        if (versionKey is null)
            return UnprocessableEntity(new ProblemDetails { Detail = "versions object is empty.", Status = 422 });
        if (innerName != fullName)
            return UnprocessableEntity(new ProblemDetails { Detail = $"package.json name '{innerName}' does not match published name '{fullName}'.", Status = 422 });
        if (innerVersion != versionKey)
            return UnprocessableEntity(new ProblemDetails { Detail = $"package.json version '{innerVersion}' does not match declared version '{versionKey}'.", Status = 422 });
        return null;
    }

    private static ValidationResult ValidateTarball(byte[] bytes, out string? name, out string? version) =>
        NpmTarballValidator.Validate(bytes, out name, out version);

    private static string DecodeNpmName(string name) => NpmRouteHelper.DecodeRouteName(name);

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

// DI-injected dependency aggregate for NpmController. Single param avoids S107 on the
// controller constructor; field unpacking in the ctor keeps the rest of the controller
// body untouched.
public sealed record NpmControllerServices(
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
    IPublicUrlBuilder Urls,
    PublishGate PublishGate,
    IPackagePublishService Publish,
    CacheAccessRecorder CacheRecorder,
    ClaimResolver ClaimResolver);
