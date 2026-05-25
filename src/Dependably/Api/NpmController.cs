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
    private readonly BlockGateService _blockGate;
    private readonly LicenseRepository _licenses;
    private readonly IPublicUrlBuilder _urls;
    private readonly IPackagePublishService _publish;
    private readonly ClaimResolver _claimResolver;
    private readonly Dependably.Storage.ProxyFetchService _proxyFetch;

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
        _blockGate = svc.BlockGate;
        _licenses = svc.Licenses;
        _urls = svc.Urls;
        _publish = svc.Publish;
        _claimResolver = svc.ClaimResolver;
        _proxyFetch = svc.ProxyFetch;
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
        // Read paths use the org-scoped overload: a token bound to a different tenant is
        // coerced to null so the existing token-null branches respect AnonymousPull
        // consistently for both anonymous and cross-org callers.
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        var fullName = scope is not null ? $"{scope}/{package}" : package;
        var purlName = fullName;

        var pkg = await _packages.GetByPurlNameAsync(orgId, "npm", purlName, ct);

        // Route by passthrough + claims, not packages.is_proxy. A name with uploaded versions
        // is still a namespace that can hold proxy-fetched versions.
        var passthroughAllowed = settings!.ProxyPassthroughEnabled
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", purlName, ct);

        if (passthroughAllowed)
        {
            if (!settings.AnonymousPull && token is null)
            {
                Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
                return Unauthorized();
            }
            return await ProxyNpmMetadata(fullName, pkg, ct);
        }

        // Passthrough disabled or claim-local — serve local-only metadata.
        if (pkg is null) return NotFound();
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }
        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        return new JsonResult(BuildNpmMetadata(pkg, versions));
    }

    private async Task<IActionResult> ProxyNpmMetadata(
        string fullName, Package? localPkg, CancellationToken ct)
    {
        var localVersions = localPkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await _packages.GetVersionsAsync(localPkg.Id, ct);

        var upstreamBase = _config["Npm:Upstream"] ?? "https://registry.npmjs.org";
        JsonNode? metadata = null;
        try
        {
            using var response = await _upstream.GetMetadataAsync($"{upstreamBase}/{fullName}", ct);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(ct);
                metadata = JsonNode.Parse(json);
                if (metadata is not null)
                    RewriteTarballUrls(metadata, fullName, NpmTarballBase());
            }
        }
        catch
        {
            // Upstream unreachable — fall back to local versions only when we have them.
        }

        if (metadata is null)
        {
            if (localPkg is null || localVersions.Count == 0) return NotFound();
            return new JsonResult(BuildNpmMetadata(localPkg, localVersions));
        }

        // Splice uploaded local versions into the upstream packument so npm install can
        // discover both private and public versions of the same name.
        if (localPkg is not null && localVersions.Count > 0)
            MergeLocalVersionsIntoPackument(metadata, localPkg, localVersions);

        return new JsonResult(metadata);
    }

    private void MergeLocalVersionsIntoPackument(JsonNode packument, Package localPkg, IReadOnlyList<PackageVersion> localVersions)
    {
        var versionsObj = packument["versions"]?.AsObject();
        if (versionsObj is null)
        {
            versionsObj = new JsonObject();
            packument["versions"] = versionsObj;
        }

        var tarballBase = NpmTarballBase();
        foreach (var v in localVersions)
        {
            if (versionsObj.ContainsKey(v.Version)) continue;
            var filename = v.BlobKey.Split('/').Last();
            var dist = new JsonObject
            {
                ["tarball"] = $"{tarballBase}/{localPkg.Name}/{filename}"
            };
            // dist.shasum is hex SHA-1 by spec — emit only when we have a real SHA-1
            // (populated at publish time / captured from upstream packuments on first-fetch).
            // Omit rather than fall back to SHA-256: clients that verify shasum would reject
            // the tarball, and clients that trust it would write the wrong hash to lockfiles.
            if (v.ChecksumSha1 is not null) dist["shasum"] = v.ChecksumSha1;
            versionsObj[v.Version] = new JsonObject
            {
                ["name"] = localPkg.Name,
                ["version"] = v.Version,
                ["dist"] = dist
            };
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
            var dist = new JsonObject
            {
                ["tarball"] = $"{tarballBase}/{pkg.Name}/{filename}"
            };
            // dist.shasum is hex SHA-1 by spec — see MergeLocalVersionsIntoPackument for why
            // we omit the field when no SHA-1 is recorded instead of substituting SHA-256.
            if (v.ChecksumSha1 is not null) dist["shasum"] = v.ChecksumSha1;
            versionsObj[v.Version] = new JsonObject
            {
                ["name"] = pkg.Name,
                ["version"] = v.Version,
                ["dist"] = dist
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
        // Org-scoped resolve: cross-org tokens behave as anonymous (respecting AnonymousPull).
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
        var pkgRecord = await _packages.GetByPurlNameAsync(orgId, "npm", fullName, ct);

        // Route by per-version origin, not packages.is_proxy. Extract version from the tarball
        // filename ({shortName}-{version}.tgz) and branch on that row's origin.
        var versionFromFilename = ExtractVersionFromTarballFilename(shortName, file);
        PackageVersion? pkgVersion = null;
        if (pkgRecord is not null && versionFromFilename is not null)
            pkgVersion = await _packages.GetVersionAsync(pkgRecord.Id, versionFromFilename, ct);

        if (pkgVersion is not null && pkgVersion.Origin == "uploaded")
            return await ServeHostedTarballVersionAsync(orgId, pkgVersion, file, token, settings!, ct);

        if (pkgVersion is not null && pkgVersion.Origin == "proxy")
        {
            var cached = await ServeCachedProxyTarballAsync(orgId, pkgVersion, file, token, settings!, ct);
            if (cached is not null) return cached;
            // Same version row exists but the cached blob doesn't match the requested file — fall through.
        }

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        var purlCheck = PurlNormalizer.Npm(fullName, "0.0.0").Split('@')[0]; // name-only PURL
        if (settings?.AllowlistMode == true && !await _allowlist.IsAllowedAsync(orgId, purlCheck, ct))
            return StatusCode(403);
        if (await _blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "npm", purlCheck, "blocked", token?.UserId,
                sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
            return StatusCode(403);
        }

        if (!settings!.ProxyPassthroughEnabled)
            return NotFound();

        // #47: claim state gates the proxy fetch.
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", fullName, ct))
            return NotFound();

        return await ProxyFetchAndCacheAsync(orgId, fullName, shortName, file, token, settings!, ct);
    }

    private static string? ExtractVersionFromTarballFilename(string shortName, string file)
    {
        var baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
        return baseName.Length > shortName.Length + 1 && baseName.StartsWith(shortName + "-", StringComparison.Ordinal)
            ? baseName[(shortName.Length + 1)..]
            : null;
    }

    private async Task<IActionResult> ServeHostedTarballVersionAsync(
        string orgId, PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }
        if (!token.HasCapability(Capabilities.ReadArtifact)) return Forbid();

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase)) return NotFound();

        var sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (await _blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt), ct)
            == BlockDecision.Blocked) return StatusCode(403);

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null) return NotFound();

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        await _audit.LogActivityAsync(orgId, "npm", pkgVersion.Purl, "download", token.UserId,
            sourceIp: sourceIp, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    private async Task<IActionResult?> ServeCachedProxyTarballAsync(
        string orgId, PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (await _blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "npm", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token?.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt), ct)
            == BlockDecision.Blocked) return StatusCode(403);

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase)) return null;

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null) return null;

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        await _audit.LogActivityAsync(orgId, "npm", pkgVersion.Purl, "download", token?.UserId,
            sourceIp: sourceIp, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    private async Task<IActionResult> ProxyFetchAndCacheAsync(
        string orgId, string fullName, string shortName, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var upstreamBase = _config["Npm:Upstream"] ?? "https://registry.npmjs.org";
        var upstreamUrl = $"{upstreamBase}/{fullName}/-/{file}";
        Response.Headers["X-Cache"] = "MISS";

        try
        {
            using var resp = await _upstream.GetMetadataAsync(upstreamUrl, ct);
            if (!resp.IsSuccessStatusCode) return NotFound();
            var bytes = await resp.Content.ReadAsByteArrayAsync(ct);

            var baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
            var version = baseName.Length > shortName.Length + 1 ? baseName[(shortName.Length + 1)..] : "unknown";
            var purl = PurlNormalizer.Npm(fullName, version);

            var meta = await TryFetchNpmFirstFetchMetadataAsync(upstreamBase, fullName, version, ct);

            // npm publishes integrity as an SRI string (e.g. "sha512-{b64}") — store verbatim
            // so operators copying out of the version detail page can paste against npmjs.com
            // without re-encoding. NULL when upstream only sent shasum (already captured to
            // checksum_sha1) or no integrity at all.
            var (integrityValue, integrityAlgo) = meta.IntegritySri is not null
                ? (meta.IntegritySri, "sha512-sri")
                : ((string?)null, (string?)null);

            var result = await _proxyFetch.RecordAndScanAsync(new Dependably.Storage.ProxyFetchRequest(
                OrgId: orgId, Ecosystem: "npm",
                PackageName: fullName, PurlName: fullName,
                Version: version, Purl: purl, File: file, Bytes: bytes,
                ExtractLicenses: LicenseExtractor.FromNpmTarballPackageJson,
                UserId: token?.UserId,
                SourceIp: HttpContext.GetNormalizedRemoteIp(),
                MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
                MinReleaseAgeHours: settings.MinReleaseAgeHours,
                CacheAccess: new CacheAccess(orgId, "npm", fullName, version, file,
                    Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: upstreamUrl),
                PublishedAt: meta.PublishedAt,
                UpstreamChecksum: meta.Checksum,
                Sha1Hex: meta.Sha1Hex,
                UpstreamIntegrityValue: integrityValue,
                UpstreamIntegrityAlgorithm: integrityAlgo
            ), ct);

            if (result.Decision == BlockDecision.Blocked) return StatusCode(403);
            return File(bytes, "application/octet-stream", file);
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch (ChecksumException)
        {
            // Upstream bytes didn't match upstream-supplied integrity — refuse the response
            // rather than serve poison. ProxyFetchService already audited + emitted the metric.
            return StatusCode(502);
        }
        catch
        {
            return NotFound();
        }
    }

    /// <summary>
    /// Fetches the npm packument once on proxy first-fetch and extracts everything we care
    /// about: the per-version published timestamp, an upstream integrity spec for fail-fast
    /// verification (<c>dist.integrity</c> SRI sha512 preferred, <c>dist.shasum</c> SHA-1
    /// fallback), the raw <c>dist.shasum</c> hex so the packument we re-emit later can carry
    /// the correct SHA-1, and the verbatim SRI string for the version detail UI. Fail-soft:
    /// any error returns a record full of nulls and the caller proceeds without verification
    /// or capture.
    /// </summary>
    private async Task<NpmFirstFetchMetadata> TryFetchNpmFirstFetchMetadataAsync(
        string upstreamBase, string fullName, string version, CancellationToken ct)
    {
        try
        {
            using var resp = await _upstream.GetMetadataAsync($"{upstreamBase}/{fullName}", ct);
            if (!resp.IsSuccessStatusCode) return NpmFirstFetchMetadata.Empty;
            var json = await resp.Content.ReadAsStringAsync(ct);
            var node = JsonNode.Parse(json);

            DateTimeOffset? publishedAt = null;
            var time = node?["time"]?[version]?.GetValue<string>();
            if (DateTimeOffset.TryParse(time, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
                publishedAt = ts;

            var dist = node?["versions"]?[version]?["dist"];
            var integrity = dist?["integrity"]?.GetValue<string>();
            var shasum = dist?["shasum"]?.GetValue<string>();
            var checksum = ChecksumVerifier.ParseNpmIntegrity(integrity, shasum);

            // Only surface the integrity string when it's actually the SHA-512 SRI form; older
            // packages might carry a non-SRI value in this field, in which case the UI label
            // ("SHA-512 SRI") would lie. Anything else stays NULL.
            var integritySri = integrity is not null
                && integrity.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase)
                ? integrity : null;

            return new NpmFirstFetchMetadata(publishedAt, checksum, shasum, integritySri);
        }
        catch { return NpmFirstFetchMetadata.Empty; }
    }

    private readonly record struct NpmFirstFetchMetadata(
        DateTimeOffset? PublishedAt,
        ChecksumSpec? Checksum,
        string? Sha1Hex,
        string? IntegritySri)
    {
        public static NpmFirstFetchMetadata Empty => new(null, null, null, null);
    }


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
        var request = BuildNpmPublishRequest(new NpmPublishContext(
            orgId, fullName, versionKey!, filename, tarball!,
            token.UserId, orgSettings?.AllowVersionOverwrite ?? false, claim.State));
        var result = await _publish.StoreAndRecordAsync(request, ct);

        if (result is PublishResult.Rejected rej) return MapPublishRejection(rej, versionKey!);

        var versionId = ((PublishResult.Accepted)result).VersionId;
        await EmitNpmLicensesAndDeprecationAsync(versionId, tarball!, versions?[versionKey!], ct);
        return Ok();
    }

    // Bundles BuildNpmPublishRequest's tail-end coordinates into a single param to keep the
    // builder's signature within S107's threshold while preserving the ergonomic call shape.
    private sealed record NpmPublishContext(
        string OrgId, string FullName, string VersionKey, string Filename, byte[] Tarball,
        string? ActorUserId, bool AllowOverwrite, string ClaimState);

    private PublishRequest BuildNpmPublishRequest(NpmPublishContext ctx)
        => new()
        {
            OrgId = ctx.OrgId,
            Ecosystem = "npm",
            Name = ctx.FullName,
            PurlName = ctx.FullName,
            Version = ctx.VersionKey,
            Filename = ctx.Filename,
            Purl = PurlNormalizer.Npm(ctx.FullName, ctx.VersionKey),
            ArtifactBytes = ctx.Tarball,
            // Already enforced by CheckUploadSizeAsync; service-side cap is defence in depth.
            SizeCap = long.MaxValue,
            Origin = "uploaded",
            ActorUserId = ctx.ActorUserId,
            AuditAction = "push",
            AllowOverwrite = ctx.AllowOverwrite,
            ClaimState = ctx.ClaimState,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
        };

    /// <summary>
    /// License: read the tarball's package.json (canonical, matches the proxy first-fetch
    /// path). Fall back to the packument when the tarball lacks a parseable
    /// package/package.json — many publish clients don't include license in the
    /// packument's version object. Deprecation only ever lives in the packument (npm
    /// deprecate writes there), so it must always come from the packument extractor.
    /// </summary>
    private async Task EmitNpmLicensesAndDeprecationAsync(
        string versionId, byte[] tarball, JsonNode? packumentVersion, CancellationToken ct)
    {
        var fromTarball = LicenseExtractor.FromNpmTarballPackageJson(tarball);
        var fromPackument = LicenseExtractor.FromNpmPackumentVersion(packumentVersion);
        var spdx = fromTarball.Spdx.Count > 0 ? fromTarball.Spdx : fromPackument.Spdx;
        if (spdx.Count > 0)
            await _licenses.SetLicensesAsync(versionId, spdx, "upstream", ct);
        if (fromPackument.Deprecated is not null)
            await _packages.UpdateDeprecatedAsync(versionId, fromPackument.Deprecated, ct);
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
        var limit = await _orgs.GetUploadLimitAsync(settings, "npm", ct);
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
    BlockGateService BlockGate,
    LicenseRepository Licenses,
    IPublicUrlBuilder Urls,
    IPackagePublishService Publish,
    ClaimResolver ClaimResolver,
    Dependably.Storage.ProxyFetchService ProxyFetch);
