using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
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
    private readonly BlockGateService _blockGate;
    private readonly LicenseRepository _licenses;
    private readonly PublishGate _publishGate;
    private readonly Dependably.Infrastructure.Publish.IPackagePublishService _publish;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ClaimResolver _claimResolver;
    private readonly Dependably.Storage.ProxyFetchService _proxyFetch;
    private readonly UpstreamRegistryResolver _registries;

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
        _blockGate = svc.BlockGate;
        _licenses = svc.Licenses;
        _publishGate = svc.PublishGate;
        _publish = svc.Publish;
        _cacheRecorder = svc.CacheRecorder;
        _claimResolver = svc.ClaimResolver;
        _proxyFetch = svc.ProxyFetch;
        _registries = svc.Registries;
    }

    // ── Read endpoints ─────────────────────────────────────────────────

    /// <summary>GET /o/{org}/simple/ — PEP 503 package listing</summary>
    [HttpGet("/simple/")]
    public async Task<IActionResult> SimpleIndex(CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

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
            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(simpleHref)}\">{System.Web.HttpUtility.HtmlEncode(name)}</a><br/>");
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
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        var purlName = NormalizePyPiName(package);
        var pkg = await _packages.GetByPurlNameAsync(orgId, "pypi", purlName, ct);

        // Always merge upstream + local versions when passthrough + claims allow. Routing must
        // not gate on packages.is_proxy — a name with privately uploaded versions is still a
        // namespace that holds proxy-fetched versions; clients need to discover both.
        var passthroughAllowed = settings!.ProxyPassthroughEffective
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
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");
        foreach (var v in versions)
        {
            var filename = v.BlobKey.Split('/').Last();
            var href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null) href += $"#sha256={v.ChecksumSha256}";

            var yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\"" : "";

            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
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

        // Walk the org's configured upstreams in priority order; the first that answers wins.
        // No configured upstream ⇒ proxying is disabled for this ecosystem, so fall through to
        // local-only below.
        var bases = await _registries.ResolveAsync(CurrentTenantId(), "pypi", ct);
        string? upstreamHtml = null;
        foreach (var upstreamBase in bases)
        {
            try
            {
                // Single-flight simple-index fetch — collapses N concurrent pip-install
                // requests onto a single upstream call when a coordinate first warms up.
                var response = await _upstream.GetOrFetchMetadataAsync($"{upstreamBase}/simple/{purlName}/", ct);
                if (!response.IsSuccessStatusCode) continue;

                var html = response.BodyAsString();
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
                        // filename/fragment come from upstream HTML — encode before re-emitting.
                        return $"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(OrgPath($"packages/{filename}{fragment}"))}\">{System.Web.HttpUtility.HtmlEncode(filename)}</a>";
                    },
                    RegexOptions.None,
                    RegexTimeout);
                upstreamHtml = html;
                break;
            }
            catch
            {
                // Upstream unreachable — try the next one, then fall back to local-only.
            }
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
            sb.Append($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
        }
        if (sb.Length == 0) return upstreamHtml;

        var bodyClose = upstreamHtml.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        return bodyClose < 0
            ? upstreamHtml + sb
            : upstreamHtml[..bodyClose] + sb + upstreamHtml[bodyClose..];
    }

    /// <summary>GET /packages/{file} — blob download with proxy cache (tenant-implicit from host)</summary>
    [HttpGet("/packages/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> DownloadPackage(string file, CancellationToken ct)
    {
        // Parse name + version up front. PEP 503/440-aware; rejects mis-shaped requests
        // before any DB / upstream work so corrupt filenames can't reach the recorders.
        if (!PyPiArtifactValidator.TryParseFilename(file, out var parsedPurlName, out var parsedVersion))
            return NotFound();
        var parsed = new PyPiFilename(parsedPurlName!, parsedVersion!);

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
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
                        token?.UserId, settings!.MaxOsvScoreTolerance, sourceIp,
                        MinReleaseAgeHours: settings.MinReleaseAgeHours,
                        PublishedAt: v.PublishedAt,
                        ActorKind: token?.ActorKind,
                        Deprecated: v.Deprecated,
                        BlockDeprecatedMode: settings.BlockDeprecated), ct)
                == BlockDecision.Blocked) return StatusCode(403);

            var cached = await TryServeCachedBlobAsync(pkgVersions.Value, file, orgId, token, sourceIp, ct);
            if (cached is not null) return cached;
        }

        // Cache miss — proxy from upstream. No configured upstream for pypi ⇒ proxying is
        // disabled for this ecosystem, so a miss is a 404 (mirrors ProxyPassthroughEnabled=false).
        Response.Headers["X-Cache"] = "MISS";
        var bases = await _registries.ResolveAsync(orgId, "pypi", ct);
        var resolved = await ResolveProxyUpstreamUrlAsync(file, parsed, pkgVersions, bases, ct);
        if (resolved is null) return NotFound();

        var gateError = await CheckProxyAllowlistBlocklistAsync(orgId, parsed, token, settings!, sourceIp, ct);
        if (gateError is not null) return gateError;

        if (!settings!.ProxyPassthroughEffective) return NotFound();

        // Claim state gates the proxy fetch. local_only (including air-gap implicit
        // local_only) disables proxy serving for that name.
        var purlNameForClaim = pkgVersions?.Package.PurlName ?? parsed.PurlName;
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlNameForClaim, ct))
            return NotFound();

        return await FetchAndCacheUpstreamAsync(file, resolved.Value.Url, resolved.Value.Sha256Hex,
            parsed, pkgVersions,
            new ProxyContext(orgId, token?.UserId, token?.ActorKind, settings!, sourceIp),
            ct);
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
    // at the tail of first-fetch can fire without re-reading settings. ActorKind pairs with
    // UserId so the first_fetch activity row can distinguish service-token from user-token
    // attribution (see ActorKinds / TokenRecord.ActorKind).
    private sealed record ProxyContext(string OrgId, string? UserId, string? ActorKind, OrgSettings Settings, string? SourceIp = null);
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
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        await _packages.IncrementDownloadCountAsync(pkgVer.Version.Id, ct);
        return File(blob, "application/octet-stream", file);
    }

    // If we have a known sha256, files.pythonhosted.org uses the sha256 as a path prefix.
    // Otherwise, look it up in the upstream simple index. Returns null on lookup failure.
    // The second tuple element is the upstream-supplied SHA-256 (hex) for fail-fast
    // verification before caching: either the previously-stored hash on the cache-hit path,
    // or the #sha256= fragment from PEP 503's <a href> on first fetch. Null when no
    // upstream-supplied hash is available.
    private async Task<(string Url, string? Sha256Hex)?> ResolveProxyUpstreamUrlAsync(
        string file, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions,
        IReadOnlyList<string> bases, CancellationToken ct)
    {
        // No configured upstream ⇒ proxying disabled for pypi; resolve nothing.
        if (bases.Count == 0) return null;

        var sha256 = pkgVersions?.Version.ChecksumSha256;
        if (sha256 is not null)
            return ($"https://files.pythonhosted.org/packages/{sha256[..2]}/{sha256[2..4]}/{sha256}/{file}", sha256);

        // Walk upstreams in priority order; the first whose simple index resolves the file wins.
        foreach (var upstreamBase in bases)
        {
            var resolved = await ResolveUpstreamPyPiUrlAsync(upstreamBase, parsed.PurlName, file, ct);
            if (resolved is not null) return (resolved.Value.Url, resolved.Value.Sha256Hex);
        }
        return null;
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
                actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
            return StatusCode(403);
        }
        return null;
    }

    private async Task<IActionResult> FetchAndCacheUpstreamAsync(
        string file, string upstreamUrl, string? upstreamSha256, PyPiFilename parsed,
        (Package Package, PackageVersion Version)? pkgVersions,
        ProxyContext gate, CancellationToken ct)
    {
        try
        {
            // Verification preference: previously-stored hash > upstream-supplied (#sha256=).
            // Both are SHA-256; we pass whichever we have into UpstreamClient so it can verify
            // before caching and throw ChecksumException → 502 on mismatch.
            var knownSha = pkgVersions?.Version.ChecksumSha256 ?? upstreamSha256;
            var fetched = await DownloadAndCacheAsync(upstreamUrl, knownSha, gate.OrgId, ct);
            if (fetched is null) return NotFound();

            Response.Headers["X-Cache"] = fetched.IsHit ? "HIT" : "MISS";
            if (pkgVersions is not null)
                Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersions.Value.Version.Purl);

            // Record into cache_artifact + tenant_artifact_access on every fetch path
            // (hit and miss). Best-effort — recorder swallows failures.
            var purlName = pkgVersions?.Package.PurlName ?? parsed.PurlName;
            var version = pkgVersions?.Version.Version ?? parsed.Version;
            await _cacheRecorder.RecordAccessAsync(new Dependably.Infrastructure.CacheAccess(
                gate.OrgId, "pypi", purlName, version, file,
                fetched.Blob.Sha256Hex, fetched.Blob.SizeBytes, fetched.Blob.BlobKey, upstreamUrl), ct);

            if (!fetched.IsHit && pkgVersions is null)
            {
                var firstFetchBlock = await RecordAndScanFirstFetchAsync(file, parsed, fetched.Blob, upstreamSha256, gate, ct);
                if (firstFetchBlock is not null) return firstFetchBlock;
            }

            // The blob is already cached (either pre-existing for HIT, or freshly written
            // by UpstreamClient / DownloadAndCacheAsync for MISS). Open a fresh stream for
            // the response so memory stays bounded regardless of artefact size + concurrency.
            var proxyStream = await fetched.Blob.OpenAsync(ct);
            return File(proxyStream, "application/octet-stream", file);
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

    /// <summary>
    /// Downloads <paramref name="upstreamUrl"/> into the proxy cache and returns a
    /// <see cref="BlobHandle"/> describing the stored artefact.
    /// <list type="bullet">
    ///   <item><b>Known-sha path:</b> routes through
    ///         <see cref="UpstreamClient.GetOrFetchStreamAsync"/> which hash-and-stages the
    ///         body to disk — no full-artefact byte[] is ever materialised.</item>
    ///   <item><b>Unknown-sha cold-start:</b> still buffers via
    ///         <see cref="UpstreamClient.GetOrFetchMetadataAsync"/> because the cache key
    ///         only exists after hashing. The byte[] residue is bounded to this path and
    ///         wrapped in a <see cref="BlobHandle"/> so all downstream code is
    ///         stream-shaped (parallel concern; tracked separately).</item>
    /// </list>
    /// </summary>
    // deepcode ignore PT,LogForging: blob put uses BlobKeys.Proxy(sha) which validates
    // 64-char lowercase hex; Serilog uses RenderedCompactJsonFormatter (CRLF-safe).
    private async Task<PyPiFetchOutcome?> DownloadAndCacheAsync(
        string upstreamUrl, string? knownSha256, string orgId, CancellationToken ct)
    {
        if (knownSha256 is not null)
        {
            // Known checksum — verify and use content-addressed cache. The streaming
            // variant returns a stream we immediately dispose: subsequent consumers
            // (license extraction, response body) open a fresh blob-store stream via
            // the BlobHandle. SizeBytes is read from the seekable stream's Length when
            // available (LocalBlobStore → FileStream); remote backends that hand back
            // a non-seekable network stream leave SizeBytes at 0, which the cache_artifact
            // recorder tolerates (best-effort, not load-bearing for the proxy fetch).
            var blobKey = BlobKeys.Proxy(knownSha256);
            var (stream, isHit) = await _upstream.GetOrFetchStreamAsync(
                blobKey, upstreamUrl, new ChecksumSpec(ChecksumAlgorithm.Sha256, knownSha256),
                "pypi", orgId, ct: ct);
            long size = 0;
            await using (stream.ConfigureAwait(false))
            {
                if (stream.CanSeek) size = stream.Length;
            }
            var blob = new BlobHandle(blobKey, knownSha256, size,
                async openCt => await _blobs.GetAsync(blobKey, openCt)
                    ?? throw new InvalidOperationException(
                        $"Blob {blobKey} vanished between PutAsync and GetAsync."));
            return new PyPiFetchOutcome(blob, isHit);
        }

        // Unknown checksum — fetch, compute, cache, wrap in a BlobHandle. Route through
        // single-flighted metadata fetch so a stampede of concurrent CI clients
        // pulling an unchecked-sha coordinate triggers just one upstream call.
        //
        // This is the PyPi cold-start residue of the proxy-fetch refactor: the SHA isn't
        // known up front so the content-addressed hash-and-stage pipeline can't
        // route this request. Wrapping the byte[] in a BlobHandle keeps the residue
        // localized — ProxyFetchService, ProxyVersionRecorder, and LicenseExtractor
        // never see a byte[].
        var resp = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, ct);
        if (!resp.IsSuccessStatusCode) return null;
        var bytes = resp.Body;
        var sha = ChecksumVerifier.ComputeSha256Hex(bytes);
        var proxyKey = BlobKeys.Proxy(sha);
        if (!await _blobs.ExistsAsync(proxyKey, ct))
            await _blobs.PutAsync(proxyKey, new MemoryStream(bytes), ct);
        var coldBlob = new BlobHandle(proxyKey, sha, bytes.LongLength,
            async openCt => await _blobs.GetAsync(proxyKey, openCt)
                ?? (Stream)new MemoryStream(bytes, writable: false));
        return new PyPiFetchOutcome(coldBlob, IsHit: false);
    }

    private sealed record PyPiFetchOutcome(BlobHandle Blob, bool IsHit);

    // deepcode ignore PT,LogForging: bytes are cached under BlobKeys.Proxy(sha) which validates
    // 64-char lowercase hex; Serilog uses RenderedCompactJsonFormatter (CRLF-safe).
    private async Task<IActionResult?> RecordAndScanFirstFetchAsync(
        string file, PyPiFilename parsed, BlobHandle blob, string? upstreamSha256,
        ProxyContext gate, CancellationToken ct)
    {
        var purl = PurlNormalizer.PyPi(parsed.PurlName, parsed.Version);
        // Use the highest-priority configured upstream for the supplementary JSON metadata fetch.
        var bases = await _registries.ResolveAsync(gate.OrgId, "pypi", ct);
        var jsonMeta = bases.Count == 0
            ? PyPiJsonMetadata.Empty
            : await TryFetchPyPiJsonMetadataAsync(bases[0], parsed.PurlName, parsed.Version, file, ct);

        // Prefer the simple-index #sha256= fragment (it's already verified against the bytes
        // by UpstreamClient on the way in). Fall back to the JSON API's digests.sha256 when
        // upstream's simple page didn't carry a fragment.
        var integrityValue = upstreamSha256 ?? jsonMeta.Sha256Hex;
        var integrityAlgo = integrityValue is not null ? "sha256" : null;

        var result = await _proxyFetch.RecordAndScanAsync(new Dependably.Storage.ProxyFetchRequest(
            OrgId: gate.OrgId, Ecosystem: "pypi",
            PackageName: parsed.PurlName, PurlName: parsed.PurlName,
            Version: parsed.Version, Purl: purl, File: file, Blob: blob,
            ExtractLicenses: stream => LicenseExtractor.FromPyPiPackageBytes(stream, file),
            UserId: gate.UserId,
            ActorKind: gate.ActorKind,
            SourceIp: gate.SourceIp,
            MaxOsvScoreTolerance: gate.Settings.MaxOsvScoreTolerance,
            MinReleaseAgeHours: gate.Settings.MinReleaseAgeHours,
            // PyPI records cache_access separately in FetchAndCacheUpstreamAsync (covers
            // both hit and miss paths); skip here to avoid the double-write.
            CacheAccess: null,
            PublishedAt: jsonMeta.PublishedAt,
            UpstreamIntegrityValue: integrityValue,
            UpstreamIntegrityAlgorithm: integrityAlgo,
            Deprecated: jsonMeta.Deprecated,
            BlockDeprecatedMode: gate.Settings.BlockDeprecated), ct);
        return result.Decision == BlockDecision.Blocked ? StatusCode(403) : null;
    }

    /// <summary>
    /// Calls PyPI's per-version JSON API and picks the <c>urls[]</c> entry matching the file
    /// we're about to record: returns its <c>upload_time_iso_8601</c> for <c>published_at</c>
    /// and its <c>digests.sha256</c> as a fallback upstream integrity value. The Simple API
    /// is HTML-only and carries no timestamps, so the JSON API is an extra request — fail-soft,
    /// never blocks the underlying artefact fetch.
    /// </summary>
    private async Task<PyPiJsonMetadata> TryFetchPyPiJsonMetadataAsync(
        string upstreamBase, string purlName, string version, string file, CancellationToken ct)
    {
        try
        {
            var url = $"{upstreamBase}/pypi/{purlName}/{version}/json";
            // Routes through single-flighted metadata fetch so an artefact stampede
            // doesn't also stampede this endpoint.
            var resp = await _upstream.GetOrFetchMetadataAsync(url, ct);
            if (!resp.IsSuccessStatusCode) return PyPiJsonMetadata.Empty;
            using var doc = JsonDocument.Parse(resp.Body);
            if (!doc.RootElement.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
                return PyPiJsonMetadata.Empty;
            var match = urls.EnumerateArray().FirstOrDefault(entry => EntryMatchesFilename(entry, file));
            return match.ValueKind == JsonValueKind.Undefined ? PyPiJsonMetadata.Empty : ParsePyPiUrlEntry(match);
        }
        catch { return PyPiJsonMetadata.Empty; }
    }

    private static bool EntryMatchesFilename(JsonElement entry, string file) =>
        entry.TryGetProperty("filename", out var fn) &&
        fn.ValueKind == JsonValueKind.String &&
        string.Equals(fn.GetString(), file, StringComparison.OrdinalIgnoreCase);

    private static PyPiJsonMetadata ParsePyPiUrlEntry(JsonElement entry)
    {
        DateTimeOffset? publishedAt = null;
        var iso = entry.TryGetProperty("upload_time_iso_8601", out var t) ? t.GetString() : null;
        if (DateTimeOffset.TryParse(iso, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
            publishedAt = ts;

        string? sha256 = null;
        if (entry.TryGetProperty("digests", out var digests)
            && digests.ValueKind == JsonValueKind.Object
            && digests.TryGetProperty("sha256", out var d)
            && d.ValueKind == JsonValueKind.String)
            sha256 = d.GetString()?.ToLowerInvariant();

        var deprecated = LicenseExtractor.FromPyPiJsonFile(entry).Deprecated;

        return new PyPiJsonMetadata(publishedAt, sha256, deprecated);
    }

    private readonly record struct PyPiJsonMetadata(DateTimeOffset? PublishedAt, string? Sha256Hex, string? Deprecated)
    {
        public static PyPiJsonMetadata Empty => new(null, null, null);
    }

    /// <summary>
    /// Fetches the upstream simple index for a package and extracts the actual download URL for a
    /// specific file, plus the <c>#sha256=</c> fragment if PEP 503 supplied one. The fragment
    /// drives fail-fast verification on first fetch — passed through as <c>knownSha256</c> to
    /// <see cref="UpstreamClient.GetOrFetchAsync"/> which throws <see cref="ChecksumException"/>
    /// on mismatch before any blob is cached. Returns null when the file isn't in the index.
    /// </summary>
    private async Task<(string Url, string? Sha256Hex)?> ResolveUpstreamPyPiUrlAsync(
        string upstreamBase, string pkgName, string filename, CancellationToken ct)
    {
        try
        {
            // This simple-index fetch fires inline with every PyPI file-download path,
            // so concurrent CI fan-out would otherwise stampede here too. Route through
            // single-flight.
            var resp = await _upstream.GetOrFetchMetadataAsync($"{upstreamBase}/simple/{pkgName}/", ct);
            if (!resp.IsSuccessStatusCode) return null;
            var html = resp.BodyAsString();
            // Group 1 = URL up to but not including the fragment; group 3 = the hex SHA-256
            // when a #sha256=... fragment is present. Older mirrors / non-PEP-503 indices
            // may omit the fragment; in that case group 3 is empty and we fall through with
            // a null hash (the request still succeeds, just without first-fetch verification).
            var match = Regex.Match(
                html,
                $@"href=""(https?://[^""#]*/{Regex.Escape(filename)})(#sha256=([0-9a-fA-F]{{64}}))?""",
                RegexOptions.None, RegexTimeout);
            if (!match.Success) return null;
            var url = match.Groups[1].Value;
            var sha = match.Groups[3].Success ? match.Groups[3].Value.ToLowerInvariant() : null;
            return (url, sha);
        }
        catch
        {
            return null;
        }
    }

    private Task<(Package Package, PackageVersion Version)?> FindVersionByFilename(
        string orgId, string filename, CancellationToken ct)
        => _packages.FindVersionByBlobKeySuffixAsync(orgId, "pypi", filename, ct);

    // ── Upload endpoint ────────────────────────────────────────────────

    /// <summary>POST /pypi/legacy/ — twine-compatible upload (tenant-implicit from host)</summary>
    [HttpPost("/pypi/legacy/")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishPypi)]
    [EnableRateLimiting("push")]
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
        var limit = await _orgs.GetUploadLimitAsync(settings, "pypi", ct);
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
            "bdist_egg"   => ValidateEgg(fileBytes),
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
            ActorKind = tenant.Token?.ActorKind,
            AuditAction = "push",
            AllowOverwrite = orgSettings?.AllowVersionOverwrite ?? false,
            ClaimState = claim.State,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
        }, ct);

        if (result is Dependably.Infrastructure.Publish.PublishResult.Rejected rej)
            return MapPyPiPublishRejection(rej, upload.Version);

        // Format-specific post-publish: license info comes from the wheel METADATA / sdist
        // PKG-INFO. Stays here because the extractor is PyPI-only. Push path holds the
        // upload bytes in memory — an upload-validation concern, out of scope here —
        // so we wrap in a MemoryStream for the unified extractor.
        var versionId = ((Dependably.Infrastructure.Publish.PublishResult.Accepted)result).VersionId;
        var extracted = LicenseExtractor.FromPyPiPackageBytes(
            new MemoryStream(upload.FileBytes, writable: false), upload.Filename);
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

    private static ValidationResult ValidateEgg(byte[] bytes)
    {
        try
        {
            using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(bytes), System.IO.Compression.ZipArchiveMode.Read);
            var hasMetadata = zip.Entries.Any(e =>
                e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
            if (!hasMetadata)
                return ValidationResult.Fail("content", "Egg is missing EGG-INFO/PKG-INFO");
            return ValidationResult.Ok();
        }
        catch
        {
            return ValidationResult.Fail("content", "Egg is not a valid ZIP file");
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
    Dependably.Storage.ProxyFetchService ProxyFetch,
    UpstreamRegistryResolver Registries);
