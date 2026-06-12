using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Caching.Memory;

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

    // Single-flight map: deduplicates concurrent simple-index rebuilds for the same key.
    private static readonly ConcurrentDictionary<string, Lazy<Task<byte[]?>>> _simpleIndexInFlight = new();

    // TTL for proxy-merged simple indices (upstream can change); local-only indices use a
    // longer TTL because invalidation on mutation is the primary expiry mechanism.
    private static readonly TimeSpan SimpleIndexProxyTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan SimpleIndexLocalTtl = TimeSpan.FromMinutes(10);

    // Serializer options for synthesized PyPI JSON documents — created once and reused so
    // every serialization shares the same cached type metadata.
    private static readonly JsonSerializerOptions CompactJsonOptions = new() { WriteIndented = false };

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
    private readonly ReservedNamespaceService _reserved;
    private readonly Dependably.Storage.ProxyFetchService _proxyFetch;
    private readonly UpstreamRegistryResolver _registries;
    private readonly ILogger<PyPiController> _logger;
    private readonly IMemoryCache _cache;

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
        _reserved = svc.ReservedNamespaces;
        _proxyFetch = svc.ProxyFetch;
        _registries = svc.Registries;
        _logger = svc.Logger;
        _cache = svc.Cache;
    }

    // Builds the IMemoryCache key for a PyPI simple index response.
    private static string SimpleIndexCacheKey(string orgId, string purlName) =>
        $"metadata:{orgId}:pypi:{purlName}";

    // ── Read endpoints ─────────────────────────────────────────────────

    /// <summary>GET /simple/ — PEP 503 package listing</summary>
    [HttpGet("/simple/")]
    public async Task<IActionResult> SimpleIndex(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
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
        foreach (string? name in pkgs.Select(pkg => pkg.PurlName))
        {
            string simpleHref = OrgPath($"simple/{name}/");
            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(simpleHref)}\">{System.Web.HttpUtility.HtmlEncode(name)}</a><br/>");
        }
        sb.AppendLine("</body></html>");

        return Content(sb.ToString(), "text/html; charset=utf-8");
    }

    /// <summary>GET /simple/{package}/ — PEP 503/592 version listing</summary>
    [HttpGet("/simple/{package}/")]
    public async Task<IActionResult> PackageIndex(string package, CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        string purlName = NormalizePyPiName(package);

        // The name flows into the upstream simple-index URL — reject traversal-shaped
        // values before any lookup or upstream call, mirroring the upload-side validation.
        if (!PathSafeValidator.ValidateUpstreamSegment(purlName, "package").IsValid)
        {
            return NotFound();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "pypi", purlName, ct);

        // Auth gate runs before any cache access so an unauthenticated request never
        // receives a cached response when AnonymousPull is disabled.
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Always merge upstream + local versions when passthrough + claims allow. Routing must
        // not gate on packages.is_proxy — a name with privately uploaded versions is still a
        // namespace that holds proxy-fetched versions; clients need to discover both.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && !await _reserved.IsReservedAsync(orgId, "pypi", purlName, ct)
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlName, ct);

        if (passthroughAllowed)
        {
            return await ServeProxySimpleIndexAsync(orgId, purlName, pkg, settings, token, ct);
        }

        // Passthrough disabled or name is claim-local — return only local versions.
        return pkg is null
            ? NotFound()
            : await ServeLocalSimpleIndexAsync(orgId, purlName, pkg, ct);
    }

    // Stamps the ETag for a simple-index body and answers 304 when the client's
    // If-None-Match matches; otherwise sets Cache-Control and returns null so the
    // caller serves the body.
    private StatusCodeResult? ServeNotModifiedOrSetCacheHeaders(byte[] body, string cacheControl)
    {
        string etag = ComputeETag(body);
        Response.Headers.ETag = etag;
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            return StatusCode(304);
        }
        Response.Headers.CacheControl = cacheControl;
        return null;
    }

    private async Task<IActionResult> ServeProxySimpleIndexAsync(
        string orgId, string purlName, Package? pkg, OrgSettings settings,
        TokenRecord? token, CancellationToken ct)
    {
        string proxyCacheKey = SimpleIndexCacheKey(orgId, purlName);
        if (_cache.TryGetValue<byte[]>(proxyCacheKey, out byte[]? proxyHit) && proxyHit is not null)
        {
            return ServeNotModifiedOrSetCacheHeaders(proxyHit, "private, max-age=60")
                ?? (IActionResult)new FileContentResult(proxyHit, "text/html; charset=utf-8");
        }

        // Single-flight: collapse concurrent rebuilds for the same proxy simple index.
        var lazy = _simpleIndexInFlight.GetOrAdd(proxyCacheKey,
            _ => new Lazy<Task<byte[]?>>(async () =>
            {
                // CancellationToken.None: shared task must not be poisoned by any one
                // caller's disconnection — callers detach via WaitAsync(ct).
                var result = await ProxyUpstreamSimpleIndex(purlName, pkg, settings, token, CancellationToken.None);
                if (result is ContentResult cr && cr.Content is not null)
                {
                    byte[] entryBytes = System.Text.Encoding.UTF8.GetBytes(cr.Content);
                    _cache.Set(proxyCacheKey, entryBytes, new MemoryCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = SimpleIndexProxyTtl,
                        Size = entryBytes.Length,
                    });
                    return entryBytes;
                }
                return null;
            }));

        byte[]? proxyBytes;
        try { proxyBytes = await lazy.Value.WaitAsync(ct); }
        finally { _simpleIndexInFlight.TryRemove(new KeyValuePair<string, Lazy<Task<byte[]?>>>(proxyCacheKey, lazy)); }

        if (proxyBytes is not null)
        {
            return new FileContentResult(proxyBytes, "text/html; charset=utf-8");
        }

        // Non-ContentResult result (e.g. Unauthorized or NotFound) — return as-is.
        return await ProxyUpstreamSimpleIndex(purlName, pkg, settings, token, ct);
    }

    private async Task<IActionResult> ServeLocalSimpleIndexAsync(
        string orgId, string purlName, Package pkg, CancellationToken ct)
    {
        string localCacheKey = SimpleIndexCacheKey(orgId, purlName);
        if (_cache.TryGetValue<byte[]>(localCacheKey, out byte[]? localHit) && localHit is not null)
        {
            return ServeNotModifiedOrSetCacheHeaders(localHit, "private, max-age=300")
                ?? (IActionResult)new FileContentResult(localHit, "text/html; charset=utf-8");
        }

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var localResult = RenderLocalSimpleIndex(pkg.PurlName, versions);
        if (localResult.Content is not null)
        {
            byte[] localBytes = System.Text.Encoding.UTF8.GetBytes(localResult.Content);
            _cache.Set(localCacheKey, localBytes, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = SimpleIndexLocalTtl,
                Size = localBytes.Length,
            });
            var notModified = ServeNotModifiedOrSetCacheHeaders(localBytes, "private, max-age=300");
            if (notModified is not null)
            {
                return notModified;
            }
        }
        return localResult;
    }

    private ContentResult RenderLocalSimpleIndex(string purlName, IReadOnlyList<PackageVersion> versions)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");
        foreach (var v in versions)
        {
            string filename = v.BlobKey.Split('/').Last();
            string href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null)
            {
                href += $"#sha256={v.ChecksumSha256}";
            }

            string yankAttr = v.Yanked
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
        foreach (string upstreamBase in bases)
        {
            try
            {
                // Single-flight simple-index fetch — collapses N concurrent pip-install
                // requests onto a single upstream call when a coordinate first warms up.
                var response = await _upstream.GetOrFetchMetadataAsync($"{upstreamBase}/simple/{purlName}/", ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                upstreamHtml = RewriteUpstreamSimpleIndexHtml(response.BodyAsString());
                break;
            }
            catch
            {
                // Upstream unreachable — try the next one, then fall back to local-only.
            }
        }

        if (upstreamHtml is null)
        {
            if (localVersions.Count == 0)
            {
                return NotFound();
            }

            var fallbackIndex = RenderLocalSimpleIndex(purlName, localVersions);
            byte[] fallbackBytes = System.Text.Encoding.UTF8.GetBytes(fallbackIndex.Content!);
            return ServeNotModifiedOrSetCacheHeaders(fallbackBytes, "private, max-age=300")
                ?? (IActionResult)fallbackIndex;
        }

        // Splice local-only filenames into the upstream index so mixed-origin namespaces
        // expose private versions alongside upstream. Filenames already present in the
        // upstream HTML are skipped to avoid duplicates.
        string merged = MergeLocalVersionsIntoUpstreamIndex(upstreamHtml, localVersions);
        byte[] mergedBytes = System.Text.Encoding.UTF8.GetBytes(merged);
        return ServeNotModifiedOrSetCacheHeaders(mergedBytes, "private, max-age=60")
            ?? (IActionResult)Content(merged, "text/html; charset=utf-8");
    }

    /// <summary>
    /// Rewrites an upstream PEP 503 simple-index page so every anchor points at the local
    /// <c>/packages/{file}</c> proxy route, stripping the metadata-sidecar attributes pip
    /// would otherwise chase upstream. The anchor's attribute run is matched inside an
    /// atomic group (<c>(?&gt;…)</c>) whose alternatives are disjoint on their first
    /// character (unquoted run vs. quoted string), so matching is linear over
    /// attacker-controlled upstream HTML — the engine can neither backtrack into an
    /// alternative nor give back iterations. The 2-second RegexTimeout stays as
    /// defence-in-depth.
    /// </summary>
    internal static string RewriteUpstreamSimpleIndexHtml(string html)
    {
        html = Regex.Replace(html, @"\s*data-(?:dist-info-metadata|core-metadata)=""[^""]*""", "", RegexOptions.None, RegexTimeout);
        return Regex.Replace(
            html,
            @"<a\b((?>(?:[^>""']+|""[^""]*""|'[^']*')*))>([^<]+)</a>",
            m =>
            {
                string attrs = m.Groups[1].Value;
                string filename = m.Groups[2].Value.Trim();
                var hrefMatch = Regex.Match(attrs, @"href=""(https?://[^""#]+)(#[^""]*)?""", RegexOptions.None, RegexTimeout);
                if (!hrefMatch.Success)
                {
                    return m.Value;
                }

                string fragment = hrefMatch.Groups[2].Value;
                // filename/fragment come from upstream HTML — encode before re-emitting.
                return $"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(OrgPath($"packages/{filename}{fragment}"))}\">{System.Web.HttpUtility.HtmlEncode(filename)}</a>";
            },
            RegexOptions.None,
            RegexTimeout);
    }

    private static string MergeLocalVersionsIntoUpstreamIndex(string upstreamHtml, IReadOnlyList<PackageVersion> localVersions)
    {
        if (localVersions.Count == 0)
        {
            return upstreamHtml;
        }

        var sb = new StringBuilder();
        foreach (var v in localVersions)
        {
            string filename = v.BlobKey.Split('/').Last();
            if (upstreamHtml.Contains($">{filename}<", StringComparison.Ordinal))
            {
                continue;
            }

            string href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null)
            {
                href += $"#sha256={v.ChecksumSha256}";
            }

            string yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\""
                : "";
            sb.Append($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
        }
        if (sb.Length == 0)
        {
            return upstreamHtml;
        }

        int bodyClose = upstreamHtml.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        return bodyClose < 0
            ? upstreamHtml + sb
            : upstreamHtml[..bodyClose] + sb + upstreamHtml[bodyClose..];
    }

    // ── JSON API ────────────────────────────────────────────────────────

    /// <summary>GET /pypi/{package}/json — PyPI JSON API for a package's latest version</summary>
    [HttpGet("/pypi/{package}/json")]
    public Task<IActionResult> PackageJson(string package, CancellationToken ct)
        => PackageJsonCore(package, version: null, ct);

    /// <summary>GET /pypi/{package}/{version}/json — PyPI JSON API for a specific version</summary>
    [HttpGet("/pypi/{package}/{version}/json")]
    public Task<IActionResult> PackageVersionJson(string package, string version, CancellationToken ct)
        => PackageJsonCore(package, version, ct);

    private async Task<IActionResult> PackageJsonCore(string package, string? version, CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);

        string purlName = NormalizePyPiName(package);

        if (!PathSafeValidator.ValidateUpstreamSegment(purlName, "package").IsValid)
        {
            return NotFound();
        }

        if (version is not null && !PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return NotFound();
        }

        var pkg = await _packages.GetByPurlNameAsync(orgId, "pypi", purlName, ct);

        // Determine whether passthrough to upstream is available.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlName, ct);

        // Collect local versions scoped to origin=uploaded (hosted packages).
        IReadOnlyList<PackageVersion>? hostedVersions = null;
        if (pkg is not null)
        {
            var allVersions = await _packages.GetVersionsAsync(pkg.Id, ct);
            hostedVersions = allVersions.Where(v => v.Origin == "uploaded").ToList();
        }

        bool hasHosted = hostedVersions is { Count: > 0 };

        // Mixed or hosted-only: synthesize the local JSON document (local shadows upstream,
        // consistent with SimpleIndex merge behaviour).
        if (hasHosted)
        {
            if (!settings.AnonymousPull && token is null)
            {
                Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return Unauthorized();
            }
            return SynthesizeLocalJsonDocument(pkg!, hostedVersions!, version, purlName);
        }

        // No hosted versions — proxy the upstream JSON document when passthrough is enabled.
        if (passthroughAllowed)
        {
            if (!settings.AnonymousPull && token is null)
            {
                Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return Unauthorized();
            }
            return await ProxyUpstreamJsonDocumentAsync(purlName, version, ct);
        }

        return NotFound();
    }

    /// <summary>
    /// Synthesizes a PyPI JSON API document from locally-hosted package versions. Includes
    /// only fields derivable from stored metadata — fields not captured at upload time are
    /// omitted rather than fabricated. URL rewriting to local download routes is intentional
    /// here; the upstream JSON document proxy path does NOT rewrite URLs so consumers get
    /// the unmodified upstream shape for proxy-only packages.
    /// </summary>
    private IActionResult SynthesizeLocalJsonDocument(
        Package pkg, IReadOnlyList<PackageVersion> versions,
        string? requestedVersion, string purlName)
    {
        var releases = BuildLocalReleaseFiles(versions);

        var infoVersion = SelectInfoVersion(versions, requestedVersion);
        if (infoVersion is null)
        {
            return NotFound();
        }

        var info = new Dictionary<string, object?>
        {
            ["name"] = pkg.Name,
            ["package_url"] = $"https://pypi.org/project/{purlName}/",
            ["project_url"] = $"https://pypi.org/project/{purlName}/",
            ["version"] = infoVersion.Version,
            // summary, author, license etc. are not captured at upload time for PyPI packages
            // hosted in this registry — fields absent from stored metadata are omitted rather
            // than emitted as null to match PyPI's own omission behaviour for sparse packages.
        };

        var infoVersionFiles = releases.TryGetValue(infoVersion.Version, out var vFiles)
            ? vFiles
            : new List<object>();

        var doc = new Dictionary<string, object?>
        {
            ["info"] = info,
            ["releases"] = releases,
            ["urls"] = infoVersionFiles,
        };

        string json = JsonSerializer.Serialize(doc, CompactJsonOptions);
        return Content(json, "application/json");
    }

    // Builds the per-version file lists for a synthesized JSON document, keyed by version string.
    private static Dictionary<string, List<object>> BuildLocalReleaseFiles(IReadOnlyList<PackageVersion> versions)
    {
        var releases = new Dictionary<string, List<object>>();
        foreach (var v in versions)
        {
            if (!releases.TryGetValue(v.Version, out var files))
            {
                files = new List<object>();
                releases[v.Version] = files;
            }
            files.Add(BuildLocalFileEntry(v));
        }
        return releases;
    }

    private static Dictionary<string, object?> BuildLocalFileEntry(PackageVersion v)
    {
        string filename = v.BlobKey.Split('/').Last();
        string downloadUrl = OrgPath($"packages/{filename}");

        var fileEntry = new Dictionary<string, object?>
        {
            ["filename"] = filename,
            ["url"] = downloadUrl,
            ["yanked"] = v.Yanked,
        };
        if (v.YankReason is not null)
        {
            fileEntry["yanked_reason"] = v.YankReason;
        }
        if (v.ChecksumSha256 is not null)
        {
            fileEntry["digests"] = new Dictionary<string, string> { ["sha256"] = v.ChecksumSha256 };
        }
        if (v.SizeBytes > 0)
        {
            fileEntry["size"] = v.SizeBytes;
        }
        if (v.PublishedAt is not null)
        {
            fileEntry["upload_time_iso_8601"] = v.PublishedAt.Value.ToString("o");
        }
        return fileEntry;
    }

    // Picks the version surfaced in `info` and `urls`: the requested version when one is
    // named, otherwise the latest non-yanked version by creation order (first version when
    // all are yanked). Null when nothing matches.
    private static PackageVersion? SelectInfoVersion(
        IReadOnlyList<PackageVersion> versions, string? requestedVersion)
    {
        return requestedVersion is not null
            ? versions.FirstOrDefault(v =>
                string.Equals(v.Version, requestedVersion, StringComparison.OrdinalIgnoreCase))
            : versions.FirstOrDefault(v => !v.Yanked) ?? (versions.Count > 0 ? versions[0] : null);
    }

    /// <summary>
    /// Forwards the PyPI JSON API document from the highest-priority configured upstream.
    /// Serves the upstream response verbatim (URLs are not rewritten — the upstream document
    /// points at files.pythonhosted.org, and scanners/version checkers using this endpoint
    /// want the authoritative upstream metadata shape, not a local proxy URL). A future
    /// iteration may rewrite URLs when mixed-origin transparency is needed.
    /// </summary>
    private async Task<IActionResult> ProxyUpstreamJsonDocumentAsync(
        string purlName, string? version, CancellationToken ct)
    {
        var bases = await _registries.ResolveAsync(CurrentTenantId(), "pypi", ct);
        if (bases.Count == 0)
        {
            return NotFound();
        }

        foreach (string upstreamBase in bases)
        {
            try
            {
                string path = version is not null
                    ? $"{upstreamBase}/pypi/{purlName}/{version}/json"
                    : $"{upstreamBase}/pypi/{purlName}/json";

                var resp = await _upstream.GetOrFetchMetadataAsync(path, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    continue;
                }

                return Content(resp.BodyAsString(), "application/json");
            }
            catch
            {
                // Upstream unreachable — try the next configured upstream.
            }
        }

        return NotFound();
    }

    /// <summary>GET /packages/{file} — blob download with proxy cache (tenant-implicit from host)</summary>
    [HttpGet("/packages/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> DownloadPackage(string file, CancellationToken ct)
    {
        // The filename flows into upstream URLs (files.pythonhosted.org path, simple-index
        // resolution) — reject traversal-shaped values before any DB / upstream work,
        // mirroring the upload-side validation.
        if (!PathSafeValidator.ValidateUpstreamSegment(file, "file").IsValid)
        {
            return NotFound();
        }

        // Parse name + version up front. PEP 503/440-aware; rejects mis-shaped requests
        // before any DB / upstream work so corrupt filenames can't reach the recorders.
        if (!PyPiArtifactValidator.TryParseFilename(file, out string? parsedPurlName, out string? parsedVersion))
        {
            return NotFound();
        }

        var parsed = new PyPiFilename(parsedPurlName!, parsedVersion!);

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
        var pkgVersions = await FindVersionByFilename(orgId, file, ct);

        var authError = CheckDownloadAuth(pkgVersions, token, settings!);
        if (authError is not null)
        {
            return authError;
        }

        string? sourceIp = HttpContext.GetNormalizedRemoteIp();
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
                        BlockDeprecatedMode: settings.BlockDeprecated,
                        BlockMaliciousMode: settings.BlockMalicious,
                        BlockKevMode: settings.BlockKev,
                        MaxEpssTolerance: settings.MaxEpssTolerance), ct)
                == BlockDecision.Blocked)
            {
                return StatusCode(403);
            }

            var cached = await TryServeCachedBlobAsync(pkgVersions.Value, file, orgId, token, sourceIp, ct);
            if (cached is not null)
            {
                return cached;
            }
        }

        // Cache miss — proxy from upstream. No configured upstream for pypi ⇒ proxying is
        // disabled for this ecosystem, so a miss is a 404 (mirrors ProxyPassthroughEnabled=false).
        Response.Headers["X-Cache"] = "MISS";
        var bases = await _registries.ResolveAsync(orgId, "pypi", ct);
        var resolved = await ResolveProxyUpstreamUrlAsync(file, parsed, pkgVersions, bases, ct);
        if (resolved is null)
        {
            return NotFound();
        }

        var gateError = await CheckProxyAllowlistBlocklistAsync(orgId, parsed, token, settings!, sourceIp, ct);
        if (gateError is not null)
        {
            return gateError;
        }

        if (!settings!.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        // Claim state and reserved namespaces gate the proxy fetch. local_only (including
        // air-gap implicit local_only) and reserved names disable proxy serving with the
        // same silent 404.
        string purlNameForClaim = pkgVersions?.Package.PurlName ?? parsed.PurlName;
        return await _reserved.IsReservedAsync(orgId, "pypi", purlNameForClaim, ct)
            || !await _claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlNameForClaim, ct)
            ? NotFound()
            : await FetchAndCacheUpstreamAsync(file, resolved.Value.Url, resolved.Value.Sha256Hex,
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
            return !token.HasCapability(Capabilities.ReadMetadata) ? Forbid() : (IActionResult?)null;
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
        if (blob is null)
        {
            return null;
        }

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVer.Version.Purl);
        if (pkgVer.Version.ChecksumSha256 is not null)
        {
            Response.Headers.ETag = $"\"sha256:{pkgVer.Version.ChecksumSha256}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
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
        if (bases.Count == 0)
        {
            return null;
        }

        string? sha256 = pkgVersions?.Version.ChecksumSha256;
        if (sha256 is not null)
        {
            return ($"https://files.pythonhosted.org/packages/{sha256[..2]}/{sha256[2..4]}/{sha256}/{file}", sha256);
        }

        // Walk upstreams in priority order; the first whose simple index resolves the file wins.
        foreach (string upstreamBase in bases)
        {
            var resolved = await ResolveUpstreamPyPiUrlAsync(upstreamBase, parsed.PurlName, file, ct);
            if (resolved is not null)
            {
                return (resolved.Value.Url, resolved.Value.Sha256Hex);
            }
        }
        return null;
    }

    private async Task<IActionResult?> CheckProxyAllowlistBlocklistAsync(string orgId, PyPiFilename parsed,
        TokenRecord? token, OrgSettings settings, string? sourceIp, CancellationToken ct)
    {
        string purlCheck = $"pkg:pypi/{parsed.PurlName}";
        if (settings.AllowlistMode && !await _allowlist.IsAllowedAsync(orgId, purlCheck, ct))
        {
            return StatusCode(403);
        }

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
            string? knownSha = pkgVersions?.Version.ChecksumSha256 ?? upstreamSha256;
            var fetched = await DownloadAndCacheAsync(upstreamUrl, knownSha, gate.OrgId, ct);
            if (fetched is null)
            {
                return NotFound();
            }

            Response.Headers["X-Cache"] = fetched.IsHit ? "HIT" : "MISS";
            if (pkgVersions is not null)
            {
                Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersions.Value.Version.Purl);
            }

            // Record into cache_artifact + tenant_artifact_access on every fetch path
            // (hit and miss). Best-effort — recorder swallows failures.
            string purlName = pkgVersions?.Package.PurlName ?? parsed.PurlName;
            string version = pkgVersions?.Version.Version ?? parsed.Version;
            await _cacheRecorder.RecordAccessAsync(new Dependably.Infrastructure.CacheAccess(
                gate.OrgId, "pypi", purlName, version, file,
                fetched.Blob.Sha256Hex, fetched.Blob.SizeBytes, fetched.Blob.BlobKey, upstreamUrl), ct);

            if (!fetched.IsHit && pkgVersions is null)
            {
                var firstFetchBlock = await RecordAndScanFirstFetchAsync(file, parsed, fetched.Blob, upstreamSha256, gate, ct);
                if (firstFetchBlock is not null)
                {
                    return firstFetchBlock;
                }
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
        catch (UpstreamResponseTooLargeException)
        {
            // Upstream body crossed the read cap (streamed or buffered) — a malformed or
            // hostile upstream, refused rather than served.
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
            string blobKey = BlobKeys.Proxy(knownSha256);
            // deepcode ignore LogForging: blobKey is BlobKeys.Proxy of a 64-char hex SHA-256 (no user input); upstreamUrl is operator-configured; Serilog structured rendering prevents log injection.
            var (stream, isHit) = await _upstream.GetOrFetchStreamAsync(
                blobKey, upstreamUrl, new ChecksumSpec(ChecksumAlgorithm.Sha256, knownSha256),
                "pypi", orgId, ct: ct);
            long size = 0;
            await using (stream.ConfigureAwait(false))
            {
                if (stream.CanSeek)
                {
                    size = stream.Length;
                }
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
        // Artifact bytes flow through the buffered path here, so the cap is the artifact
        // limit, not the (much smaller) default metadata limit.
        var resp = await _upstream.GetOrFetchMetadataAsync(
            upstreamUrl, UpstreamClient.MaxUpstreamResponseBytes, ct);
        if (!resp.IsSuccessStatusCode)
        {
            return null;
        }

        byte[] bytes = resp.Body;
        string sha = ChecksumVerifier.ComputeSha256Hex(bytes);
        string proxyKey = BlobKeys.Proxy(sha);
        if (!await _blobs.ExistsAsync(proxyKey, ct))
        {
            await _blobs.PutAsync(proxyKey, new MemoryStream(bytes), ct);
        }

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
        string purl = PurlNormalizer.PyPi(parsed.PurlName, parsed.Version);
        // Use the highest-priority configured upstream for the supplementary JSON metadata fetch.
        var bases = await _registries.ResolveAsync(gate.OrgId, "pypi", ct);
        var jsonMeta = bases.Count == 0
            ? PyPiJsonMetadata.Empty
            : await TryFetchPyPiJsonMetadataAsync(bases[0], parsed.PurlName, parsed.Version, file, ct);

        // Prefer the simple-index #sha256= fragment (it's already verified against the bytes
        // by UpstreamClient on the way in). Fall back to the JSON API's digests.sha256 when
        // upstream's simple page didn't carry a fragment.
        string? integrityValue = upstreamSha256 ?? jsonMeta.Sha256Hex;
        string? integrityAlgo = integrityValue is not null ? "sha256" : null;

        // deepcode ignore LogForging: file is a PyPI filename parsed and validated by PyPiFilename.TryParse before this method is called; Serilog structured rendering prevents log injection.
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
            BlockDeprecatedMode: gate.Settings.BlockDeprecated,
            BlockMaliciousMode: gate.Settings.BlockMalicious,
            BlockKevMode: gate.Settings.BlockKev,
            MaxEpssTolerance: gate.Settings.MaxEpssTolerance), ct);
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
            string url = $"{upstreamBase}/pypi/{purlName}/{version}/json";
            // Routes through single-flighted metadata fetch so an artefact stampede
            // doesn't also stampede this endpoint.
            var resp = await _upstream.GetOrFetchMetadataAsync(url, ct);
            if (!resp.IsSuccessStatusCode)
            {
                return PyPiJsonMetadata.Empty;
            }

            using var doc = JsonDocument.Parse(resp.Body);
            if (!doc.RootElement.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
            {
                return PyPiJsonMetadata.Empty;
            }

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
        string? iso = entry.TryGetProperty("upload_time_iso_8601", out var t) ? t.GetString() : null;
        if (DateTimeOffset.TryParse(iso, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
        {
            publishedAt = ts;
        }

        string? sha256 = null;
        if (entry.TryGetProperty("digests", out var digests)
            && digests.ValueKind == JsonValueKind.Object
            && digests.TryGetProperty("sha256", out var d)
            && d.ValueKind == JsonValueKind.String)
        {
            sha256 = d.GetString()?.ToLowerInvariant();
        }

        string? deprecated = LicenseExtractor.FromPyPiJsonFile(entry).Deprecated;

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
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            string html = resp.BodyAsString();
            // Group 1 = URL up to but not including the fragment; group 3 = the hex SHA-256
            // when a #sha256=... fragment is present. Older mirrors / non-PEP-503 indices
            // may omit the fragment; in that case group 3 is empty and we fall through with
            // a null hash (the request still succeeds, just without first-fetch verification).
            var match = Regex.Match(
                html,
                $@"href=""(https?://[^""#]*/{Regex.Escape(filename)})(#sha256=([0-9a-fA-F]{{64}}))?""",
                RegexOptions.None, RegexTimeout);
            if (!match.Success)
            {
                return null;
            }

            string url = match.Groups[1].Value;
            string? sha = match.Groups[3].Success ? match.Groups[3].Value.ToLowerInvariant() : null;
            return (url, sha);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or RegexMatchTimeoutException)
        {
            _logger.LogWarning(
                ex,
                "Upstream simple-index fetch failed for {PackageName}: {ExceptionType} trace={TraceId}",
                pkgName,
                ex.GetType().Name,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
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
        string orgId = CurrentTenantId();

        var authError = await CheckUploadAuthAsync(orgId, ct);
        if (authError is not null)
        {
            return authError;
        }

        var token = (await Request.ResolveTokenAsync(_tokens, ct))!;

        if (!Request.HasFormContentType)
        {
            return BadRequest("Expected multipart/form-data.");
        }

        var form = await Request.ReadFormAsync(ct);

        var (name, version, sha256Digest, file, formError) = ValidateUploadForm(form);
        if (formError is not null)
        {
            return formError;
        }

        var pathError = ValidatePathSafety(name!, version!, file!.FileName);
        if (pathError is not null)
        {
            return pathError;
        }

        var claimReject = await _publishGate.CheckAsync(orgId, "pypi", name!.ToLowerInvariant(), ct);
        if (claimReject is not null)
        {
            return claimReject;
        }

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms, ct);
        byte[] fileBytes = ms.ToArray();

        var sizeError = await CheckPyPiUploadSizeAsync(orgId, fileBytes.Length, ct);
        if (sizeError is not null)
        {
            return sizeError;
        }

        var hashError = VerifyDigests(fileBytes, sha256Digest!, form["md5_digest"].FirstOrDefault(), out string? actualSha256);
        if (hashError is not null)
        {
            return hashError;
        }

        var fileTypeError = ValidateFileTypeContents(form["filetype"].FirstOrDefault() ?? "", fileBytes, name!, file.FileName);
        return fileTypeError is not null
            ? fileTypeError
            : await StoreAndRecordUploadAsync(
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
        {
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = ":action must be 'file_upload'", Status = 422 }));
        }

        string? metadataVersion = form["metadata_version"].FirstOrDefault();
        if (!ValidMetadataVersions.Contains(metadataVersion ?? ""))
        {
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Invalid metadata_version: {metadataVersion}", Status = 422 }));
        }

        string name = form["name"].FirstOrDefault() ?? "";
        string version = form["version"].FirstOrDefault() ?? "";
        string sha256Digest = form["sha256_digest"].FirstOrDefault() ?? "";

        if (!Pep508NameRegex().IsMatch(name))
        {
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Invalid package name: {name}", Status = 422 }));
        }

        if (!Pep440VersionRegex().IsMatch(version))
        {
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = $"Invalid version: {version}", Status = 422 }));
        }

        if (string.IsNullOrEmpty(sha256Digest))
        {
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = "sha256_digest is required", Status = 422 }));
        }

        var file = form.Files.GetFile("content");
        if (file is null)
        {
            return (null, null, null, null, UnprocessableEntity(new ProblemDetails { Detail = "File content is required", Status = 422 }));
        }

        return (name, version, sha256Digest, file, null);
    }

    private UnprocessableEntityObjectResult? ValidatePathSafety(string name, string version, string filename)
    {
        foreach (var (value, kind) in new[] { (name, "name"), (version, "version"), (filename, "filename") })
        {
            var check = PathSafeValidator.Validate(value, kind);
            if (!check.IsValid)
            {
                return UnprocessableEntity(new ProblemDetails { Detail = check.Message, Status = 422 });
            }
        }
        return null;
    }

    private async Task<IActionResult?> CheckPyPiUploadSizeAsync(string orgId, long size, CancellationToken ct)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        long limit = await _orgs.GetUploadLimitAsync(settings, "pypi", ct);
        return size > limit
            ? StatusCode(413, new ProblemDetails { Detail = "Upload exceeds size limit.", Status = 413 })
            : null;
    }

    private UnprocessableEntityObjectResult? VerifyDigests(byte[] fileBytes, string sha256Digest, string? md5Digest, out string actualSha256)
    {
        actualSha256 = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();
        if (!string.Equals(actualSha256, sha256Digest, StringComparison.OrdinalIgnoreCase))
        {
            return UnprocessableEntity(new ProblemDetails { Detail = "SHA-256 digest mismatch.", Status = 422 });
        }

        if (string.IsNullOrEmpty(md5Digest))
        {
            return null;
        }

        string actualMd5 = Convert.ToHexString(MD5.HashData(fileBytes)).ToLowerInvariant();
        return string.Equals(actualMd5, md5Digest, StringComparison.OrdinalIgnoreCase)
            ? null
            : UnprocessableEntity(new ProblemDetails { Detail = "MD5 digest mismatch.", Status = 422 });
    }

    private UnprocessableEntityObjectResult? ValidateFileTypeContents(string fileType, byte[] fileBytes, string name, string filename)
    {
        var result = fileType switch
        {
            "bdist_wheel" => ValidateWheel(fileBytes),
            "bdist_egg" => ValidateEgg(fileBytes),
            "sdist" => ValidateSdist(name, filename),
            _ => ValidationResult.Ok(),
        };
        return result.IsValid ? null : UnprocessableEntity(new ProblemDetails { Detail = result.Message, Status = 422 });
    }

    private async Task<IActionResult> StoreAndRecordUploadAsync(
        PyPiUpload upload, ProxyTenantContext tenant, CancellationToken ct)
    {
        string purlName = NormalizePyPiName(upload.Name);
        string purl = PurlNormalizer.PyPi(upload.Name, upload.Version);

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
        {
            return MapPyPiPublishRejection(rej, upload.Version);
        }

        // Format-specific post-publish: license info comes from the wheel METADATA / sdist
        // PKG-INFO. Stays here because the extractor is PyPI-only. Push path holds the
        // upload bytes in memory — an upload-validation concern, out of scope here —
        // so we wrap in a MemoryStream for the unified extractor.
        string versionId = ((Dependably.Infrastructure.Publish.PublishResult.Accepted)result).VersionId;
        var extracted = LicenseExtractor.FromPyPiPackageBytes(
            new MemoryStream(upload.FileBytes, writable: false), upload.Filename);
        if (extracted.Spdx.Count > 0)
        {
            await _licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);
        }

        // Evict the cached simple index so the newly-published version appears immediately.
        _cache.Remove(SimpleIndexCacheKey(tenant.OrgId, NormalizePyPiName(upload.Name)));

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
            bool hasMetadata = zip.Entries.Any(e =>
                e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
            return !hasMetadata ? ValidationResult.Fail("content", "Wheel is missing .dist-info/METADATA") : ValidationResult.Ok();
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
            bool hasMetadata = zip.Entries.Any(e =>
                e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
            return !hasMetadata ? ValidationResult.Fail("content", "Egg is missing EGG-INFO/PKG-INFO") : ValidationResult.Ok();
        }
        catch
        {
            return ValidationResult.Fail("content", "Egg is not a valid ZIP file");
        }
    }

    private static ValidationResult ValidateSdist(string name, string filename)
    {
        if (!filename.EndsWith(".tar.gz") && !filename.EndsWith(".zip"))
        {
            return ValidationResult.Fail("filename", "sdist must end in .tar.gz or .zip");
        }

        // Basic check: filename should contain name-version
        string normalized = Regex.Replace(name, @"[-_.]+", "-", RegexOptions.None, RegexTimeout).ToLowerInvariant();
        return !filename.StartsWith(normalized, StringComparison.OrdinalIgnoreCase)
            ? ValidationResult.Fail("filename", "Filename does not match declared package name")
            : ValidationResult.Ok();
    }

    /// <summary>
    /// Returns a host-relative URL for a PEP 503 href. Tenancy is host-resolved, so paths
    /// are always root-relative with no org prefix.
    /// </summary>
    private static string OrgPath(string rest) => "/" + rest;

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

    private static string NormalizePyPiName(string name)
        => Regex.Replace(name, @"[-_.]+", "-", RegexOptions.None, RegexTimeout).ToLowerInvariant();

    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");

    private static string ComputeETag(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..16].ToLowerInvariant() + "\"";
    }
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
    ReservedNamespaceService ReservedNamespaces,
    Dependably.Storage.ProxyFetchService ProxyFetch,
    UpstreamRegistryResolver Registries,
    ILogger<PyPiController> Logger,
    IMemoryCache Cache);
