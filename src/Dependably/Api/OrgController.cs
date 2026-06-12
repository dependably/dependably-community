using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Api;

/// <summary>
/// Slim tenant-scoped controller for the resources that didn't fit a dedicated controller:
/// packages, stats, and the setup-snippet generator. Most tenant-scoped surface has been
/// split out into <see cref="OrgSettingsController"/>, <see cref="OrgTokensController"/>,
/// <see cref="OrgInvitesController"/>, <see cref="OrgUsersController"/>,
/// <see cref="OrgListsController"/>, <see cref="OrgAuditController"/>, and
/// <c>OrgAuthConfigController</c>.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgController : OrgScopedControllerBase
{
    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly PackageAnalyticsRepository _packageAnalytics;
    private readonly StatsSnapshotRepository _statsSnapshots;
    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;
    private readonly IBlobStore _blobs;
    private readonly TieredBlobStorage _blobStorage;
    private readonly LicenseRepository _licenses;
    private readonly VulnerabilityRepository _vulns;
    private readonly IPublicUrlBuilder _urls;
    private readonly ILogger<OrgController> _logger;
    private readonly IMemoryCache _cache;

    public OrgController(OrgControllerServices svc)
    {
        _orgs = svc.Orgs;
        _packages = svc.Packages;
        _packageAnalytics = svc.PackageAnalytics;
        _statsSnapshots = svc.StatsSnapshots;
        _audit = svc.Audit;
        _guard = svc.Guard;
        _blobs = svc.Blobs;
        _blobStorage = svc.BlobStorage;
        _licenses = svc.Licenses;
        _vulns = svc.Vulns;
        _urls = svc.Urls;
        _logger = svc.Logger;
        _cache = svc.Cache;
    }

    // Org CRUD lives on SystemController (/api/v1/system/tenants). Tenant users have no
    // authority to list, create, or delete orgs — those are operator concerns.

    // ── Packages ──────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/packages</summary>
    [HttpGet("api/v1/packages")]
    public async Task<IActionResult> ListPackages(
        [FromQuery] int limit = 50,
        [FromQuery] int page = 1,
        [FromQuery] string? ecosystem = null,
        [FromQuery] string? search = null,
        [FromQuery] string sortBy = "created",
        [FromQuery] string sortDir = "asc",
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        limit = Math.Clamp(limit, 1, 200);
        page = Math.Max(page, 1);
        int offset = (page - 1) * limit;

        var (items, total) = await _packages.ListPaginatedAsync(
            new PackageListQuery(orgId, limit, offset, ecosystem, search, sortBy, sortDir), ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>GET /api/v1/orgs/{org}/packages/{ecosystem}/{name}</summary>
    [HttpGet("api/v1/packages/{ecosystem}/{name}")]
    public async Task<IActionResult> GetPackage(string ecosystem, string name, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var licenseMap = await _licenses.GetSpdxForVersionsAsync(versions.Select(v => v.Id), ct);
        var scoreMap = await _vulns.GetMaxScoresForVersionsAsync(versions.Select(v => v.Id), ct);
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        double tolerance = settings?.MaxOsvScoreTolerance ?? 10.0;
        string blockDeprecatedMode = settings?.BlockDeprecated ?? "off";

        var versionsWithLicenses = versions.Select(v =>
        {
            scoreMap.TryGetValue(v.Id, out double maxScore);
            bool hasMax = scoreMap.ContainsKey(v.Id);
            string status = ComputeVersionStatus(v, hasMax ? maxScore : (double?)null, tolerance, blockDeprecatedMode);
            return new
            {
                v.Id,
                v.PackageId,
                v.Version,
                v.Purl,
                v.BlobKey,
                v.SizeBytes,
                v.ChecksumSha256,
                v.ChecksumSha1,
                v.Yanked,
                v.YankReason,
                v.FirstFetch,
                v.DownloadCount,
                v.CreatedAt,
                v.VulnCheckedAt,
                v.PublishedAt,
                v.ManualBlockState,
                v.Deprecated,
                v.Origin,
                v.UpstreamIntegrityValue,
                v.UpstreamIntegrityAlgorithm,
                MaxOsvScore = hasMax ? maxScore : (double?)null,
                Status = status,
                Licenses = licenseMap[v.Id].ToArray()
            };
        });
        return Ok(new { package = pkg, versions = versionsWithLicenses });
    }

    private static string ComputeVersionStatus(PackageVersion v, double? maxScore, double tolerance, string blockDeprecatedMode = "off")
    {
        if (v.ManualBlockState == "blocked")
        {
            return "blocked";
        }
        // Only block_all denies an already-cached deprecated version; under block_new the cached
        // version keeps serving, so it surfaces as "deprecated" below. Legacy 'block' == block_all.
        if (v.Deprecated is not null && blockDeprecatedMode is "block_all" or "block")
        {
            return "blocked";
        }

        bool autoBlocked = v.VulnCheckedAt is not null && maxScore.HasValue && maxScore.Value > tolerance;
        return (v.ManualBlockState, autoBlocked) switch
        {
            ("allowed", true) => "allowed",
            ("allowed", false) => "clean",
            (_, true) => "blocked",
            _ when v.Deprecated is not null => "deprecated",
            _ when v.VulnCheckedAt is null => "unscanned",
            _ => "clean",
        };
    }

    /// <summary>DELETE /api/v1/orgs/{org}/packages/{ecosystem}/{name}/{version}</summary>
    [HttpDelete("api/v1/packages/{ecosystem}/{name}/{version}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteVersion(string ecosystem, string name, string version, CancellationToken ct)
    {
        // Per-ecosystem yank capability — admin/owner role sets enumerate yank:* leaves.
        // Unknown ecosystem names fail the lookup below, but we 404 here so an invalid path
        // doesn't read as 403. Authorisation outcomes for *known* ecosystems remain semantic:
        // missing capability → 403 (via AuthorizeCapAsync), missing package/version → 404.
        string? yankCap = ecosystem switch
        {
            "npm" => Capabilities.YankNpm,
            "pypi" => Capabilities.YankPypi,
            "nuget" => Capabilities.YankNuget,
            "maven" => Capabilities.YankMaven,
            "rpm" => Capabilities.YankRpm,
            "oci" => Capabilities.YankOci,
            _ => null
        };
        if (yankCap is null)
        {
            return NotFound();
        }

        var result = await _guard.AuthorizeCapAsync(User, HttpContext, yankCap, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null)
        {
            return NotFound();
        }

        await _blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        await _packages.DeleteVersionAsync(ver.Id, ct);
        // GC the parent row when this was the last version. Orphan packages rows otherwise
        // accumulate across delete/republish cycles and cause "empty package" UI cards.
        // Atomic NOT EXISTS guard handles the race against a concurrent publish.
        await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct);

        // Evict any cached metadata so the deleted version is not served from cache.
        switch (ecosystem)
        {
            case "npm":
                _cache.Remove($"metadata:{orgId}:npm:{pkg.Name}");
                break;
            case "pypi":
                _cache.Remove($"metadata:{orgId}:pypi:{pkg.Name}");
                break;
            case "nuget":
                string nugetId = pkg.Name.ToLowerInvariant();
                _cache.Remove($"metadata:{orgId}:nuget:{nugetId}:sv1");
                _cache.Remove($"metadata:{orgId}:nuget:{nugetId}:sv2");
                break;
        }

        // Activity is the right sink for a per-version operator action — audit_log is for
        // tenant-level config/security events. Never dual-write the same event to both.
        await _audit.LogActivityAsync(orgId, ecosystem, ver.Purl, "delete", GetUserId(),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>GET /api/v1/packages/{ecosystem}/{name}/{version}/download — stream one artifact to the UI</summary>
    [HttpGet("api/v1/packages/{ecosystem}/{name}/{version}/download")]
    public async Task<IActionResult> DownloadVersion(string ecosystem, string name, string version, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadArtifact, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(name), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null)
        {
            return NotFound();
        }

        // Route by per-version origin: proxy artifacts live on the eviction-friendly cache tier,
        // uploaded artifacts on the durable registry tier. Under split storage these are distinct
        // backends, so picking the wrong tier would 404 or serve the wrong bytes.
        var store = ver.Origin == "proxy" ? _blobStorage.Cache : _blobStorage.Registry;
        var stream = await store.GetAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        // Count the UI download the same way protocol pulls are counted, and log it as a
        // 'download' activity so it also appears on the dashboard chart — the UI is just
        // another download surface.
        await _audit.LogActivityAsync(orgId, ecosystem, ver.Purl, "download", GetUserId(),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        await _packages.IncrementDownloadCountAsync(ver.Id, ct);

        string filename = ver.BlobKey.Split('/').Last();
        return File(stream, "application/octet-stream", filename);
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/stats</summary>
    [HttpGet("api/v1/stats")]
    public async Task<IActionResult> GetStats(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();

        // Serve the pre-computed snapshot kept warm by StatsRefreshService rather than running
        // the eight live aggregate queries per request. Deserialize and return through Ok() so
        // the MVC pipeline is the single serialization authority — the cached and live paths
        // produce byte-identical shape/casing, and the read tolerates any stored casing. Cache
        // miss (new org, or before the first refresh pass) falls back to a live compute so the
        // first load is never blank.
        var snapshot = await _statsSnapshots.GetSnapshotAsync(orgId, ct);
        if (snapshot is not null)
        {
            try
            {
                var cached = System.Text.Json.JsonSerializer.Deserialize<OrgStats>(
                    snapshot.StatsJson, StatsJsonOptions);
                if (cached is not null)
                {
                    return Ok(cached);
                }
            }
            catch (System.Text.Json.JsonException ex)
            {
                // A corrupt snapshot row (truncated write, hand-edited DB, format drift) must not
                // 500 the dashboard — fall through to a live compute, which also overwrites the
                // bad row on the next refresh pass.
                _logger.LogWarning(ex,
                    "Discarding malformed stats snapshot for org {OrgId}; recomputing live. TraceId={TraceId}",
                    orgId, System.Diagnostics.Activity.Current?.TraceId);
            }
        }

        var stats = await _packageAnalytics.GetOrgStatsAsync(orgId, ct);
        return Ok(stats);
    }

    private static readonly System.Text.Json.JsonSerializerOptions StatsJsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    // ── Setup snippets ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/setup/{ecosystem}</summary>
    [HttpGet("api/v1/setup/{ecosystem}")]
    public async Task<IActionResult> GetSetup(string ecosystem, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        // Tenant-implicit URLs: every request is already on the tenant's host (multi mode) or
        // the single-tenant install. Snippets use the request's host directly.
        string baseUrl = _urls.BaseUrl(HttpContext);
        string slug = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantSlug ?? "";

        string? snippet = ecosystem switch
        {
            "pypi" => GeneratePyPiSnippet(baseUrl, slug, settings),
            "npm" => GenerateNpmSnippet(baseUrl, slug, settings),
            "nuget" => GenerateNuGetSnippet(baseUrl, slug, settings),
            "maven" => GenerateMavenSnippet(baseUrl, slug, settings),
            "rpm" => GenerateRpmSnippet(baseUrl, slug, settings),
            "oci" => GenerateOciSnippet(baseUrl, slug, settings),
            _ => null
        };

        return snippet is null ? NotFound() : Ok(new { ecosystem, snippet });
    }

    // Snippet generators emit tenant-implicit URLs (host-relative). The slug parameter is
    // unused at the URL level today but kept so the future-multi-mode form `slug.apex/simple/`
    // could be reconstructed if needed; the request's host already carries the tenant.
    private static string GeneratePyPiSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        string trustedHost = uri.Scheme == "http" ? $" --trusted-host {uri.Host}" : "";
        string indexUrl = $"{baseUrl}/simple/";
        return $"""
            # pip.conf / pyproject.toml
            [global]
            index-url = {indexUrl}

            # One-liner install example:
            pip install <package>==<version> --index-url {indexUrl}{trustedHost} --no-deps
            # Max upload: {s?.MaxUploadBytesPyPi ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    private static string GenerateNpmSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        return $"""
            # .npmrc
            registry={baseUrl}/npm/
            # Max upload: {s?.MaxUploadBytesNpm ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    private static string GenerateNuGetSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        return $"""
            <!-- nuget.config -->
            <configuration>
              <packageSources>
                <add key="dependably" value="{baseUrl}/nuget/v3/index.json" />
              </packageSources>
            </configuration>
            <!-- Max upload: {s?.MaxUploadBytesNuGet ?? s?.MaxUploadBytes ?? 0} bytes -->
            """;
    }

    // Maven snippet bundles both publish (distributionManagement, used by `mvn deploy`) and
    // consume (repositories, used at resolution time). A registry is no use if onboarding only
    // covers one half of the workflow.
    private static string GenerateMavenSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        return $"""
            <!-- ~/.m2/settings.xml — publish + consume -->
            <settings>
              <servers>
                <server>
                  <id>dependably</id>
                  <username>your-username</username>
                  <password>your-token</password>
                </server>
              </servers>
              <profiles>
                <profile>
                  <id>dependably</id>
                  <repositories>
                    <repository>
                      <id>dependably</id>
                      <url>{baseUrl}/maven/</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
              <activeProfiles><activeProfile>dependably</activeProfile></activeProfiles>
            </settings>

            <!-- In your project pom.xml, for `mvn deploy`: -->
            <distributionManagement>
              <repository>
                <id>dependably</id>
                <url>{baseUrl}/maven/</url>
              </repository>
            </distributionManagement>
            <!-- Max upload: {s?.MaxUploadBytesMaven ?? s?.MaxUploadBytes ?? 0} bytes -->
            """;
    }

    // RPM .repo file pointing at the yum/dnf-compatible directory layout, plus a curl one-liner
    // for the push side. gpgcheck=0 by default — operators turn it on once signing is wired.
    private static string GenerateRpmSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        return $"""
            # /etc/yum.repos.d/dependably.repo
            [dependably]
            name=dependably
            baseurl={baseUrl}/rpm/
            enabled=1
            gpgcheck=0

            # Push an RPM:
            curl -u user:<token> --upload-file pkg.rpm {baseUrl}/rpm/upload
            # Max upload: {s?.MaxUploadBytesRpm ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    private static string GenerateOciSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        string host = new Uri(baseUrl).Host;
        return $"""
            # Docker / OCI — login, pull, push
            docker login {host}
            docker pull  {host}/<image>:<tag>
            docker push  {host}/<image>:<tag>
            # Max upload (per blob): {s?.MaxUploadBytesOci ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    // The UI encodes '/' as %2F for every ecosystem (npm scopes, OCI image
    // namespaces like library/ubuntu, etc.); ASP.NET keeps %2F encoded in route
    // values to prevent path splitting, so decode it back before lookup.
    private static string AsPurlName(string name) =>
        NpmRouteHelper.DecodeRouteName(name);
}
