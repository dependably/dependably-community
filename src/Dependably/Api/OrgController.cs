using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

/// <summary>
/// Slim tenant-scoped controller for the resources that didn't fit a dedicated controller:
/// packages, stats, and the setup-snippet generator. Most tenant-scoped surface has been
/// split out (#61) into <see cref="OrgSettingsController"/>, <see cref="OrgTokensController"/>,
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
    private readonly AuditRepository _audit;
    private readonly OrgAccessGuard _guard;
    private readonly IBlobStore _blobs;
    private readonly LicenseRepository _licenses;
    private readonly VulnerabilityRepository _vulns;
    private readonly IPublicUrlBuilder _urls;

    public OrgController(OrgControllerServices svc)
    {
        _orgs = svc.Orgs;
        _packages = svc.Packages;
        _packageAnalytics = svc.PackageAnalytics;
        _audit = svc.Audit;
        _guard = svc.Guard;
        _blobs = svc.Blobs;
        _licenses = svc.Licenses;
        _vulns = svc.Vulns;
        _urls = svc.Urls;
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
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        limit  = Math.Clamp(limit, 1, 200);
        page   = Math.Max(page, 1);
        var offset = (page - 1) * limit;

        var (items, total) = await _packages.ListPaginatedAsync(
            new PackageListQuery(orgId, limit, offset, ecosystem, search, sortBy, sortDir), ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>GET /api/v1/orgs/{org}/packages/{ecosystem}/{name}</summary>
    [HttpGet("api/v1/packages/{ecosystem}/{name}")]
    public async Task<IActionResult> GetPackage(string ecosystem, string name, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null) return NotFound();

        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        var licenseMap = await _licenses.GetSpdxForVersionsAsync(versions.Select(v => v.Id), ct);
        var scoreMap = await _vulns.GetMaxScoresForVersionsAsync(versions.Select(v => v.Id), ct);
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var tolerance = settings?.MaxOsvScoreTolerance ?? 10.0;

        var versionsWithLicenses = versions.Select(v => {
            scoreMap.TryGetValue(v.Id, out var maxScore);
            var hasMax = scoreMap.ContainsKey(v.Id);
            var status = ComputeVersionStatus(v, hasMax ? maxScore : (double?)null, tolerance);
            return new {
                v.Id, v.PackageId, v.Version, v.Purl, v.BlobKey,
                v.SizeBytes, v.ChecksumSha256, v.ChecksumSha1, v.Yanked, v.YankReason,
                v.FirstFetch, v.CreatedAt, v.VulnCheckedAt, v.PublishedAt,
                v.ManualBlockState,
                v.Deprecated, v.Origin,
                v.UpstreamIntegrityValue, v.UpstreamIntegrityAlgorithm,
                MaxOsvScore = hasMax ? maxScore : (double?)null,
                Status = status,
                Licenses = licenseMap[v.Id].ToArray()
            };
        });
        return Ok(new { package = pkg, versions = versionsWithLicenses });
    }

    private static string ComputeVersionStatus(PackageVersion v, double? maxScore, double tolerance)
    {
        if (v.ManualBlockState == "blocked") return "blocked";
        var autoBlocked = v.VulnCheckedAt is not null && maxScore.HasValue && maxScore.Value > tolerance;
        if (v.ManualBlockState == "allowed") return autoBlocked ? "allowed" : "clean";
        if (autoBlocked) return "blocked";
        if (v.VulnCheckedAt is null) return "unscanned";
        return "clean";
    }

    /// <summary>DELETE /api/v1/orgs/{org}/packages/{ecosystem}/{name}/{version}</summary>
    [HttpDelete("api/v1/packages/{ecosystem}/{name}/{version}")]
    public async Task<IActionResult> DeleteVersion(string ecosystem, string name, string version, CancellationToken ct)
    {
        // Per-ecosystem yank capability — admin/owner role sets enumerate yank:* leaves.
        // Unknown ecosystem names fail the lookup below, but we 404 here so an invalid path
        // doesn't read as 403. Authorisation outcomes for *known* ecosystems remain semantic:
        // missing capability → 403 (via AuthorizeCapAsync), missing package/version → 404.
        var yankCap = ecosystem switch
        {
            "npm"   => Capabilities.YankNpm,
            "pypi"  => Capabilities.YankPypi,
            "nuget" => Capabilities.YankNuget,
            "maven" => Capabilities.YankMaven,
            "rpm"   => Capabilities.YankRpm,
            "oci"   => Capabilities.YankOci,
            _ => null
        };
        if (yankCap is null) return NotFound();
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, yankCap, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, AsPurlName(ecosystem, name), ct);
        if (pkg is null) return NotFound();

        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null) return NotFound();

        await _blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        await _packages.DeleteVersionAsync(ver.Id, ct);
        // GC the parent row when this was the last version. Orphan packages rows otherwise
        // accumulate across delete/republish cycles and cause "empty package" UI cards.
        // Atomic NOT EXISTS guard handles the race against a concurrent publish.
        await _packages.DeletePackageIfEmptyAsync(pkg.Id, ct);

        // Activity is the right sink for a per-version operator action — audit_log is for
        // tenant-level config/security events. Never dual-write the same event to both.
        await _audit.LogActivityAsync(orgId, ecosystem, ver.Purl, "delete", GetUserId(),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/stats</summary>
    [HttpGet("api/v1/stats")]
    public async Task<IActionResult> GetStats(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var stats = await _packageAnalytics.GetOrgStatsAsync(orgId, ct);
        return Ok(stats);
    }

    // ── Setup snippets ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/setup/{ecosystem}</summary>
    [HttpGet("api/v1/setup/{ecosystem}")]
    public async Task<IActionResult> GetSetup(string ecosystem, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        // Tenant-implicit URLs: every request is already on the tenant's host (multi mode) or
        // the single-tenant install. Snippets use the request's host directly.
        var baseUrl = _urls.BaseUrl(HttpContext);
        var slug = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantSlug ?? "";

        var snippet = ecosystem switch
        {
            "pypi"  => GeneratePyPiSnippet(baseUrl, slug, settings),
            "npm"   => GenerateNpmSnippet(baseUrl, slug, settings),
            "nuget" => GenerateNuGetSnippet(baseUrl, slug, settings),
            "maven" => GenerateMavenSnippet(baseUrl, slug, settings),
            "rpm"   => GenerateRpmSnippet(baseUrl, slug, settings),
            "oci"   => GenerateOciSnippet(baseUrl, slug, settings),
            _ => null
        };

        if (snippet is null) return NotFound();
        return Ok(new { ecosystem, snippet });
    }

    // Snippet generators emit tenant-implicit URLs (host-relative). The slug parameter is
    // unused at the URL level today but kept so the future-multi-mode form `slug.apex/simple/`
    // could be reconstructed if needed; the request's host already carries the tenant.
    private static string GeneratePyPiSnippet(string baseUrl, string slug, OrgSettings? s)
    {
        _ = slug;
        var uri = new Uri(baseUrl);
        var trustedHost = uri.Scheme == "http" ? $" --trusted-host {uri.Host}" : "";
        var indexUrl = $"{baseUrl}/simple/";
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
        var host = new Uri(baseUrl).Host;
        return $"""
            # Docker / OCI — login, pull, push
            docker login {host}
            docker pull  {host}/<image>:<tag>
            docker push  {host}/<image>:<tag>
            # Max upload (per blob): {s?.MaxUploadBytesOci ?? s?.MaxUploadBytes ?? 0} bytes
            """;
    }

    private static string AsPurlName(string ecosystem, string name) =>
        ecosystem == "npm" ? NpmRouteHelper.DecodeRouteName(name) : name;
}
