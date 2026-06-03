using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
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
    private readonly BlockGateService _blockGate;
    private readonly LicenseRepository _licenses;
    private readonly IPublicUrlBuilder _urls;
    private readonly PublishGate _publishGate;
    private readonly Dependably.Infrastructure.Publish.IPackagePublishService _publish;
    private readonly ClaimResolver _claimResolver;
    private readonly Dependably.Storage.ProxyFetchService _proxyFetch;
    private readonly ILogger<NuGetController> _logger;
    private readonly UpstreamRegistryResolver _registries;

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
        _blockGate = svc.BlockGate;
        _licenses = svc.Licenses;
        _urls = svc.Urls;
        _publishGate = svc.PublishGate;
        _publish = svc.Publish;
        _claimResolver = svc.ClaimResolver;
        _proxyFetch = svc.ProxyFetch;
        _logger = svc.Logger;
        _registries = svc.Registries;
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

        // Advertise both registration resource types so SemVer 2-aware clients pick the
        // semver2 base URL (which we serve from the registration5-{,gz-}semver2 alias),
        // while older clients keep using the unversioned RegistrationsBaseUrl.
        return new JsonResult(new
        {
            version = "3.0.0",
            resources = new[]
            {
                R($"{baseUrl}/query",                       "SearchQueryService"),
                R($"{baseUrl}/registration",                "RegistrationsBaseUrl"),
                R($"{baseUrl}/registration5-gz-semver2",    "RegistrationsBaseUrl/3.6.0"),
                R($"{baseUrl}/flatcontainer",               "PackageBaseAddress/3.0.0"),
                R($"{baseUrl}/publish",                     "PackagePublish/2.0.0"),
                R($"{baseUrl}/symbols",                     "SymbolPackagePublish/4.9.0")
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
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
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

    /// <summary>GET /o/{org}/nuget/registration/{id}/ — registration index (SemVer 1, unversioned alias)</summary>
    // SemVer 1 routes — the unversioned path is the canonical one we advertise in the service
    // index. The "5-semver1" / "5-gz-semver1" aliases exist for tooling that hardcodes the
    // upstream URL shape (xunit.runner.visualstudio probes these directly regardless of the
    // service index). The "-gz-" variant is by convention only; HttpClient handles
    // Content-Encoding transparently, so the wire format is identical to the uncompressed one.
    // NuGet V3 clients build the registration index URL as `{RegistrationsBaseUrl}/{lowerId}/index.json`
    // (the service index advertises only the base). The `index.json` literal MUST be a routed segment
    // — `{id}/` alone matches `.../{id}/` but not `.../{id}/index.json`, so every real client (incl.
    // `dotnet restore` / `dotnet tool restore`) 404s on the registration lookup. Both forms are kept:
    // `index.json` for clients, the bare `{id}/` for direct/manual probes.
    [HttpGet("/nuget/registration/{id}/")]
    [HttpGet("/nuget/registration/{id}/index.json")]
    [HttpGet("/nuget/registration5-semver1/{id}/")]
    [HttpGet("/nuget/registration5-semver1/{id}/index.json")]
    [HttpGet("/nuget/registration5-gz-semver1/{id}/")]
    [HttpGet("/nuget/registration5-gz-semver1/{id}/index.json")]
    public Task<IActionResult> RegistrationIndex(string id, CancellationToken ct)
        => RegistrationIndexCoreAsync(id, semVer2: false, ct);

    /// <summary>GET /o/{org}/nuget/registration5-{,gz-}semver2/{id}/index.json — SemVer 2 registration</summary>
    [HttpGet("/nuget/registration5-semver2/{id}/")]
    [HttpGet("/nuget/registration5-semver2/{id}/index.json")]
    [HttpGet("/nuget/registration5-gz-semver2/{id}/")]
    [HttpGet("/nuget/registration5-gz-semver2/{id}/index.json")]
    public Task<IActionResult> RegistrationIndexSemVer2(string id, CancellationToken ct)
        => RegistrationIndexCoreAsync(id, semVer2: true, ct);

    // Per-version registration leaf: `{RegistrationsBaseUrl}/{lowerId}/{version}.json`. The index we
    // serve is inlined (catalogEntry embedded in the page), so clients never need to follow the leaf
    // @id today — but the index emits these leaf URLs (BuildLocalRegistration/BuildLocalLeaf) and a
    // paged registry (or a client that fetches leaves directly) would 404 without a route here.
    // The literal `index.json` route out-ranks `{version}.json`, so the index path is unaffected.
    [HttpGet("/nuget/registration/{id}/{version}.json")]
    [HttpGet("/nuget/registration5-semver1/{id}/{version}.json")]
    [HttpGet("/nuget/registration5-gz-semver1/{id}/{version}.json")]
    public Task<IActionResult> RegistrationLeaf(string id, string version, CancellationToken ct)
        => RegistrationLeafCoreAsync(id, version, semVer2: false, ct);

    /// <summary>GET /o/{org}/nuget/registration5-{,gz-}semver2/{id}/{version}.json — SemVer 2 leaf</summary>
    [HttpGet("/nuget/registration5-semver2/{id}/{version}.json")]
    [HttpGet("/nuget/registration5-gz-semver2/{id}/{version}.json")]
    public Task<IActionResult> RegistrationLeafSemVer2(string id, string version, CancellationToken ct)
        => RegistrationLeafCoreAsync(id, version, semVer2: true, ct);

    private async Task<IActionResult> RegistrationLeafCoreAsync(string id, string version, bool semVer2, CancellationToken ct)
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

        var normalizedId = id.ToLowerInvariant();
        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // A version with a local row (uploaded or proxy-cached) is served from our own data — its
        // packageContent points at our flatcontainer, matching per-version download routing.
        if (pkg is not null)
        {
            var pkgVersion = await _packages.GetVersionAsync(pkg.Id, NormalizeNuGetVersion(version), ct);
            if (pkgVersion is not null && !pkgVersion.Yanked)
                return BuildLocalLeafResponse(normalizedId, pkg.Name, pkgVersion.Version);
        }

        // Otherwise the version lives upstream — proxy its leaf when passthrough + claims allow.
        if (settings.ProxyPassthroughEffective
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct))
        {
            return await ProxyRegistrationLeafAsync(orgId, normalizedId, version, semVer2, ct);
        }

        return NotFound();
    }

    private JsonResult BuildLocalLeafResponse(string normalizedId, string pkgName, string version)
    {
        var baseUrl = BaseUrl();
        var packageContent = $"{baseUrl}/flatcontainer/{normalizedId}/{version}/{normalizedId}.{version}.nupkg";
        return new JsonResult(new
        {
            @id = $"{baseUrl}/registration/{normalizedId}/{version}.json",
            @type = "Package",
            catalogEntry = new
            {
                id = pkgName,
                version,
                listed = true,
                packageContent
            },
            listed = true,
            packageContent,
            registration = $"{baseUrl}/registration/{normalizedId}/index.json"
        });
    }

    private async Task<IActionResult> ProxyRegistrationLeafAsync(string orgId, string normalizedId, string version, bool semVer2, CancellationToken ct)
    {
        var variant = semVer2 ? "registration5-gz-semver2" : "registration5-semver1";
        // Walk the org's configured upstreams in priority order; the first that answers wins.
        // No configured upstream ⇒ proxying is disabled for nuget, so the loop is skipped and
        // the leaf 404s.
        var bases = await _registries.ResolveAsync(orgId, "nuget", ct);
        foreach (var upstreamBase in bases)
        {
            var upstreamUrl = $"{upstreamBase}/{variant}/{normalizedId}/{version.ToLowerInvariant()}.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                var resp = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, linkedCts.Token);
                if (resp.IsSuccessStatusCode)
                    return Content(resp.BodyAsString(), "application/json");
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                _logger.LogWarning("NuGet upstream registration leaf fetch failed: {Status} for {Url}", resp.StatusCode, upstreamUrl);
            }
            catch (Exception ex)
            {
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                _logger.LogWarning(ex, "NuGet upstream registration leaf fetch threw for {Url}", upstreamUrl);
            }
        }
        return NotFound();
    }

    private async Task<IActionResult> RegistrationIndexCoreAsync(string id, bool semVer2, CancellationToken ct)
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

        var normalizedId = id.ToLowerInvariant();
        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // Always merge upstream + local versions when passthrough + claims allow. An existing
        // local pkg is just a namespace marker, not a signal to suppress upstream — uploading
        // a private prerelease must not delete the public version line from the listing, or
        // downstream packages pinning ">= <stable>" of the same name fail NU1103. Mirrors
        // FlatcontainerVersions and PyPi's PackageIndex.
        var passthroughAllowed = settings.ProxyPassthroughEffective
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct);

        if (passthroughAllowed)
            return await ProxyMergedRegistrationAsync(orgId, id, pkg, semVer2, ct);

        // Passthrough disabled or claim-local — local-only.
        if (pkg is null) return NotFound();
        var versions = await _packages.GetVersionsAsync(pkg.Id, ct);
        return BuildLocalRegistration(id, pkg, versions);
    }

    private JsonResult BuildLocalRegistration(string id, Package pkg, IReadOnlyList<PackageVersion> versions)
    {
        var normalizedId = id.ToLowerInvariant();
        var baseUrl = BaseUrl();
        var leaves = versions.Where(v => !v.Yanked).Select(v => new
        {
            @id = $"{baseUrl}/registration/{normalizedId}/{v.Version}.json",
            catalogEntry = new
            {
                id = pkg.Name,
                version = v.Version,
                listed = true,
                packageContent = $"{baseUrl}/flatcontainer/{normalizedId}/{v.Version}/{normalizedId}.{v.Version}.nupkg"
            }
        }).ToList();

        return new JsonResult(new
        {
            @id = $"{baseUrl}/registration/{normalizedId}/",
            items = new[]
            {
                new
                {
                    @id = $"{baseUrl}/registration/{normalizedId}/index.json",
                    items = leaves
                }
            }
        });
    }

    private async Task<IActionResult> ProxyMergedRegistrationAsync(string orgId, string id, Package? pkg, bool semVer2, CancellationToken ct)
    {
        var normalizedId = id.ToLowerInvariant();
        // semver1 excludes SemVer-2 build metadata (+suffix); semver2 is the superset. Pick the
        // upstream variant that matches what the client asked for. api.nuget.org publishes
        // -semver1 uncompressed but only -gz-semver2 for the SemVer 2 superset (the
        // registration5-semver2 path returns 404); HttpClient's AutomaticDecompression handles
        // the gzip transparently.
        var variant = semVer2 ? "registration5-gz-semver2" : "registration5-semver1";

        // Walk the org's configured upstreams in priority order; the first that answers wins.
        // No configured upstream ⇒ proxying is disabled for nuget, so the loop is skipped and
        // we fall through to local-only below.
        var bases = await _registries.ResolveAsync(orgId, "nuget", ct);
        string? upstreamJson = null;
        foreach (var upstreamBase in bases)
        {
            var upstreamUrl = $"{upstreamBase}/{variant}/{normalizedId}/index.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                // Single-flight registration fetch.
                var resp = await _upstream.GetOrFetchMetadataAsync(upstreamUrl, linkedCts.Token);
                if (resp.IsSuccessStatusCode)
                {
                    upstreamJson = resp.BodyAsString();
                    break;
                }
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                _logger.LogWarning("NuGet upstream registration fetch failed: {Status} for {Url}", resp.StatusCode, upstreamUrl);
            }
            catch (Exception ex)
            {
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                _logger.LogWarning(ex, "NuGet upstream registration fetch threw for {Url}", upstreamUrl);
            }
        }

        var localVersions = pkg is null
            ? Array.Empty<PackageVersion>() as IReadOnlyList<PackageVersion>
            : await _packages.GetVersionsAsync(pkg.Id, ct);

        if (upstreamJson is null)
        {
            if (pkg is null || localVersions.Count == 0) return NotFound();
            return BuildLocalRegistration(id, pkg, localVersions);
        }

        if (pkg is null || localVersions.Count == 0)
            return Content(upstreamJson, "application/json");

        var merged = MergeLocalIntoUpstreamRegistration(upstreamJson, localVersions, pkg, id);
        return Content(merged, "application/json");
    }

    // Splice local-only versions into upstream registration JSON as an extra CatalogPage.
    // Dedupes by version against the upstream catalog entries already present so a name with
    // a privately uploaded build of an upstream version doesn't appear twice. Public so unit
    // tests can verify the splice without spinning up the controller.
    internal static string MergeLocalIntoUpstreamRegistration(
        string upstreamJson, IReadOnlyList<PackageVersion> localVersions, Package pkg, string id)
    {
        var normalizedId = id.ToLowerInvariant();
        JsonObject? root;
        try { root = JsonNode.Parse(upstreamJson) as JsonObject; }
        catch (JsonException) { return upstreamJson; }
        if (root is null) return upstreamJson;

        var upstreamVersionSet = CollectUpstreamVersions(root);
        var localOnly = localVersions
            .Where(v => !v.Yanked && !upstreamVersionSet.Contains(v.Version))
            .ToList();
        if (localOnly.Count == 0) return upstreamJson;

        var localPage = BuildLocalPage(localOnly, normalizedId, pkg.Name);
        AppendPage(root, localPage);
        return root.ToJsonString();
    }

    private static HashSet<string> CollectUpstreamVersions(JsonObject root)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (root["items"] is not JsonArray pages) return set;
        var entries = pages
            .OfType<JsonObject>()
            .SelectMany(p => (p["items"] as JsonArray)?.OfType<JsonObject>() ?? []);
        foreach (var entry in entries)
        {
            var v = entry["catalogEntry"]?["version"]?.GetValue<string>();
            if (v is not null) set.Add(v);
        }
        return set;
    }

    // BaseUrl isn't available in a static context — leaves reference our own registration/
    // flatcontainer at relative paths. NuGet clients combine these with the service-index
    // base, so relative URLs resolve correctly.
    private static JsonObject BuildLocalLeaf(PackageVersion v, string normalizedId, string pkgName) => new()
    {
        ["@id"] = $"/nuget/registration/{normalizedId}/{v.Version}.json",
        ["@type"] = "Package",
        ["catalogEntry"] = new JsonObject
        {
            ["id"] = pkgName,
            ["version"] = v.Version,
            ["listed"] = true,
            ["packageContent"] = $"/nuget/flatcontainer/{normalizedId}/{v.Version}/{normalizedId}.{v.Version}.nupkg"
        }
    };

    private static JsonObject BuildLocalPage(IReadOnlyList<PackageVersion> localOnly, string normalizedId, string pkgName)
    {
        var localItems = new JsonArray(localOnly
            .Select(v => (JsonNode)BuildLocalLeaf(v, normalizedId, pkgName))
            .ToArray());
        var (lower, upper) = ComputeRange(localOnly);
        return new JsonObject
        {
            ["@id"] = $"/nuget/registration/{normalizedId}/index.json#page/local",
            ["@type"] = "catalog:CatalogPage",
            ["count"] = localItems.Count,
            ["items"] = localItems,
            ["lower"] = lower,
            ["upper"] = upper,
            ["parent"] = $"/nuget/registration/{normalizedId}/index.json"
        };
    }

    private static (string Lower, string Upper) ComputeRange(IReadOnlyList<PackageVersion> localOnly)
    {
        var sorted = localOnly
            .Select(v => (Parsed: NuGetVersion.TryParse(v.Version, out var nv) ? nv : null, Raw: v.Version))
            .Where(t => t.Parsed is not null)
            .OrderBy(t => t.Parsed)
            .Select(t => t.Raw)
            .ToList();
        return sorted.Count > 0
            ? (sorted[0], sorted[^1])
            : (localOnly[0].Version, localOnly[^1].Version);
    }

    private static void AppendPage(JsonObject root, JsonObject page)
    {
        if (root["items"] is not JsonArray pages)
        {
            pages = new JsonArray();
            root["items"] = pages;
        }
        pages.Add(page);
        if (root["count"] is not null) root["count"] = pages.Count;
    }

    // ── Flatcontainer / download ─────────────────────────────────────────────

    /// <summary>GET /o/{org}/nuget/flatcontainer/{id}/index.json — version list</summary>
    [HttpGet("/nuget/flatcontainer/{id}/index.json")]
    public async Task<IActionResult> FlatcontainerVersions(string id, CancellationToken ct)
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

        var normalizedId = id.ToLowerInvariant();
        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        var versionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await CollectLocalVersionsAsync(pkg, versionSet, ct);

        // Merge upstream regardless of pkg.IsProxy — a name with uploaded versions is still a
        // namespace that can hold proxy-fetched versions. Gate on passthrough + claims, not on
        // whether anyone has ever published into this name.
        if (settings.ProxyPassthroughEffective
            && await _claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct))
        {
            await MergeUpstreamVersionsAsync(orgId, id, versionSet, ct);
        }
        else
        {
            Response.Headers["X-Upstream-Status"] = "skipped";
        }

        if (versionSet.Count == 0) return NotFound();
        return new JsonResult(new { versions = versionSet.Order() });
    }

    private async Task CollectLocalVersionsAsync(Package? pkg, HashSet<string> versionSet, CancellationToken ct)
    {
        if (pkg is null) return;
        var local = await _packages.GetVersionsAsync(pkg.Id, ct);
        foreach (var v in local.Where(v => !v.Yanked)) versionSet.Add(v.Version);
    }

    // Fetch the upstream version list and merge. Short timeout so slow upstream responses don't
    // hang clients after they have what they need. Sets X-Upstream-Status header (ok|error|timeout)
    // and logs at warning level when the merge fails so operators can see silent fallbacks.
    private async Task MergeUpstreamVersionsAsync(string orgId, string id, HashSet<string> versionSet, CancellationToken ct)
    {
        // Walk the org's configured upstreams in priority order; the first that returns a usable
        // version list wins and we stop. No configured upstream ⇒ proxying is disabled for nuget,
        // so the loop is skipped and the status reflects the unreachable/empty outcome.
        var bases = await _registries.ResolveAsync(orgId, "nuget", ct);
        foreach (var upstreamBase in bases)
        {
            var url = $"{upstreamBase}/flatcontainer/{id.ToLowerInvariant()}/index.json";
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                // Single-flight: collapses N concurrent NuGet list requests onto one
                // upstream call for the same flatcontainer index.
                var resp = await _upstream.GetOrFetchMetadataAsync(url, linkedCts.Token);
                if (!resp.IsSuccessStatusCode)
                {
                    Response.Headers["X-Upstream-Status"] = "error";
                    // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                    _logger.LogWarning("NuGet upstream version-list fetch failed: {Status} for {Url}", resp.StatusCode, url);
                    continue;
                }

                using var doc = JsonDocument.Parse(resp.Body);
                if (!doc.RootElement.TryGetProperty("versions", out var versionsElem))
                {
                    Response.Headers["X-Upstream-Status"] = "error";
                    // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                    _logger.LogWarning("NuGet upstream version-list response missing 'versions' property for {Url}", url);
                    continue;
                }
                foreach (var v in versionsElem.EnumerateArray())
                {
                    var ver = v.GetString();
                    if (ver is not null) versionSet.Add(ver);
                }
                Response.Headers["X-Upstream-Status"] = "ok";
                return;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                Response.Headers["X-Upstream-Status"] = "timeout";
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                _logger.LogWarning("NuGet upstream version-list fetch timed out for {Url}", url);
            }
            catch (Exception ex)
            {
                Response.Headers["X-Upstream-Status"] = "error";
                // deepcode ignore LogForging: RenderedCompactJsonFormatter JSON-encodes {Url}.
                _logger.LogWarning(ex, "NuGet upstream version-list fetch threw for {Url}", url);
            }
        }
    }

    /// <summary>GET /o/{org}/nuget/flatcontainer/{id}/{version}/{file} — package download</summary>
    [HttpGet("/nuget/flatcontainer/{id}/{version}/{file}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Flatcontainer(string id, string version, string file, CancellationToken ct)
    {
        var orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
        var normalizedId = id.ToLowerInvariant();
        var pkg = await _packages.GetByPurlNameAsync(orgId, "nuget", normalizedId, ct);

        // Route by the specific version's origin (per-version state), not by the package-level
        // is_proxy flag. A package name is a namespace that can hold mixed-origin versions:
        // some uploaded private builds and some proxy-fetched public versions can coexist.
        if (pkg is not null)
        {
            var routed = await TryRouteToKnownVersionAsync(pkg, version, file, orgId, token, settings!, ct);
            if (routed is not null) return routed;
        }

        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var purlCheck = $"pkg:nuget/{normalizedId}";
        if (settings.AllowlistMode && !await _allowlist.IsAllowedAsync(orgId, purlCheck, ct))
            return StatusCode(403);
        if (await _blocklist.IsBlockedAsync(orgId, purlCheck, ct))
        {
            await _audit.LogActivityAsync(orgId, "nuget", purlCheck, "blocked", token?.UserId,
                actorKind: token?.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
            return StatusCode(403);
        }

        if (!settings.ProxyPassthroughEffective) return NotFound();

        // Claim state gates the proxy fetch. local_only (or air-gap implicit local_only)
        // disables proxy serving for that name.
        if (!await _claimResolver.IsProxyFetchAllowedAsync(orgId, "nuget", normalizedId, ct))
            return NotFound();

        return await ProxyFetchNupkgAsync(orgId, id, version, file, token, settings, ct);
    }

    // Per-version origin routing: returns a hosted version, a cached proxy version, or null
    // when the caller should fall through to the proxy-fetch path (no matching version row,
    // or cached proxy blob is for a different file type than requested).
    private async Task<IActionResult?> TryRouteToKnownVersionAsync(
        Package pkg, string version, string file, string orgId, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var normalizedVersion = NormalizeNuGetVersion(version);
        var pkgVersion = await _packages.GetVersionAsync(pkg.Id, normalizedVersion, ct);
        if (pkgVersion is null) return null;

        if (pkgVersion.Origin == "uploaded")
            return await ServeHostedVersionAsync(orgId, pkgVersion, file, token, settings, ct);

        if (pkgVersion.Origin == "proxy")
            return await TryServeCachedProxyVersionAsync(orgId, pkgVersion, file, token, settings, ct);

        return null;
    }

    private async Task<IActionResult> ServeHostedVersionAsync(
        string orgId, PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // Version exists and is privately hosted — token is required to download.
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        var sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (await _blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "nuget", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated), ct)
            == BlockDecision.Blocked) return StatusCode(403);

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null) return NotFound();

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        await _audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "download", token.UserId,
            actorKind: token.ActorKind, sourceIp: sourceIp, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    // For proxy versions: serve from cache only when the cached blob is for the exact requested file.
    // Each file type (nupkg, nuspec, sha512) has a distinct sha256 and blob. Serving the wrong blob
    // (e.g., nupkg bytes when the client requests the .sha512 hash) causes integrity verification to fail.
    // Returns 403 if blocked, the file IActionResult if cached, or null if cache miss → caller proxies.
    private async Task<IActionResult?> TryServeCachedProxyVersionAsync(
        string orgId, PackageVersion pkgVersion, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        var sourceIp = HttpContext.GetNormalizedRemoteIp();
        if (await _blockGate.EvaluateAsync(
                new BlockGateRequest(orgId, "nuget", pkgVersion.Purl, pkgVersion.Id,
                    pkgVersion.ManualBlockState, pkgVersion.VulnCheckedAt,
                    token?.UserId, settings.MaxOsvScoreTolerance, sourceIp,
                    MinReleaseAgeHours: settings.MinReleaseAgeHours,
                    PublishedAt: pkgVersion.PublishedAt,
                    ActorKind: token?.ActorKind,
                    Deprecated: pkgVersion.Deprecated,
                    BlockDeprecatedMode: settings.BlockDeprecated), ct)
            == BlockDecision.Blocked) return StatusCode(403);

        if (!pkgVersion.BlobKey.EndsWith("/" + file, StringComparison.OrdinalIgnoreCase))
            return null;

        var stream = await _blobs.GetAsync(BlobKeys.StoreKey(pkgVersion.BlobKey), ct);
        if (stream is null) return null;

        Response.Headers["X-Cache"] = "HIT";
        Response.Headers["X-Dependably-PURL"] = SanitizeHeader(pkgVersion.Purl);
        await _audit.LogActivityAsync(orgId, "nuget", pkgVersion.Purl, "download", token?.UserId,
            actorKind: token?.ActorKind, sourceIp: sourceIp, ct: ct);
        return File(stream, "application/octet-stream", file);
    }

    private static string NormalizeNuGetVersion(string version) =>
        NuGet.Versioning.NuGetVersion.TryParse(version, out var nv)
            ? nv.ToNormalizedString().ToLowerInvariant()
            : version.ToLowerInvariant();

    private async Task<IActionResult> ProxyFetchNupkgAsync(
        string orgId, string id, string version, string file, TokenRecord? token, OrgSettings settings, CancellationToken ct)
    {
        // Resolve the org's configured upstreams in priority order. An empty list means
        // proxying is disabled for nuget — a download miss is a 404.
        var bases = await _registries.ResolveAsync(orgId, "nuget", ct);
        if (bases.Count == 0) return NotFound();

        Response.Headers["X-Cache"] = "MISS";
        try
        {
            // Walk upstreams in priority order; the first reachable one to return the artefact
            // wins, and the heavy cache/record/scan/serve work runs single-shot for that URL.
            //
            // NuGet artefacts still route through GetOrFetchMetadataAsync (a buffered
            // byte[]) because flatcontainer URLs don't carry a content-addressed hash,
            // and we haven't yet flipped this path onto FetchAndStageAsync. That's a
            // parallel concern; the proxy-fetch refactor isolates the residue here by wrapping the byte[]
            // in a BlobHandle so everything downstream (ProxyFetchService,
            // ProxyVersionRecorder, LicenseExtractor) stays uniformly stream-shaped.
            string? upstreamBase = null;
            byte[]? bytes = null;
            foreach (var candidateBase in bases)
            {
                // Single-flight flatcontainer fetch — collapses concurrent first-fetches
                // of the same coordinate onto one upstream call.
                var resp = await _upstream.GetOrFetchMetadataAsync(
                    $"{candidateBase}/flatcontainer/{id.ToLowerInvariant()}/{version}/{file}", ct);
                if (!resp.IsSuccessStatusCode) continue;
                upstreamBase = candidateBase;
                bytes = resp.Body;
                break;
            }
            if (upstreamBase is null || bytes is null) return NotFound();

            var normalizedId = id.ToLowerInvariant();
            var normalizedVersion = NormalizeNuGetVersion(version);
            var canonicalId = ResolveCanonicalNuGetId(file, bytes, normalizedId);
            var purl = PurlNormalizer.NuGet(canonicalId, normalizedVersion);

            var meta = await TryFetchNuGetFirstFetchMetadataAsync(upstreamBase, normalizedId, normalizedVersion, ct);

            // Cache the artefact under its content-addressed key once and describe it
            // with a BlobHandle. OpenAsync prefers the blob-store stream; the byte[]
            // fallback covers the edge case where the blob vanishes between the put and
            // the licence read.
            var sha = ChecksumVerifier.ComputeSha256Hex(bytes);
            var proxyKey = BlobKeys.Proxy(sha);
            if (!await _blobs.ExistsAsync(proxyKey, ct))
                await _blobs.PutAsync(proxyKey, new MemoryStream(bytes), ct);
            var blob = new BlobHandle(proxyKey, sha, bytes.LongLength,
                async openCt => await _blobs.GetAsync(proxyKey, openCt)
                    ?? (Stream)new MemoryStream(bytes, writable: false));

            // deepcode ignore PT,LogForging: ProxyFetchService stores under BlobKeys.Proxy(sha256),
            // which validates a 64-char lowercase hex — path traversal cannot escape that key. All
            // structured logs use Serilog RenderedCompactJsonFormatter (CRLF-safe).
            var result = await _proxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
                OrgId: orgId, Ecosystem: "nuget",
                PackageName: normalizedId, PurlName: normalizedId,
                Version: normalizedVersion, Purl: purl, File: file, Blob: blob,
                ExtractLicenses: stream => file.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
                    ? LicenseExtractor.FromNuspec(stream)
                    : LicenseExtractor.ExtractedMetadata.Empty,
                UserId: token?.UserId,
                ActorKind: token?.ActorKind,
                SourceIp: HttpContext.GetNormalizedRemoteIp(),
                MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
                MinReleaseAgeHours: settings.MinReleaseAgeHours,
                CacheAccess: new CacheAccess(orgId, "nuget", normalizedId, normalizedVersion, file,
                    Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: $"{upstreamBase}/flatcontainer/{normalizedId}/{normalizedVersion}/{file}"),
                PublishedAt: meta.PublishedAt,
                UpstreamChecksum: meta.Checksum,
                UpstreamIntegrityValue: meta.IntegrityBase64,
                UpstreamIntegrityAlgorithm: meta.IntegrityBase64 is not null ? "sha512-b64" : null,
                Deprecated: meta.Deprecated,
                BlockDeprecatedMode: settings.BlockDeprecated
            ), ct);

            if (result.Decision == BlockDecision.Blocked) return StatusCode(403);

            // Stream the cached blob back to the client (response memory is one read
            // buffer, not the whole artefact).
            var blobStream = await _blobs.GetAsync(result.BlobKey, ct);
            if (blobStream is null) return File(bytes, "application/octet-stream", file);
            return File(blobStream, "application/octet-stream", file);
        }
        catch (Microsoft.Data.Sqlite.SqliteException) { throw; }
        catch (ChecksumException) { return StatusCode(502); }
        catch { return NotFound(); }
    }

    /// <summary>
    /// Fetches a single NuGet registration leaf and pulls out everything we capture at
    /// first-fetch: the <c>published</c> timestamp, a SHA-512 verification spec from
    /// <c>packageHash</c> + <c>packageHashAlgorithm</c>, and the raw base64 hash so the UI
    /// can surface what upstream claims. Fail-soft on any error. The unlisted sentinel
    /// (<c>1900-01-01</c>) is coerced to null so callers see "unknown" rather than a
    /// misleading timestamp.
    /// </summary>
    private async Task<NuGetFirstFetchMetadata> TryFetchNuGetFirstFetchMetadataAsync(
        string upstreamBase, string normalizedId, string normalizedVersion, CancellationToken ct)
    {
        try
        {
            var leafUrl = $"{upstreamBase}/registration5-semver1/{normalizedId}/{normalizedVersion}.json";
            // Route through single-flight — this leaf fetch is called inline with
            // every NuGet first-fetch download, so concurrent fan-out would otherwise
            // stampede the registration URL too.
            var resp = await _upstream.GetOrFetchMetadataAsync(leafUrl, ct);
            if (!resp.IsSuccessStatusCode) return NuGetFirstFetchMetadata.Empty;
            var node = JsonNode.Parse(resp.BodyAsString());

            DateTimeOffset? publishedAt = null;
            var published = node?["published"]?.GetValue<string>()
                ?? node?["catalogEntry"]?["published"]?.GetValue<string>();
            if (DateTimeOffset.TryParse(published, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts)
                && ts.Year >= 1901)
                publishedAt = ts;

            // packageHash + packageHashAlgorithm live at the leaf root on most NuGet
            // sources; fall back to catalogEntry.* for older feeds that nest them there.
            var hash = node?["packageHash"]?.GetValue<string>()
                ?? node?["catalogEntry"]?["packageHash"]?.GetValue<string>();
            var algorithm = node?["packageHashAlgorithm"]?.GetValue<string>()
                ?? node?["catalogEntry"]?["packageHashAlgorithm"]?.GetValue<string>();
            var checksum = ChecksumVerifier.ParseNuGetHash(hash, algorithm);

            // Only surface the raw value when it's the SHA-512-base64 form we recognise —
            // otherwise the UI label would lie about the algorithm. The verification spec
            // above is gated the same way (ParseNuGetHash returns null for non-SHA512).
            var integrityB64 = !string.IsNullOrEmpty(hash)
                && string.Equals(algorithm, "SHA512", StringComparison.OrdinalIgnoreCase)
                ? hash : null;

            string? deprecated = null;
            var listed = node?["listed"] ?? node?["catalogEntry"]?["listed"];
            if (listed is JsonValue lv && lv.TryGetValue<bool>(out var listedVal) && !listedVal)
                deprecated = "Unlisted upstream";

            return new NuGetFirstFetchMetadata(publishedAt, checksum, integrityB64, deprecated);
        }
        catch { return NuGetFirstFetchMetadata.Empty; }
    }

    private readonly record struct NuGetFirstFetchMetadata(
        DateTimeOffset? PublishedAt,
        ChecksumSpec? Checksum,
        string? IntegrityBase64,
        string? Deprecated)
    {
        public static NuGetFirstFetchMetadata Empty => new(null, null, null, null);
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


    // ── Push ─────────────────────────────────────────────────────────────────

    /// <summary>PUT /o/{org}/nuget/publish — push a .nupkg</summary>
    [HttpPut("/nuget/publish")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNuget)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(500 * 1024 * 1024)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> Push(CancellationToken ct)
        => PushPackage(isSymbol: false, ct);

    /// <summary>PUT /o/{org}/nuget/symbols — push a .snupkg</summary>
    [HttpPut("/nuget/symbols")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNuget)]
    [EnableRateLimiting("push")]
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
        var limit = await _orgs.GetUploadLimitAsync(settings, "nuget", ct);
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
        var normalizedVersion = PurlNormalizer.NormalizeNuGetVersionString(nuspecVersion);
        var purlName = nuspecId.ToLowerInvariant();
        var filename = $"{purlName}.{normalizedVersion.ToLowerInvariant()}.{(isSymbol ? "snupkg" : "nupkg")}";

        if (ValidateNuspecCoordinates(nuspecId, nuspecVersion, filename) is { } pathError) return pathError;
        if (await _publishGate.CheckAsync(ctx.OrgId, "nuget", purlName, ct) is { } claimReject) return claimReject;
        if (bytes.Length > ctx.Limit)
            return StatusCode(413, new ProblemDetails { Detail = "Upload exceeds NuGet size limit.", Status = 413 });

        var claim = await _claimResolver.ResolveAsync(ctx.OrgId, "nuget", purlName, ct);
        var publishResult = await _publish.StoreAndRecordAsync(
            BuildNuspecPublishRequest(ctx, nuspecId, purlName, normalizedVersion, filename, bytes, claim.State), ct);

        if (publishResult is Dependably.Infrastructure.Publish.PublishResult.Rejected rej)
        {
            return rej.Code == "version_exists"
                ? Conflict(new ProblemDetails { Detail = $"Version {normalizedVersion} already exists.", Status = 409 })
                : StatusCode(rej.HttpStatus, new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus });
        }

        var versionId = ((Dependably.Infrastructure.Publish.PublishResult.Accepted)publishResult).VersionId;
        await EmitNuspecLicensesAsync(versionId, bytes, ct);
        return StatusCode(201);
    }

    /// <summary>
    /// Three path-safety guards in one place. Returns the 422 result on the first failure
    /// or null when all three checks pass. Filename is rebuilt from the normalised id +
    /// version + extension so the safety check covers the actual stored path.
    /// </summary>
    private UnprocessableEntityObjectResult? ValidateNuspecCoordinates(string nuspecId, string nuspecVersion, string filename)
    {
        foreach (var (value, kind) in new[] { (nuspecId, "id"), (nuspecVersion, "version"), (filename, "filename") })
        {
            var check = PathSafeValidator.Validate(value, kind);
            if (!check.IsValid)
                return UnprocessableEntity(new ProblemDetails { Detail = check.Message, Status = 422 });
        }
        return null;
    }

    private Dependably.Infrastructure.Publish.PublishRequest BuildNuspecPublishRequest(
        NuGetPushContext ctx, string nuspecId, string purlName, string normalizedVersion,
        string filename, byte[] bytes, string claimState)
        => new()
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
            ActorKind = ctx.Token.ActorKind,
            AuditAction = "push",
            AllowOverwrite = ctx.Settings?.AllowVersionOverwrite ?? false,
            ClaimState = claimState,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
        };

    /// <summary>
    /// License rows from the .nuspec inside the .nupkg. Deprecation lives in registration
    /// metadata, not the nuspec — never available at push time, only on proxy fetches with
    /// a registration leaf.
    /// </summary>
    private async Task EmitNuspecLicensesAsync(string versionId, byte[] bytes, CancellationToken ct)
    {
        // Push path holds the .nupkg bytes in memory (upload validation concern,
        // out of scope for this change). Wrap in a MemoryStream for the unified extractor.
        var extracted = LicenseExtractor.FromNuspec(new MemoryStream(bytes, writable: false));
        if (extracted.Spdx.Count > 0)
            await _licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);
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
        // Org-scoped resolve: cross-org tokens are coerced to null so AnonymousPull governs.
        var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
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
    BlockGateService BlockGate,
    LicenseRepository Licenses,
    IPublicUrlBuilder Urls,
    PublishGate PublishGate,
    Dependably.Infrastructure.Publish.IPackagePublishService Publish,
    ClaimResolver ClaimResolver,
    Dependably.Storage.ProxyFetchService ProxyFetch,
    ILogger<NuGetController> Logger,
    UpstreamRegistryResolver Registries);
