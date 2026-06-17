using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

[ApiController]
public partial class NuGetController : ControllerBase
{
    // Route-level hard ceiling for NuGet push requests (500 MiB).
    private const long NuGetUploadSizeLimitBytes = 500L * 1024 * 1024;

    private readonly NuGetServiceIndexHandler _serviceIndex;
    private readonly NuGetSearchHandler _search;
    private readonly NuGetRegistrationHandler _registration;
    private readonly NuGetFlatContainerHandler _flatContainer;
    private readonly NuGetPublishHandler _publishHandler;

    public NuGetController(NuGetControllerServices svc)
    {
        _serviceIndex = svc.ServiceIndex;
        _search = svc.Search;
        _registration = svc.Registration;
        _flatContainer = svc.FlatContainer;
        _publishHandler = svc.Publish;
    }

    // ── Service index ────────────────────────────────────────────────────────

    /// <summary>GET /nuget/v3/index.json and /nuget/index.json — NuGet v3 service index</summary>
    [HttpGet("/nuget/v3/index.json")]
    [HttpGet("/nuget/index.json")]
    public Task<IActionResult> ServiceIndex(CancellationToken ct) =>
        Task.FromResult(_serviceIndex.Handle(HttpContext));

    // ── Search ───────────────────────────────────────────────────────────────

    /// <summary>GET /nuget/query — NuGet search endpoint</summary>
    [HttpGet("/nuget/query")]
    public Task<IActionResult> Search(
        [FromQuery] string? q,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 20,
        CancellationToken ct = default) =>
        _search.SearchAsync(HttpContext, CurrentTenantId(), q, skip, take, ct);

    // ── Autocomplete ─────────────────────────────────────────────────────────

    /// <summary>
    /// GET /o/{org}/nuget/autocomplete — NuGet v3 autocomplete endpoint.
    /// Two forms per the NuGet v3 autocomplete spec:
    /// - id-prefix search: ?q=&amp;skip=&amp;take=&amp;prerelease=&amp;semVerLevel=
    ///   returns { "totalHits": N, "data": ["PackageId", ...] }
    /// - version enumeration: ?id={id}&amp;prerelease=
    ///   returns { "data": ["1.0.0", ...] }
    /// The <c>id</c> parameter discriminates the two forms; when both are present, version
    /// enumeration takes precedence (matching the NuGet.org behavior).
    /// </summary>
    [HttpGet("/nuget/autocomplete")]
    public Task<IActionResult> Autocomplete(
        [FromQuery] string? q,
        [FromQuery] string? id,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 20,
        [FromQuery] bool prerelease = false,
        CancellationToken ct = default) =>
        _search.AutocompleteAsync(HttpContext, CurrentTenantId(), new NuGetAutocompleteParams(q, id, skip, take, prerelease), ct);

    // ── Registration ─────────────────────────────────────────────────────────

    /// <summary>GET /nuget/registration/{id}/ — registration index (SemVer 1, unversioned alias)</summary>
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
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> RegistrationIndex(string id, CancellationToken ct)
        => _registration.RegistrationIndexAsync(HttpContext, CurrentTenantId(), id, semVer2: false, ct);

    /// <summary>GET /nuget/registration5-{,gz-}semver2/{id}/index.json — SemVer 2 registration</summary>
    [HttpGet("/nuget/registration5-semver2/{id}/")]
    [HttpGet("/nuget/registration5-semver2/{id}/index.json")]
    [HttpGet("/nuget/registration5-gz-semver2/{id}/")]
    [HttpGet("/nuget/registration5-gz-semver2/{id}/index.json")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> RegistrationIndexSemVer2(string id, CancellationToken ct)
        => _registration.RegistrationIndexAsync(HttpContext, CurrentTenantId(), id, semVer2: true, ct);

    // Per-version registration leaf: `{RegistrationsBaseUrl}/{lowerId}/{version}.json`. The index we
    // serve is inlined (catalogEntry embedded in the page), so clients never need to follow the leaf
    // @id today — but the index emits these leaf URLs (BuildLocalRegistration/BuildLocalLeaf) and a
    // paged registry (or a client that fetches leaves directly) would 404 without a route here.
    // The literal `index.json` route out-ranks `{version}.json`, so the index path is unaffected.
    [HttpGet("/nuget/registration/{id}/{version}.json")]
    [HttpGet("/nuget/registration5-semver1/{id}/{version}.json")]
    [HttpGet("/nuget/registration5-gz-semver1/{id}/{version}.json")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> RegistrationLeaf(string id, string version, CancellationToken ct)
        => _registration.RegistrationLeafAsync(HttpContext, CurrentTenantId(), id, version, semVer2: false, ct);

    /// <summary>GET /nuget/registration5-{,gz-}semver2/{id}/{version}.json — SemVer 2 leaf</summary>
    [HttpGet("/nuget/registration5-semver2/{id}/{version}.json")]
    [HttpGet("/nuget/registration5-gz-semver2/{id}/{version}.json")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> RegistrationLeafSemVer2(string id, string version, CancellationToken ct)
        => _registration.RegistrationLeafAsync(HttpContext, CurrentTenantId(), id, version, semVer2: true, ct);

    // ── Flatcontainer / download ─────────────────────────────────────────────

    /// <summary>GET /nuget/flatcontainer/{id}/index.json — version list</summary>
    [HttpGet("/nuget/flatcontainer/{id}/index.json")]
    public Task<IActionResult> FlatcontainerVersions(string id, CancellationToken ct)
        => _flatContainer.FlatcontainerVersionsAsync(HttpContext, CurrentTenantId(), id, ct);

    /// <summary>GET /nuget/flatcontainer/{id}/{version}/{file} — package download</summary>
    [HttpGet("/nuget/flatcontainer/{id}/{version}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> Flatcontainer(string id, string version, string file, CancellationToken ct)
        => _flatContainer.FlatcontainerDownloadAsync(HttpContext, CurrentTenantId(), id, version, file, ct);

    /// <summary>
    /// HEAD /nuget/flatcontainer/{id}/{version}/{file} — returns headers (size, checksum,
    /// content-type) without opening the blob stream. Enforces the same auth and block gates
    /// as GET. Returns 404 on proxy cache-miss (blob not yet cached locally).
    /// </summary>
    [HttpHead("/nuget/flatcontainer/{id}/{version}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> FlatcontainerHead(string id, string version, string file, CancellationToken ct)
        => _flatContainer.FlatcontainerHeadAsync(HttpContext, CurrentTenantId(), id, version, file, ct);

    // ── Push ─────────────────────────────────────────────────────────────────

    /// <summary>PUT /nuget/publish — push a .nupkg</summary>
    [HttpPut("/nuget/publish")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNuget)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(NuGetUploadSizeLimitBytes)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> Push(CancellationToken ct)
        => _publishHandler.PushAsync(HttpContext, CurrentTenantId(), ct);

    /// <summary>PUT /nuget/symbols — push a .snupkg</summary>
    [HttpPut("/nuget/symbols")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNuget)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(NuGetUploadSizeLimitBytes)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> PushSymbols(CancellationToken ct)
        => _publishHandler.PushSymbolsAsync(HttpContext, CurrentTenantId(), ct);

    // ── Unlist ───────────────────────────────────────────────────────────────

    /// <summary>DELETE /nuget/publish/{id}/{version} — unlist (not hard-delete)</summary>
    [HttpDelete("/nuget/publish/{id}/{version}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.YankNuget)]
    public Task<IActionResult> Unlist(string id, string version, CancellationToken ct)
        => _publishHandler.UnlistAsync(HttpContext, CurrentTenantId(), id, version, ct);

    // ── Symbol download ──────────────────────────────────────────────────────

    /// <summary>GET /nuget/symbols/{id}/{version}/{file}</summary>
    [HttpGet("/nuget/symbols/{id}/{version}/{file}")]
    public Task<IActionResult> GetSymbols(string id, string version, string file, CancellationToken ct)
        => _publishHandler.GetSymbolsAsync(HttpContext, CurrentTenantId(), id, version, file, ct);

    // ── Static helpers used by tests ─────────────────────────────────────────

    // These forward to NuGetRegistrationHelpers so existing tests continue to call
    // NuGetController.* without change.

    internal static string MergeLocalIntoUpstreamRegistration(
        string upstreamJson, IReadOnlyList<PackageVersion> localVersions, Package pkg, string id,
        string? baseUrl = null) =>
        NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(upstreamJson, localVersions, pkg, id, baseUrl);

    internal static string RewriteRegistrationIndexUrls(string indexJson, string normalizedId, string baseUrl) =>
        NuGetRegistrationHelpers.RewriteRegistrationIndexUrls(indexJson, normalizedId, baseUrl);

    internal static string RewriteRegistrationLeafUrls(string leafJson, string normalizedId, string baseUrl) =>
        NuGetRegistrationHelpers.RewriteRegistrationLeafUrls(leafJson, normalizedId, baseUrl);

    // ── Shared utilities ─────────────────────────────────────────────────────

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
}

// DI-injected dependency aggregate for NuGetController. Single param avoids S107.
public sealed record NuGetControllerServices(
    NuGetProtocol.NuGetServiceIndexHandler ServiceIndex,
    NuGetProtocol.NuGetSearchHandler Search,
    NuGetProtocol.NuGetRegistrationHandler Registration,
    NuGetProtocol.NuGetFlatContainerHandler FlatContainer,
    NuGetProtocol.NuGetPublishHandler Publish);
