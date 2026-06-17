using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

[ApiController]
public class PyPiController : ControllerBase
{
    // Route-level hard ceiling for PyPI uploads (500 MiB).
    private const long PyPiUploadSizeLimitBytes = PyPiConstants.UploadSizeLimitBytes;

    private readonly PyPiSimpleIndexHandler _simpleIndex;
    private readonly PyPiDownloadHandler _download;
    private readonly PyPiPublishHandler _publish;
    private readonly PyPiJsonApiHandler _jsonApi;

    public PyPiController(PyPiControllerServices svc)
    {
        _simpleIndex = svc.SimpleIndex;
        _download = svc.Download;
        _publish = svc.Publish;
        _jsonApi = svc.JsonApi;
    }

    // ── Read endpoints ─────────────────────────────────────────────────

    /// <summary>GET /simple/ — PEP 503 package listing</summary>
    [HttpGet("/simple/")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> SimpleIndex(CancellationToken ct)
        => _simpleIndex.SimpleIndexAsync(HttpContext, CurrentTenantId(), ct);

    /// <summary>GET /simple/{package}/ — PEP 503/592 version listing</summary>
    [HttpGet("/simple/{package}/")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> PackageIndex(string package, CancellationToken ct)
        => _simpleIndex.PackageIndexAsync(HttpContext, CurrentTenantId(), package, ct);

    // ── JSON API ────────────────────────────────────────────────────────

    /// <summary>GET /pypi/{package}/json — PyPI JSON API for a package's latest version</summary>
    [HttpGet("/pypi/{package}/json")]
    public Task<IActionResult> PackageJson(string package, CancellationToken ct)
        => _jsonApi.PackageJsonAsync(HttpContext, CurrentTenantId(), package, ct);

    /// <summary>GET /pypi/{package}/{version}/json — PyPI JSON API for a specific version</summary>
    [HttpGet("/pypi/{package}/{version}/json")]
    public Task<IActionResult> PackageVersionJson(string package, string version, CancellationToken ct)
        => _jsonApi.PackageVersionJsonAsync(HttpContext, CurrentTenantId(), package, version, ct);

    // ── Download endpoints ─────────────────────────────────────────────

    /// <summary>
    /// HEAD /packages/{file} — returns headers (size, checksum, content-type) without opening
    /// the blob stream. Enforces the same auth and block gates as GET but uses
    /// <see cref="IBlobStore.ExistsAsync"/> instead of <see cref="IBlobStore.GetAsync"/>, so no
    /// network stream is opened for S3/Azure-backed stores. Returns 404 on proxy cache-miss
    /// (the client would receive a 404 on GET too until the blob is fetched and cached).
    /// </summary>
    [HttpHead("/packages/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> HeadPackage(string file, CancellationToken ct)
        => _download.HeadPackageAsync(HttpContext, CurrentTenantId(), file, ct);

    /// <summary>GET /packages/{file} — blob download with proxy cache (tenant-implicit from host)</summary>
    [HttpGet("/packages/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> DownloadPackage(string file, CancellationToken ct)
        => _download.DownloadPackageAsync(HttpContext, CurrentTenantId(), file, ct);

    // ── Upload endpoint ────────────────────────────────────────────────

    /// <summary>POST /pypi/legacy/ — twine-compatible upload (tenant-implicit from host)</summary>
    [HttpPost("/pypi/legacy/")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishPypi)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(PyPiUploadSizeLimitBytes)] // hard ceiling; per-tenant limit checked below
    public Task<IActionResult> Upload(CancellationToken ct)
        => _publish.UploadAsync(HttpContext, CurrentTenantId(), ct);

    // ── Compatibility shim for unit tests ─────────────────────────────

    /// <summary>
    /// Forwards to <see cref="PyPiSimpleIndexHelper.RewriteUpstreamSimpleIndexHtml"/> for
    /// backward compatibility with unit tests that reference this method via the controller type.
    /// </summary>
    internal static string RewriteUpstreamSimpleIndexHtml(string html)
        => PyPiSimpleIndexHelper.RewriteUpstreamSimpleIndexHtml(html);

    // ── Helpers ────────────────────────────────────────────────────────

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
}

// DI-injected dependency aggregate for PyPiController. Single param avoids S107.
public sealed record PyPiControllerServices(
    PyPiSimpleIndexHandler SimpleIndex,
    PyPiDownloadHandler Download,
    PyPiPublishHandler Publish,
    PyPiJsonApiHandler JsonApi);
