using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

[ApiController]
[NpmErrorEnvelope]
public class NpmController : ControllerBase
{
    // Route-level hard ceiling for npm publish requests (500 MiB); per-tenant limits are
    // enforced by UploadSizeLimitMiddleware before any blob is written.
    private const long NpmPublishSizeLimitBytes = 500L * 1024 * 1024;

    private readonly NpmPackumentHandler _packument;
    private readonly NpmTarballHandler _tarball;
    private readonly NpmPublishHandler _publish;
    private readonly NpmDistTagsHandler _distTags;

    public NpmController(NpmControllerHandlers svc)
    {
        _packument = svc.Packument;
        _tarball = svc.Tarball;
        _publish = svc.Publish;
        _distTags = svc.DistTags;
    }

    // ── npm client probes ────────────────────────────────────────────────────

    /// <summary>
    /// GET /npm/-/ping — connectivity probe (<c>npm ping</c>). No auth required and
    /// no tenant data touched: the response shape is identical to registry.npmjs.org's empty
    /// JSON object, so npm/yarn/pnpm clients treat a 200 as "registry reachable" without
    /// further inspection. Literal <c>-/ping</c> segments win the route match over
    /// <c>/npm/{package}/{version}</c> by ASP.NET's literal-beats-parameter precedence.
    /// </summary>
    [HttpGet("/npm/-/ping")]
    public IActionResult Ping() => _distTags.Ping();

    /// <summary>
    /// GET /npm/-/whoami — identity probe (<c>npm whoami</c>). Bearer-only: returns
    /// 200 <c>{"username":"..."}</c> on a valid token, 401 with <c>WWW-Authenticate: Bearer</c>
    /// otherwise. User tokens project the owner's email; service tokens project
    /// <c>service:&lt;name&gt;</c> (see <see cref="TokenRepository.GetWhoAmIIdentifierAsync"/>) —
    /// chosen over a 401 so CI pipelines using service tokens get a stable identifier they
    /// can echo into logs. Cross-tenant tokens are coerced to null by the org-scoped resolver
    /// and fall into the same 401 branch as anonymous callers (no information leak).
    /// </summary>
    [HttpGet("/npm/-/whoami")]
    public Task<IActionResult> WhoAmI(CancellationToken ct)
        => _distTags.WhoAmIAsync(HttpContext, CurrentTenantId(), ct);

    // ── Read endpoints ───────────────────────────────────────────────────────

    /// <summary>GET /npm/{package} — CouchDB package metadata</summary>
    [HttpGet("/npm/{package}")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> GetPackage(string package, CancellationToken ct)
        => _packument.GetPackageAsync(HttpContext, CurrentTenantId(), package, ct);

    /// <summary>GET /npm/@{scope}/{package} — scoped package metadata</summary>
    [HttpGet("/npm/@{scope}/{package}")]
    [EnableRateLimiting("metadata")]
    public Task<IActionResult> GetScopedPackage(string scope, string package, CancellationToken ct)
        => _packument.GetScopedPackageAsync(HttpContext, CurrentTenantId(), scope, package, ct);

    /// <summary>GET /npm/{package}/{version} — specific version metadata</summary>
    [HttpGet("/npm/{package}/{version}")]
    public Task<IActionResult> GetVersion(string package, string version, CancellationToken ct)
        => _packument.GetVersionAsync(HttpContext, CurrentTenantId(), package, version, ct);

    // ── Tarball download ─────────────────────────────────────────────────────

    /// <summary>GET /npm/tarballs/{pkg}/{file} — tarball download</summary>
    [HttpGet("/npm/tarballs/{pkg}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetTarball(string pkg, string file, CancellationToken ct)
        => _tarball.GetTarballAsync(HttpContext, CurrentTenantId(), pkg, file, ct);

    /// <summary>GET /npm/tarballs/@{scope}/{pkg}/{file} — scoped package tarball download</summary>
    [HttpGet("/npm/tarballs/@{scope}/{pkg}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetScopedTarball(string scope, string pkg, string file, CancellationToken ct)
        => _tarball.GetScopedTarballAsync(HttpContext, CurrentTenantId(), scope, pkg, file, ct);

    /// <summary>
    /// GET /npm/{pkg}/-/{file} — tarball download at the <em>conventional</em> npm path.
    /// <c>npm ci</c> installs from package-lock.json's <c>resolved</c> URLs; when those
    /// point at the public registry but the configured <c>registry</c> is this one, npm swaps
    /// only the host and keeps the canonical <c>/{pkg}/-/{file}</c> layout — it never fetches
    /// the packument, so it never sees the rewritten <c>/npm/tarballs/…</c> URL. Routing the
    /// conventional path to the same handler lets <c>npm ci</c> resolve against a public lockfile.
    /// </summary>
    [HttpGet("/npm/{pkg}/-/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetTarballConventional(string pkg, string file, CancellationToken ct)
        => _tarball.GetTarballConventionalAsync(HttpContext, CurrentTenantId(), pkg, file, ct);

    /// <summary>GET /npm/@{scope}/{pkg}/-/{file} — scoped tarball at the conventional npm path (see <see cref="GetTarballConventional"/>).</summary>
    [HttpGet("/npm/@{scope}/{pkg}/-/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> GetScopedTarballConventional(string scope, string pkg, string file, CancellationToken ct)
        => _tarball.GetScopedTarballConventionalAsync(HttpContext, CurrentTenantId(), scope, pkg, file, ct);

    /// <summary>HEAD /npm/tarballs/{pkg}/{file} — returns headers without opening the blob stream.</summary>
    [HttpHead("/npm/tarballs/{pkg}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> HeadTarball(string pkg, string file, CancellationToken ct)
        => _tarball.HeadTarballAsync(HttpContext, CurrentTenantId(), pkg, file, ct);

    /// <summary>HEAD /npm/tarballs/@{scope}/{pkg}/{file} — scoped package tarball HEAD.</summary>
    [HttpHead("/npm/tarballs/@{scope}/{pkg}/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> HeadScopedTarball(string scope, string pkg, string file, CancellationToken ct)
        => _tarball.HeadScopedTarballAsync(HttpContext, CurrentTenantId(), scope, pkg, file, ct);

    /// <summary>HEAD /npm/{pkg}/-/{file} — conventional path tarball HEAD.</summary>
    [HttpHead("/npm/{pkg}/-/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> HeadTarballConventional(string pkg, string file, CancellationToken ct)
        => _tarball.HeadTarballConventionalAsync(HttpContext, CurrentTenantId(), pkg, file, ct);

    /// <summary>HEAD /npm/@{scope}/{pkg}/-/{file} — scoped conventional path tarball HEAD.</summary>
    [HttpHead("/npm/@{scope}/{pkg}/-/{file}")]
    [EnableRateLimiting("download")]
    public Task<IActionResult> HeadScopedTarballConventional(string scope, string pkg, string file, CancellationToken ct)
        => _tarball.HeadScopedTarballConventionalAsync(HttpContext, CurrentTenantId(), scope, pkg, file, ct);

    // ── Publish endpoint ─────────────────────────────────────────────────────

    /// <summary>PUT /npm/{package} — npm publish</summary>
    [HttpPut("/npm/{package}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(NpmPublishSizeLimitBytes)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> Publish(string package, CancellationToken ct)
        => _publish.PublishAsync(HttpContext, CurrentTenantId(), package, ct);

    /// <summary>PUT /npm/@{scope}/{package} — scoped npm publish</summary>
    [HttpPut("/npm/@{scope}/{package}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(NpmPublishSizeLimitBytes)] // hard ceiling; UploadSizeLimitMiddleware enforces tighter per-tenant/ecosystem caps before any blob is written
    public Task<IActionResult> PublishScoped(string scope, string package, CancellationToken ct)
        => _publish.PublishScopedAsync(HttpContext, CurrentTenantId(), scope, package, ct);

    // ── dist-tag management endpoints ────────────────────────────────────────

    /// <summary>GET /npm/-/package/{pkg}/dist-tags — list all dist-tags</summary>
    [HttpGet("/npm/-/package/{pkg}/dist-tags")]
    public Task<IActionResult> GetDistTags(string pkg, CancellationToken ct)
        => _distTags.GetDistTagsAsync(HttpContext, CurrentTenantId(), pkg, ct);

    /// <summary>GET /npm/-/package/@{scope}/{pkg}/dist-tags — list dist-tags for scoped package</summary>
    [HttpGet("/npm/-/package/@{scope}/{pkg}/dist-tags")]
    public Task<IActionResult> GetScopedDistTags(string scope, string pkg, CancellationToken ct)
        => _distTags.GetScopedDistTagsAsync(HttpContext, CurrentTenantId(), scope, pkg, ct);

    /// <summary>PUT /npm/-/package/{pkg}/dist-tags/{tag} — set a dist-tag</summary>
    [HttpPut("/npm/-/package/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> PutDistTag(string pkg, string tag, CancellationToken ct)
        => _distTags.PutDistTagAsync(HttpContext, CurrentTenantId(), pkg, tag, ct);

    /// <summary>PUT /npm/-/package/@{scope}/{pkg}/dist-tags/{tag} — set a dist-tag for scoped package</summary>
    [HttpPut("/npm/-/package/@{scope}/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> PutScopedDistTag(string scope, string pkg, string tag, CancellationToken ct)
        => _distTags.PutScopedDistTagAsync(HttpContext, CurrentTenantId(), scope, pkg, tag, ct);

    /// <summary>DELETE /npm/-/package/{pkg}/dist-tags/{tag} — remove a dist-tag</summary>
    [HttpDelete("/npm/-/package/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> DeleteDistTag(string pkg, string tag, CancellationToken ct)
        => _distTags.DeleteDistTagAsync(HttpContext, CurrentTenantId(), pkg, tag, ct);

    /// <summary>DELETE /npm/-/package/@{scope}/{pkg}/dist-tags/{tag} — remove a dist-tag for scoped package</summary>
    [HttpDelete("/npm/-/package/@{scope}/{pkg}/dist-tags/{tag}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishNpm)]
    public Task<IActionResult> DeleteScopedDistTag(string scope, string pkg, string tag, CancellationToken ct)
        => _distTags.DeleteScopedDistTagAsync(HttpContext, CurrentTenantId(), scope, pkg, tag, ct);

    // ── Unpublish endpoint ───────────────────────────────────────────────────

    /// <summary>
    /// DELETE /npm/{pkg}/-rev/{rev} — version unpublish (<c>npm unpublish pkg@version</c>).
    /// The npm CLI sends this shape for per-version unpublish. The version row and its tarball
    /// are hard-deleted from the registry, and any dist-tags pointing at the removed version are
    /// pruned; 'latest' is re-anchored to the highest remaining stable version when it was among
    /// the pruned tags. Requires the YankNpm capability.
    /// Whole-package unpublish (all versions at once) returns 403 — use the management API.
    /// </summary>
    [HttpDelete("/npm/{pkg}/-rev/{rev}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.YankNpm)]
    public Task<IActionResult> Unpublish(string pkg, string rev, CancellationToken ct)
        => _publish.UnpublishAsync(HttpContext, CurrentTenantId(), pkg, rev, ct);

    /// <summary>DELETE /npm/@{scope}/{pkg}/-rev/{rev} — scoped package version unpublish</summary>
    [HttpDelete("/npm/@{scope}/{pkg}/-rev/{rev}")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.YankNpm)]
    public Task<IActionResult> UnpublishScoped(string scope, string pkg, string rev, CancellationToken ct)
        => _publish.UnpublishScopedAsync(HttpContext, CurrentTenantId(), scope, pkg, rev, ct);

    // ── Search endpoint ──────────────────────────────────────────────────────

    /// <summary>
    /// GET /npm/-/v1/search?text=&amp;size=&amp;from= — package search.
    /// Returns a minimal npm search response over the org's hosted packages.
    /// text is a LIKE pattern applied to package names. size is clamped 1..50.
    /// Auth: same anonymous-pull gate as packument GET.
    /// </summary>
    [HttpGet("/npm/-/v1/search")]
    public Task<IActionResult> Search(
        [FromQuery] string? text,
        [FromQuery] int size = 20,
        [FromQuery] int from = 0,
        CancellationToken ct = default)
        => _distTags.SearchAsync(HttpContext, CurrentTenantId(), text, size, from, ct);

    // ── Shared utilities ─────────────────────────────────────────────────────

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
}

// DI-injected dependency aggregate for NpmController. Single param avoids S107 on the
// controller constructor.
public sealed record NpmControllerHandlers(
    NpmProtocol.NpmPackumentHandler Packument,
    NpmProtocol.NpmTarballHandler Tarball,
    NpmProtocol.NpmPublishHandler Publish,
    NpmProtocol.NpmDistTagsHandler DistTags);
