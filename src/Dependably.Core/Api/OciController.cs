using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// OCI Distribution Spec v2 surface. Docker daemons configured against <c>/v2/</c> can both
/// <c>docker pull</c> (read side) and <c>docker push</c> (write side) images.
///
/// Write side: blob uploads (<c>POST</c> init, <c>PATCH</c> chunk, <c>PUT</c> finalize) and
/// manifest puts (<c>PUT .../manifests/...</c>) are delegated to <see cref="OciUploadService"/>,
/// which hashes-and-stages blob bytes, verifies the client digest, and writes to the Registry
/// tier with <c>origin='uploaded'</c> — the same rows the read side below serves back.
///
/// Cache-miss path: when a manifest, blob, or tag list is not found in the local DB /
/// blob store, <see cref="OciUpstreamResolver"/> is consulted. It probes the first matching
/// upstream registry (prefix-based routing), fetches with Bearer-token auth, verifies the blob
/// SHA-256 digest, writes to the Cache tier, and returns a stream the controller serves
/// directly. Subsequent requests for the same digest are served from cache without an upstream
/// round-trip.
///
/// Routing note: OCI repository names embed slashes (e.g. <c>library/ubuntu</c>), so all v2
/// paths route through a single <c>{**path}</c> handler that parses the suffix manually.
///
/// Errors use the OCI Distribution Spec error response shape.
/// </summary>
[ApiController]
public sealed partial class OciController : OrgScopedControllerBase
{
    private readonly OciControllerServices _svc;
    private readonly ILogger<OciController> _logger;

    public OciController(OciControllerServices svc, ILogger<OciController> logger)
    {
        _svc = svc;
        _logger = logger;
    }

    // Route-level hard ceiling for OCI upload requests (2048 MiB matches the OCI default).
    private const long OciUploadSizeLimitBytes = 2048L * 1024 * 1024;

    // Manifest-body cap (4 MiB). Real OCI manifests are a few KB; even a configured tenant OCI
    // limit is sized for image layers, orders of magnitude too large to bound a manifest PUT.
    // The manifest body is fully buffered (it must be parsed and digest-verified), so it is
    // capped before buffering — independently of the layer-sized per-tenant limit — so a hostile
    // near-2 GiB manifest PUT cannot OOM the process before any size check runs.
    private const long OciManifestMaxBytes = 4L * 1024 * 1024;

    // Referrer scan cap: repositories with more manifests return an incomplete list (valid per OCI 1.1).
    private const int OciReferrersScanCap = 10000;

    /// <summary>
    /// GET dispatcher — parses the v2 path suffix and routes to manifest / blob / tags
    /// handlers. An empty or null <paramref name="path"/> is the Distribution Spec auth probe
    /// (Docker daemon hits it before any pull/push).
    /// </summary>
    [HttpGet("/v2/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Get(string? path, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(path))
        {
            return await PingAsync(ct);
        }

        var route = OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.Manifest => await ServeManifestAsync(route.Name, route.Reference!, headOnly: false, ct),
                OciRouteKind.Blob => await ServeBlobAsync(route.Name, route.Reference!, headOnly: false, ct),
                OciRouteKind.TagsList => await ListTagsAsync(route.Name, ct),
                OciRouteKind.Referrers => await ListReferrersAsync(route.Name, route.Reference!, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// HEAD dispatcher — same shape as GET but no body.
    /// </summary>
    [HttpHead("/v2/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Head(string? path, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(path))
        {
            return await PingAsync(ct);
        }

        var route = OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.Manifest => await ServeManifestAsync(route.Name, route.Reference!, headOnly: true, ct),
                OciRouteKind.Blob => await ServeBlobAsync(route.Name, route.Reference!, headOnly: true, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// POST dispatcher — begins a blob upload session (<c>/blobs/uploads</c>). A monolithic
    /// single-POST (<c>?digest=</c> with the full body) is finalized inline.
    /// </summary>
    [HttpPost("/v2/{**path}")]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(OciUploadSizeLimitBytes)] // hard ceiling matching the 2048 MB OCI default; UploadSizeLimitMiddleware + the cumulative check enforce tighter per-tenant caps
    public async Task<IActionResult> Post(string? path, CancellationToken ct)
    {
        // Fail-closed on an edge node: OCI stages uploads outside the shared publish service, so
        // upload-initiation (POST /v2/.../blobs/uploads/) is refused here at the choke point.
        if (_svc.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.BlobUploadInit => await HandleUploadInitAsync(route.Name, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>PATCH dispatcher — appends a chunk to an open blob upload session.</summary>
    [HttpPatch("/v2/{**path}")]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(OciUploadSizeLimitBytes)] // hard ceiling matching the 2048 MB OCI default; UploadSizeLimitMiddleware + the cumulative check enforce tighter per-tenant caps
    public async Task<IActionResult> Patch(string? path, CancellationToken ct)
    {
        // Fail-closed on an edge node: a chunk PATCH streams blob bytes to staging disk toward a
        // registry-tier finalize, so the whole upload surface is refused here at the choke point.
        if (_svc.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.BlobUploadSession => await HandleUploadChunkAsync(route.Name, route.Reference!, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// PUT dispatcher — finalizes a blob upload (<c>/blobs/uploads/{id}?digest=</c>) or stores
    /// a manifest (<c>/manifests/{reference}</c>).
    /// </summary>
    [HttpPut("/v2/{**path}")]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(OciUploadSizeLimitBytes)] // hard ceiling matching the 2048 MB OCI default; UploadSizeLimitMiddleware + the cumulative check enforce tighter per-tenant caps
    public async Task<IActionResult> Put(string? path, CancellationToken ct)
    {
        // Fail-closed on an edge node: manifest PUT and blob finalize both write the registry
        // tier, so the whole upload-finalize surface is refused here at the choke point.
        if (_svc.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.BlobUploadSession => await HandleBlobFinalizeAsync(route.Name, route.Reference!, ct),
                OciRouteKind.Manifest => await HandleManifestPutAsync(route.Name, route.Reference!, ct),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    /// <summary>
    /// DELETE dispatcher — manifest delete by digest or tag, blob delete (405 per spec).
    /// Requires <c>yank:oci</c> capability (same gate as the management-API delete).
    /// </summary>
    [HttpDelete("/v2/{**path}")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> Delete(string? path, CancellationToken ct)
    {
        // Fail-closed on an edge node: a cache edge holds no authoritative manifest to remove, so
        // the delete surface is refused here before any lookup or mutation.
        if (_svc.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var route = string.IsNullOrEmpty(path) ? null : OciRoute.Parse(path);
        return route is null
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.")
            : route.Kind switch
            {
                OciRouteKind.Manifest => await HandleManifestDeleteAsync(route.Name, route.Reference!, ct),
                OciRouteKind.Blob => HandleBlobDeleteNotAllowed(),
                _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
            };
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    // Advertise Basic, not Bearer: a Bearer challenge's realm must be the absolute
    // URL of a token endpoint, which we do not run. ResolveTokenAsync accepts
    // base64(user:PAT) over Basic — the same scheme PyPI/NuGet/Maven advertise — so
    // docker/skopeo authenticate without a token-exchange flow.
    private const string BasicChallenge = "Basic realm=\"dependably\"";

    /// <summary>
    /// The Distribution-Spec <c>/v2/</c> ping is the auth-discovery endpoint: docker,
    /// skopeo and containerd hit it first and read <c>WWW-Authenticate</c> to decide
    /// whether — and how — to authenticate. Answering 200 with no challenge makes a
    /// client conclude the registry needs no auth and send every later request
    /// (including the manifest <c>PUT</c>) anonymously, so push fails at the first
    /// authed write. Challenge an unauthenticated ping so clients switch into
    /// Basic-auth mode; a credential-less client retries reads without auth, which the
    /// read endpoints still serve when anonymous pull is allowed.
    /// </summary>
    private async Task<IActionResult> PingAsync(CancellationToken ct)
    {
        Response.Headers["Docker-Distribution-API-Version"] = "registry/2.0";
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required.");
        }
        return Ok();
    }

    private async Task<(TokenRecord? Token, IActionResult? Unauthorized)> AuthorizePullAsync(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        return (token, null);
    }

    private async Task<(TokenRecord? Token, IActionResult? Error)> AuthorizePushAsync(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        if (!token.HasCapability(Capabilities.PublishOci))
        {
            return (null, OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
                "Insufficient scope: publish:oci required."));
        }

        return (token, null);
    }

    private async Task<(TokenRecord? Token, IActionResult? Error)> AuthorizeYankAsync(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = BasicChallenge;
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        if (!token.HasCapability(Capabilities.YankOci))
        {
            return (null, OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
                "Insufficient scope: yank:oci required."));
        }

        return (token, null);
    }

    private async Task<string?> ResolveDigestAsync(string orgId, OciCoordinates coords, CancellationToken ct)
    {
        if (coords.IsDigest)
        {
            return coords.Reference;
        }

        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT digest FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = coords.Repository, tag = coords.Reference });
    }

    /// <summary>
    /// Returns the blob-store tier to read from based on the <c>origin</c> column.
    /// Proxy blobs live in the Cache tier (eviction-friendly); hosted blobs in Registry.
    /// </summary>
    private IBlobStore BlobTierFor(string? origin)
        => origin == "proxy" ? _svc.BlobStore.Cache : _svc.BlobStore.Registry;

    /// <summary>
    /// A locally catalogued blob resolved for serving: the tier it lives in, its storage
    /// key, and the content metadata stamped on the response.
    /// </summary>
    private sealed record ResolvedLocalBlob(IBlobStore Tier, string BlobKey, long SizeBytes, string? MediaType);

    private static ObjectResult OciError(int statusCode, OciErrorCode code, string message)
    {
        var body = new OciErrorResponse(new[] { new OciError(code, message) });
        return new ObjectResult(body) { StatusCode = statusCode };
    }
}

/// <summary>Parses a v2 path suffix into one of three Distribution-Spec verbs.</summary>
internal sealed record OciRoute(OciRouteKind Kind, string Name, string? Reference)
{
    public static OciRoute? Parse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        path = path.Trim('/');

        // Tags list: trailing "/tags/list".
        const string tagsSuffix = "/tags/list";
        if (path.EndsWith(tagsSuffix, StringComparison.Ordinal))
        {
            string name = path[..^tagsSuffix.Length];
            return name.Length > 0 ? new OciRoute(OciRouteKind.TagsList, name, null) : null;
        }

        // Referrers: "/referrers/{digest}" somewhere after the repo name.
        const string referrersMarker = "/referrers/";
        int referrersIdx = path.IndexOf(referrersMarker, StringComparison.Ordinal);
        if (referrersIdx > 0)
        {
            string name = path[..referrersIdx];
            string reference = path[(referrersIdx + referrersMarker.Length)..];
            return reference.Length > 0 ? new OciRoute(OciRouteKind.Referrers, name, reference) : null;
        }

        // Manifests: "/manifests/{reference}" somewhere after the repo name.
        const string manifestsMarker = "/manifests/";
        int manifestsIdx = path.IndexOf(manifestsMarker, StringComparison.Ordinal);
        if (manifestsIdx > 0)
        {
            string name = path[..manifestsIdx];
            string reference = path[(manifestsIdx + manifestsMarker.Length)..];
            return reference.Length > 0 ? new OciRoute(OciRouteKind.Manifest, name, reference) : null;
        }

        // Blobs: "/blobs/{digest}" (pull) or the push upload sub-paths.
        const string blobsMarker = "/blobs/";
        int blobsIdx = path.IndexOf(blobsMarker, StringComparison.Ordinal);
        return blobsIdx > 0 ? ParseBlobs(path[..blobsIdx], path[(blobsIdx + blobsMarker.Length)..]) : null;
    }

    /// <summary>Resolves the "/blobs/…" tail into a pull, an upload-init, or an upload-session verb.</summary>
    private static OciRoute? ParseBlobs(string name, string rest)
    {
        // Push: "/blobs/uploads" begins a session; "/blobs/uploads/{id}" advances one.
        if (rest == "uploads")
        {
            return new OciRoute(OciRouteKind.BlobUploadInit, name, null);
        }

        const string uploadsPrefix = "uploads/";
        if (rest.StartsWith(uploadsPrefix, StringComparison.Ordinal))
        {
            string uploadId = rest[uploadsPrefix.Length..];
            return uploadId.Length > 0 ? new OciRoute(OciRouteKind.BlobUploadSession, name, uploadId) : null;
        }

        return rest.Length > 0 ? new OciRoute(OciRouteKind.Blob, name, rest) : null;
    }
}

internal enum OciRouteKind { Manifest, Blob, TagsList, BlobUploadInit, BlobUploadSession, Referrers }

/// <summary>Scoped DI bundle for the OCI controller.</summary>
public sealed record OciControllerServices(
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    TieredBlobStorage BlobStore,
    IMetadataStore Db,
    OciUpstreamResolver Upstream,
    OciUploadService Uploads,
    OciOrphanBlobDeleter OrphanBlobs,
    BlockGateService BlockGate,
    Dependably.Infrastructure.Edge.EdgePublishGuard EdgeGuard,
    PackageRepository Packages,
    TenantArtifactAccessRepository TenantArtifactAccess);
