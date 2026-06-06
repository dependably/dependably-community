using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

/// <summary>
/// OCI Distribution Spec v2 surface. Implements the read side so Docker daemons
/// configured against <c>/v2/</c> can <c>docker pull</c> images. Push is deferred.
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
public sealed class OciController : OrgScopedControllerBase
{
    private readonly OciControllerServices _svc;

    public OciController(OciControllerServices svc) => _svc = svc;

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
            Response.Headers["Docker-Distribution-API-Version"] = "registry/2.0";
            return Ok();
        }
        var route = OciRoute.Parse(path);
        if (route is null) return OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.");
        return route.Kind switch
        {
            OciRouteKind.Manifest => await ServeManifestAsync(route.Name, route.Reference!, headOnly: false, ct),
            OciRouteKind.Blob     => await ServeBlobAsync(route.Name, route.Reference!, headOnly: false, ct),
            OciRouteKind.TagsList => await ListTagsAsync(route.Name, ct),
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
            Response.Headers["Docker-Distribution-API-Version"] = "registry/2.0";
            return Ok();
        }
        var route = OciRoute.Parse(path);
        if (route is null) return OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path.");
        return route.Kind switch
        {
            OciRouteKind.Manifest => await ServeManifestAsync(route.Name, route.Reference!, headOnly: true, ct),
            OciRouteKind.Blob     => await ServeBlobAsync(route.Name, route.Reference!, headOnly: true, ct),
            _ => OciError(StatusCodes.Status404NotFound, OciErrorCode.UNSUPPORTED, "Unsupported v2 path."),
        };
    }

    // ── Action handlers ────────────────────────────────────────────────────────

    private async Task<IActionResult> ServeManifestAsync(
        string name, string reference, bool headOnly, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null) return auth.Unauthorized;

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID,
                "Invalid repository or reference.");

        var orgId = CurrentTenantId();

        // ── Local cache lookup ─────────────────────────────────────────────────
        // Resolve tag → digest first (returns the reference unchanged if it's already a digest).
        var resolved = await ResolveDigestAsync(orgId, coords, ct);
        if (resolved is not null)
        {
            // xtenant: (digest, org_id) PK is tenant-scoped.
            await using var conn = await _svc.Db.OpenAsync(ct);
            // deepcode ignore Sqli: Dapper binds @digest/@orgId as parameters; SQL string is a constant literal.
            var row = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin)>(
                "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin " +
                "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                new { digest = resolved, orgId });

            if (row.BlobKey is not null)
            {
                var tier   = BlobTierFor(row.Origin);
                var stream = await tier.GetAsync(row.BlobKey, ct);
                if (stream is not null)
                {
                    Response.Headers["Docker-Content-Digest"] = resolved;
                    Response.Headers["Content-Length"]        = row.SizeBytes.ToString();
                    Response.Headers["X-Cache"]               = "HIT";
                    Response.ContentType = row.MediaType;
                    if (headOnly) return Ok();
                    // "download" is the canonical fetch event across ecosystems (npm/PyPI/NuGet)
                    // and the only one the Audit page filter knows; the PURL digest distinguishes
                    // a manifest pull from a layer pull, so a dedicated event name isn't needed.
                    //
                    // OCI is deliberately omitted from the package_versions.download_count counter:
                    // one `docker pull` fans out into a manifest GET plus N layer-blob GETs (which
                    // would multi-count a single pull), and the bare digest PURL logged here doesn't
                    // match the version row's canonical PURL (which carries ?repository_url=…&tag=…).
                    // OCI download volume is still tracked org-wide via these activity rows.
                    await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{resolved}", "download",
                        actorId: auth.Token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
                    return File(stream, row.MediaType!);
                }
                // Blob evicted from store — fall through to upstream.
            }
        }

        // ── Upstream proxy fallback ────────────────────────────────────────────
        var upstreamResult = await _svc.Upstream.FetchManifestAsync(
            orgId, name, reference, coords.IsDigest, ct);
        if (upstreamResult is not null)
        {
            Response.Headers["Docker-Content-Digest"] = upstreamResult.Digest;
            Response.Headers["Content-Length"]        = upstreamResult.SizeBytes.ToString();
            Response.Headers["X-Cache"]               = "MISS";
            Response.ContentType = upstreamResult.MediaType;
            if (headOnly) return Ok();
            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{upstreamResult.Digest}", "download",
                actorId: auth.Token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
            return File(upstreamResult.Content, upstreamResult.MediaType);
        }

        return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
            $"Manifest unknown: {reference}");
    }

    private async Task<IActionResult> ServeBlobAsync(
        string name, string digest, bool headOnly, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null) return auth.Unauthorized;
        if (!OciCoordinatesParser.IsValidRepositoryName(name))
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        if (!OciCoordinatesParser.IsValidDigest(digest))
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID, "Invalid digest format.");

        var orgId = CurrentTenantId();

        // ── Local cache lookup ─────────────────────────────────────────────────
        // xtenant: (digest, org_id) PK is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        // deepcode ignore Sqli: Dapper binds @digest/@orgId as parameters; SQL string is a constant literal.
        var row = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (row.BlobKey is not null)
        {
            var tier   = BlobTierFor(row.Origin);
            var stream = await tier.GetAsync(row.BlobKey, ct);
            if (stream is not null)
            {
                Response.Headers["Docker-Content-Digest"] = digest;
                Response.Headers["Content-Length"]        = row.SizeBytes.ToString();
                Response.Headers["X-Cache"]               = "HIT";
                Response.ContentType = row.MediaType;
                if (headOnly) return Ok();
                await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{digest}", "download",
                    actorId: auth.Token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
                return File(stream, row.MediaType!);
            }
            // Blob evicted — fall through to upstream.
        }

        // ── Upstream proxy fallback ────────────────────────────────────────────
        var upstreamResult = await _svc.Upstream.FetchBlobAsync(orgId, name, digest, ct);
        if (upstreamResult is not null)
        {
            Response.Headers["Docker-Content-Digest"] = digest;
            Response.Headers["X-Cache"]               = "MISS";
            Response.ContentType = upstreamResult.MediaType;
            if (headOnly) return Ok();
            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{digest}", "download",
                actorId: auth.Token?.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
            return File(upstreamResult.Content, upstreamResult.MediaType);
        }

        return OciError(StatusCodes.Status404NotFound, OciErrorCode.BLOB_UNKNOWN, $"Blob unknown: {digest}");
    }

    private async Task<IActionResult> ListTagsAsync(string name, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null) return auth.Unauthorized;
        if (!OciCoordinatesParser.IsValidRepositoryName(name))
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");

        var orgId = CurrentTenantId();

        // ── Local tag list ─────────────────────────────────────────────────────
        // xtenant: (org_id, repository) index is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var localTags = (await conn.QueryAsync<string>(
            "SELECT tag FROM oci_tags WHERE org_id = @orgId AND repository = @repo ORDER BY tag ASC",
            new { orgId, repo = name })).ToList();

        if (localTags.Count > 0)
            return new JsonResult(new { name, tags = localTags });

        // ── Upstream fallback ──────────────────────────────────────────────────
        var upstreamTags = await _svc.Upstream.FetchTagsAsync(name, ct);
        if (upstreamTags is { Count: > 0 })
            return new JsonResult(new { name, tags = upstreamTags });

        return OciError(StatusCodes.Status404NotFound, OciErrorCode.NAME_UNKNOWN, "Repository unknown.");
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task<(TokenRecord? Token, IActionResult? Unauthorized)> AuthorizePullAsync(CancellationToken ct)
    {
        var orgId    = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token    = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\",service=\"v2\"";
            return (null, OciError(StatusCodes.Status401Unauthorized, OciErrorCode.UNAUTHORIZED,
                "Authentication required."));
        }
        return (token, null);
    }

    private async Task<string?> ResolveDigestAsync(string orgId, OciCoordinates coords, CancellationToken ct)
    {
        if (coords.IsDigest) return coords.Reference;
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
        if (string.IsNullOrWhiteSpace(path)) return null;
        path = path.Trim('/');

        // Tags list: trailing "/tags/list".
        const string tagsSuffix = "/tags/list";
        if (path.EndsWith(tagsSuffix, StringComparison.Ordinal))
        {
            var name = path[..^tagsSuffix.Length];
            return name.Length > 0 ? new OciRoute(OciRouteKind.TagsList, name, null) : null;
        }

        // Manifests: "/manifests/{reference}" somewhere after the repo name.
        const string manifestsMarker = "/manifests/";
        var manifestsIdx = path.IndexOf(manifestsMarker, StringComparison.Ordinal);
        if (manifestsIdx > 0)
        {
            var name      = path[..manifestsIdx];
            var reference = path[(manifestsIdx + manifestsMarker.Length)..];
            return reference.Length > 0 ? new OciRoute(OciRouteKind.Manifest, name, reference) : null;
        }

        // Blobs: "/blobs/{digest}" somewhere after the repo name.
        const string blobsMarker = "/blobs/";
        var blobsIdx = path.IndexOf(blobsMarker, StringComparison.Ordinal);
        if (blobsIdx > 0)
        {
            var name   = path[..blobsIdx];
            var digest = path[(blobsIdx + blobsMarker.Length)..];
            // Reject blob upload sub-paths (/blobs/uploads/...) — push is not implemented.
            if (digest.StartsWith("uploads", StringComparison.Ordinal)) return null;
            return digest.Length > 0 ? new OciRoute(OciRouteKind.Blob, name, digest) : null;
        }

        return null;
    }
}

internal enum OciRouteKind { Manifest, Blob, TagsList }

/// <summary>Scoped DI bundle for the OCI controller.</summary>
public sealed record OciControllerServices(
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    TieredBlobStorage BlobStore,
    IMetadataStore Db,
    OciUpstreamResolver Upstream);
