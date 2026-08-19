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

    /// <param name="allowPushProbe">
    /// Additionally admits a token holding <see cref="Capabilities.PublishOci"/>. The OCI push
    /// protocol reads through this same gate before it writes anything — a blob HEAD
    /// existence/cross-mount probe, and a manifest HEAD/GET to resolve a tag or skip
    /// re-pushing a digest already present — and dependably ships publish-only OCI tokens
    /// with no read capability at all (the web token modal's "push" preset mints exactly
    /// <c>publish:*</c>). Set only on the two call sites those probes actually reach: the
    /// manifest read path (both GET and HEAD) and the blob read path's HEAD form. It is
    /// deliberately <b>not</b> set for blob GET (full layer content — the substantive image
    /// bytes push never needs to read back), tag list, or the referrers list: none of those
    /// are steps a push performs, and admitting them would hand a publish-only token the
    /// general pull/enumerate licence this gate exists to deny.
    /// </param>
    private async Task<(TokenRecord? Token, IActionResult? Unauthorized)> AuthorizePullAsync(
        CancellationToken ct, bool allowPushProbe = false)
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
        // A presented token must carry a read-capable scope: either the OCI-specific
        // pull:oci (minted for a narrow, pull-only token) or the cross-ecosystem
        // read:artifact that every reader/admin/owner role already grants. Without this
        // check any active token — regardless of what it was scoped for — pulls every
        // hosted and proxied image in the org, since ResolveTokenAsync only validates
        // that the token is active and belongs to the tenant. See allowPushProbe above for
        // the narrow publish:oci exception admitted on the push protocol's own read probes.
        if (token is not null
            && !token.HasCapability(Capabilities.PullOci)
            && !token.HasCapability(Capabilities.ReadArtifact)
            && !(allowPushProbe && token.HasCapability(Capabilities.PublishOci)))
        {
            return (null, await DenyInsufficientScopeAsync(
                token, "pull:oci or read:artifact", "pull", ct));
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
            return (null, await DenyInsufficientScopeAsync(token, Capabilities.PublishOci, "push", ct));
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
            return (null, await DenyInsufficientScopeAsync(token, Capabilities.YankOci, "yank", ct));
        }

        return (token, null);
    }

    /// <summary>
    /// The OCI plane's license block-gate arm, shared by the manifest and blob read paths.
    /// Returns a 403 result when the tenant enforces licenses in 'block' mode and the SPDX
    /// expression captured on this <c>oci_blobs</c> row fails the policy; returns <c>null</c>
    /// (serve) otherwise — including whenever the row carries no captured expression, which is
    /// every layer and config blob.
    ///
    /// <para>
    /// Both read paths run it because both can return the same bytes: a manifest is reachable at
    /// <c>/v2/{name}/manifests/{ref}</c> and, by its digest, at <c>/v2/{name}/blobs/{digest}</c>.
    /// Gating only the first would leave the second as an ungated route to a blocked image's
    /// manifest, and would leave the presigned-redirect path issuing a URL for content the
    /// streaming path refuses.
    /// </para>
    /// </summary>
    private async Task<IActionResult?> EvaluateLicenseBlockAsync(
        string orgId, string purl, string? licenseSpdx, TokenRecord? token, CancellationToken ct)
    {
        if (licenseSpdx is null)
        {
            return null;
        }

        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        if (settings?.LicenseEnforcementMode != "block")
        {
            return null;
        }

        // gate-request-ok: not a download block-gate request. EvaluateLicenseExpressionAsync
        // reads only the licence policy and the expression handed to it, so the remaining
        // arms have nothing to act on; a factory here would thread a dozen fields into a
        // call that reads one.
        var gate = new BlockGateRequest(
            OrgId: orgId,
            Ecosystem: "oci",
            Purl: purl,
            VersionId: "",
            ManualState: null,
            VulnCheckedAt: null,
            AuditActorId: token?.AuditActorId, AuditActorLabel: token?.AuditActorLabel,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            SourceIp: HttpContext.GetNormalizedRemoteIp(),
            ActorKind: token?.ActorKind,
            LicenseEnforcementMode: settings.LicenseEnforcementMode);

        if (await _svc.BlockGate.EvaluateLicenseExpressionAsync(gate, [licenseSpdx], ct) != BlockDecision.Blocked)
        {
            return null;
        }

        // OCI already carries a spec-shaped error body, so the header is additive rather than the
        // only signal — but it keeps one refusal spelled the same way across every ecosystem, which
        // is what makes an operator's header-based diagnosis portable.
        HttpContext.Response.Headers[BlockRefusalResult.ReasonHeader] =
            new BlockOutcome(BlockDecision.Blocked, BlockArm.License).ReasonToken;

        return OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
            "Image license is blocked by the organization's license policy.");
    }

    /// <summary>
    /// Resolves an OCI reference to the digest held locally, together with the tag entry's
    /// <c>last_revalidated</c> stamp so the caller can judge whether a mutable reference is
    /// still fresh. <c>Digest</c> is null when nothing is held locally.
    ///
    /// <para>
    /// A digest reference resolves to itself and carries no stamp — it is content-addressed and
    /// has no expiry. Only a tag needs the stamp, because only a tag can be repointed upstream.
    /// </para>
    /// </summary>
    private async Task<LocalReference> ResolveDigestAsync(string orgId, OciCoordinates coords, CancellationToken ct)
    {
        if (coords.IsDigest)
        {
            return new LocalReference(coords.Reference, null);
        }

        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = coords.Repository, tag = coords.Reference });
        return new LocalReference(Digest, LastRevalidated);
    }

    /// <summary>
    /// A reference resolved against local state: the digest it names (null when not held here),
    /// and the <c>oci_tags.last_revalidated</c> stamp when it was reached through a tag.
    /// </summary>
    private readonly record struct LocalReference(string? Digest, string? LastRevalidated);

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

    /// <summary>
    /// True when <paramref name="ex"/> is the upstream failing to serve — rather than a fault in
    /// this registry (a bug here stays a 500) or a definitive upstream miss (a 404). Three
    /// shapes qualify: the transport layer failing (DNS, connect, TLS, read timeout); the
    /// upstream answering with an error status (<see cref="OciUpstreamUnavailableException"/> —
    /// a 429 or 5xx, which must never masquerade as MANIFEST_UNKNOWN); and the token-exchange
    /// endpoint refusing or failing (<see cref="OciUnauthorizedException"/> — e.g.
    /// auth.docker.io returning 429/503, or an untrusted challenge realm), which without this
    /// classification would surface as an unhandled 500 on the pull path.
    ///
    /// <para>
    /// A caller-cancelled request is deliberately excluded: when <paramref name="ct"/> is already
    /// cancelled the client hung up, and there is nobody to send a status to. Swallowing that as an
    /// upstream failure would report a client disconnect as an upstream outage in the logs and the
    /// metrics, which is the sort of noise that makes a real outage harder to see.
    /// </para>
    /// </summary>
    private static bool IsUpstreamFailure(Exception ex, CancellationToken ct) =>
        !ct.IsCancellationRequested
        && ex is HttpRequestException
            or System.Net.Sockets.SocketException
            or System.Security.Authentication.AuthenticationException
            or TaskCanceledException   // HttpClient surfaces its own timeout as this
            or OciUpstreamUnavailableException
            or OciUnauthorizedException;

    /// <summary>
    /// The answer when a configured upstream could not be reached: 502, not 500.
    ///
    /// <para>
    /// The distinction matters to the caller. 500 says "this registry is broken" — a client cannot
    /// tell whether retrying helps, and an operator starts looking in the wrong place. 502 says the
    /// gateway's upstream failed, which is exactly what happened and is worth retrying. The
    /// exception is logged with the repository and reference so the next occurrence is diagnosable
    /// from the log alone rather than from a status code with no context.
    /// </para>
    /// </summary>
    private ObjectResult UpstreamUnreachable(Exception ex, string name, string reference)
    {
        _logger.LogWarning(ex,
            "OCI upstream unreachable while resolving {Repository}/{Reference}: {ExceptionType}",
            name, reference, ex.GetType().Name);

        return OciError(StatusCodes.Status502BadGateway, OciErrorCode.UNAVAILABLE,
            $"Upstream registry unreachable while resolving {reference}.");
    }

    private static ObjectResult OciError(
        int statusCode, OciErrorCode code, string message, object? detail = null)
    {
        var body = new OciErrorResponse(new[] { new OciError(code, message, detail) });
        return new ObjectResult(body) { StatusCode = statusCode };
    }

    /// <summary>
    /// Builds — and records — the 403 for a capability-gated v2 route.
    ///
    /// <para>
    /// The failure this has to stay diagnosable for is not "the token is scoped wrong" — it is
    /// "the client presented a different credential than the operator believes it did". That one
    /// is invisible from the client: <c>docker login</c> succeeds either way, because the
    /// <c>/v2/</c> ping checks only that a token resolves and runs no capability check at all,
    /// and a read-scoped token additionally clears the blob HEAD probes a push issues before each
    /// layer. A <c>~/.docker/config.json</c> holding two entries for the same host, or a CI
    /// variable whose value drifted from the token it is named after, both land here. So the
    /// response names <b>which</b> credential was refused — never what it can do.
    /// </para>
    ///
    /// <para>
    /// The granted capability set is deliberately <b>not</b> on the wire. <c>/v2/</c> is a public
    /// protocol surface and its error bodies travel further than the credential ever did — into
    /// CI job logs, screenshots, support tickets. Enumerating a token's powers there also hands a
    /// holder of a stolen token in one silent response what they would otherwise have to sweep
    /// endpoints to learn, and that sweep is exactly the noise the rate limiter and the audit log
    /// exist to catch. The full set goes to the Serilog line and the audit row instead, both of
    /// which are operator-side. The token reference is a truncated database key, never the
    /// secret, and identifies without disclosing.
    /// </para>
    ///
    /// <para>
    /// The denial is audited so an operator can answer "which credential was refused, and what
    /// did it carry" when the client-side log belongs to somebody else's CI job — resolving the
    /// trace ref the client did get. Reaching this line requires a live, in-tenant token, so it
    /// is a tenant writing to its own audit log, under the <c>push</c> limiter's ceiling and the
    /// retention sweep's horizon.
    /// </para>
    /// </summary>
    private async Task<ObjectResult> DenyInsufficientScopeAsync(
        TokenRecord token, string requiredLabel, string route, CancellationToken ct)
    {
        string[] granted = token.CapabilitySet
            .OrderBy(c => c, StringComparer.Ordinal)
            .ToArray();
        string grantedLabel = granted.Length == 0 ? "none" : string.Join(", ", granted);
        string tokenRef = TokenReference(token.Id);
        string? traceId = System.Diagnostics.Activity.Current?.TraceId.ToString();

        // Always logged, at most once per cooldown window audited. The log line is per-request
        // because log volume is already bounded by retention and rotation; the audit row is not.
        _logger.LogWarning(
            "OCI {Route} denied for token {TokenId} in org {OrgId}: requires {Required}, token grants {Granted}. TraceId={TraceId}",
            route, token.Id, token.OrgId, requiredLabel, grantedLabel, traceId);

        if (_svc.DenialAudit.ShouldAudit(token.OrgId, token.Id, route))
        {
            try
            {
                await _svc.Audit.LogAsync(
                    "oci.scope_denied",
                    orgId: token.OrgId,
                    actorId: token.AuditActorId,
                    actorKind: token.ActorKind,
                    ecosystem: "oci",
                    detail: $"{route} requires {requiredLabel}; token grants {grantedLabel}",
                    sourceIp: HttpContext.GetNormalizedRemoteIp(),
                    actorLabel: token.AuditActorLabel,
                    ct: ct);
            }
            catch (Exception ex)
            {
                // The 403 is the security decision and it has already been made; a failed audit
                // write must not convert a correct denial into a 500 the client reads as a
                // server fault worth retrying.
                _logger.LogWarning(ex,
                    "{ExceptionType} writing the OCI {Route} denial audit row for token {TokenId}",
                    ex.GetType().Name, route, token.Id);
            }
        }

        string locator = traceId is null
            ? $"token {tokenRef}…"
            : $"token {tokenRef}…, ref {traceId}";

        return OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
            $"Insufficient scope: {requiredLabel} required ({locator}).",
            new { required = requiredLabel, tokenRef, traceId });
    }

    /// <summary>
    /// The leading segment of a token's database id — enough for an operator to tell two
    /// credentials apart in a job log, short enough that the response is not republishing a
    /// whole internal key. Ids are 32-hex-character GUIDs, so eight characters distinguish any
    /// pair of tokens a tenant realistically holds.
    /// </summary>
    private static string TokenReference(string tokenId) =>
        tokenId.Length <= 8 ? tokenId : tokenId[..8];
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
    TenantArtifactAccessRepository TenantArtifactAccess,
    Dependably.Security.AuthDenialAuditCoalescer DenialAudit,
    Dependably.Security.NameBindingGate? NameBinding = null,
    BlobPresignService? Presign = null);
