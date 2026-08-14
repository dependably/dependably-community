using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Admin CRUD on package-name claims. The state machine lives in
/// <see cref="ClaimStateMachine"/>; the persistence in <see cref="ClaimRepository"/>;
/// this controller is a thin HTTP wrapper that authorises (admin role), validates input,
/// runs the transition through the state machine, persists the result, and emits the
/// audit event.
///
/// Route surface:
/// <list type="bullet">
///   <item>GET    /api/v1/admin/claims                         — list, filter by ecosystem/state/search</item>
///   <item>GET    /api/v1/admin/claims/{ecosystem}/{name}      — single claim</item>
///   <item>POST   /api/v1/admin/claims                         — create from unclaimed</item>
///   <item>PATCH  /api/v1/admin/claims/{ecosystem}/{name}      — transition state</item>
///   <item>DELETE /api/v1/admin/claims/{ecosystem}/{name}      — release back to unclaimed</item>
///   <item>POST   /api/v1/admin/claims/bulk                    — claim a list of names at once</item>
/// </list>
/// Cache purging on transitions to <c>local_only</c> runs synchronously through
/// <see cref="PurgeProxyArtefactsAsync"/>: every cached proxy version for the name is dropped
/// across both catalogues — legacy <c>origin = 'proxy'</c> rows on the uploaded plane and the
/// org's <c>tenant_artifact_access</c> rows on the shared cache plane — and each dereferenced
/// blob best-effort deleted <em>after</em> the claim transition is persisted. Persisting first
/// closes the window (present when purge ran first) where a proxy fetch landing between the
/// purge and the persist could read the still-old claim state, re-fetch, and repopulate the
/// cache with a row no later purge would ever remove — an in-flight fetch that re-checks the
/// claim after this point observes <c>local_only</c> immediately. The purged count is folded
/// into <c>claim_history.purged_count</c> (via a follow-up update once the purge completes) and
/// the response body so the UI can report what changed. Imported / private artefacts are never
/// touched.
/// </summary>
[ApiController]
[Authorize]
public sealed class ClaimsController : ControllerBase
{
    private readonly OrgAccessGuard _guard;
    private readonly ClaimRepository _claims;
    private readonly ClaimResolver _resolver;
    private readonly AuditRepository _audit;
    private readonly Dependably.Infrastructure.Audit.IAuditEmitter _auditEmitter;
    private readonly PackageRepository _packages;
    private readonly CacheArtifactRepository _cache;
    private readonly Dependably.Infrastructure.CacheOrphanBlobDeleter _cacheOrphanBlobs;
    private readonly Dependably.Storage.IBlobStore _blobs;
    private readonly ILogger<ClaimsController> _logger;
    private readonly TimeProvider _time;

    public ClaimsController(ClaimsControllerServices svc)
    {
        _guard = svc.Guard;
        _claims = svc.Claims;
        _resolver = svc.Resolver;
        _audit = svc.Audit;
        _auditEmitter = svc.AuditEmitter;
        _packages = svc.Packages;
        _cache = svc.Cache;
        _cacheOrphanBlobs = svc.CacheOrphanBlobs;
        _blobs = svc.Blobs;
        _logger = svc.Logger;
        _time = svc.Time;
    }

    /// <summary>
    /// When a transition flips the claim into <c>local_only</c>, every cached proxy
    /// version for that name must be evicted — both the metadata row and the underlying
    /// blob — so subsequent installs are forced through the local-only artefact set rather
    /// than serving a stale proxy copy. A proxied artefact reaches the org through either
    /// catalogue, so both are purged: legacy <c>origin='proxy'</c> rows on the uploaded plane
    /// and the org's <c>tenant_artifact_access</c> rows on the shared cache plane (where every
    /// current proxy fetch lands). Purging only the uploaded plane would leave the cached copy
    /// still advertised and served for every ecosystem whose proxy artefacts live on the cache
    /// plane. Returns the total versions evicted across both planes for the audit/history record.
    /// Blob deletes are best-effort: a failed delete logs a warning but does not fail the
    /// transition (the row is already gone, so the storage entry is dereferenced garbage).
    /// The cache-plane blob keys are content-addressed and shared across every coordinate with
    /// byte-identical upstream bytes, so each goes through
    /// <see cref="Dependably.Infrastructure.CacheOrphanBlobDeleter"/>'s locked refcount guard
    /// rather than an unconditional delete — a sibling coordinate that still shares the same key
    /// keeps its blob. The uploaded plane carries both namespaces, so it routes each key by shape
    /// through <see cref="DeleteUploadedPlaneBlobAsync"/>.
    /// </summary>
    private async Task<int> PurgeProxyArtefactsAsync(
        string orgId, string ecosystem, string name, CancellationToken ct)
    {
        var uploadedBlobKeys = await _packages.DeleteProxyVersionsForNameAsync(orgId, ecosystem, name, ct);
        var cacheEviction = await _cache.EvictTenantProxyVersionsForNameAsync(orgId, ecosystem, name, ct);

        foreach (string key in uploadedBlobKeys)
        {
            try { await DeleteUploadedPlaneBlobAsync(key, ct); }
            catch (Exception ex)
            {
                // Serilog RenderedCompactJsonFormatter JSON-encodes property
                // values, so CRLF in tenant-route inputs (org/ecosystem/name) cannot break the log envelope.
                _logger.LogWarning(ex,
                    "Failed to delete proxy blob {BlobKey} during local_only purge for {Org}/{Ecosystem}/{Name}.",
                    key, orgId, ecosystem, name);
            }
        }

        foreach (string key in cacheEviction.DereferencedBlobKeys)
        {
            try
            {
                // The cache_artifact row that referenced this key is already gone — deleted
                // inside EvictTenantProxyVersionsForNameAsync's own transaction — so there is no
                // row left to exclude from the shared-key count; string.Empty can never match a
                // real (GUID) id and so excludes nothing. The store key is the DB key verbatim,
                // matching this path's delete target before this guard existed.
                await _cacheOrphanBlobs.DeleteIfUnreferencedAsync(key, string.Empty, key, _blobs, ct);
            }
            catch (Exception ex)
            {
                // Serilog RenderedCompactJsonFormatter JSON-encodes property
                // values, so CRLF in tenant-route inputs (org/ecosystem/name) cannot break the log envelope.
                _logger.LogWarning(ex,
                    "Failed to delete proxy blob {BlobKey} during local_only purge for {Org}/{Ecosystem}/{Name}.",
                    key, orgId, ecosystem, name);
            }
        }
        return uploadedBlobKeys.Count + cacheEviction.VersionsEvicted;
    }

    /// <summary>
    /// Deletes one blob dereferenced by a legacy <c>origin = 'proxy'</c> <c>package_versions</c>
    /// row. Three key shapes reach this loop and each needs different handling:
    /// <list type="bullet">
    ///   <item>An org-namespaced key (<c>hosted/{orgId}/…</c>, and the
    ///   <c>go|cargo|apk|terraform/{orgId}/…</c> proxy shapes) belongs to this org alone and comes
    ///   off unconditionally — no other tenant can reference it.</item>
    ///   <item><c>proxy/{sha256}</c> is content-addressed with no org segment, so the identical
    ///   key is what every other tenant's cache-plane row for byte-identical content records.
    ///   Deleting it outright turns one org's claim transition into a serve-time 404 for every
    ///   tenant still holding that artifact, so it goes through the same locked refcount guard the
    ///   cache-plane loop above uses. The store key stays the DB key verbatim, leaving the delete
    ///   target exactly what it was and adding only the guard.</item>
    ///   <item><c>oci/{algo}/{hex}</c> is content-addressed too, but its references live in
    ///   <c>oci_blobs</c>/<c>oci_tags</c>, which the cache-plane refcount cannot see — a
    ///   cache-guarded delete would still strand another tenant's manifest. Physical reclaim of an
    ///   OCI digest belongs to <see cref="Dependably.Protocol.OciBlobReclaimer"/>, which frees it
    ///   only once every claim on it is gone, so this path leaves those bytes alone.</item>
    /// </list>
    /// </summary>
    private async Task DeleteUploadedPlaneBlobAsync(string key, CancellationToken ct)
    {
        if (key.StartsWith("oci/", StringComparison.Ordinal))
        {
            return;
        }

        if (key.StartsWith("proxy/", StringComparison.Ordinal))
        {
            // The package_versions row referencing this key is already gone (deleted inside
            // DeleteProxyVersionsForNameAsync), and string.Empty can never match a real
            // cache_artifact id, so nothing is excluded from the shared-key count.
            await _cacheOrphanBlobs.DeleteIfUnreferencedAsync(key, string.Empty, key, _blobs, ct);
            return;
        }

        await _blobs.DeleteAsync(key, ct);
    }

    /// <summary>GET /api/v1/admin/claims</summary>
    // claim:manage (not read:claims) matches what AuthorizeAsync enforces below — the claims
    // admin surface is manager-only, reads included. Accepts a PAT/service token carrying
    // claim:manage; the gate is unchanged, only the accepted authentication scheme widens.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("/api/v1/admin/claims")]
    [RequireCapability(Capabilities.ClaimManage)]
    public async Task<IActionResult> List(
        [FromQuery] string? ecosystem,
        [FromQuery] string? state,
        [FromQuery] string? search,
        [FromQuery] int limit = 100,
        CancellationToken ct = default)
    {
        var (Error, OrgId, _) = await AuthorizeAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var rows = await _claims.ListAsync(OrgId!, ecosystem, state, search,
            limit: Math.Clamp(limit, 1, 500), ct);
        return Ok(new { items = rows.Select(ToDto), total = rows.Count });
    }

    /// <summary>GET /api/v1/admin/claims/{ecosystem}/{name}</summary>
    // claim:manage (not read:claims) matches what AuthorizeAsync enforces below — the claims
    // admin surface is manager-only, reads included. Accepts a PAT/service token carrying
    // claim:manage; the gate is unchanged, only the accepted authentication scheme widens.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("/api/v1/admin/claims/{ecosystem}/{name}")]
    [RequireCapability(Capabilities.ClaimManage)]
    public async Task<IActionResult> Get(string ecosystem, string name, CancellationToken ct)
    {
        var (Error, OrgId, _) = await AuthorizeAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        string canonicalEcosystem = ecosystem.ToLowerInvariant();
        string canonicalName = PurlNormalizer.CanonicalName(canonicalEcosystem, name);
        var eff = await _resolver.ResolveAsync(OrgId!, canonicalEcosystem, canonicalName, ct);
        return Ok(new
        {
            ecosystem = canonicalEcosystem,
            name = canonicalName,
            state = eff.State,
            isImplicit = eff.IsImplicit,
            claim = eff.Row is null ? null : ToDto(eff.Row),
        });
    }

    /// <summary>POST /api/v1/admin/claims — create a claim from unclaimed.</summary>
    [HttpPost("/api/v1/admin/claims")]
    [RequireCapability(Capabilities.ClaimManage)]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> Create(
        [FromBody] CreateClaimRequest req, CancellationToken ct)
    {
        var (Error, OrgId, ActorId) = await AuthorizeAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var (validationError, ecosystem, name, validation) = await ValidateCreateRequestAsync(req, OrgId!, ct);
        if (validationError is not null)
        {
            return validationError;
        }

        var tx = new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString("D"),
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = OrgId!,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = req.State,
            Reason = req.Reason!,
            ActorId = ActorId,
            OccurredAt = _time.GetUtcNow(),
            PurgedCount = 0,
        };
        // Persist the claim transition BEFORE purging cached proxy artefacts (see the class
        // doc comment for the race this ordering closes). purged_count starts at 0 in this
        // insert and is patched to the real count once the purge below completes. A tombstoned
        // (soft-deleted) row for this name is revived in place by ApplyTransitionAsync; only a
        // race against a still-live claim (the check above already ruled out the common case)
        // reaches ClaimConflictException here.
        try
        {
            await _claims.ApplyTransitionAsync(tx, ct);
        }
        catch (ClaimConflictException)
        {
            return Conflict(new ProblemDetails
            {
                Status = StatusCodes.Status409Conflict,
                Detail = $"Claim already exists for {ecosystem}/{name}. Use PATCH to transition.",
            });
        }

        int purgedCount = validation.PurgesProxy
            ? await PurgeProxyArtefactsAsync(OrgId!, ecosystem, name, ct)
            : 0;
        if (purgedCount > 0)
        {
            await _claims.UpdateHistoryPurgedCountAsync(tx.HistoryId, purgedCount, ct);
        }
        string createDetail = $"{{\"state\":\"{req.State}\"," +
            $"\"reason\":{System.Text.Json.JsonSerializer.Serialize(req.Reason, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail)}," +
            $"\"purged\":{purgedCount}}}";
        await _audit.LogAsync("claim.create", OrgId, ActorId,
            actorKind: ActorKinds.User,
            ecosystem: ecosystem,
            purl: PurlNormalizer.NameOnly(ecosystem, name),
            detail: createDetail,
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        // Typed event into audit_event.
        string createPayload = new Dependably.Infrastructure.Audit.Events.ClaimEvents.Create(
            ecosystem, name, req.State!, req.Reason!, validation.PurgesProxy).ToJson();
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.ClaimEvents.TypeCreate,
            OrgId, "user", ActorId, "accepted", createPayload, ct);

        var created = await _claims.GetAsync(OrgId!, ecosystem, name, ct);
        return Created($"/api/v1/admin/claims/{ecosystem}/{name}", new
        {
            claim = ToDto(created!),
            purgesProxy = validation.PurgesProxy,
            purgedCount,
        });
    }

    // Validates the create request body, the ecosystem/name, that no live claim already exists
    // for the coordinate, and the requested target state against the claim state machine. Returns
    // the first failing IActionResult, or null with the resolved ecosystem/name/validation result
    // once every check passes.
    private async Task<(IActionResult? Error, string Ecosystem, string Name, ClaimTransitionResult Validation)>
        ValidateCreateRequestAsync(CreateClaimRequest req, string orgId, CancellationToken ct)
    {
        if (req is null)
        {
            return (BadRequest("Body required."), "", "", default);
        }

        if (string.IsNullOrWhiteSpace(req.Reason))
        {
            return (BadRequest("reason is required."), "", "", default);
        }

        string ecosystem = req.Ecosystem?.ToLowerInvariant() ?? "";
        if (!ClaimEcosystems.Enforced.Contains(ecosystem))
        {
            return (BadRequest(ClaimEcosystems.IsClaimAware(ecosystem)
                ? $"claims are not enforced for the '{ecosystem}' ecosystem — no data path consults them, so a claim would be a silent no-op. Accepted: {ClaimEcosystems.AcceptedList}."
                : $"ecosystem must be one of: {ClaimEcosystems.AcceptedList}."), "", "", default);
        }

        string name = PurlNormalizer.CanonicalName(ecosystem, req.Name ?? "");
        if (string.IsNullOrEmpty(name))
        {
            return (BadRequest("name is required."), "", "", default);
        }

        var existing = await _claims.GetAsync(orgId, ecosystem, name, ct);
        if (existing is not null)
        {
            return (Conflict(new ProblemDetails
            {
                Status = StatusCodes.Status409Conflict,
                Detail = $"Claim already exists for {ecosystem}/{name} (state: {existing.State}). " +
                         "Use PATCH to transition.",
            }), "", "", default);
        }

        var validation = ClaimStateMachine.ValidateCreate(req.State ?? "");
        if (!validation.Allowed)
        {
            return (BadRequest(new ProblemDetails { Status = StatusCodes.Status400BadRequest, Detail = validation.RejectionReason }), "", "", default);
        }

        return (null, ecosystem, name, validation);
    }

    /// <summary>PATCH /api/v1/admin/claims/{ecosystem}/{name} — transition state.</summary>
    [HttpPatch("/api/v1/admin/claims/{ecosystem}/{name}")]
    [RequireCapability(Capabilities.ClaimManage)]
    public async Task<IActionResult> Transition(
        string ecosystem, string name,
        [FromBody] TransitionClaimRequest req, CancellationToken ct)
    {
        var (Error, OrgId, ActorId) = await AuthorizeAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        if (req is null || string.IsNullOrWhiteSpace(req.State) || string.IsNullOrWhiteSpace(req.Reason))
        {
            return BadRequest("state and reason are required.");
        }

        ecosystem = ecosystem.ToLowerInvariant();
        name = PurlNormalizer.CanonicalName(ecosystem, name);

        var existing = await _claims.GetAsync(OrgId!, ecosystem, name, ct);
        if (existing is null)
        {
            return NotFound();
        }

        var validation = ClaimStateMachine.ValidateChange(existing.State, req.State!);
        if (!validation.Allowed)
        {
            return BadRequest(new ProblemDetails { Status = StatusCodes.Status400BadRequest, Detail = validation.RejectionReason });
        }

        var tx = new ClaimTransition
        {
            ClaimId = existing.Id,
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = OrgId!,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = existing.State,
            NewState = req.State,
            Reason = req.Reason!,
            ActorId = ActorId,
            OccurredAt = _time.GetUtcNow(),
            PurgedCount = 0,
        };
        // Persist on mixed → local_only BEFORE purging. See Create / the class doc comment
        // for the purge-after-persist rationale.
        await _claims.ApplyTransitionAsync(tx, ct);

        int purgedCount = validation.PurgesProxy
            ? await PurgeProxyArtefactsAsync(OrgId!, ecosystem, name, ct)
            : 0;
        if (purgedCount > 0)
        {
            await _claims.UpdateHistoryPurgedCountAsync(tx.HistoryId, purgedCount, ct);
        }
        await _audit.LogAsync("claim.transition", OrgId, ActorId,
            actorKind: ActorKinds.User,
            ecosystem: ecosystem,
            purl: PurlNormalizer.NameOnly(ecosystem, name),
            detail: $"{{\"from\":\"{existing.State}\",\"to\":\"{req.State}\",\"purged\":{purgedCount}}}",
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        string transitionPayload = new Dependably.Infrastructure.Audit.Events.ClaimEvents.Transition(
            ecosystem, name, existing.State, req.State!, req.Reason!, validation.PurgesProxy).ToJson();
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.ClaimEvents.TypeTransition,
            OrgId, "user", ActorId, "accepted", transitionPayload, ct);

        var updated = await _claims.GetAsync(OrgId!, ecosystem, name, ct);
        return Ok(new { claim = ToDto(updated!), purgesProxy = validation.PurgesProxy, purgedCount });
    }

    /// <summary>DELETE /api/v1/admin/claims/{ecosystem}/{name} — release back to unclaimed.</summary>
    [HttpDelete("/api/v1/admin/claims/{ecosystem}/{name}")]
    [RequireCapability(Capabilities.ClaimManage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Release(
        string ecosystem, string name,
        [FromQuery] string? reason, CancellationToken ct)
    {
        var (Error, OrgId, ActorId) = await AuthorizeAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        ecosystem = ecosystem.ToLowerInvariant();
        name = PurlNormalizer.CanonicalName(ecosystem, name);

        var existing = await _claims.GetAsync(OrgId!, ecosystem, name, ct);
        if (existing is null)
        {
            return NotFound();
        }

        int localCount = await _claims.CountLocalVersionsAsync(OrgId!, ecosystem, name, ct);
        var validation = ClaimStateMachine.ValidateRelease(existing.State, localCount);
        if (!validation.Allowed)
        {
            return Conflict(new ProblemDetails
            {
                Status = StatusCodes.Status409Conflict,
                Detail = validation.RejectionReason,
                Extensions = { ["localVersionCount"] = localCount }
            });
        }

        var tx = new ClaimTransition
        {
            ClaimId = existing.Id,
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = OrgId!,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = existing.State,
            NewState = null,
            Reason = reason ?? "released",
            ActorId = ActorId,
            OccurredAt = _time.GetUtcNow(),
        };
        await _claims.ApplyTransitionAsync(tx, ct);
        await _audit.LogAsync("claim.release", OrgId, ActorId,
            actorKind: ActorKinds.User,
            ecosystem: ecosystem,
            purl: PurlNormalizer.NameOnly(ecosystem, name),
            detail: $"{{\"from\":\"{existing.State}\"}}",
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        string releasePayload = new Dependably.Infrastructure.Audit.Events.ClaimEvents.Release(
            ecosystem, name, existing.State, reason ?? "released", localCount).ToJson();
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.ClaimEvents.TypeRelease,
            OrgId, "user", ActorId, "accepted", releasePayload, ct);


        return NoContent();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<(IActionResult? Error, string? OrgId, string? ActorId)> AuthorizeAsync(CancellationToken ct)
    {
        var deny = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ClaimManage, ct);
        if (deny is not null)
        {
            return (deny, null, null);
        }

        var ctx = (TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!;
        string? actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? User.FindFirst("sub")?.Value;
        return (null, ctx.TenantId, actorId);
    }

    private static object ToDto(NameClaim c) => new
    {
        id = c.Id,
        ecosystem = c.Ecosystem,
        name = c.Name,
        state = c.State,
        reason = c.Reason,
        createdBy = c.CreatedBy,
        createdAt = c.CreatedAt,
        updatedAt = c.UpdatedAt,
    };
}

public sealed record CreateClaimRequest(string? Ecosystem, string? Name, string? State, string? Reason);
public sealed record TransitionClaimRequest(string? State, string? Reason);

public sealed record ClaimsControllerServices(
    OrgAccessGuard Guard,
    ClaimRepository Claims,
    ClaimResolver Resolver,
    AuditRepository Audit,
    Dependably.Infrastructure.Audit.IAuditEmitter AuditEmitter,
    PackageRepository Packages,
    CacheArtifactRepository Cache,
    Dependably.Infrastructure.CacheOrphanBlobDeleter CacheOrphanBlobs,
    Dependably.Storage.IBlobStore Blobs,
    ILogger<ClaimsController> Logger,
    TimeProvider Time);
