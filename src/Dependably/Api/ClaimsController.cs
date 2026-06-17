using System.Security.Claims;
using Dependably.Infrastructure;
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
/// <see cref="PurgeProxyArtefactsAsync"/>: every <c>origin = 'proxy'</c> version row for
/// the name is dropped and its blob best-effort deleted before the claim row is persisted.
/// The count lands in <c>claim_history.purged_count</c> and the response body so the UI
/// can report what changed. Imported / private artefacts are never touched.
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
        _blobs = svc.Blobs;
        _logger = svc.Logger;
        _time = svc.Time;
    }

    /// <summary>
    /// When a transition flips the claim into <c>local_only</c>, every cached proxy
    /// version for that name must be evicted — both the metadata row and the underlying
    /// blob — so subsequent installs are forced through the local-only artefact set rather
    /// than serving a stale proxy copy. Returns the count for the audit/history record.
    /// Blob deletes are best-effort: a failed delete logs a warning but does not fail the
    /// transition (the row is already gone, so the storage entry is dereferenced garbage).
    /// </summary>
    private async Task<int> PurgeProxyArtefactsAsync(
        string orgId, string ecosystem, string name, CancellationToken ct)
    {
        var blobKeys = await _packages.DeleteProxyVersionsForNameAsync(orgId, ecosystem, name, ct);
        foreach (string key in blobKeys)
        {
            try { await _blobs.DeleteAsync(key, ct); }
            catch (Exception ex)
            {
                // deepcode ignore LogForging: Serilog RenderedCompactJsonFormatter JSON-encodes property
                // values, so CRLF in tenant-route inputs (org/ecosystem/name) cannot break the log envelope.
                _logger.LogWarning(ex,
                    "Failed to delete proxy blob {BlobKey} during local_only purge for {Org}/{Ecosystem}/{Name}.",
                    key, orgId, ecosystem, name);
            }
        }
        return blobKeys.Count;
    }

    /// <summary>GET /api/v1/admin/claims</summary>
    // claim:manage (not read:claims) matches what AuthorizeAsync enforces below — the claims
    // admin surface is manager-only, reads included.
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
    // admin surface is manager-only, reads included.
    [HttpGet("/api/v1/admin/claims/{ecosystem}/{name}")]
    [RequireCapability(Capabilities.ClaimManage)]
    public async Task<IActionResult> Get(string ecosystem, string name, CancellationToken ct)
    {
        var (Error, OrgId, _) = await AuthorizeAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var eff = await _resolver.ResolveAsync(OrgId!, ecosystem, name.ToLowerInvariant(), ct);
        return Ok(new
        {
            ecosystem,
            name = name.ToLowerInvariant(),
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

        if (req is null)
        {
            return BadRequest("Body required.");
        }

        if (string.IsNullOrWhiteSpace(req.Reason))
        {
            return BadRequest("reason is required.");
        }

        string ecosystem = req.Ecosystem?.ToLowerInvariant() ?? "";
        string name = req.Name?.ToLowerInvariant() ?? "";
        if (ecosystem is not ("npm" or "pypi" or "nuget" or "maven" or "rpm" or "oci"))
        {
            return BadRequest("ecosystem must be one of: npm, pypi, nuget, maven, rpm, oci.");
        }

        if (string.IsNullOrEmpty(name))
        {
            return BadRequest("name is required.");
        }

        var existing = await _claims.GetAsync(OrgId!, ecosystem, name, ct);
        if (existing is not null)
        {
            return Conflict(new ProblemDetails
            {
                Status = StatusCodes.Status409Conflict,
                Detail = $"Claim already exists for {ecosystem}/{name} (state: {existing.State}). " +
                         "Use PATCH to transition.",
            });
        }

        var validation = ClaimStateMachine.ValidateCreate(req.State ?? "");
        if (!validation.Allowed)
        {
            return BadRequest(new ProblemDetails { Status = StatusCodes.Status400BadRequest, Detail = validation.RejectionReason });
        }

        // Purge: when the claim transition demands it (creating with state=local_only),
        // evict cached proxy versions BEFORE persisting the transition. Doing it before
        // means a concurrent install racing the create can't repopulate the cache between
        // purge and claim-row creation.
        int purgedCount = validation.PurgesProxy
            ? await PurgeProxyArtefactsAsync(OrgId!, ecosystem, name, ct)
            : 0;

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
            PurgedCount = purgedCount,
        };
        await _claims.ApplyTransitionAsync(tx, ct);
        await _audit.LogAsync("claim.create", OrgId, ActorId, ecosystem,
            $"pkg:{ecosystem}/{name}",
            detail: $"{{\"state\":\"{req.State}\",\"reason\":{System.Text.Json.JsonSerializer.Serialize(req.Reason)},\"purged\":{purgedCount}}}",
            ct: ct);
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
        name = name.ToLowerInvariant();

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

        // Purge on mixed → local_only. See Create for the purge-before-persist rationale.
        int purgedCount = validation.PurgesProxy
            ? await PurgeProxyArtefactsAsync(OrgId!, ecosystem, name, ct)
            : 0;

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
            PurgedCount = purgedCount,
        };
        await _claims.ApplyTransitionAsync(tx, ct);
        await _audit.LogAsync("claim.transition", OrgId, ActorId, ecosystem,
            $"pkg:{ecosystem}/{name}",
            detail: $"{{\"from\":\"{existing.State}\",\"to\":\"{req.State}\",\"purged\":{purgedCount}}}",
            ct: ct);
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
        name = name.ToLowerInvariant();

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
        await _audit.LogAsync("claim.release", OrgId, ActorId, ecosystem,
            $"pkg:{ecosystem}/{name}",
            detail: $"{{\"from\":\"{existing.State}\"}}",
            ct: ct);
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
    Dependably.Storage.IBlobStore Blobs,
    ILogger<ClaimsController> Logger,
    TimeProvider Time);
