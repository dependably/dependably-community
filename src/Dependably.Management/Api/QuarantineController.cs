using System.Diagnostics.CodeAnalysis;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Review queue for policy-gate blocks. An admin surface end to end: list requires
/// ReadTenant, decisions require TenantConfigure.
///   GET  /api/v1/quarantine                — paged list, filtered by state/ecosystem/gate/search
///                                            and sorted by a whitelisted column
///   POST /api/v1/quarantine/{id}/decide    — approve or deny a pending entry
/// Approval sets the version's manual allow override (the existing short-circuit unblocks
/// every gate); denial sets the manual block. Version-less entries (proxy artifacts, which
/// carry no package_versions row) instead flip the override on every tenant_artifact_access
/// row for the purl's coordinate, since that is what the proxy cache-hit gate reads.
/// The download-time blocked_* events were already written by the gate into activity;
/// only the human decision lands in audit_log.
/// </summary>
[ApiController]
[Authorize]
public sealed class QuarantineController : OrgScopedControllerBase
{
    // Maximum page size for quarantine list responses.
    private const int MaxQuarantinePageSize = 200;

    // Longest accepted `search` term; anything past this is truncated, not rejected.
    private const int MaxSearchLength = 200;

    private readonly QuarantineRepository _quarantine;
    private readonly PackageRepository _packages;
    private readonly OrgRepository _orgs;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly ManualBlockFanout _fanout;

    // Constructor injection of independently-registered DI services — each parameter is a
    // distinct collaborator, not a candidate for further bundling.
#pragma warning disable S107
    public QuarantineController(
        QuarantineRepository quarantine,
        PackageRepository packages,
        OrgRepository orgs,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        CacheArtifactRepository cacheArtifacts,
        TenantArtifactAccessRepository tenantAccess)
#pragma warning restore S107
    {
        _quarantine = quarantine;
        _packages = packages;
        _orgs = orgs;
        _guard = guard;
        _audit = audit;
        _problems = problems;
        _fanout = new ManualBlockFanout(packages, cacheArtifacts, tenantAccess, quarantine);
    }

    /// <summary>
    /// GET /api/v1/quarantine?state=pending&amp;ecosystem=npm&amp;gate=malicious&amp;search=lodash
    ///     &amp;sort=updated&amp;dir=desc&amp;limit=50&amp;offset=0
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:tenant. The decide action below
    // stays JWT-only (class-level [Authorize]) — its TenantConfigure gate is unaffected.
    //
    // Every filter is a server parameter rather than something the client narrows after the fact:
    // the response is one page of a larger queue, so a client-side filter would filter the page
    // and disagree with the `total` the pager is drawn from.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/quarantine")]
    [SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each parameter is an independent query-string filter, sort, or paging " +
                        "input bound by the framework; bundling them into a model would hide the " +
                        "endpoint's contract from the generated OpenAPI document.")]
    public async Task<IActionResult> List(
        [FromQuery] string? state, [FromQuery] string? ecosystem,
        [FromQuery] string? gate, [FromQuery] string? search,
        [FromQuery] string? sort, [FromQuery] string? dir,
        [FromQuery] int limit = 50, [FromQuery] int offset = 0,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        if (state is not (null or "pending" or "approved" or "denied"))
        {
            return _problems.ValidationErrorActionKey("state", "error.quarantine.stateInvalid");
        }

        limit = Math.Clamp(limit, 1, MaxQuarantinePageSize);
        offset = Math.Max(offset, 0);
        // An over-long search is truncated rather than rejected: it only ever widens into a LIKE
        // pattern, and a bounded one keeps the scan bounded too. `gate`, `sort`, and `dir` need no
        // validation here — an unknown gate simply matches nothing, and the repository's sort
        // whitelist falls back to its default for anything it does not recognise.
        if (search is { Length: > MaxSearchLength })
        {
            search = search[..MaxSearchLength];
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        await _quarantine.PurgeAgedReleaseHoldsAsync(orgId, settings?.MinReleaseAgeHours, ct);
        var (items, total) = await _quarantine.ListAsync(
            new QuarantineListQuery(orgId, state, ecosystem, gate, search, limit, offset, sort, dir), ct);
        // snake_case, unlike the camelCase house style for browser-facing payloads: this endpoint
        // already ships decided_by/updated_at to PAT and service-token consumers, and recasing it
        // would break them for no gain. The frontend reads these names as they are.
        return Ok(new
        {
            total,
            items = items.Select(e => new
            {
                id = e.Id,
                ecosystem = e.Ecosystem,
                purl = e.Purl,
                // The canonical, per-ecosystem-folded name the rest of the product keys a
                // coordinate by, derived here rather than in the browser: PurlNormalizer is the
                // single source of truth for that folding, and a client re-deriving it would
                // silently disagree for scoped npm, underscored PyPI and mixed-case NuGet names.
                // Null when the stored purl names a type with no registry mapping.
                purl_name = Dependably.Infrastructure.Sbom.SbomPurlKey.TryParse(e.Purl)?.Name,
                gate = e.Gate,
                detail = e.Detail,
                state = e.State,
                decided_by = e.DecidedBy,
                decided_by_email = e.DecidedByEmail,
                decided_at = e.DecidedAt,
                note = e.Note,
                created_at = e.CreatedAt,
                updated_at = e.UpdatedAt,
            }),
        });
    }

    /// <summary>
    /// POST /api/v1/quarantine/{id}/decide — body {"decision":"approved"|"denied"|"pending","note":"..."}
    /// A pending entry takes its initial decision (approve/deny); an already-decided entry can be
    /// re-decided or reset to pending — the admin "change my mind" path.
    /// </summary>
    [HttpPost("api/v1/quarantine/{id}/decide")]
    public async Task<IActionResult> Decide(
        string id, [FromBody] QuarantineDecisionRequest req, CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (req.Decision is not ("approved" or "denied" or "pending"))
        {
            return _problems.ValidationErrorActionKey("decision", "error.quarantine.decisionInvalid");
        }

        string orgId = CurrentTenantId();
        var entry = await _quarantine.GetByIdAsync(orgId, id, ct);
        if (entry is null)
        {
            // Unknown or cross-tenant id — indistinguishable by design (BOLA guard).
            return NotFound();
        }

        string? userId = GetUserId();
        var transitionResult = await ApplyDecisionTransitionAsync(orgId, id, entry, req, userId, ct);
        if (transitionResult is not null)
        {
            return transitionResult;
        }

        // The version's manual override is what actually unblocks/blocks the gates; the
        // review row records why. approve ⇒ allow, deny ⇒ block, reset to pending ⇒ clear the
        // override.
        string? manualState = req.Decision switch
        {
            "approved" => "allowed",
            "denied" => "blocked",
            _ => null,
        };

        // An approval past the OCI 'unscanned' arm is scoped to that arm: the gate reads it back
        // by gate (QuarantineRepository.HasApprovedForGateAsync), and setting the manual allow
        // here would short-circuit every arm, so a KEV or malicious finding that lands on the
        // digest after the approval would be waived forever. The decision is recorded only.
        // A prior deny of the same row set a manual block; the approval lifts that block (back to
        // no override, never to allow) so the arm-scoped approval is what the gate then reads.
        if (req.Decision == "approved" && entry.Gate == BlockGateService.UnscannedGate)
        {
            if (entry.State == "denied" && await DenyOwnsManualBlockAsync(orgId, entry, ct))
            {
                await ApplyManualBlockOverrideAsync(orgId, entry, null, userId, ct);
            }
        }
        else
        {
            await ApplyManualBlockOverrideAsync(orgId, entry, manualState, userId, ct);
        }

        await _audit.LogAsync("quarantine_decision", orgId, userId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                purl = entry.Purl,
                gate = entry.Gate,
                from = entry.State,
                decision = req.Decision,
                note = req.Note,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(new { id = entry.Id, state = req.Decision });
    }

    // True when the manual block on this entry's coordinate was set by the deny being reversed,
    // rather than by an operator's own block. The review row is unique per (org, purl), so a
    // second quarantine row cannot be the other source; the other source is the version
    // block endpoint, which resolves a pending row as "resolved via manual" and writes a
    // package_version_blocked audit row. Either trace, or an audit row at or after the deny, means
    // the block is not this deny's to lift. A deny with neither trace owns its block.
    private async Task<bool> DenyOwnsManualBlockAsync(string orgId, QuarantineEntry entry, CancellationToken ct)
    {
        if (entry.Note is { } note && note.StartsWith("resolved via manual", StringComparison.Ordinal))
        {
            return false;
        }

        string since = (entry.DecidedAt ?? entry.UpdatedAt).ToUtcIsoMillis();
        return !await _audit.HasActionSinceAsync(orgId, entry.Purl, "package_version_blocked", since, ct);
    }

    // Applies the pending→decided transition, or an already-decided entry's re-decide/reset.
    // Returns a short-circuit IActionResult (a validation error, a 409 race conflict, or the
    // already-current-state 200) when the caller should return immediately without applying the
    // manual override or logging the decision audit event; null once the transition is applied
    // and the caller should proceed.
    private async Task<IActionResult?> ApplyDecisionTransitionAsync(
        string orgId, string id, QuarantineEntry entry, QuarantineDecisionRequest req, string? userId, CancellationToken ct)
    {
        if (entry.State == "pending")
        {
            // Initial decision — only approve or deny; "pending" would be a no-op transition.
            if (req.Decision == "pending")
            {
                return _problems.ValidationErrorActionKey("decision", "error.quarantine.alreadyPending");
            }
            if (!await _quarantine.DecideAsync(orgId, id, req.Decision, userId, req.Note, ct))
            {
                // Raced with another reviewer between the read and the guarded update.
                return Conflict(new { detail = "Entry already decided." });
            }
            return null;
        }

        if (entry.State != req.Decision)
        {
            // Re-decide or reset to pending — the admin "change my mind" path.
            await _quarantine.ChangeStateAsync(orgId, id, req.Decision, userId, req.Note, ct);
            return null;
        }

        // Target already matches the current state — nothing to change.
        return Ok(new { id = entry.Id, state = entry.State });
    }

    // Flips the manual block-gate override to match the decision: on the version row when one
    // exists, or (for a version-less proxy entry, which has no package_versions row) on the
    // matching tenant_artifact_access rows instead — the cache-hit serve gate reads its override
    // from there via BlockGateRequest.ForProxyCacheFacts. ManualBlockFanout decides the rest of the
    // coverage, the same way the direct block/unblock endpoints do: a PyPI denial spreads to every
    // spelling on both planes and resolves their pending entries, while an approval stays on the
    // uploaded version (or the proxied artifact) the entry names.
    private async Task ApplyManualBlockOverrideAsync(
        string orgId, QuarantineEntry entry, string? manualState, string? userId, CancellationToken ct)
    {
        // TryParseCacheCoordinate (not TryParse) is required: RPM/apk purls carry an ?arch=…
        // qualifier and apk an alpine/ namespace, and Maven uses a group/artifact path separator —
        // none of which appear in cache_artifact.name/version. A raw TryParse leaves those on and
        // the coordinate never matches, silently no-opping the decision.
        var parsed = PurlParser.TryParseCacheCoordinate(entry.Purl);
        if (parsed is null)
        {
            if (entry.PackageVersionId is { } versionId)
            {
                await _packages.SetManualBlockStateAsync(versionId, manualState, ct);
            }

            return;
        }

        await _fanout.ApplyAsync(new ManualBlockDecision(
            orgId, entry.Ecosystem, parsed.Name, parsed.Version, manualState, userId,
            entry.PackageVersionId is null ? ManualBlockOrigin.ProxiedEntry : ManualBlockOrigin.UploadedEntry,
            entry.PackageVersionId), ct);
    }
}

public sealed record QuarantineDecisionRequest(string Decision, string? Note = null);
