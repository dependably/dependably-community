using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Review queue for policy-gate blocks. An admin surface end to end: list requires
/// ReadTenant, decisions require TenantConfigure.
///   GET  /api/v1/quarantine                — list entries, filterable by state/ecosystem
///   POST /api/v1/quarantine/{id}/decide    — approve or deny a pending entry
/// Approval sets the version's manual allow override (the existing short-circuit unblocks
/// every gate); denial sets the manual block. Version-less entries (first-fetch blocks)
/// have no version row to flag — an approved row itself unblocks the next first fetch.
/// The download-time blocked_* events were already written by the gate into activity;
/// only the human decision lands in audit_log.
/// </summary>
[ApiController]
[Authorize]
public sealed class QuarantineController : OrgScopedControllerBase
{
    private readonly QuarantineRepository _quarantine;
    private readonly PackageRepository _packages;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;

    public QuarantineController(
        QuarantineRepository quarantine,
        PackageRepository packages,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _quarantine = quarantine;
        _packages = packages;
        _guard = guard;
        _audit = audit;
        _problems = problems;
    }

    /// <summary>GET /api/v1/quarantine?state=pending&amp;ecosystem=npm&amp;limit=50&amp;offset=0</summary>
    [HttpGet("api/v1/quarantine")]
    public async Task<IActionResult> List(
        [FromQuery] string? state, [FromQuery] string? ecosystem,
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
            return _problems.ValidationErrorAction("state", "Must be 'pending', 'approved', or 'denied'.");
        }

        limit = Math.Clamp(limit, 1, 200);
        offset = Math.Max(offset, 0);

        string orgId = CurrentTenantId();
        var (items, total) = await _quarantine.ListAsync(orgId, state, ecosystem, limit, offset, ct);
        return Ok(new
        {
            total,
            items = items.Select(e => new
            {
                id = e.Id,
                ecosystem = e.Ecosystem,
                purl = e.Purl,
                gate = e.Gate,
                detail = e.Detail,
                state = e.State,
                decided_by = e.DecidedBy,
                decided_at = e.DecidedAt,
                note = e.Note,
                created_at = e.CreatedAt,
                updated_at = e.UpdatedAt,
            }),
        });
    }

    /// <summary>POST /api/v1/quarantine/{id}/decide — body {"decision":"approved"|"denied","note":"..."}</summary>
    [HttpPost("api/v1/quarantine/{id}/decide")]
    public async Task<IActionResult> Decide(
        string id, [FromBody] QuarantineDecisionRequest req, CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (req.Decision is not ("approved" or "denied"))
        {
            return _problems.ValidationErrorAction("decision", "Must be 'approved' or 'denied'.");
        }

        string orgId = CurrentTenantId();
        var entry = await _quarantine.GetByIdAsync(orgId, id, ct);
        if (entry is null)
        {
            // Unknown or cross-tenant id — indistinguishable by design (BOLA guard).
            return NotFound();
        }

        if (entry.State != "pending")
        {
            return Conflict(new { detail = $"Entry already {entry.State}." });
        }

        string? userId = GetUserId();
        if (!await _quarantine.DecideAsync(orgId, id, req.Decision, userId, req.Note, ct))
        {
            // Raced with another reviewer between the read and the guarded update.
            return Conflict(new { detail = "Entry already decided." });
        }

        // The version's manual override is what actually unblocks/blocks the gates; the
        // review row records why. Version-less entries (first-fetch blocks) skip this —
        // the approved row itself is the first-fetch unblock signal.
        if (entry.PackageVersionId is { } versionId)
        {
            await _packages.SetManualBlockStateAsync(
                versionId, req.Decision == "approved" ? "allowed" : "blocked", ct);
        }

        await _audit.LogAsync("quarantine_decision", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                purl = entry.Purl,
                gate = entry.Gate,
                decision = req.Decision,
                note = req.Note,
            }), ct: ct);

        return Ok(new { id = entry.Id, state = req.Decision });
    }
}

public sealed record QuarantineDecisionRequest(string Decision, string? Note = null);
