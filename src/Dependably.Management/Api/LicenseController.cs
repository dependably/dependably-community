using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// License governance endpoints.
///
///   GET    /api/v1/license-policy                              — get mode + lists (member+)
///   PUT    /api/v1/license-policy/mode                         — set enforcement mode (admin+)
///   GET    /api/v1/license-policy/review                       — undecided observed licences (admin+)
///   GET    /api/v1/license-policy/allowlist                    — list allow/conditional entries (member+)
///   POST   /api/v1/license-policy/allowlist                    — add entry (admin+)
///   PATCH  /api/v1/license-policy/allowlist/{spdx}             — edit disposition/note (admin+)
///   DELETE /api/v1/license-policy/allowlist/{spdx}             — remove entry (admin+)
///   GET    /api/v1/license-policy/blocklist                    — list blocklist (member+)
///   POST   /api/v1/license-policy/blocklist                    — add entry (admin+)
///   PATCH  /api/v1/license-policy/blocklist/{spdx}             — edit note (admin+)
///   DELETE /api/v1/license-policy/blocklist/{spdx}             — remove entry (admin+)
///
/// The allowlist carries both non-denied dispositions: 'allowed' is a blanket yes and
/// 'conditional' means the licence is acceptable only in some contexts, with the condition
/// recorded in the entry's note. Both serve and publish; only the blocklist refuses.
/// </summary>
[ApiController]
[Authorize]
public sealed class LicenseController : ControllerBase
{
    private readonly LicenseRepository _licenses;
    private readonly OrgRepository _orgs;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;
    private readonly AuditRepository _audit;

    public LicenseController(
        LicenseRepository licenses,
        OrgRepository orgs,
        OrgAccessGuard guard,
        ProblemResults problems,
        AuditRepository audit)
    {
        _licenses = licenses;
        _orgs = orgs;
        _guard = guard;
        _problems = problems;
        _audit = audit;
    }

    private string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    // ── Policy summary ────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/license-policy")]
    public async Task<IActionResult> GetPolicy(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        var allowlist = await _licenses.GetAllowlistAsync(orgId, ct);
        var blocklist = await _licenses.GetBlocklistAsync(orgId, ct);

        return Ok(new
        {
            mode = settings?.LicenseEnforcementMode ?? "off",
            publishMode = settings?.LicensePublishEnforcementMode ?? "off",
            allowlist,
            blocklist
        });
    }

    // ── Review queue ──────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy/review — licenses observed during
    /// ingestion that are on neither the allow- nor block-list. Admin-only because the UI
    /// surfaces it next to mutating Approve/Block actions.</summary>
    [HttpGet("api/v1/license-policy/review")]
    public async Task<IActionResult> GetReviewQueue(
        [FromQuery] bool includeDeprecated, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
        var entries = await _licenses.GetReviewQueueAsync(orgId, includeDeprecated, ct);
        return Ok(entries);
    }

    // ── Enforcement mode ──────────────────────────────────────────────────────

    /// <summary>
    /// PUT /api/v1/orgs/{org}/license-policy/mode. <c>mode</c> (the serve-path gate) is
    /// required and always applied. <c>publishMode</c> (the independent publish-path gate) is
    /// optional and leave-unchanged-on-absent — an older client that only knows about
    /// <c>mode</c> never resets the stored publish policy back to 'off'.
    /// </summary>
    [HttpPut("api/v1/license-policy/mode")]
    public async Task<IActionResult> SetMode([FromBody] SetModeRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (req.Mode is not ("off" or "warn" or "block"))
        {
            return _problems.ValidationErrorActionKey("mode", "error.license.modeInvalid");
        }

        if (req.PublishMode is not (null or "off" or "warn" or "block"))
        {
            return _problems.ValidationErrorActionKey("publish_mode", "error.license.publishModeInvalid");
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        await _orgs.UpsertLicensePolicyModeAsync(orgId, req.Mode, req.PublishMode, ct);

        await _audit.LogAsync("license_policy_mode_changed", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { mode = req.Mode, publish_mode = req.PublishMode }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        var updated = await _orgs.GetSettingsAsync(orgId, ct);
        return Ok(new { mode = req.Mode, publishMode = updated?.LicensePublishEnforcementMode ?? "off" });
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy/allowlist</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/license-policy/allowlist")]
    public async Task<IActionResult> GetAllowlist(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entries = await _licenses.GetAllowlistAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/license-policy/allowlist</summary>
    [HttpPost("api/v1/license-policy/allowlist")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> AddAllowlist([FromBody] LicenseEntryRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (string.IsNullOrWhiteSpace(req.LicenseSpdx))
        {
            return _problems.ValidationErrorActionKey("license_spdx", "error.license.spdxRequired");
        }

        string disposition = req.Disposition ?? LicenseDispositions.Allowed;
        if (!LicenseDispositions.IsValid(disposition))
        {
            return _problems.ValidationErrorActionKey("disposition", "error.license.dispositionInvalid");
        }

        if (req.Note is { Length: > MaxNoteLength })
        {
            return _problems.ValidationErrorActionKey("note", "error.license.noteTooLong");
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
        string? note = NormalizeNote(req.Note);
        string? userId = GetUserId();

        var entry = await _licenses.AddAllowlistAsync(
            orgId, req.LicenseSpdx.Trim(), disposition, note, userId, ct);
        if (entry is null)
        {
            return _problems.ConflictActionKeyFormat("error.license.allowlistDuplicate", req.LicenseSpdx);
        }

        await _audit.LogAsync("license_allowlist_added", orgId, userId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx = entry.LicenseSpdx, disposition, note }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return CreatedAtAction(nameof(GetAllowlist), null, entry);
    }

    /// <summary>PATCH /api/v1/license-policy/allowlist/{spdx}. Edits an entry in place rather
    /// than forcing a delete/re-add round trip, which would lose created_at and momentarily leave
    /// the licence unlisted — under 'block' mode that gap is a refusal. Both fields are
    /// leave-unchanged when absent; an explicit null note clears it.</summary>
    [HttpPatch("api/v1/license-policy/allowlist/{spdx}")]
    public async Task<IActionResult> UpdateAllowlist(
        string spdx, [FromBody] LicenseEntryPatchRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (req.Disposition is not null && !LicenseDispositions.IsValid(req.Disposition))
        {
            return _problems.ValidationErrorActionKey("disposition", "error.license.dispositionInvalid");
        }

        if (req.Note.IsPresent && req.Note.Value is { Length: > MaxNoteLength })
        {
            return _problems.ValidationErrorActionKey("note", "error.license.noteTooLong");
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entry = await _licenses.UpdateAllowlistAsync(
            orgId, spdx, req.Disposition, req.Note.IsPresent, NormalizeNote(req.Note.Value), ct);
        if (entry is null)
        {
            return NotFound();
        }

        await _audit.LogAsync("license_allowlist_updated", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx = entry.LicenseSpdx, disposition = entry.Disposition, note = entry.Note }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/license-policy/allowlist/{spdx}</summary>
    [HttpDelete("api/v1/license-policy/allowlist/{spdx}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RemoveAllowlist(string spdx, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        bool removed = await _licenses.RemoveAllowlistAsync(orgId, spdx, ct);
        if (!removed)
        {
            return NotFound();
        }

        await _audit.LogAsync("license_allowlist_removed", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    /// <summary>GET /api/v1/orgs/{org}/license-policy/blocklist</summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/license-policy/blocklist")]
    public async Task<IActionResult> GetBlocklist(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entries = await _licenses.GetBlocklistAsync(orgId, ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/license-policy/blocklist</summary>
    [HttpPost("api/v1/license-policy/blocklist")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> AddBlocklist([FromBody] LicenseEntryRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (string.IsNullOrWhiteSpace(req.LicenseSpdx))
        {
            return _problems.ValidationErrorActionKey("license_spdx", "error.license.spdxRequired");
        }

        if (req.Note is { Length: > MaxNoteLength })
        {
            return _problems.ValidationErrorActionKey("note", "error.license.noteTooLong");
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
        string? note = NormalizeNote(req.Note);
        string? userId = GetUserId();

        var entry = await _licenses.AddBlocklistAsync(orgId, req.LicenseSpdx.Trim(), note, userId, ct);
        if (entry is null)
        {
            return _problems.ConflictActionKeyFormat("error.license.blocklistDuplicate", req.LicenseSpdx);
        }

        await _audit.LogAsync("license_blocklist_added", orgId, userId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx = entry.LicenseSpdx, note }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return CreatedAtAction(nameof(GetBlocklist), null, entry);
    }

    /// <summary>PATCH /api/v1/license-policy/blocklist/{spdx}. Edits the refusal note in place.
    /// Leave-unchanged when absent; an explicit null clears it.</summary>
    [HttpPatch("api/v1/license-policy/blocklist/{spdx}")]
    public async Task<IActionResult> UpdateBlocklist(
        string spdx, [FromBody] LicenseEntryPatchRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (req.Note.IsPresent && req.Note.Value is { Length: > MaxNoteLength })
        {
            return _problems.ValidationErrorActionKey("note", "error.license.noteTooLong");
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        var entry = await _licenses.UpdateBlocklistAsync(
            orgId, spdx, req.Note.IsPresent, NormalizeNote(req.Note.Value), ct);
        if (entry is null)
        {
            return NotFound();
        }

        await _audit.LogAsync("license_blocklist_updated", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx = entry.LicenseSpdx, note = entry.Note }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(entry);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/license-policy/blocklist/{spdx}</summary>
    [HttpDelete("api/v1/license-policy/blocklist/{spdx}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RemoveBlocklist(string spdx, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        bool removed = await _licenses.RemoveBlocklistAsync(orgId, spdx, ct);
        if (!removed)
        {
            return NotFound();
        }

        await _audit.LogAsync("license_blocklist_removed", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { spdx }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    // A policy note is a short human rationale, not a document. The cap keeps one tenant from
    // parking megabytes of prose in a config row that every policy read pulls into memory.
    internal const int MaxNoteLength = 2000;

    // Whitespace-only is the same statement as "no note"; storing it would render as an empty
    // row in the UI that reads as a note nobody can see.
    private static string? NormalizeNote(string? note) =>
        string.IsNullOrWhiteSpace(note) ? null : note.Trim();
}

public record SetModeRequest(string Mode, string? PublishMode = null);

/// <summary>Add-entry body. <c>Disposition</c> is allowlist-only and defaults to 'allowed', so a
/// client that predates conditional entries keeps its existing behaviour.</summary>
public record LicenseEntryRequest(string LicenseSpdx, string? Disposition = null, string? Note = null);

/// <summary>Edit-entry body. <c>Note</c> is <see cref="Optional{T}"/> rather than a plain nullable
/// string because absent (leave the note alone) and explicit null (clear it) are different
/// intents that a nullable field cannot tell apart.
///
/// <para>It is declared as a property, never a positional constructor parameter: a custom-struct
/// parameter's <c>default</c> reflects back as a bare CLR null that the OpenAPI exporter cannot
/// unbox into the non-nullable struct, which 500s the whole management document. Same reason
/// <c>UpdateProxySettingsRequest</c> declares its two <see cref="Optional{T}"/> fields as
/// properties — see the comment there. System.Text.Json binds a property-form field from JSON
/// exactly the same way.</para></summary>
public record LicenseEntryPatchRequest(string? Disposition = null)
{
    public Optional<string> Note { get; init; }
}
