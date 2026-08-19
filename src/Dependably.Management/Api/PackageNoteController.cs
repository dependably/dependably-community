using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Standing compliance annotations on a package coordinate.
///
///   GET    /api/v1/package-notes?ecosystem=&amp;name=&amp;version=  — notes for a package (member+)
///   POST   /api/v1/package-notes                             — add a note (admin+)
///   PUT    /api/v1/package-notes/{id}                        — rewrite a note (admin+)
///   DELETE /api/v1/package-notes/{id}                        — remove a note (admin+)
///
/// This is where the rationale for accepting a package under a conditional licence lives, and
/// equally where an admin leaves any other note about a package. Reads need only ReadPackages so
/// a developer who hits a conditional licence can see why the org accepted it; writes are an
/// admin decision.
/// </summary>
[ApiController]
[Authorize]
public sealed class PackageNoteController : ControllerBase
{
    // A compliance note is a paragraph, not a document. Bounded so one tenant cannot park
    // megabytes of prose on a row every package view reads.
    internal const int MaxNoteLength = 4000;

    private readonly PackageNoteRepository _notes;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;
    private readonly AuditRepository _audit;

    public PackageNoteController(
        PackageNoteRepository notes,
        OrgAccessGuard guard,
        ProblemResults problems,
        AuditRepository audit)
    {
        _notes = notes;
        _guard = guard;
        _problems = problems;
        _audit = audit;
    }

    private string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    private static string OrgId(HttpContext ctx) =>
        ((TenantContext)ctx.Items[TenantContext.HttpItemsKey]!).TenantId!;

    /// <summary>GET /api/v1/package-notes</summary>
    [HttpGet("api/v1/package-notes")]
    public async Task<IActionResult> List(
        [FromQuery] string? ecosystem, [FromQuery] string? name, [FromQuery] string? version,
        CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(name))
        {
            return _problems.ValidationErrorActionKey("name", "error.packageNote.coordinateRequired");
        }

        var entries = await _notes.ListAsync(
            OrgId(HttpContext), ecosystem.Trim(), name.Trim(),
            string.IsNullOrWhiteSpace(version) ? null : version.Trim(), ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/package-notes</summary>
    [HttpPost("api/v1/package-notes")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> Add([FromBody] PackageNoteRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (string.IsNullOrWhiteSpace(req.Ecosystem) || string.IsNullOrWhiteSpace(req.Name))
        {
            return _problems.ValidationErrorActionKey("name", "error.packageNote.coordinateRequired");
        }

        if (string.IsNullOrWhiteSpace(req.Note))
        {
            return _problems.ValidationErrorActionKey("note", "error.packageNote.noteRequired");
        }

        if (req.Note.Length > MaxNoteLength)
        {
            return _problems.ValidationErrorActionKey("note", "error.packageNote.noteTooLong");
        }

        string orgId = OrgId(HttpContext);
        string? userId = GetUserId();
        var entry = await _notes.AddAsync(
            orgId, req.Ecosystem.Trim(), req.Name.Trim(),
            string.IsNullOrWhiteSpace(req.Version) ? null : req.Version.Trim(),
            req.Note.Trim(), userId, ct);

        await _audit.LogAsync("package_note_added", orgId, userId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(
                new { ecosystem = entry.Ecosystem, name = entry.Name, version = entry.Version },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
    }

    /// <summary>PUT /api/v1/package-notes/{id}</summary>
    [HttpPut("api/v1/package-notes/{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] PackageNoteUpdateRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        if (string.IsNullOrWhiteSpace(req.Note))
        {
            return _problems.ValidationErrorActionKey("note", "error.packageNote.noteRequired");
        }

        if (req.Note.Length > MaxNoteLength)
        {
            return _problems.ValidationErrorActionKey("note", "error.packageNote.noteTooLong");
        }

        string orgId = OrgId(HttpContext);
        bool updated = await _notes.UpdateAsync(orgId, id, req.Note.Trim(), ct);
        if (!updated)
        {
            return NotFound();
        }

        await _audit.LogAsync("package_note_updated", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(
                new { note_id = id }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>DELETE /api/v1/package-notes/{id}</summary>
    [HttpDelete("api/v1/package-notes/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = OrgId(HttpContext);
        bool removed = await _notes.DeleteAsync(orgId, id, ct);
        if (!removed)
        {
            return NotFound();
        }

        await _audit.LogAsync("package_note_removed", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(
                new { note_id = id }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }
}

public record PackageNoteRequest(string Ecosystem, string Name, string? Version, string Note);
public record PackageNoteUpdateRequest(string Note);
