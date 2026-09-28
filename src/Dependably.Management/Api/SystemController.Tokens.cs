using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// System API-token minting on <c>/api/v1/system/tokens</c>. Stays on the controller's default
/// JWT-only <c>[Authorize]</c> — a session is required to mint or revoke, deliberately, so a
/// system token can never mint another (it isn't a scheme this policy accepts).
/// </summary>
public sealed partial class SystemController
{
    /// <summary>Operator-facing token name shown in the apex Tokens page. Same cap as OrgTokensController's.</summary>
    private const int MaxSystemTokenNameLength = 200;
    private const int MaxSystemTokenDescriptionLength = 200;

    /// <summary>Confirmed decision: an expiry is required and at most this many days out.</summary>
    private const int MaxSystemTokenExpiryDays = 365;

    /// <summary>GET /api/v1/system/tokens — list every system token. Any system admin can see all of them.</summary>
    [HttpGet("tokens")]
    public async Task<IActionResult> ListSystemTokens(CancellationToken ct)
    {
        var items = await _systemTokens.ListAsync(ct);
        return Ok(items);
    }

    /// <summary>
    /// POST /api/v1/system/tokens — mints a token scoped to the tenant-lifecycle and usage-limit actions.
    /// The plaintext secret is returned only in this response.
    /// </summary>
    [HttpPost("tokens")]
    [EnableRateLimiting("token-create")]
    public async Task<IActionResult> CreateSystemToken(
        [FromBody] CreateSystemTokenRequest req, CancellationToken ct)
    {
        if (req is null || string.IsNullOrWhiteSpace(req.Name))
        {
            return _problems.ValidationErrorActionKey("name", "error.token.nameRequired");
        }

        if (req.Name.Trim().Length > MaxSystemTokenNameLength)
        {
            return _problems.ValidationErrorActionKey("name", "error.token.nameTooLong", MaxSystemTokenNameLength);
        }

        if (req.Name.Any(char.IsControl))
        {
            return _problems.ValidationErrorActionKey("name", "error.token.nameInvalidChars");
        }

        if (ValidateSystemTokenDescription(req.Description, out string? description) is { } invalidDescription)
        {
            return invalidDescription;
        }

        var now = _time.GetUtcNow();
        if (req.ExpiresAt is not { } expiresAt || expiresAt <= now)
        {
            return _problems.ValidationErrorActionKey("expiresAt", "error.token.expiryRequired");
        }

        if (expiresAt > now.AddDays(MaxSystemTokenExpiryDays))
        {
            return _problems.ValidationErrorActionKey(
                "expiresAt", "error.token.expiryTooFar", MaxSystemTokenExpiryDays);
        }

        var actor = SystemActor.From(User);
        if (actor.Id is null)
        {
            return Unauthorized();
        }

        // Session-invalidation signal snapshotted at JWT issuance, same claim and same
        // absent-defaults-to-1 fallback as AuthStartupExtensions.OnJwtTokenValidatedAsync — passed
        // through so CreateAsync can re-check it live, inside its own transaction, against the
        // outer gate's cache window (see SystemTokenOwnerSessionStaleException).
        long callerTokenVersion = long.TryParse(User.FindFirst("tver")?.Value, out long tver) ? tver : 1;

        string raw;
        SystemTokenRecord record;
        try
        {
            (raw, record) = await _systemTokens.CreateAsync(
                actor.Id, req.Name.Trim(), expiresAt, callerTokenVersion, description, ct);
        }
        catch (SystemTokenCapExceededException ex)
        {
            return _problems.ValidationErrorActionKey("tokens", "error.systemToken.limitReached", ex.Cap);
        }
        catch (SystemTokenOwnerSessionStaleException)
        {
            return Unauthorized();
        }

        // actor.Kind and actor.Label resolve NULL under this controller's JWT-only [Authorize];
        // threading them through SystemActor keeps the row correctly attributed if the accepted
        // schemes ever widen to a system token.
        await _audit.LogSystemAsync(
            action: "system_admin.token_created",
            actorId: actor.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                name = record.Name,
                expires_at = record.ExpiresAt,
                description,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            actorKind: actor.Kind,
            actorLabel: actor.Label,
            ct: ct);

        return Ok(new { token = raw, record });
    }

    /// <summary>
    /// Validates an optional token description, yielding it trimmed (null when blank), or returns
    /// the validation problem to send instead.
    /// </summary>
    private IActionResult? ValidateSystemTokenDescription(string? raw, out string? description)
    {
        description = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        string trimmed = raw.Trim();
        if (trimmed.Length > MaxSystemTokenDescriptionLength)
        {
            return _problems.ValidationErrorActionKey(
                "description", "error.token.descriptionTooLong", MaxSystemTokenDescriptionLength);
        }

        if (trimmed.Any(char.IsControl))
        {
            return _problems.ValidationErrorActionKey("description", "error.token.descriptionInvalidChars");
        }

        description = trimmed;
        return null;
    }

    /// <summary>DELETE /api/v1/system/tokens/{id} — any system admin can revoke any token. 404 when the id doesn't exist.</summary>
    [HttpDelete("tokens/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteSystemToken(string id, CancellationToken ct)
    {
        int deleted = await _systemTokens.DeleteAsync(id, ct);
        if (deleted == 0)
        {
            return NotFound();
        }

        var actor = SystemActor.From(User);
        await _audit.LogSystemAsync(
            action: "system_admin.token_revoked",
            actorId: actor.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { token_id = id }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            actorKind: actor.Kind,
            actorLabel: actor.Label,
            ct: ct);

        return NoContent();
    }
}

public sealed record CreateSystemTokenRequest(
    string Name,
    DateTimeOffset? ExpiresAt,
    string? Description = null);
