using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

public sealed partial class SystemController
{
    // ── system_admin CRUD on /api/v1/system/admins ─────────────────────────────
    // Operators manage other operators here. Three guards beyond the route-level scope check:
    //   1. no-self: operator cannot modify themselves through these endpoints (self-rotation
    //      lives at POST /me/password). Returns 403 reason=cannot_modify_self.
    //   2. last-active: disable/lock/delete refuse if doing so would leave zero active admins.
    //      Returns 409 reason=last_active_admin.
    //   3. delete-requires-disabled: hard-delete only succeeds when target is already
    //      account_status='disabled'. Returns 409 reason=must_disable_first.

    /// <summary>GET /api/v1/system/admins — list all system_admins. Never returns password_hash.</summary>
    [HttpGet("admins")]
    public async Task<IActionResult> ListAdmins(CancellationToken ct)
    {
        var admins = await _systemAdmins.ListAsync(ct);
        return Ok(admins.Select(a => new
        {
            id = a.Id,
            email = a.Email,
            accountStatus = a.AccountStatus,
            mustChangePassword = a.MustChangePassword,
            lastLoginAt = a.LastLoginAt,
            passwordResetIssuedAt = a.PasswordResetIssuedAt,
            createdAt = a.CreatedAt,
            mfaEnabled = a.MfaEnabled,
        }));
    }

    /// <summary>GET /api/v1/system/admins/{id} — fetch a single system_admin.</summary>
    [HttpGet("admins/{id}")]
    public async Task<IActionResult> GetAdmin(string id, CancellationToken ct)
    {
        var a = await _systemAdmins.GetByIdAsync(id, ct);
        return a is null
            ? NotFound()
            : Ok(new
            {
                id = a.Id,
                email = a.Email,
                accountStatus = a.AccountStatus,
                mustChangePassword = a.MustChangePassword,
                lastLoginAt = a.LastLoginAt,
                passwordResetIssuedAt = a.PasswordResetIssuedAt,
                createdAt = a.CreatedAt,
            });
    }

    /// <summary>
    /// POST /api/v1/system/admins — create a new system_admin. The server generates a temp
    /// password (16 random bytes, base64), hashes it with BCrypt (workFactor 12), and returns
    /// the plaintext in the response exactly once. <c>must_change_password=1</c> forces rotation
    /// on first login. Email match is case-insensitive; duplicates → 409.
    /// </summary>
    [HttpPost("admins")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> CreateAdmin([FromBody] CreateAdminRequest req, CancellationToken ct)
    {
        if (req is null || string.IsNullOrWhiteSpace(req.Email))
        {
            return _problems.ValidationErrorAction("email", "email is required.");
        }

        var existing = await _systemAdmins.GetByEmailAsync(req.Email, ct);
        if (existing is not null)
        {
            return _problems.ConflictAction("A system_admin with that email already exists.", reason: "duplicate_email");
        }

        string rawPassword = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(GeneratedPasswordByteLength));
        string hash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        string id = await _systemAdmins.CreateAsync(req.Email, hash, mustChangePassword: true, ct);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.admin_created",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new { id, email = req.Email }),
            ct: ct);

        return CreatedAtAction(nameof(GetAdmin), new { id }, new
        {
            id,
            email = req.Email,
            accountStatus = "active",
            temporaryPassword = rawPassword,
            issuedAt = _time.GetUtcNow(),
            mustChangePassword = true,
        });
    }

    /// <summary>
    /// PATCH /api/v1/system/admins/{id}/account-status — change status to active/locked/disabled.
    /// </summary>
    [HttpPatch("admins/{id}/account-status")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetAdminAccountStatus(
        string id, [FromBody] SetAdminAccountStatusRequest req, CancellationToken ct)
    {
        if (req is null || req.AccountStatus is not ("active" or "locked" or "disabled"))
        {
            return _problems.ValidationErrorAction("accountStatus", "Must be 'active', 'locked', or 'disabled'.");
        }

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (string.Equals(actor, id, StringComparison.Ordinal))
        {
            return _problems.ForbiddenAction(
                "Operators cannot change their own account status; use /api/v1/system/me/password instead.",
                reason: "cannot_modify_self");
        }

        var target = await _systemAdmins.GetByIdAsync(id, ct);
        if (target is null)
        {
            return NotFound();
        }

        if (req.AccountStatus != "active")
        {
            int otherActive = await _systemAdmins.CountActiveExcludingAsync(id, ct);
            if (otherActive == 0)
            {
                return _problems.ConflictAction(
                    "Cannot disable or lock the last active system_admin.",
                    reason: "last_active_admin");
            }
        }

        bool ok = await _systemAdmins.SetAccountStatusAsync(id, req.AccountStatus, ct);
        if (!ok)
        {
            return NotFound();
        }

        await _audit.LogSystemAsync(
            action: "system_admin.admin_account_status_changed",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new { id, accountStatus = req.AccountStatus }),
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// POST /api/v1/system/admins/{id}/password-reset — issues a temporary password for another
    /// admin. Self-reset is rejected; the operator must use POST /me/password for their own
    /// password. The temp password is returned once and never persisted in plaintext.
    /// </summary>
    [HttpPost("admins/{id}/password-reset")]
    public async Task<IActionResult> ResetAdminPassword(string id, CancellationToken ct)
    {
        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (string.Equals(actor, id, StringComparison.Ordinal))
        {
            return _problems.ForbiddenAction(
                "Operators cannot reset their own password through this endpoint; use /api/v1/system/me/password instead.",
                reason: "cannot_modify_self");
        }

        var target = await _systemAdmins.GetByIdAsync(id, ct);
        if (target is null)
        {
            return NotFound();
        }

        string rawPassword = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(GeneratedPasswordByteLength));
        string hash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        var issuedAt = _time.GetUtcNow();
        bool ok = await _systemAdmins.ResetPasswordAsync(id, hash, issuedAt, ct);
        if (!ok)
        {
            return NotFound();
        }

        await _audit.LogSystemAsync(
            action: "system_admin.admin_password_reset",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new { id, email = target.Email }),
            ct: ct);

        return Ok(new
        {
            id,
            email = target.Email,
            temporaryPassword = rawPassword,
            issuedAt,
            mustChangePassword = true,
        });
    }

    /// <summary>
    /// DELETE /api/v1/system/admins/{id} — hard-delete. Only succeeds when the target is already
    /// account_status='disabled'. Self-deletion is forbidden; deleting the last active admin is
    /// not possible (target must already be disabled, which only succeeds when another admin is
    /// active).
    /// </summary>
    [HttpDelete("admins/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteAdmin(string id, CancellationToken ct)
    {
        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (string.Equals(actor, id, StringComparison.Ordinal))
        {
            return _problems.ForbiddenAction(
                "Operators cannot delete their own account.",
                reason: "cannot_modify_self");
        }

        var target = await _systemAdmins.GetByIdAsync(id, ct);
        if (target is null)
        {
            return NotFound();
        }

        if (target.AccountStatus != "disabled")
        {
            return _problems.ConflictAction(
                "Disable the system_admin (PATCH /account-status with 'disabled') before deleting.",
                reason: "must_disable_first");
        }

        int affected = await _systemAdmins.DeleteIfDisabledAsync(id, ct);
        if (affected == 0)
        {
            return NotFound();
        }

        await _audit.LogSystemAsync(
            action: "system_admin.admin_deleted",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new { id, email = target.Email }),
            ct: ct);

        return NoContent();
    }
}
