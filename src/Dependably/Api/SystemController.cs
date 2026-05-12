using System.Security.Claims;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;

namespace Dependably.Api;

/// <summary>
/// Apex-only operator surface (multi-tenant deployments). Every route requires
/// <c>scope=system</c> and <c>TenantContext.IsApex</c>; <see cref="Dependably.Security.RouteScopeFilter"/>
/// enforces this globally so individual handlers don't need to repeat the check.
///
/// Phase 2 ships the bare minimum: tenant CRUD (create + list), with an atomic owner-bootstrap
/// at create time. Soft-delete + grace-period restore lands in Phase 3 alongside the
/// <c>orgs.deleted_at</c> column. Audit log entries are written with <c>scope='system'</c> per
/// the locked decision (no separate <c>tenant_lifecycle_audit</c> table — Phase 3 adds the
/// scope column to the existing <c>audit_log</c> table).
///
/// system_admin **never** sees tenant business data: no packages, vulns, allowlists, tokens, or
/// per-tenant audit. The data-plane plug is at <see cref="Dependably.Security.OrgAccessGuard"/>,
/// which (post-Phase 2) no longer has the legacy <c>instance_admin</c> bypass.
/// </summary>
[ApiController]
[Authorize]
[Route("api/v1/system")]
public sealed class SystemController : ControllerBase
{
    private readonly OrgRepository _orgs;
    private readonly SystemAdminRepository _systemAdmins;
    private readonly IMetadataStore _db;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly IConfiguration _config;

    public SystemController(
        OrgRepository orgs,
        SystemAdminRepository systemAdmins,
        IMetadataStore db,
        AuditRepository audit,
        ProblemResults problems,
        IConfiguration config)
    {
        _orgs = orgs;
        _systemAdmins = systemAdmins;
        _db = db;
        _audit = audit;
        _problems = problems;
        _config = config;
    }

    /// <summary>GET /api/v1/system/tenants — list all tenants.</summary>
    [HttpGet("tenants")]
    public async Task<IActionResult> ListTenants(
        [FromQuery] int limit = 50, [FromQuery] int page = 1, CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        page = Math.Max(page, 1);
        var offset = (page - 1) * limit;
        var (items, total) = await _orgs.ListOrgsAsync(limit, offset, ct: ct);

        // Project to a control-plane-only shape: id, slug, createdAt. Phase 3 adds deletedAt
        // + memberCount; Phase 4 may add storageBytes (aggregate metadata, not enumerated).
        var rows = items.Select(o => new
        {
            id = o.Id,
            slug = o.Slug,
            createdAt = o.CreatedAt,
            deletedAt = o.DeletedAt,
        }).ToList();
        return Ok(new { items = rows, total, limit, offset });
    }

    /// <summary>POST /api/v1/system/tenants — atomically create a tenant + its first owner.</summary>
    [HttpPost("tenants")]
    public async Task<IActionResult> CreateTenant([FromBody] CreateTenantRequest req, CancellationToken ct)
    {
        if (req is null) return _problems.ValidationErrorAction("body", "Body is required.");

        var extraReserved = ReservedSlugs.ParseExtra(_config["RESERVED_SUBDOMAINS"]);
        var slug = ReservedSlugs.Normalize(req.Slug, extraReserved);
        if (slug is null)
            return _problems.ValidationErrorAction("slug", "Slug is missing, reserved, or contains invalid characters.");

        if (string.IsNullOrWhiteSpace(req.OwnerEmail) || !req.OwnerEmail.Contains('@'))
            return _problems.ValidationErrorAction("ownerEmail", "Valid owner email is required.");

        string orgId;
        string ownerPassword;
        await using (var conn = await _db.OpenAsync(ct))
        {
            await conn.ExecuteAsync("BEGIN IMMEDIATE");
            try
            {
                // Slug uniqueness check before commit so the response is a clean 409 instead of
                // a SQLite UNIQUE constraint exception bubbling up.
                var existing = await conn.ExecuteScalarAsync<int>(
                    "SELECT COUNT(*) FROM orgs WHERE slug = @slug", new { slug });
                if (existing > 0)
                {
                    await conn.ExecuteAsync("ROLLBACK");
                    return _problems.ConflictAction("A tenant with that slug already exists.");
                }

                // Email uniqueness is per-tenant — the same email can be a separate account in
                // another tenant. No cross-tenant existence check needed since this tenant is
                // about to be created fresh and contains no users yet.
                orgId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                    new { id = orgId, slug });
                await conn.ExecuteAsync(
                    "INSERT INTO org_settings (org_id) VALUES (@id)",
                    new { id = orgId });

                ownerPassword = Convert.ToBase64String(
                    System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
                var hash = BCrypt.Net.BCrypt.HashPassword(ownerPassword, workFactor: 12);
                var userId = Guid.NewGuid().ToString("N");

                await conn.ExecuteAsync(
                    """
                    INSERT INTO users (id, tenant_id, email, password_hash, role, must_change_password)
                    VALUES (@id, @tenantId, @email, @hash, 'owner', 1)
                    """,
                    new { id = userId, tenantId = orgId, email = req.OwnerEmail, hash });

                await conn.ExecuteAsync("COMMIT");
            }
            catch
            {
                await conn.ExecuteAsync("ROLLBACK");
                throw;
            }
        }

        // Audit on a fresh connection — opening it inside the BEGIN IMMEDIATE above would
        // deadlock SQLite's single writer lock.
        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "tenant.created",
            actorId: actor,
            orgId: orgId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { slug, ownerEmail = req.OwnerEmail }),
            ct: ct);

        return Ok(new
        {
            tenant = new { id = orgId, slug },
            owner = new { email = req.OwnerEmail, ownerPassword, mustChangePassword = true },
        });
    }

    /// <summary>
    /// DELETE /api/v1/system/tenants/{slug} — soft-delete. Sets <c>orgs.deleted_at</c>; the
    /// subdomain immediately starts returning 404. system_admin can restore via the restore
    /// endpoint within <c>TENANT_HARD_DELETE_GRACE_DAYS</c> (default 30); after that, the
    /// background <see cref="Background.TenantHardDeleteService"/> hard-deletes via FK cascade.
    /// </summary>
    [HttpDelete("tenants/{slug}")]
    public async Task<IActionResult> SoftDeleteTenant(string slug, CancellationToken ct)
    {
        var org = await _orgs.GetBySlugAsync(slug, ct: ct);
        if (org is null) return NotFound();

        await _orgs.SoftDeleteOrgAsync(org.Id, ct);

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "tenant.deleted",
            actorId: actor,
            orgId: org.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { slug }),
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// PATCH /api/v1/system/tenants/{slug}/restore — restore a soft-deleted tenant. Returns 404
    /// if the tenant doesn't exist or isn't currently soft-deleted (idempotent on already-active).
    /// </summary>
    [HttpPatch("tenants/{slug}/restore")]
    public async Task<IActionResult> RestoreTenant(string slug, CancellationToken ct)
    {
        var org = await _orgs.GetBySlugAsync(slug, includeDeleted: true, ct: ct);
        if (org is null) return NotFound();
        if (org.DeletedAt is null)
            return _problems.ConflictAction("Tenant is already active.");

        var restored = await _orgs.RestoreOrgAsync(org.Id, ct);
        if (!restored) return NotFound();

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "tenant.restored",
            actorId: actor,
            orgId: org.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { slug }),
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// GET /api/v1/system/users?email=...&amp;tenantSlug=... — minimal user lookup for support
    /// workflows. Returns control-plane metadata only (no business data). At least one of
    /// <c>email</c> or <c>tenantSlug</c> is required.
    /// </summary>
    [HttpGet("users")]
    public async Task<IActionResult> LookupUsers(
        [FromQuery] string? email,
        [FromQuery] string? tenantSlug,
        [FromQuery] int limit = 50,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(email) && string.IsNullOrWhiteSpace(tenantSlug))
            return _problems.ValidationErrorAction("query", "Provide at least one of: email, tenantSlug.");

        limit = Math.Clamp(limit, 1, 200);
        var items = await _orgs.LookupUsersAsync(
            string.IsNullOrWhiteSpace(email) ? null : email,
            string.IsNullOrWhiteSpace(tenantSlug) ? null : tenantSlug,
            limit, ct);
        return Ok(new { items });
    }

    /// <summary>
    /// GET /api/v1/system/audit — operator audit log. Filters strictly to <c>scope='system'</c>
    /// at the repository layer; never returns tenant business events.
    /// </summary>
    [HttpGet("audit")]
    public async Task<IActionResult> ListAudit(
        [FromQuery] int limit = 50, [FromQuery] int page = 1, CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        page = Math.Max(page, 1);
        var offset = (page - 1) * limit;
        var (items, total) = await _audit.ListSystemAuditAsync(limit, offset, ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>
    /// GET /api/v1/system/settings — instance-wide settings (upload limits, GC schedule, etc.).
    /// In multi mode, this is system_admin-only. The legacy <c>/api/v1/instance/settings</c>
    /// is gated on tenant role=owner and remains available in single mode.
    /// </summary>
    [HttpGet("settings")]
    public async Task<IActionResult> GetSettings(CancellationToken ct)
    {
        var settings = await _orgs.ListInstanceSettingsAsync(ct);
        return Ok(settings);
    }

    private static readonly HashSet<string> AllowedInstanceSettingKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "max_upload_bytes",
        "max_upload_bytes_pypi",
        "max_upload_bytes_npm",
        "max_upload_bytes_nuget",
        "gc_schedule",
        "siem_max_lookback_days",
    };

    /// <summary>PUT /api/v1/system/settings — update instance-wide settings.</summary>
    [HttpPut("settings")]
    public async Task<IActionResult> UpdateSettings(
        [FromBody] Dictionary<string, string> settings, CancellationToken ct)
    {
        foreach (var key in settings.Keys)
        {
            if (!AllowedInstanceSettingKeys.Contains(key))
                return _problems.ValidationErrorAction("settings", $"Unknown setting key: {key}");
        }

        foreach (var (key, value) in settings)
            await _orgs.SetInstanceSettingAsync(key, value, ct);

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.instance_settings_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                keys = settings.Keys.ToArray(),
                values = settings,
            }),
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// PATCH /api/v1/system/users/{email}/account-status — lock / unlock / disable a tenant
    /// user account. Body: <c>{ accountStatus, tenantSlug }</c>. Audited.
    /// </summary>
    [HttpPatch("users/{email}/account-status")]
    public async Task<IActionResult> SetAccountStatus(
        string email, [FromBody] SetAccountStatusRequest req, CancellationToken ct)
    {
        if (req is null || string.IsNullOrWhiteSpace(req.TenantSlug))
            return _problems.ValidationErrorAction("tenantSlug", "tenantSlug is required.");
        if (req.AccountStatus is not ("active" or "locked" or "disabled"))
            return _problems.ValidationErrorAction("accountStatus", "Must be 'active', 'locked', or 'disabled'.");

        var ok = await _orgs.SetUserAccountStatusAsync(email, req.TenantSlug, req.AccountStatus, ct);
        if (!ok) return NotFound();

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.account_status_changed",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new { email, tenantSlug = req.TenantSlug, accountStatus = req.AccountStatus }),
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// POST /api/v1/system/users/{email}/password-reset — issues a temporary password and
    /// forces rotation on next login. Body: <c>{ tenantSlug }</c>. The temporary password is
    /// returned in the response so the operator can hand it to the user out-of-band; it is
    /// not persisted in plaintext anywhere. Audited.
    /// </summary>
    [HttpPost("users/{email}/password-reset")]
    public async Task<IActionResult> IssuePasswordReset(
        string email, [FromBody] PasswordResetRequest req, CancellationToken ct)
    {
        if (req is null || string.IsNullOrWhiteSpace(req.TenantSlug))
            return _problems.ValidationErrorAction("tenantSlug", "tenantSlug is required.");

        var result = await _orgs.IssuePasswordResetAsync(email, req.TenantSlug, ct);
        if (result is null) return NotFound();

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.password_reset",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new { email, tenantSlug = req.TenantSlug }),
            ct: ct);

        return Ok(new
        {
            email,
            tenantSlug = req.TenantSlug,
            temporaryPassword = result.Value.TemporaryPassword,
            issuedAt = result.Value.IssuedAt,
            mustChangePassword = true,
        });
    }

    /// <summary>
    /// POST /api/v1/system/me/password — system_admin self-rotation. Required after first
    /// boot (must_change_password=1) and any time the operator wants to rotate.
    /// </summary>
    [HttpPost("me/password")]
    public async Task<IActionResult> ChangeMyPassword(
        [FromBody] ChangePasswordRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
            return _problems.ValidationErrorAction("currentPassword", "Current password is required.");
        if (string.IsNullOrWhiteSpace(req.NewPassword) || req.NewPassword.Length < 12)
            return _problems.ValidationErrorAction("newPassword", "New password must be at least 12 characters.");
        if (req.NewPassword == req.CurrentPassword)
            return _problems.ValidationErrorAction("newPassword", "New password must differ from current.");

        var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null) return Unauthorized();

        var newHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword, workFactor: 12);
        var rotated = await _systemAdmins.RotatePasswordAsync(sub, req.CurrentPassword, newHash, ct);
        if (!rotated) return Unauthorized(new { detail = "Current password is incorrect." });

        await _audit.LogSystemAsync(
            action: "system_admin.password_changed",
            actorId: sub,
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// GET /api/v1/system/me — minimal identity for the apex SPA: who am I and do I need
    /// to rotate.
    /// </summary>
    [HttpGet("me")]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null) return Unauthorized();

        var sa = await _systemAdmins.GetByIdAsync(sub, ct);
        if (sa is null) return NotFound();

        return Ok(new
        {
            id = sa.Id,
            email = sa.Email,
            mustChangePassword = sa.MustChangePassword,
            lastLoginAt = sa.LastLoginAt,
            language = string.IsNullOrEmpty(sa.Language) ? LanguageCodes.Default : sa.Language,
        });
    }

    /// <summary>POST /api/v1/system/me/language — set the system_admin's locale override.</summary>
    [HttpPost("me/language")]
    public async Task<IActionResult> UpdateMyLanguage(
        [FromBody] UpdateLanguageRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Language) || !LanguageCodes.IsSupported(req.Language))
            return _problems.ValidationErrorAction("language",
                $"Unsupported language code. Allowed: {string.Join(", ", LanguageCodes.Supported)}.");

        var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null) return Unauthorized();

        await _systemAdmins.UpdateLanguageAsync(sub, req.Language, ct);

        await _audit.LogSystemAsync(
            action: "system_admin.language_changed",
            actorId: sub,
            detail: System.Text.Json.JsonSerializer.Serialize(new { language = req.Language }),
            ct: ct);

        return NoContent();
    }
}

public sealed record SetAccountStatusRequest(string AccountStatus, string TenantSlug);
public sealed record PasswordResetRequest(string TenantSlug);

public sealed record CreateTenantRequest(string Slug, string OwnerEmail);
