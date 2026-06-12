using System.Security.Claims;
using Dapper;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

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
    private readonly Dependably.Security.PasswordPolicy _passwordPolicy;
    private readonly ITenantSlugCacheInvalidator? _tenantCache;

    // Static vocabulary surfaced on the background-jobs facets endpoint. Mirrors the
    // <c>dependably.background_job.duration</c> histogram outcome label values.
    private static readonly string[] BackgroundJobOutcomes = ["success", "server_error", "cancelled"];

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Controller aggregates 8 independent DI-resolved services (3 repos, metadata store, problem-results helper, configuration, password policy, optional cache invalidator). Bundling into a wrapper record would obscure the DI graph and force every test setup to materialise the wrapper for unrelated callers.")]
    public SystemController(
        OrgRepository orgs,
        SystemAdminRepository systemAdmins,
        IMetadataStore db,
        AuditRepository audit,
        ProblemResults problems,
        IConfiguration config,
        Dependably.Security.PasswordPolicy passwordPolicy,
        ITenantSlugCacheInvalidator? tenantCache = null)
    {
        _orgs = orgs;
        _systemAdmins = systemAdmins;
        _db = db;
        _audit = audit;
        _problems = problems;
        _config = config;
        _passwordPolicy = passwordPolicy;
        _tenantCache = tenantCache;
    }

    /// <summary>GET /api/v1/system/tenants — list all tenants.</summary>
    [HttpGet("tenants")]
    public async Task<IActionResult> ListTenants(
        [FromQuery] int limit = 50, [FromQuery] int page = 1, CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        page = Math.Max(page, 1);
        int offset = (page - 1) * limit;
        var (items, total) = await _orgs.ListOrgsAsync(limit, offset, ct: ct);

        // Control-plane-only projection. memberCount/storageBytes are computed inline in
        // ListOrgsAsync (pre-aggregated subqueries); aggregatesComputedAt is the contract hook
        // for future caching — flip the source from "now" to the cache row's timestamp without
        // a client change.
        var rows = items.Select(o => new
        {
            id = o.Id,
            slug = o.Slug,
            createdAt = o.CreatedAt,
            deletedAt = o.DeletedAt,
            status = o.Status,
            storageQuotaBytes = o.StorageQuotaBytes,
            memberCount = o.MemberCount,
            storageBytes = o.StorageBytes,
        }).ToList();
        return Ok(new
        {
            items = rows,
            total,
            limit,
            offset,
            aggregatesComputedAt = DateTimeOffset.UtcNow,
        });
    }

    /// <summary>POST /api/v1/system/tenants — atomically create a tenant + its first owner.</summary>
    [HttpPost("tenants")]
    public async Task<IActionResult> CreateTenant([FromBody] CreateTenantRequest req, CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorAction("body", "Body is required.");
        }

        var extraReserved = ReservedSlugs.ParseExtra(_config["RESERVED_SUBDOMAINS"]);
        string? slug = ReservedSlugs.Normalize(req.Slug, extraReserved);
        if (slug is null)
        {
            return _problems.ValidationErrorAction("slug", "Slug is missing, reserved, or contains invalid characters.");
        }

        if (string.IsNullOrWhiteSpace(req.OwnerEmail) || !req.OwnerEmail.Contains('@'))
        {
            return _problems.ValidationErrorAction("ownerEmail", "Valid owner email is required.");
        }

        string orgId;
        string ownerPassword;
        await using (var conn = await _db.OpenAsync(ct))
        {
            await conn.ExecuteAsync("BEGIN IMMEDIATE");
            try
            {
                // Slug uniqueness check before commit so the response is a clean 409 instead of
                // a SQLite UNIQUE constraint exception bubbling up.
                int existing = await conn.ExecuteScalarAsync<int>(
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
                // Seed the standard public upstreams so the new tenant proxies out of the box.
                await Dependably.Infrastructure.UpstreamRegistrySeeder.SeedForOrgAsync(conn, orgId, _config, ct: ct);

                ownerPassword = Convert.ToBase64String(
                    System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
                string hash = BCrypt.Net.BCrypt.HashPassword(ownerPassword, workFactor: 12);
                string userId = Guid.NewGuid().ToString("N");

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
        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SoftDeleteTenant(string slug, CancellationToken ct)
    {
        var org = await _orgs.GetBySlugAsync(slug, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        await _orgs.SoftDeleteOrgAsync(org.Id, ct);
        _tenantCache?.InvalidateSlug(slug);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
    /// PATCH /api/v1/system/tenants/{slug}/storage-quota — set (or clear) the tenant's
    /// aggregate storage cap. Body shape: <c>{ "quotaBytes": 1234567890 }</c> sets the cap;
    /// <c>{ "quotaBytes": null }</c> clears it (tenant becomes unlimited). Zero or negative
    /// values are rejected as 422 — clearing must go through an explicit <c>null</c>.
    /// </summary>
    [HttpPatch("tenants/{slug}/storage-quota")]
    public async Task<IActionResult> SetTenantStorageQuota(
        string slug,
        [FromBody] SetStorageQuotaRequest? req,
        CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorAction("body", "Body is required.");
        }

        if (req.QuotaBytes is long bytes && bytes <= 0)
        {
            return _problems.ValidationErrorAction("quotaBytes",
                "Quota must be a positive number of bytes, or null to clear.");
        }

        var org = await _orgs.GetBySlugAsync(slug, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        await _orgs.SetStorageQuotaBytesAsync(org.Id, req.QuotaBytes, ct);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "tenant.quota_changed",
            actorId: actor,
            orgId: org.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                slug,
                quotaBytes = req.QuotaBytes,
                priorQuotaBytes = org.StorageQuotaBytes,
            }),
            ct: ct);

        return Ok(new { slug, quotaBytes = req.QuotaBytes });
    }

    /// <summary>
    /// PATCH /api/v1/system/tenants/{slug}/status — flip the tenant lifecycle gate between
    /// <c>'active'</c> and <c>'suspended'</c>. Suspending immediately causes
    /// <see cref="Storage.ITenantStorageResolver"/> to reject registry writes for the tenant
    /// (raising <see cref="Storage.TenantNotReadyException"/>); existing data is preserved.
    /// Body: <c>{ "status": "active" | "suspended" }</c>. Soft-deleted tenants must be restored
    /// first. <c>'archived'</c> and <c>'deleting'</c> are enterprise-only and rejected here.
    /// </summary>
    [HttpPatch("tenants/{slug}/status")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetTenantStatus(
        string slug,
        [FromBody] SetTenantStatusRequest? req,
        CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorAction("body", "Body is required.");
        }

        if (req.Status is not ("active" or "suspended"))
        {
            return _problems.ValidationErrorAction("status",
                "Must be 'active' or 'suspended'. ('archived' and 'deleting' are enterprise-only.)");
        }

        var org = await _orgs.GetBySlugAsync(slug, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        string priorStatus = org.Status;
        bool ok = await _orgs.UpdateOrgStatusAsync(org.Id, req.Status, ct);
        if (!ok)
        {
            return NotFound();
        }

        _tenantCache?.InvalidateSlug(slug);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "tenant.status_changed",
            actorId: actor,
            orgId: org.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { slug, status = req.Status, priorStatus }),
            ct: ct);

        return NoContent();
    }

    /// <summary>
    /// PATCH /api/v1/system/tenants/{slug}/restore — restore a soft-deleted tenant. Returns 404
    /// if the tenant doesn't exist or isn't currently soft-deleted (idempotent on already-active).
    /// </summary>
    [HttpPatch("tenants/{slug}/restore")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RestoreTenant(string slug, CancellationToken ct)
    {
        var org = await _orgs.GetBySlugAsync(slug, includeDeleted: true, ct: ct);
        if (org is null)
        {
            return NotFound();
        }

        if (org.DeletedAt is null)
        {
            return _problems.ConflictAction("Tenant is already active.");
        }

        bool restored = await _orgs.RestoreOrgAsync(org.Id, ct);
        if (!restored)
        {
            return NotFound();
        }

        _tenantCache?.InvalidateSlug(slug);

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
        {
            return _problems.ValidationErrorAction("query", "Provide at least one of: email, tenantSlug.");
        }

        limit = Math.Clamp(limit, 1, 200);
        var items = await _orgs.LookupUsersAsync(
            string.IsNullOrWhiteSpace(email) ? null : email,
            string.IsNullOrWhiteSpace(tenantSlug) ? null : tenantSlug,
            limit, ct);
        return Ok(new { items });
    }

    /// <summary>
    /// GET /api/v1/system/audit — operator audit log. Filters strictly to <c>scope='system'</c>
    /// at the repository layer; never returns tenant business events. Supports
    /// <c>?search=</c> (substring across action/actor/org/detail), <c>?action=</c> (exact),
    /// <c>?sortBy=createdAt|action</c>, <c>?sortDir=asc|desc</c>.
    /// </summary>
    [HttpGet("audit")]
    public async Task<IActionResult> ListAudit(
        [FromQuery] int limit = 50, [FromQuery] int page = 1,
        [FromQuery] string? search = null, [FromQuery] string? action = null,
        [FromQuery] string? sortBy = null, [FromQuery] string? sortDir = null,
        CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        page = Math.Max(page, 1);
        int offset = (page - 1) * limit;
        var (items, total) = await _audit.ListSystemAuditAsync(
            limit, offset, search, action, sortBy, sortDir, ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>
    /// GET /api/v1/system/audit/actions — distinct action values for the system audit-log
    /// filter dropdown. Cheap query; client can cache for the lifetime of the page.
    /// </summary>
    [HttpGet("audit/actions")]
    public async Task<IActionResult> ListAuditActions(CancellationToken ct = default)
    {
        var actions = await _audit.ListDistinctSystemActionsAsync(ct);
        return Ok(new { actions });
    }

    /// <summary>
    /// GET /api/v1/system/background-jobs — per-run history for the IHostedService workers
    /// (vuln scan / rescan, retention, cache eviction, orphan reconciler, …). Replaces an
    /// earlier in-memory last-success dictionary with a persistent per-run record.
    /// Filters: <c>?search=</c>, <c>?jobName=</c>, <c>?outcome=</c>. Sort:
    /// <c>?sortBy=startedAt|jobName|durationMs|outcome</c>, <c>?sortDir=asc|desc</c>.
    /// </summary>
    [HttpGet("background-jobs")]
    public async Task<IActionResult> ListBackgroundJobs(
        [FromServices] BackgroundJobRunRepository repo,
        [FromQuery] BackgroundJobsQuery query,
        CancellationToken ct = default)
    {
        int limit = Math.Clamp(query.Limit, 1, 200);
        int page = Math.Max(query.Page, 1);
        int offset = (page - 1) * limit;
        var (items, total) = await repo.ListAsync(
            new BackgroundJobRunQuery(
                Search: query.Search,
                JobName: query.JobName,
                Outcome: query.Outcome,
                SortBy: query.SortBy,
                SortDir: query.SortDir,
                Limit: limit,
                Offset: offset),
            ct);
        return Ok(new { items, total, limit, offset });
    }

    /// <summary>
    /// GET /api/v1/system/background-jobs/facets — distinct job_name values and the static
    /// outcome vocabulary, for the filter dropdowns. Cheap query; client can cache.
    /// </summary>
    [HttpGet("background-jobs/facets")]
    public async Task<IActionResult> ListBackgroundJobFacets(
        [FromServices] BackgroundJobRunRepository repo, CancellationToken ct = default)
    {
        var jobNames = await repo.ListDistinctJobNamesAsync(ct);
        return Ok(new
        {
            jobNames,
            outcomes = BackgroundJobOutcomes,
        });
    }

    /// <summary>
    /// GET /api/v1/system/dashboard — operator landing snapshot. Tenant + admin counts bucketed
    /// by lifecycle state, plus the last 5 background-job runs for quick health-at-a-glance.
    /// One-shot render — no polling — so three small queries beats one busy one.
    /// </summary>
    [HttpGet("dashboard")]
    public async Task<IActionResult> GetDashboard(
        [FromServices] BackgroundJobRunRepository jobs, CancellationToken ct = default)
    {
        var (activeTenants, suspendedTenants, softDeletedTenants) = await _orgs.CountByStatusAsync(ct);
        var (activeAdmins, lockedAdmins, disabledAdmins) = await _systemAdmins.CountByAccountStatusAsync(ct);
        var (recentJobs, _) = await jobs.ListAsync(
            new BackgroundJobRunQuery(SortBy: "startedAt", SortDir: "desc", Limit: 5, Offset: 0),
            ct);

        return Ok(new
        {
            tenants = new
            {
                active = activeTenants,
                suspended = suspendedTenants,
                softDeleted = softDeletedTenants,
                total = activeTenants + suspendedTenants + softDeletedTenants,
            },
            admins = new
            {
                active = activeAdmins,
                locked = lockedAdmins,
                disabled = disabledAdmins,
                total = activeAdmins + lockedAdmins + disabledAdmins,
            },
            recentJobs,
        });
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
        "default_storage_quota_bytes",
        "max_active_tokens_per_tenant",
    };

    /// <summary>PUT /api/v1/system/settings — update instance-wide settings.</summary>
    [HttpPut("settings")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateSettings(
        [FromBody] Dictionary<string, string> settings, CancellationToken ct)
    {
        foreach (string key in settings.Keys)
        {
            if (!AllowedInstanceSettingKeys.Contains(key))
            {
                return _problems.ValidationErrorAction("settings", $"Unknown setting key: {key}");
            }
        }

        foreach (var (key, value) in settings)
        {
            await _orgs.SetInstanceSettingAsync(key, value, ct);
        }

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetAccountStatus(
        string email, [FromBody] SetAccountStatusRequest req, CancellationToken ct)
    {
        if (req is null || string.IsNullOrWhiteSpace(req.TenantSlug))
        {
            return _problems.ValidationErrorAction("tenantSlug", "tenantSlug is required.");
        }

        if (req.AccountStatus is not ("active" or "locked" or "disabled"))
        {
            return _problems.ValidationErrorAction("accountStatus", "Must be 'active', 'locked', or 'disabled'.");
        }

        bool ok = await _orgs.SetUserAccountStatusAsync(email, req.TenantSlug, req.AccountStatus, ct);
        if (!ok)
        {
            return NotFound();
        }

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
        {
            return _problems.ValidationErrorAction("tenantSlug", "tenantSlug is required.");
        }

        var result = await _orgs.IssuePasswordResetAsync(email, req.TenantSlug, ct);
        if (result is null)
        {
            return NotFound();
        }

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ChangeMyPassword(
        [FromBody] ChangePasswordRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
        {
            return _problems.ValidationErrorAction("currentPassword", "Current password is required.");
        }

        var verdict = _passwordPolicy.Evaluate(req.NewPassword, new Dependably.Security.PasswordContext());
        if (!verdict.IsOk)
        {
            return _problems.ValidationErrorAction("newPassword", verdict.ToReason());
        }

        if (req.NewPassword == req.CurrentPassword)
        {
            return _problems.ValidationErrorAction("newPassword", "New password must differ from current.");
        }

        string? sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        string newHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword, workFactor: 12);
        bool rotated = await _systemAdmins.RotatePasswordAsync(sub, req.CurrentPassword, newHash, ct);
        if (!rotated)
        {
            return Unauthorized(new { detail = "Current password is incorrect." });
        }

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
        string? sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        var sa = await _systemAdmins.GetByIdAsync(sub, ct);
        return sa is null
            ? NotFound()
            : Ok(new
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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateMyLanguage(
        [FromBody] UpdateLanguageRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Language) || !LanguageCodes.IsSupported(req.Language))
        {
            return _problems.ValidationErrorAction("language",
                $"Unsupported language code. Allowed: {string.Join(", ", LanguageCodes.Supported)}.");
        }

        string? sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        await _systemAdmins.UpdateLanguageAsync(sub, req.Language, ct);

        await _audit.LogSystemAsync(
            action: "system_admin.language_changed",
            actorId: sub,
            detail: System.Text.Json.JsonSerializer.Serialize(new { language = req.Language }),
            ct: ct);

        return NoContent();
    }

    // ── /metrics access config + sysadmin observability page ───────────────────

    /// <summary>
    /// GET /api/v1/system/metrics-access — current resolved /metrics
    /// access config (enable + IP allowlist) plus which source each
    /// knob is coming from. Used by the sysadmin UI to show the
    /// "locked by env" badges.
    /// </summary>
    [HttpGet("metrics-access")]
    public async Task<IActionResult> GetMetricsAccess(
        [FromServices] Dependably.Security.MetricsAccessConfig access,
        CancellationToken ct)
    {
        var resolved = await access.ResolveAsync(ct);
        return Ok(new
        {
            enabled = resolved.Enabled,
            enabledSource = resolved.EnabledSource.ToString().ToLowerInvariant(),
            enabledLockedByEnv = resolved.EnabledLockedByEnv,
            allowedIps = resolved.AllowedRaw,
            allowlistSource = resolved.AllowlistSource.ToString().ToLowerInvariant(),
            allowlistLockedByEnv = resolved.AllowlistLockedByEnv,
        });
    }

    /// <summary>
    /// PUT /api/v1/system/metrics-access — update the /metrics access
    /// config in instance_settings. Returns 409 when the corresponding
    /// env var locks the knob (no silent DB write behind an env
    /// override). Validates each CIDR; rejects malformed with 400.
    /// Accepts and warns on broad /0 entries.
    /// </summary>
    [HttpPut("metrics-access")]
    public async Task<IActionResult> UpdateMetricsAccess(
        [FromBody] UpdateMetricsAccessRequest req,
        [FromServices] Dependably.Security.MetricsAccessConfig access,
        CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorAction("body", "Request body required.");
        }

        var resolved = await access.ResolveAsync(ct);

        if (req.Enabled.HasValue && resolved.EnabledLockedByEnv)
        {
            return EnvLockedConflict("metrics_enabled", "METRICS_ENABLED");
        }

        if (req.AllowedIps is not null && resolved.AllowlistLockedByEnv)
        {
            return EnvLockedConflict("metrics_allowed_ips", "METRICS_ALLOWED_IPS");
        }

        var warnings = new List<string>();
        if (req.AllowedIps is not null)
        {
            var validationError = ValidateAllowedIps(req.AllowedIps, warnings);
            if (validationError is not null)
            {
                return validationError;
            }
        }

        if (req.Enabled.HasValue)
        {
            await _orgs.SetInstanceSettingAsync("metrics_enabled", req.Enabled.Value ? "1" : "0", ct);
        }

        if (req.AllowedIps is not null)
        {
            await _orgs.SetInstanceSettingAsync(
                "metrics_allowed_ips",
                System.Text.Json.JsonSerializer.Serialize(req.AllowedIps),
                ct);
        }

        access.Invalidate();

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.metrics_access_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                allowedIps = req.AllowedIps,
            }),
            ct: ct);

        return Ok(new { warnings });
    }

    private ConflictObjectResult EnvLockedConflict(string field, string envVar) =>
        Conflict(new
        {
            type = "/problems/env-var-locked",
            title = $"{field} is locked by env var",
            detail = $"{envVar} is set; unset the env var to manage via UI.",
        });

    // Strict CIDR validation — malformed entries reject the whole request so
    // the DB never contains junk that MetricsAccessConfig has to silently drop.
    private IActionResult? ValidateAllowedIps(IReadOnlyList<string> allowed, List<string> warnings)
    {
        foreach (string raw in allowed)
        {
            if (!NetTools.IPAddressRange.TryParse(raw, out _))
            {
                return _problems.ValidationErrorAction(
                    "allowedIps",
                    $"\"{raw}\" is not a valid IP or CIDR.");
            }

            if (raw is "0.0.0.0/0" or "::/0")
            {
                warnings.Add($"Allowlist entry \"{raw}\" matches all addresses — this disables the IP gate entirely.");
            }
        }
        return null;
    }

    /// <summary>
    /// GET /api/v1/system/observability — Tier 1 in-app operator view.
    /// Reads in-memory snapshot + scrape diagnostics + metrics-access
    /// config; no DB hits, no OTel introspection. Counters are labelled
    /// "since startup" — rates and percentiles stay in Grafana.
    /// </summary>
    [HttpGet("observability")]
    public async Task<IActionResult> GetObservability(
        [FromServices] Dependably.Infrastructure.Observability.MetricsSnapshotProvider snapshots,
        [FromServices] Dependably.Security.ScrapeDiagnostics diagnostics,
        [FromServices] Dependably.Security.MetricsAccessConfig access,
        CancellationToken ct)
    {
        var snap = snapshots.Capture();
        var (allowedTotal, deniedIpTotal, deniedDisabledTotal) = diagnostics.LifetimeCounts();
        var resolved = await access.ResolveAsync(ct);
        var now = DateTimeOffset.UtcNow;

        return Ok(new
        {
            numbers = new
            {
                activeTenants = snap.ActiveTenants,
                blobStoreSizesByTier = snap.BlobStoreSizesByTier,
                backgroundJobs = snap.BackgroundJobLastSuccessUnixSeconds.ToDictionary(
                    kv => kv.Key,
                    kv => new
                    {
                        lastSuccessUnixSeconds = kv.Value,
                        ageSeconds = now.ToUnixTimeSeconds() - kv.Value,
                    }),
                sinceStartup = new
                {
                    publishes = snap.PublishCountSinceStartup,
                    proxyFetches = snap.ProxyFetchCountSinceStartup,
                    cacheHits = snap.CacheHitsSinceStartup,
                    cacheMisses = snap.CacheMissesSinceStartup,
                },
                capturedAt = snap.CapturedAt,
            },
            scrapeDiagnostics = new
            {
                recent = diagnostics.Recent(50).Select(e => new
                {
                    timestamp = e.Timestamp,
                    remoteIp = e.RemoteIp,
                    outcome = e.Outcome.ToString().ToLowerInvariant(),
                }),
                lifetimeCounts = new
                {
                    allowed = allowedTotal,
                    deniedIp = deniedIpTotal,
                    deniedDisabled = deniedDisabledTotal,
                },
            },
            metricsAccess = new
            {
                enabled = resolved.Enabled,
                enabledSource = resolved.EnabledSource.ToString().ToLowerInvariant(),
                allowedIps = resolved.AllowedRaw,
                allowlistSource = resolved.AllowlistSource.ToString().ToLowerInvariant(),
                enabledLockedByEnv = resolved.EnabledLockedByEnv,
                allowlistLockedByEnv = resolved.AllowlistLockedByEnv,
            },
        });
    }

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

        string rawPassword = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
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
            issuedAt = DateTimeOffset.UtcNow,
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

        string rawPassword = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        string hash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        var issuedAt = DateTimeOffset.UtcNow;
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

public sealed record SetAccountStatusRequest(string AccountStatus, string TenantSlug);
public sealed record PasswordResetRequest(string TenantSlug);

public sealed record CreateTenantRequest(string Slug, string OwnerEmail);
public sealed record SetStorageQuotaRequest(long? QuotaBytes);
public sealed record SetTenantStatusRequest(string Status);
public sealed record CreateAdminRequest(string Email);
public sealed record SetAdminAccountStatusRequest(string AccountStatus);

public sealed record UpdateMetricsAccessRequest(bool? Enabled, IReadOnlyList<string>? AllowedIps);

/// <summary>
/// Query-string binding for GET /api/v1/system/background-jobs. ASP.NET binds record properties
/// from query string the same way it binds individual <c>[FromQuery]</c> params, so the public
/// surface is identical to the prior 7-parameter signature.
/// </summary>
public sealed record BackgroundJobsQuery(
    int Limit = 50,
    int Page = 1,
    string? Search = null,
    string? JobName = null,
    string? Outcome = null,
    string? SortBy = null,
    string? SortDir = null);
