using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Health;
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
public sealed partial class SystemController : ControllerBase
{
    // Maximum page size for system admin list responses.
    private const int MaxSystemAdminPageSize = 200;

    // Snapshot age threshold for "stale" warning on tenant health: 2 hours.
    private static readonly TimeSpan SnapshotStaleThreshold = TimeSpan.FromHours(2);

    // Storage utilisation thresholds for per-tenant health signals.
    private const double StorageWarnFraction = 0.90;

    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

    // Random byte count for generated admin passwords (produces a base64 string ≈ 22 chars).
    private const int GeneratedPasswordByteLength = 16;

    // Number of recent diagnostic events surfaced on the diagnostics endpoint.
    private const int DiagnosticsRecentEventCount = 50;

    private readonly OrgRepository _orgs;
    private readonly SystemAdminRepository _systemAdmins;
    private readonly IMetadataStore _db;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly IConfiguration _config;
    private readonly Dependably.Security.PasswordPolicy _passwordPolicy;
    private readonly TimeProvider _time;
    private readonly ITenantSlugCacheInvalidator? _tenantCache;

    // Static vocabulary surfaced on the background-jobs facets endpoint. Mirrors the
    // <c>dependably.background_job.duration</c> histogram outcome label values.
    private static readonly string[] BackgroundJobOutcomes = ["success", "server_error", "cancelled"];

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Controller aggregates 9 independent DI-resolved services (3 repos, metadata store, problem-results helper, " +
            "configuration, password policy, clock, optional cache invalidator). Bundling into a wrapper record would obscure the DI " +
            "graph and force every test setup to materialise the wrapper for unrelated callers.")]
    public SystemController(
        OrgRepository orgs,
        SystemAdminRepository systemAdmins,
        IMetadataStore db,
        AuditRepository audit,
        ProblemResults problems,
        IConfiguration config,
        Dependably.Security.PasswordPolicy passwordPolicy,
        TimeProvider time,
        ITenantSlugCacheInvalidator? tenantCache = null)
    {
        _orgs = orgs;
        _systemAdmins = systemAdmins;
        _db = db;
        _audit = audit;
        _problems = problems;
        _config = config;
        _passwordPolicy = passwordPolicy;
        _time = time;
        _tenantCache = tenantCache;
    }

    /// <summary>GET /api/v1/system/tenants — list all tenants.</summary>
    [HttpGet("tenants")]
    public async Task<IActionResult> ListTenants(
        [FromQuery] int limit = 50, [FromQuery] int page = 1, CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, MaxSystemAdminPageSize);
        page = Math.Max(page, 1);
        int offset = (page - 1) * limit;
        var (items, total) = await _orgs.ListOrgsAsync(limit, offset, ct: ct);

        // Control-plane-only projection. memberCount/storageBytes are computed inline in
        // ListOrgsAsync (pre-aggregated subqueries); aggregatesComputedAt is the contract hook
        // for future caching — flip the source from "now" to the cache row's timestamp without
        // a client change. health derives from suspended status, quota utilisation, stale
        // snapshot, critical vulns, and quarantine pending — deserialized in-handler from
        // the stats_json blob joined per row.
        var now = _time.GetUtcNow();
        var rows = items.Select(o =>
        {
            var (health, stats) = DeriveHealthAndStats(o, now);
            return new
            {
                id = o.Id,
                slug = o.Slug,
                createdAt = o.CreatedAt,
                deletedAt = o.DeletedAt,
                status = o.Status,
                storageQuotaBytes = o.StorageQuotaBytes,
                memberCount = o.MemberCount,
                storageBytes = o.StorageBytes,
                health,
                stats,
            };
        }).ToList();
        return Ok(new
        {
            items = rows,
            total,
            limit,
            offset,
            aggregatesComputedAt = _time.GetUtcNow(),
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
                    System.Security.Cryptography.RandomNumberGenerator.GetBytes(GeneratedPasswordByteLength));
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

        limit = Math.Clamp(limit, 1, MaxSystemAdminPageSize);
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
        limit = Math.Clamp(limit, 1, MaxSystemAdminPageSize);
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
        [FromServices] BackgroundJobRunRepository jobs,
        [FromServices] Dependably.Infrastructure.Observability.MetricsSnapshotProvider snapshots,
        CancellationToken ct = default)
    {
        var (activeTenants, suspendedTenants, softDeletedTenants) = await _orgs.CountByStatusAsync(ct);
        var (activeAdmins, lockedAdmins, disabledAdmins) = await _systemAdmins.CountByAccountStatusAsync(ct);
        var (recentJobs, _) = await jobs.ListAsync(
            new BackgroundJobRunQuery(SortBy: "startedAt", SortDir: "desc", Limit: 5, Offset: 0),
            ct);

        // Instance-wide disk figure from the same in-memory poller snapshot the
        // observability page reads. Empty dictionary (poller hasn't run yet) sums to 0.
        var byTier = snapshots.Capture().BlobStoreSizesByTier;
        long totalBytes = byTier.Values.Sum();

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
            storage = new
            {
                totalBytes,
                byTier,
            },
            recentJobs,
        });
    }

    /// <summary>
    /// GET /api/v1/system/health — instance health rollup. Dependencies (DB · blob store · Redis),
    /// background-job statuses, staging-disk state, and a count of tenants needing attention.
    /// System-admin + apex access enforced by <see cref="Dependably.Security.RouteScopeFilter"/>.
    /// </summary>
    [HttpGet("health")]
    public async Task<IActionResult> GetHealth(
        [FromServices] Dependably.Infrastructure.Health.HealthService health,
        CancellationToken ct = default)
    {
        var report = await health.GetReportAsync(ct);

        return Ok(new
        {
            overall = report.Overall,
            dependencies = report.Dependencies.Select(d => new
            {
                name = d.Name,
                status = d.Status,
            }),
            jobs = report.Jobs.Select(j => new
            {
                name = j.Name,
                status = j.Status,
                ageSeconds = j.AgeSeconds,
                lastRunAt = j.LastRunAt,
                lastOutcome = j.LastOutcome,
            }),
            storage = new
            {
                blobSizesByTier = report.Storage.BlobSizesByTier,
                stagingAvailableBytes = report.Storage.StagingAvailableBytes,
                stagingUsedBytes = report.Storage.StagingUsedBytes,
                stagingBelowThreshold = report.Storage.StagingBelowThreshold,
            },
            tenants = new
            {
                needAttention = report.Tenants.NeedAttention,
            },
            staleSnapshotCount = report.StaleSnapshotCount,
            capturedAt = report.CapturedAt,
        });
    }

    // Severity rank for health status promotion: higher rank wins.
    private const int RankOk = 0;
    private const int RankWarn = 1;
    private const int RankCritical = 2;

    private static int SeverityRank(string s) =>
        s switch { "critical" => RankCritical, "warn" => RankWarn, _ => RankOk };

    // Promotes status to the higher-severity value; "ok" < "warn" < "critical".
    private static string Promote(string current, string candidate) =>
        SeverityRank(candidate) > SeverityRank(current) ? candidate : current;

    // Derives per-tenant health status and a stats summary from OrgListItem data. Returns
    // both so the list projection can include a stats object alongside the health verdict
    // without a second query or parse pass.
    private static (object Health, object? Stats) DeriveHealthAndStats(OrgListItem org, DateTimeOffset now)
    {
        var reasons = new List<string>();
        string status = "ok";
        object? statsSummary = null;

        if (org.Status == "suspended")
        {
            reasons.Add("suspended");
            status = Promote(status, "warn");
        }

        if (org.StorageQuotaBytes.HasValue && org.StorageQuotaBytes.Value > 0)
        {
            double fraction = (double)org.StorageBytes / org.StorageQuotaBytes.Value;
            if (fraction >= 1.0)
            {
                reasons.Add("storage_quota_exceeded");
                status = Promote(status, "critical");
            }
            else if (fraction >= StorageWarnFraction)
            {
                reasons.Add("storage_quota_near");
                status = Promote(status, "warn");
            }
        }

        if (org.StatsComputedAt is null)
        {
            reasons.Add("stats_missing");
            status = Promote(status, "warn");
        }
        else if (!DateTimeOffset.TryParse(org.StatsComputedAt, out var computedAt)
            || now - computedAt > SnapshotStaleThreshold)
        {
            // An unparseable timestamp is surfaced as a stale snapshot, not silently ignored.
            reasons.Add("stats_stale");
            status = Promote(status, "warn");
        }

        if (org.StatsJson is not null)
        {
            var (statsStatus, statsReasons, statsSnapshotSummary) =
                EvaluateStatsHealth(org.StatsJson, org.StatsComputedAt);
            foreach (string reason in statsReasons)
            {
                if (!reasons.Contains(reason))
                {
                    reasons.Add(reason);
                }
            }

            status = Promote(status, statsStatus);
            statsSummary = statsSnapshotSummary;
        }

        var health = new { status, reasons };
        return (health, statsSummary);
    }

    // Evaluates the per-tenant stats snapshot in isolation so the snapshot parsing and its
    // nesting stay out of DeriveHealthAndStats. Returns the health verdict plus a summary object
    // built from the same parse (so the list projection needs no second parse). A stale or
    // malformed snapshot surfaces as "stats_stale" and a null summary.
    private static (string Status, IReadOnlyList<string> Reasons, object? Summary) EvaluateStatsHealth(
        string statsJson, string? computedAt)
    {
        var reasons = new List<string>();
        string status = "ok";
        object? summary = null;

        try
        {
            var stats = JsonSerializer.Deserialize<OrgStats>(statsJson, WebJsonOptions);
            if (stats is not null)
            {
                if (stats.QuarantinePending > 0)
                {
                    reasons.Add("quarantine_pending");
                    status = Promote(status, "warn");
                }

                // Summary for the frontend detail panel, from the already-parsed stats object.
                summary = new
                {
                    packagesByEcosystem = stats.PackagesByEcosystem,
                    vulnsByEcosystemAndSeverity = stats.VulnsByEcosystemAndSeverity,
                    diskByEcosystem = stats.DiskByEcosystem,
                    totalDownloads30d = stats.TotalDownloads30d,
                    quarantinePending = stats.QuarantinePending,
                    computedAt,
                };
            }
        }
        catch (JsonException)
        {
            // Stale or malformed snapshot: surface as stale, not a crash.
            reasons.Add("stats_stale");
            status = Promote(status, "warn");
        }

        return (status, reasons, summary);
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

    /// <summary>PUT /api/v1/system/settings — update instance-wide settings.</summary>
    [HttpPut("settings")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateSettings(
        [FromBody] Dictionary<string, string> settings, CancellationToken ct)
    {
        foreach (string key in settings.Keys)
        {
            if (!InstanceSettingDefaults.AllowedKeys.Contains(key))
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
        [FromServices] Dependably.Security.ScrapeDiagnostics diagnostics,
        CancellationToken ct)
    {
        var resolved = await access.ResolveAsync(ct);
        return Ok(Dependably.Security.MetricsAccessView.Build(resolved, diagnostics));
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
            return Conflict(Dependably.Security.MetricsAccessEditing.EnvLockedConflictBody("metrics_enabled", "METRICS_ENABLED"));
        }

        if (req.AllowedIps is not null && resolved.AllowlistLockedByEnv)
        {
            return Conflict(Dependably.Security.MetricsAccessEditing.EnvLockedConflictBody("metrics_allowed_ips", "METRICS_ALLOWED_IPS"));
        }

        var warnings = new List<string>();
        if (req.AllowedIps is not null)
        {
            string? invalid = Dependably.Security.MetricsAccessEditing.FindInvalidEntry(req.AllowedIps, warnings);
            if (invalid is not null)
            {
                return _problems.ValidationErrorAction("allowedIps", $"\"{invalid}\" is not a valid IP or CIDR.");
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
        var now = _time.GetUtcNow();

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
                recent = diagnostics.Recent(DiagnosticsRecentEventCount).Select(e => new
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
