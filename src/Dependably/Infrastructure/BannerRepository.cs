using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// CRUD and active-banner resolution for the <c>banners</c> and <c>banner_dismissals</c> tables.
///
/// Scope rules:
/// <list type="bullet">
///   <item>Tenant writes are pinned <c>WHERE scope='tenant' AND org_id=@orgId</c> — 0 rows = 404 (BOLA).</item>
///   <item>System writes are pinned <c>WHERE scope='system'</c>.</item>
///   <item>The resolution query unions system-plane banners (scope='system') with the caller's tenant
///   banners (scope='tenant' AND org_id=@orgId) — annotated xtenant below.</item>
/// </list>
/// </summary>
public sealed class BannerRepository
{
    // Maximum length for the banner body text.
    public const int MaxBodyLength = 2000;

    // Maximum lengths for link fields.
    public const int MaxLinkUrlLength = 2048;
    public const int MaxLinkLabelLength = 200;

    // Maximum simultaneously active (enabled + within time window) banners per scope per tenant.
    public const int MaxActiveBannersPerScope = 10;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public BannerRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    private string NowZ() =>
        _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

    // ── Tenant CRUD ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Lists all banners (including disabled/expired) for the given tenant, for the management
    /// list endpoint. Returns only rows with <c>scope='tenant' AND org_id=@orgId</c>.
    /// </summary>
    public async Task<IReadOnlyList<Banner>> ListTenantAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<Banner>(
            """
            SELECT id, scope, org_id as OrgId, severity, body, link_url as LinkUrl,
                   link_label as LinkLabel, target_role as TargetRole,
                   starts_at as StartsAt, ends_at as EndsAt, enabled, created_by as CreatedBy,
                   created_at as CreatedAt
            FROM banners
            WHERE scope = 'tenant' AND org_id = @orgId
            ORDER BY created_at DESC
            """,
            new { orgId });
        return rows.AsList();
    }

    /// <summary>
    /// Inserts a new tenant-scoped banner. Forces <c>scope='tenant'</c> and <c>org_id=@orgId</c>
    /// regardless of the caller-supplied values.
    /// </summary>
    public async Task<Banner> CreateTenantAsync(
        string orgId, string createdBy, BannerCreateRequest req, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string now = NowZ();
        string severity = req.Severity;
        string body = req.Body;
        string? linkUrl = req.LinkUrl;
        string? linkLabel = req.LinkLabel;
        string targetRole = req.TargetRole;
        string startsAt = req.StartsAt;
        string endsAt = req.EndsAt;
        bool enabled = req.Enabled;
        string createdAt = now;
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO banners (id, scope, org_id, severity, body, link_url, link_label,
                                 target_role, starts_at, ends_at, enabled, created_by, created_at)
            VALUES (@id, 'tenant', @orgId, @severity, @body, @linkUrl, @linkLabel,
                    @targetRole, @startsAt, @endsAt, @enabled, @createdBy, @createdAt)
            """,
            new { id, orgId, severity, body, linkUrl, linkLabel, targetRole, startsAt, endsAt, enabled, createdBy, createdAt });
        return new Banner
        {
            Id = id,
            Scope = "tenant",
            OrgId = orgId,
            Severity = severity,
            Body = body,
            LinkUrl = linkUrl,
            LinkLabel = linkLabel,
            TargetRole = targetRole,
            StartsAt = startsAt,
            EndsAt = endsAt,
            Enabled = enabled,
            CreatedBy = createdBy,
            CreatedAt = now
        };
    }

    /// <summary>
    /// Updates a tenant-scoped banner. Returns <c>true</c> when a row was updated;
    /// <c>false</c> (404) when no row matches <c>id AND scope='tenant' AND org_id=@orgId</c>.
    /// </summary>
    public async Task<bool> UpdateTenantAsync(
        string orgId, string id, BannerUpdateRequest req, CancellationToken ct = default)
    {
        string severity = req.Severity;
        string body = req.Body;
        string? linkUrl = req.LinkUrl;
        string? linkLabel = req.LinkLabel;
        string targetRole = req.TargetRole;
        string startsAt = req.StartsAt;
        string endsAt = req.EndsAt;
        bool enabled = req.Enabled;
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE banners
            SET severity = @severity, body = @body, link_url = @linkUrl, link_label = @linkLabel,
                target_role = @targetRole, starts_at = @startsAt, ends_at = @endsAt, enabled = @enabled
            WHERE id = @id AND scope = 'tenant' AND org_id = @orgId
            """,
            new { id, orgId, severity, body, linkUrl, linkLabel, targetRole, startsAt, endsAt, enabled });
        return rows > 0;
    }

    /// <summary>
    /// Deletes a tenant-scoped banner. Returns <c>true</c> when deleted;
    /// <c>false</c> (404) when no row matches.
    /// </summary>
    public async Task<bool> DeleteTenantAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "DELETE FROM banners WHERE id = @id AND scope = 'tenant' AND org_id = @orgId",
            new { id, orgId });
        return rows > 0;
    }

    // ── System CRUD ──────────────────────────────────────────────────────────────────────────

    /// <summary>Lists all system-scoped banners for the operator management view.</summary>
    public async Task<IReadOnlyList<Banner>> ListSystemAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<Banner>(
            """
            SELECT id, scope, org_id as OrgId, severity, body, link_url as LinkUrl,
                   link_label as LinkLabel, target_role as TargetRole,
                   starts_at as StartsAt, ends_at as EndsAt, enabled, created_by as CreatedBy,
                   created_at as CreatedAt
            FROM banners
            WHERE scope = 'system'
            ORDER BY created_at DESC
            """);
        return rows.AsList();
    }

    /// <summary>Inserts a new system-scoped banner. Forces <c>scope='system'</c> and <c>org_id=NULL</c>.</summary>
    public async Task<Banner> CreateSystemAsync(
        string createdBy, BannerCreateRequest req, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string now = NowZ();
        string severity = req.Severity;
        string body = req.Body;
        string? linkUrl = req.LinkUrl;
        string? linkLabel = req.LinkLabel;
        string targetRole = req.TargetRole;
        string startsAt = req.StartsAt;
        string endsAt = req.EndsAt;
        bool enabled = req.Enabled;
        string createdAt = now;
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO banners (id, scope, org_id, severity, body, link_url, link_label,
                                 target_role, starts_at, ends_at, enabled, created_by, created_at)
            VALUES (@id, 'system', NULL, @severity, @body, @linkUrl, @linkLabel,
                    @targetRole, @startsAt, @endsAt, @enabled, @createdBy, @createdAt)
            """,
            new { id, severity, body, linkUrl, linkLabel, targetRole, startsAt, endsAt, enabled, createdBy, createdAt });
        return new Banner
        {
            Id = id,
            Scope = "system",
            OrgId = null,
            Severity = severity,
            Body = body,
            LinkUrl = linkUrl,
            LinkLabel = linkLabel,
            TargetRole = targetRole,
            StartsAt = startsAt,
            EndsAt = endsAt,
            Enabled = enabled,
            CreatedBy = createdBy,
            CreatedAt = now
        };
    }

    /// <summary>
    /// Updates a system-scoped banner. Returns <c>true</c> when a row was updated;
    /// <c>false</c> (404) when no row matches <c>id AND scope='system'</c>.
    /// </summary>
    public async Task<bool> UpdateSystemAsync(string id, BannerUpdateRequest req, CancellationToken ct = default)
    {
        string severity = req.Severity;
        string body = req.Body;
        string? linkUrl = req.LinkUrl;
        string? linkLabel = req.LinkLabel;
        string targetRole = req.TargetRole;
        string startsAt = req.StartsAt;
        string endsAt = req.EndsAt;
        bool enabled = req.Enabled;
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE banners
            SET severity = @severity, body = @body, link_url = @linkUrl, link_label = @linkLabel,
                target_role = @targetRole, starts_at = @startsAt, ends_at = @endsAt, enabled = @enabled
            WHERE id = @id AND scope = 'system'
            """,
            new { id, severity, body, linkUrl, linkLabel, targetRole, startsAt, endsAt, enabled });
        return rows > 0;
    }

    /// <summary>
    /// Deletes a system-scoped banner. Returns <c>true</c> when deleted;
    /// <c>false</c> (404) when no row matches.
    /// </summary>
    public async Task<bool> DeleteSystemAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "DELETE FROM banners WHERE id = @id AND scope = 'system'",
            new { id });
        return rows > 0;
    }

    // ── Resolution ───────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the active, non-dismissed banners visible to the authenticated user.
    /// Unions system-plane banners with the caller's tenant banners; both arms filter on
    /// the time window and role target. Results are ordered severity-first (alert → warn → info)
    /// then by start time descending.
    /// </summary>
    public async Task<IReadOnlyList<Banner>> GetActiveAsync(
        string orgId, string userId, string role, CancellationToken ct = default)
    {
        string now = NowZ();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: unions system-plane banners (scope='system', org_id IS NULL) with the
        // caller's tenant banners (scope='tenant' AND org_id=@orgId). System arm is global
        // by design; tenant arm is pinned to @orgId so no other tenant's rows leak.
        var rows = await conn.QueryAsync<Banner>(
            """
            SELECT b.id, b.severity, b.body, b.link_url as LinkUrl, b.link_label as LinkLabel,
                   b.scope, b.org_id as OrgId, b.target_role as TargetRole,
                   b.starts_at as StartsAt, b.ends_at as EndsAt, b.enabled,
                   b.created_by as CreatedBy, b.created_at as CreatedAt
            FROM banners b
            WHERE b.enabled = 1
              AND b.starts_at <= @now
              AND b.ends_at   >  @now
              AND (b.target_role = 'all' OR b.target_role = @role)
              AND ( (b.scope = 'system')
                 OR (b.scope = 'tenant' AND b.org_id = @orgId) )
              AND NOT EXISTS (SELECT 1 FROM banner_dismissals d
                              WHERE d.banner_id = b.id AND d.user_id = @userId)
            ORDER BY CASE b.severity WHEN 'alert' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
                     b.starts_at DESC
            """,
            new { orgId, userId, role, now });
        return rows.AsList();
    }

    // ── Dismissal ────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Records that the user dismissed the given banner. Idempotent via ON CONFLICT DO NOTHING.
    /// Returns <c>true</c> when the banner exists (the dismissal was recorded or was already
    /// present); <c>false</c> when no banner with the given id exists (caller should 404).
    /// </summary>
    public async Task<bool> DismissAsync(string bannerId, string userId, CancellationToken ct = default)
    {
        string now = NowZ();
        await using var conn = await _db.OpenAsync(ct);
        int bannerCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM banners WHERE id = @bannerId",
            new { bannerId });
        if (bannerCount == 0)
        {
            return false;
        }

        await conn.ExecuteAsync(
            """
            INSERT INTO banner_dismissals (banner_id, user_id, dismissed_at)
            VALUES (@bannerId, @userId, @now)
            ON CONFLICT DO NOTHING
            """,
            new { bannerId, userId, now });
        return true;
    }

    // ── Active-count gate ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the count of currently active (enabled + within time window) banners for a given
    /// scope and optional org. Used to enforce <see cref="MaxActiveBannersPerScope"/>.
    /// </summary>
    public async Task<int> CountActiveForScopeAsync(
        string scope, string? orgId, CancellationToken ct = default)
    {
        string now = NowZ();
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM banners
            WHERE scope = @scope
              AND (@orgId IS NULL OR org_id = @orgId)
              AND enabled = 1
              AND starts_at <= @now
              AND ends_at > @now
            """,
            new { scope, orgId, now });
    }

    // ── Tenant hard-delete cleanup ────────────────────────────────────────────────────────────

    /// <summary>
    /// Deletes all tenant-scoped banners for the given org (and their dismissals, via CASCADE).
    /// Called from <see cref="Dependably.Background.TenantHardDeleteService"/> because
    /// <c>banners.org_id</c> carries no FK and won't cascade on <c>DELETE FROM orgs</c>.
    /// </summary>
    public async Task DeleteForOrgAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM banners WHERE scope = 'tenant' AND org_id = @orgId",
            new { orgId });
    }
}

// ── Request DTOs ──────────────────────────────────────────────────────────────────────────────

/// <summary>Payload for creating a banner (tenant or system scope).</summary>
public record BannerCreateRequest(
    string Severity,
    string Body,
    string? LinkUrl,
    string? LinkLabel,
    string TargetRole,
    string StartsAt,
    string EndsAt,
    bool Enabled = true);

/// <summary>Payload for updating a banner (tenant or system scope).</summary>
public record BannerUpdateRequest(
    string Severity,
    string Body,
    string? LinkUrl,
    string? LinkLabel,
    string TargetRole,
    string StartsAt,
    string EndsAt,
    bool Enabled = true);
