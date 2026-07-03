using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

public sealed class AuditRepository
{
    private readonly IMetadataStore _db;
    private readonly ActivityWriter? _activityWriter;
    private readonly TimeProvider _time;

    public AuditRepository(IMetadataStore db, ActivityWriter? activityWriter = null, TimeProvider? time = null)
    {
        _db = db;
        _activityWriter = activityWriter;
        _time = time ?? TimeProvider.System;
    }

    // Millisecond-precision UTC ISO-8601, so multiple events emitted in the same wall-clock
    // second still order deterministically (e.g. first_fetch → vuln_scan → blocked_vuln_score).
    private string NowMs() =>
        _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture);

    // Convenience overload for tenant-scope events. Most call sites use this; the action plus
    // a handful of optional named arguments (orgId, actorId, actorKind, ecosystem, purl, detail,
    // sourceIp) read clearly. sourceIp expects the canonical form produced by
    // HttpContext.GetNormalizedRemoteIp(). actorKind is one of <see cref="ActorKinds"/> (or NULL
    // for legacy/anonymous); pass <c>token.ActorKind</c> when the event was attributed to a
    // resolved <see cref="TokenRecord"/>, or <see cref="ActorKinds.User"/> for JWT-session events.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Optional named-arg surface for the audit log; bundling into a context type would force ~70 call sites to allocate just to skip a single field.")]
    public Task LogAsync(
        string action,
        string? orgId = null,
        string? actorId = null,
        string? actorKind = null,
        string? ecosystem = null,
        string? purl = null,
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
        => WriteAsync(new AuditWrite(action, "tenant", orgId, actorId, actorKind, ecosystem, purl, detail, sourceIp), ct);

    // System-scope events (operator dashboard) — keeps tenant-business events filtered out of
    // the system audit list and vice versa. system_admin actors aren't users or service tokens,
    // so actorKind stays NULL — the system audit list joins to system_admins, not users.
    public Task LogSystemAsync(
        string action,
        string? actorId = null,
        string? orgId = null,
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
        => WriteAsync(new AuditWrite(action, "system", orgId, actorId, null, null, null, detail, sourceIp), ct);

    private async Task WriteAsync(AuditWrite entry, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, actor_kind, action, ecosystem, purl, detail, source_ip, created_at)
            VALUES (@id, @scope, @orgId, @actorId, @actorKind, @action, @ecosystem, @purl, @detail, @sourceIp, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                scope = entry.Scope,
                orgId = entry.OrgId,
                actorId = entry.ActorId,
                actorKind = entry.ActorKind,
                action = entry.Action,
                ecosystem = entry.Ecosystem,
                purl = entry.Purl,
                detail = entry.Detail,
                sourceIp = entry.SourceIp,
                createdAt = NowMs(),
            });
    }

    private sealed record AuditWrite(
        string Action, string Scope,
        string? OrgId, string? ActorId, string? ActorKind,
        string? Ecosystem, string? Purl, string? Detail,
        string? SourceIp);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Optional named-arg surface for per-version activity events; bundling would churn dozens of call sites for no readability gain.")]
    public async Task LogActivityAsync(
        string orgId,
        string ecosystem,
        string? purl,
        string eventType,
        string? actorId = null,
        string? actorKind = null,
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
    {
        var record = new ActivityRecord(
            Id: Guid.NewGuid().ToString("N"),
            OrgId: orgId,
            Ecosystem: ecosystem,
            Purl: purl,
            EventType: eventType,
            ActorId: actorId,
            ActorKind: actorKind,
            Detail: detail,
            SourceIp: sourceIp,
            CreatedAt: NowMs());

        // Fast path — when the async writer is wired (production DI), enqueue and
        // return without touching the DB on the request thread. The hosted-service
        // drainer batches inserts. The synchronous fallback below preserves test
        // behaviour (tests that introspect the `activity` table after a call still see
        // their row) and is also the path used when the writer is intentionally absent.
        if (_activityWriter is not null)
        {
            _activityWriter.TryEnqueue(record);
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id, actor_kind, detail, source_ip, created_at)
            VALUES (@Id, @OrgId, @Ecosystem, @Purl, @EventType, @ActorId, @ActorKind, @Detail, @SourceIp, @CreatedAt)
            """,
            record);
    }

    /// <summary>
    /// Tenant-facing audit list: filters strictly to <c>scope='tenant'</c> so a sloppy join
    /// can never surface operator events to a tenant user.
    /// </summary>
    public async Task<(IReadOnlyList<AuditEntry> Items, int Total)> ListAuditAsync(
        string orgId, int limit, int offset, string? action = null, string? search = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? searchPattern = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim().ToLowerInvariant()}%";
        // The COUNT carries the same actor joins as the list so a search on actor email keeps
        // the total in step with the rows returned (no paging drift).
        int total = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM audit_log a
            LEFT JOIN users u
                ON u.id = a.actor_id
                AND (a.actor_kind IS NULL OR a.actor_kind = 'user')
            LEFT JOIN service_tokens st
                ON st.id = a.actor_id
                AND a.actor_kind = 'service'
            WHERE a.org_id = @orgId AND a.scope = 'tenant'
              AND (@action IS NULL OR a.action = @action)
              AND (@searchPattern IS NULL
                   OR lower(a.action) LIKE @searchPattern
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
            """,
            new { orgId, action, searchPattern });
        // Service-token actors live in a different table than users; resolve both and pick
        // by actor_kind. NULL actor_kind = legacy row (pre-migration) — fall back to the
        // users join for back-compat. The 'service:<name>' prefix matches the npm whoami
        // identifier shape (TokenRepository.GetWhoAmIIdentifierAsync) so operators see the
        // same string in audit rows and in package metadata.
        var rows = await conn.QueryAsync<AuditEntry>(
            """
            SELECT a.id, a.scope as Scope, a.org_id as OrgId, a.actor_id as ActorId,
                   CASE WHEN a.actor_kind = 'service' THEN 'service:' || st.name
                        ELSE u.email
                   END as ActorEmail,
                   a.action as Action,
                   a.ecosystem as Ecosystem, a.purl as Purl, a.detail as Detail,
                   a.created_at as CreatedAt
            FROM audit_log a
            LEFT JOIN users u
                ON u.id = a.actor_id
                AND (a.actor_kind IS NULL OR a.actor_kind = 'user')
            LEFT JOIN service_tokens st
                ON st.id = a.actor_id
                AND a.actor_kind = 'service'
            WHERE a.org_id = @orgId AND a.scope = 'tenant'
              AND (@action IS NULL OR a.action = @action)
              AND (@searchPattern IS NULL
                   OR lower(a.action) LIKE @searchPattern
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
            ORDER BY a.created_at DESC, a.id DESC LIMIT @limit OFFSET @offset
            """,
            new { orgId, limit, offset, action, searchPattern });
        return (rows.ToList(), total);
    }

    /// <summary>
    /// system_admin-facing audit list: filters strictly to <c>scope='system'</c> events
    /// (tenant.created, tenant.deleted, tenant.restored, tenant.hard_deleted, tenant.status_changed,
    /// system_admin.*). Never returns tenant-business events.
    /// </summary>
    /// <param name="search">Optional case-insensitive substring match across action, actor_id, org_id, detail.</param>
    /// <param name="action">Optional exact-match filter on the action column.</param>
    /// <param name="sortBy">'createdAt' (default) or 'action'. Unknown values fall back to 'createdAt'.</param>
    /// <param name="sortDir">'asc' or 'desc' (default). Unknown values fall back to 'desc'.</param>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated WHERE fragments are const strings containing only @param placeholders. " +
                        "ORDER BY column and direction are whitelisted via switch expressions that return " +
                        "compile-time-constant literals (\"action\"/\"created_at\") and the literal strings " +
                        "\"ASC\"/\"DESC\"; caller input only selects which constant to use.")]
    public async Task<(IReadOnlyList<AuditEntry> Items, int Total)> ListSystemAuditAsync(
        int limit, int offset,
        string? search = null, string? action = null,
        string? sortBy = null, string? sortDir = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // ORDER BY is interpolated into the SQL — whitelist before use. Never trust raw input here.
        string orderColumn = sortBy switch
        {
            "action" => "action",
            _ => "created_at",
        };
        string orderDirection = string.Equals(sortDir, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC" : "DESC";

        string? searchPattern = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim().ToLowerInvariant()}%";
        string? actionFilter = string.IsNullOrWhiteSpace(action) ? null : action;

        // Single where clause shared by the count and list queries — both join system_admins
        // (for ActorEmail / email search) and orgs (for OrgSlug / tenant-name search), so the
        // total reflects the same slug matches the page shows.
        const string listWhereClause = """
            a.scope = 'system'
              AND (@action IS NULL OR a.action = @action)
              AND (@searchPattern IS NULL
                   OR lower(a.action) LIKE @searchPattern
                   OR lower(COALESCE(a.actor_id, '')) LIKE @searchPattern
                   OR lower(COALESCE(sa.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.org_id, '')) LIKE @searchPattern
                   OR lower(COALESCE(o.slug, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern)
            """;

        // rawsql: only the const listWhereClause (only @param placeholders) is interpolated (see S2077 justification above).
        int total = await conn.ExecuteScalarAsync<int>(
            $"SELECT COUNT(*) FROM audit_log a LEFT JOIN system_admins sa ON sa.id = a.actor_id LEFT JOIN orgs o ON o.id = a.org_id WHERE {listWhereClause}",
            new { action = actionFilter, searchPattern });

        // LEFT JOIN system_admins (not users) — every scope='system' actor is a system_admin.
        // Unmatched actor_ids surface as NULL ActorEmail; the UI falls back to actor_id.
        // LEFT JOIN orgs resolves the tenant slug for display; NULL for apex events or a deleted org.
        // rawsql: only the whitelisted ORDER BY column/direction are interpolated (see S2077 justification above).
        string listSql = $"""
            SELECT a.id, a.scope as Scope, a.org_id as OrgId, o.slug as OrgSlug, a.actor_id as ActorId,
                   sa.email as ActorEmail, a.action as Action,
                   a.ecosystem as Ecosystem, a.purl as Purl, a.detail as Detail,
                   a.created_at as CreatedAt
            FROM audit_log a LEFT JOIN system_admins sa ON sa.id = a.actor_id LEFT JOIN orgs o ON o.id = a.org_id
            WHERE {listWhereClause}
            ORDER BY a.{orderColumn} {orderDirection}, a.id DESC LIMIT @limit OFFSET @offset
            """;

        var rows = await conn.QueryAsync<AuditEntry>(
            listSql,
            new { limit, offset, action = actionFilter, searchPattern });
        return (rows.ToList(), total);
    }

    /// <summary>
    /// Returns the distinct set of <c>action</c> values for <c>scope='system'</c> audit rows,
    /// for populating the operator audit-page filter dropdown. Sorted alphabetically.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListDistinctSystemActionsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<string>(
            "SELECT DISTINCT action FROM audit_log WHERE scope = 'system' ORDER BY action ASC");
        return rows.ToList();
    }

    /// <summary>
    /// Lists auth-relevant audit events for the SIEM events/auth endpoint.
    /// Filters by action prefix (e.g. "login.") and optional org scope.
    /// Paged by (created_at DESC, id DESC); cursor = base64(timestamp|id).
    /// </summary>
    public async Task<(IReadOnlyList<AuditEntry> Items, string? NextCursor)> ListAuthEventsAsync(
        DateTimeOffset since,
        DateTimeOffset until,
        string? orgId,
        IReadOnlyList<string>? actionFilter,
        int limit,
        string? afterCursor,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Default: all security-relevant event categories
        string[] defaultActions = new[] { "login.", "lockout.", "token.", "rbac." };
        string[] patterns = actionFilter?.Count > 0
            ? actionFilter.Select(a => a.TrimEnd('.') + ".").ToArray()
            : defaultActions;

        // Decode cursor
        string? cursorTs = null;
        string? cursorId = null;
        if (afterCursor is not null)
        {
            try
            {
                string decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(afterCursor));
                string[] parts = decoded.Split('|', 2);
                if (parts.Length == 2) { cursorTs = parts[0]; cursorId = parts[1]; }
            }
            catch { /* invalid cursor — ignore, return first page */ }
        }

        // Action prefix filter passed as JSON array; json_each unfolds it inline so the
        // SQL stays static regardless of how many prefixes the caller supplies.
        string patternsJson = System.Text.Json.JsonSerializer.Serialize(patterns.Select(p => p + "%"));

        const string sql = """
            SELECT id, org_id as OrgId, actor_id as ActorId, action as Action,
                   ecosystem as Ecosystem, purl as Purl, detail as Detail,
                   created_at as CreatedAt
            FROM audit_log al
            WHERE EXISTS (SELECT 1 FROM json_each(@patternsJson) j WHERE al.action LIKE j.value)
              AND al.created_at >= @since
              AND al.created_at <= @until
              AND (@orgId IS NULL OR al.org_id = @orgId)
              AND (@cursorTs IS NULL OR al.created_at < @cursorTs OR (al.created_at = @cursorTs AND al.id < @cursorId))
            ORDER BY al.created_at DESC, al.id DESC
            LIMIT @fetch
            """;

        var rows = (await conn.QueryAsync<AuditEntry>(sql, new
        {
            patternsJson,
            since = since.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            until = until.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            orgId,
            fetch = limit + 1,
            cursorTs,
            cursorId,
        })).ToList();

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            rows.RemoveAt(rows.Count - 1);
            var last = rows[^1];
            nextCursor = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes($"{last.CreatedAt:yyyy-MM-ddTHH:mm:ssZ}|{last.Id}"));
        }

        return (rows, nextCursor);
    }

    public async Task<(IReadOnlyList<ActivityEntry> Items, int Total)> ListActivityAsync(
        string orgId, int limit, int offset, string? eventType = null, string? search = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? searchPattern = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim().ToLowerInvariant()}%";
        // The 'blocked' token selects the whole block-gate family (blocked, blocked_release_age,
        // blocked_malicious, …) so the filter agrees with the dashboard's 'blocked%' tally; any
        // specific 'blocked_<gate>' value still matches exactly. The COUNT carries the same actor
        // joins as the list so a search on actor email keeps the total in step (no paging drift).
        int total = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM activity a
            LEFT JOIN users u
                ON u.id = a.actor_id
                AND (a.actor_kind IS NULL OR a.actor_kind = 'user')
            LEFT JOIN service_tokens st
                ON st.id = a.actor_id
                AND a.actor_kind = 'service'
            WHERE a.org_id = @orgId
              AND (@eventType IS NULL
                   OR (@eventType = 'blocked' AND a.event_type LIKE 'blocked%')
                   OR (@eventType <> 'blocked' AND a.event_type = @eventType))
              AND (@searchPattern IS NULL
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern
                   OR lower(a.event_type) LIKE @searchPattern
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
            """,
            new { orgId, eventType, searchPattern });
        // See ListAuditAsync for the actor_kind branching rationale.
        var rows = await conn.QueryAsync<ActivityEntry>(
            """
            SELECT a.id, a.org_id as OrgId, a.ecosystem as Ecosystem, a.purl as Purl,
                   a.event_type as EventType, a.actor_id as ActorId,
                   CASE WHEN a.actor_kind = 'service' THEN 'service:' || st.name
                        ELSE u.email
                   END as ActorEmail,
                   a.detail as Detail, a.source_ip as SourceIp, a.created_at as CreatedAt
            FROM activity a
            LEFT JOIN users u
                ON u.id = a.actor_id
                AND (a.actor_kind IS NULL OR a.actor_kind = 'user')
            LEFT JOIN service_tokens st
                ON st.id = a.actor_id
                AND a.actor_kind = 'service'
            WHERE a.org_id = @orgId
              AND (@eventType IS NULL
                   OR (@eventType = 'blocked' AND a.event_type LIKE 'blocked%')
                   OR (@eventType <> 'blocked' AND a.event_type = @eventType))
              AND (@searchPattern IS NULL
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern
                   OR lower(a.event_type) LIKE @searchPattern
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT @limit OFFSET @offset
            """,
            new { orgId, limit, offset, eventType, searchPattern });
        return (rows.ToList(), total);
    }
}
