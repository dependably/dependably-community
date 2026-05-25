using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

public sealed class AuditRepository
{
    private readonly IMetadataStore _db;

    public AuditRepository(IMetadataStore db) => _db = db;

    // Millisecond-precision UTC ISO-8601, so multiple events emitted in the same wall-clock
    // second still order deterministically (e.g. first_fetch → vuln_scan → blocked_vuln_score).
    private static string NowMs() =>
        DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture);

    // Convenience overload for tenant-scope events. Most call sites use this; the action plus
    // a handful of optional named arguments (orgId, actorId, ecosystem, purl, detail, sourceIp)
    // read clearly. sourceIp expects the canonical form produced by HttpContext.GetNormalizedRemoteIp().
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Optional named-arg surface for the audit log; bundling into a context type would force ~70 call sites to allocate just to skip a single field.")]
    public Task LogAsync(
        string action,
        string? orgId = null,
        string? actorId = null,
        string? ecosystem = null,
        string? purl = null,
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
        => WriteAsync(new AuditWrite(action, "tenant", orgId, actorId, ecosystem, purl, detail, sourceIp), ct);

    // System-scope events (operator dashboard) — keeps tenant-business events filtered out of
    // the system audit list and vice versa.
    public Task LogSystemAsync(
        string action,
        string? actorId = null,
        string? orgId = null,
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
        => WriteAsync(new AuditWrite(action, "system", orgId, actorId, null, null, detail, sourceIp), ct);

    private async Task WriteAsync(AuditWrite entry, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, action, ecosystem, purl, detail, source_ip, created_at)
            VALUES (@id, @scope, @orgId, @actorId, @action, @ecosystem, @purl, @detail, @sourceIp, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                scope = entry.Scope,
                orgId = entry.OrgId,
                actorId = entry.ActorId,
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
        string? OrgId, string? ActorId,
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
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id, detail, source_ip, created_at)
            VALUES (@id, @orgId, @ecosystem, @purl, @eventType, @actorId, @detail, @sourceIp, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                ecosystem,
                purl,
                eventType,
                actorId,
                detail,
                sourceIp,
                createdAt = NowMs()
            });
    }

    /// <summary>
    /// Tenant-facing audit list: filters strictly to <c>scope='tenant'</c> so a sloppy join
    /// can never surface operator events to a tenant user.
    /// </summary>
    public async Task<(IReadOnlyList<AuditEntry> Items, int Total)> ListAuditAsync(
        string orgId, int limit, int offset, string? action = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var total = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE org_id = @orgId AND scope = 'tenant'
              AND (@action IS NULL OR action = @action)
            """,
            new { orgId, action });
        var rows = await conn.QueryAsync<AuditEntry>(
            """
            SELECT a.id, a.scope as Scope, a.org_id as OrgId, a.actor_id as ActorId,
                   u.email as ActorEmail, a.action as Action,
                   a.ecosystem as Ecosystem, a.purl as Purl, a.detail as Detail,
                   a.created_at as CreatedAt
            FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
            WHERE a.org_id = @orgId AND a.scope = 'tenant'
              AND (@action IS NULL OR a.action = @action)
            ORDER BY a.created_at DESC, a.id DESC LIMIT @limit OFFSET @offset
            """,
            new { orgId, limit, offset, action });
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
        var orderColumn = sortBy switch
        {
            "action" => "action",
            _ => "created_at",
        };
        var orderDirection = string.Equals(sortDir, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC" : "DESC";

        var searchPattern = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim().ToLowerInvariant()}%";
        var actionFilter = string.IsNullOrWhiteSpace(action) ? null : action;

        // Two where clauses because the count query doesn't need the system_admins join — but
        // the list query does, so search can match on operator email and the result projection
        // can return ActorEmail without a second round-trip.
        const string countWhereClause = """
            scope = 'system'
              AND (@action IS NULL OR action = @action)
              AND (@searchPattern IS NULL
                   OR lower(action) LIKE @searchPattern
                   OR lower(COALESCE(actor_id, '')) LIKE @searchPattern
                   OR lower(COALESCE(org_id, '')) LIKE @searchPattern
                   OR lower(COALESCE(detail, '')) LIKE @searchPattern)
            """;

        const string listWhereClause = """
            a.scope = 'system'
              AND (@action IS NULL OR a.action = @action)
              AND (@searchPattern IS NULL
                   OR lower(a.action) LIKE @searchPattern
                   OR lower(COALESCE(a.actor_id, '')) LIKE @searchPattern
                   OR lower(COALESCE(sa.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.org_id, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern)
            """;

        var total = await conn.ExecuteScalarAsync<int>(
            $"SELECT COUNT(*) FROM audit_log WHERE {countWhereClause}",
            new { action = actionFilter, searchPattern });

        // LEFT JOIN system_admins (not users) — every scope='system' actor is a system_admin.
        // Unmatched actor_ids surface as NULL ActorEmail; the UI falls back to actor_id.
        var listSql = $"""
            SELECT a.id, a.scope as Scope, a.org_id as OrgId, a.actor_id as ActorId,
                   sa.email as ActorEmail, a.action as Action,
                   a.ecosystem as Ecosystem, a.purl as Purl, a.detail as Detail,
                   a.created_at as CreatedAt
            FROM audit_log a LEFT JOIN system_admins sa ON sa.id = a.actor_id
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
        var defaultActions = new[] { "login.", "lockout.", "token.", "rbac." };
        var patterns = actionFilter?.Count > 0
            ? actionFilter.Select(a => a.TrimEnd('.') + ".").ToArray()
            : defaultActions;

        // Decode cursor
        string? cursorTs = null;
        string? cursorId = null;
        if (afterCursor is not null)
        {
            try
            {
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(afterCursor));
                var parts = decoded.Split('|', 2);
                if (parts.Length == 2) { cursorTs = parts[0]; cursorId = parts[1]; }
            }
            catch { /* invalid cursor — ignore, return first page */ }
        }

        // Action prefix filter passed as JSON array; json_each unfolds it inline so the
        // SQL stays static regardless of how many prefixes the caller supplies.
        var patternsJson = System.Text.Json.JsonSerializer.Serialize(patterns.Select(p => p + "%"));

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
        string orgId, int limit, int offset, string? eventType = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var total = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM activity
            WHERE org_id = @orgId
              AND (@eventType IS NULL OR event_type = @eventType)
            """,
            new { orgId, eventType });
        var rows = await conn.QueryAsync<ActivityEntry>(
            """
            SELECT a.id, a.org_id as OrgId, a.ecosystem as Ecosystem, a.purl as Purl,
                   a.event_type as EventType, a.actor_id as ActorId, u.email as ActorEmail,
                   a.detail as Detail, a.source_ip as SourceIp, a.created_at as CreatedAt
            FROM activity a LEFT JOIN users u ON u.id = a.actor_id
            WHERE a.org_id = @orgId
              AND (@eventType IS NULL OR a.event_type = @eventType)
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT @limit OFFSET @offset
            """,
            new { orgId, limit, offset, eventType });
        return (rows.ToList(), total);
    }
}
