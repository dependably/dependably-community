using System.Data.Common;
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
    private string NowMs() => _time.GetUtcNow().ToUtcIsoMillis();

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
        string? actorLabel = null,
        CancellationToken ct = default)
        => WriteAsync(new AuditWrite(action, "tenant", orgId, actorId, actorKind, ecosystem, purl, detail, sourceIp, actorLabel), ct);

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
        => WriteAsync(new AuditWrite(action, "system", orgId, actorId, null, null, null, detail, sourceIp, null), ct);

    /// <summary>
    /// <see cref="LogSystemAsync(string,string?,string?,string?,string?,CancellationToken)"/> written
    /// on a caller-supplied connection and transaction, so the audit row lands in the same atomic
    /// unit as the work it records. <see cref="Dependably.Background.TenantHardDeleteService"/> needs
    /// this: its erasure sequence is one transaction, and a <c>tenant.hard_deleted</c> row written
    /// outside it would either claim a deletion that later rolled back, or be lost while the
    /// deletion committed.
    /// </summary>
    public Task LogSystemAsync(
        DbConnection conn,
        DbTransaction? tx,
        string action,
        string? actorId = null,
        string? orgId = null,
        string? detail = null,
        string? sourceIp = null,
        CancellationToken ct = default)
        => WriteAsync(new AuditWrite(action, "system", orgId, actorId, null, null, null, detail, sourceIp, null), conn, tx, ct);

    private async Task WriteAsync(AuditWrite entry, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        await WriteAsync(entry, conn, tx: null, ct);
    }

    private async Task WriteAsync(AuditWrite entry, DbConnection conn, DbTransaction? tx, CancellationToken ct)
    {
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, actor_kind, actor_label, action, ecosystem, purl, detail, source_ip, created_at)
            VALUES (@id, @scope, @orgId, @actorId, @actorKind, @actorLabel, @action, @ecosystem, @purl, @detail, @sourceIp, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                scope = entry.Scope,
                orgId = entry.OrgId,
                actorId = entry.ActorId,
                actorKind = entry.ActorKind,
                actorLabel = entry.ActorLabel,
                action = entry.Action,
                ecosystem = entry.Ecosystem,
                purl = entry.Purl,
                detail = entry.Detail,
                sourceIp = entry.SourceIp,
                createdAt = NowMs(),
            },
            transaction: tx, cancellationToken: ct));
    }

    private sealed record AuditWrite(
        string Action, string Scope,
        string? OrgId, string? ActorId, string? ActorKind,
        string? Ecosystem, string? Purl, string? Detail,
        string? SourceIp, string? ActorLabel);

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
        // Appended rather than placed beside actorKind on purpose: AuditAttributionComplianceTests
        // resolves these arguments positionally as a fallback, so inserting mid-signature would
        // silently shift sourceIp's index and blind that gate on positional call sites.
        string? actorLabel = null,
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
            ActorLabel: actorLabel,
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
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id, actor_kind, actor_label, detail, source_ip, created_at)
            VALUES (@Id, @OrgId, @Ecosystem, @Purl, @EventType, @ActorId, @ActorKind, @ActorLabel, @Detail, @SourceIp, @CreatedAt)
            """,
            record);
    }

    /// <summary>
    /// Upper bound on the exact total reported by the paged tenant lists
    /// (<see cref="ListAuditAsync"/>, <see cref="ListActivityAsync"/>). Counting an org's
    /// entire history on every page view is what made the audit page time out on large
    /// instances, so the count stops probing past this bound and the caller reports
    /// "10,000+" instead of an exact figure. The list queries themselves are unaffected —
    /// rows past the cap are still pageable.
    /// </summary>
    public const int ListTotalCap = 10_000;

    /// <summary>
    /// Upper bound on the rows a <em>search</em> examines on the paged tenant lists. The search
    /// predicates are leading-wildcard <c>LIKE</c>s across six columns, which no index can serve,
    /// so an unbounded search reads every row in the filtered window — and the debounced search
    /// box issues one such request per pause in typing. Bounding the scan to the newest
    /// <c>SearchScanCap</c> rows keeps the cost flat as the table grows; the caller reports the
    /// total as capped, because older matches may exist beyond the scanned window.
    /// <para>
    /// The bound applies to every search, the CSV export included. An export is a one-shot action,
    /// but nothing stops a caller from issuing it repeatedly with a term that matches nothing, and
    /// each such request reads the org's entire history — one <c>read:audit</c> holder can put a
    /// single-writer store under sustained full-table scans. The truncation is not silent: the
    /// export path reports it through <c>TotalCapped</c> (see <see cref="ListAuditAsync"/> and
    /// <see cref="ListActivityAsync"/>), which the controller surfaces on the response, so a
    /// compliance export that needs the older window can be narrowed by <c>action</c>/<c>since</c>
    /// or run without a search term instead of quietly coming back short.
    /// </para>
    /// </summary>
    public const int SearchScanCap = 50_000;

    /// <summary>
    /// Resolves the <c>created_at</c> floor that bounds a search to the newest
    /// <see cref="SearchScanCap"/> rows of the filtered window, or null when the window holds
    /// fewer rows than the cap (nothing to bound, and the total stays exact).
    /// <para>
    /// The probe deliberately omits the <c>a.id</c> tiebreak the list orders by: it only needs a
    /// timestamp threshold, and dropping the tiebreak lets the ordering come straight off
    /// <c>idx_activity_org</c> as a covering scan instead of through a temp B-tree. Ties on the
    /// boundary timestamp are all admitted by the <c>&gt;=</c> comparison, so the bound is
    /// approximate by at most one timestamp's worth of rows — which is the point: it is a cost
    /// ceiling, not a row-exact limit.
    /// </para>
    /// </summary>
    private static async Task<string?> ResolveActivityScanFloorAsync(
        DbConnection conn, string orgId, string? eventType, string? since) =>
        await conn.ExecuteScalarAsync<string?>(
            """
            SELECT a.created_at
            FROM activity a
            WHERE a.org_id = @orgId
              AND (@eventType IS NULL
                   OR (@eventType = 'blocked' AND a.event_type LIKE 'blocked%')
                   OR (@eventType <> 'blocked' AND a.event_type = @eventType))
              AND (@since IS NULL OR a.created_at >= @since)
            ORDER BY a.created_at DESC
            LIMIT 1 OFFSET @scanCap
            """,
            new { orgId, eventType, since, scanCap = SearchScanCap });

    /// <summary>
    /// The <see cref="ListAuditAsync"/> counterpart of <see cref="ResolveActivityScanFloorAsync"/>,
    /// over <c>audit_log</c> and its <c>scope='tenant'</c> / <c>login.success</c> filters.
    /// </summary>
    private static async Task<string?> ResolveAuditScanFloorAsync(
        DbConnection conn, string orgId, string? action) =>
        await conn.ExecuteScalarAsync<string?>(
            """
            SELECT a.created_at
            FROM audit_log a
            WHERE a.org_id = @orgId AND a.scope = 'tenant'
              AND a.action <> 'login.success'
              AND (@action IS NULL OR a.action = @action)
            ORDER BY a.created_at DESC
            LIMIT 1 OFFSET @scanCap
            """,
            new { orgId, action, scanCap = SearchScanCap });

    /// <summary>
    /// Tenant-facing audit list: filters strictly to <c>scope='tenant'</c> so a sloppy join
    /// can never surface operator events to a tenant user.
    /// <para>
    /// <c>login.success</c> is excluded: this list backs the configuration/security audit, and a
    /// routine successful login is neither. Successful logins are surfaced in the activity feed
    /// (<see cref="ListActivityAsync"/>, <c>ecosystem='auth'</c>). The audit_log row still exists,
    /// and still carries <c>org_id</c>, purely so <see cref="ListAuthEventsAsync"/> can export it
    /// to a SIEM — a security feed blind to successful logins would be worthless. Failures,
    /// lockouts, and credential changes are security events and DO belong on this list.
    /// </para>
    /// <para>
    /// The total is capped at <see cref="ListTotalCap"/> (probe one past the cap, report
    /// <c>TotalCapped</c>) and, when no search is active, counted without the actor joins:
    /// the joins exist only so a search can match <c>u.email</c>/<c>st.name</c>, but their mere
    /// presence in the statement defeats LEFT-JOIN elimination, costing two B-tree probes per
    /// audited row across the org's whole history. Callers that discard the total (CSV export)
    /// pass <paramref name="includeTotal"/>=false to skip the count entirely.
    /// </para>
    /// <para>
    /// A <em>search</em> is additionally bounded to the newest <see cref="SearchScanCap"/> rows
    /// (see <see cref="ResolveAuditScanFloorAsync"/>), because its <c>LIKE</c> predicates cannot
    /// be served by any index and would otherwise read the org's whole history per keystroke.
    /// Count and list share the one floor, so the total never drifts from the rows returned; a
    /// truncated window reports <c>TotalCapped</c> even when the total is under the cap.
    /// </para>
    /// </summary>
    public async Task<(IReadOnlyList<AuditEntry> Items, int Total, bool TotalCapped)> ListAuditAsync(
        string orgId, int limit, int offset, string? action = null, string? search = null,
        bool includeTotal = true, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? searchPattern = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim().ToLowerInvariant()}%";

        // Only a search needs bounding — the no-search path is already served by the index, and
        // bounding it would stop rows past the cap from being pageable. Every search is bounded,
        // including the total-less CSV export: an unindexable full-history scan a caller can
        // re-issue at will is a cost lever, not a one-shot.
        string? scanFloor = searchPattern is not null
            ? await ResolveAuditScanFloorAsync(conn, orgId, action)
            : null;

        // With no total to compute, a truncated scan window is still what TotalCapped reports —
        // it is the only signal the export path has that older matches went unexamined.
        var (total, totalCapped) = includeTotal
            ? await ComputeAuditTotalAsync(conn, orgId, action, searchPattern, scanFloor)
            : (0, scanFloor is not null);

        // Service-token actors live in a different table than users; resolve both and pick
        // by actor_kind. NULL actor_kind = legacy row (pre-migration) — fall back to the
        // users join for back-compat. The 'service:<name>' prefix matches the npm whoami
        // identifier shape (TokenRepository.GetWhoAmIIdentifierAsync) so operators see the
        // same string in audit rows and in package metadata.
        var rows = await conn.QueryAsync<AuditEntry>(
            """
            SELECT a.id, a.scope as Scope, a.org_id as OrgId, a.actor_id as ActorId,
                   CASE WHEN a.actor_kind = 'service'
                             THEN 'service:' || COALESCE(a.actor_label, st.name)
                        ELSE u.email
                   END as ActorEmail,
                   a.action as Action,
                   a.ecosystem as Ecosystem, a.purl as Purl, a.detail as Detail,
                   a.source_ip as SourceIp,
                   a.created_at as CreatedAt
            FROM audit_log a
            LEFT JOIN users u
                ON u.id = a.actor_id
                AND (a.actor_kind IS NULL OR a.actor_kind = 'user')
            LEFT JOIN service_tokens st
                ON st.id = a.actor_id
                AND a.actor_kind = 'service'
            WHERE a.org_id = @orgId AND a.scope = 'tenant'
              AND a.action <> 'login.success'
              AND (@action IS NULL OR a.action = @action)
              AND (@scanFloor IS NULL OR a.created_at >= @scanFloor)
              AND (@searchPattern IS NULL
                   OR lower(a.action) LIKE @searchPattern
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
            ORDER BY a.created_at DESC, a.id DESC LIMIT @limit OFFSET @offset
            """,
            new { orgId, limit, offset, action, searchPattern, scanFloor });
        return (rows.ToList(), total, totalCapped);
    }

    /// <summary>
    /// The row count backing <see cref="ListAuditAsync"/>'s <c>Total</c>, capped at
    /// <see cref="ListTotalCap"/>. A search counts through the same actor joins the list matches
    /// against (u.email / st.name) and under the same <paramref name="scanFloor"/>, or the total
    /// drifts from the rows returned; an inactive search skips those joins entirely, because
    /// their mere presence in the statement defeats LEFT-JOIN elimination.
    /// </summary>
    private static async Task<(int Total, bool Capped)> ComputeAuditTotalAsync(
        DbConnection conn, string orgId, string? action, string? searchPattern, string? scanFloor)
    {
        int probed = searchPattern is null
            ? await conn.ExecuteScalarAsync<int>(
                """
                SELECT COUNT(*)
                FROM (SELECT 1
                      FROM audit_log a
                      WHERE a.org_id = @orgId AND a.scope = 'tenant'
                        AND a.action <> 'login.success'
                        AND (@action IS NULL OR a.action = @action)
                      LIMIT @countProbe)
                """,
                new { orgId, action, countProbe = ListTotalCap + 1 })
            : await conn.ExecuteScalarAsync<int>(
                """
                SELECT COUNT(*)
                FROM (SELECT 1
                      FROM audit_log a
                      LEFT JOIN users u
                          ON u.id = a.actor_id
                          AND (a.actor_kind IS NULL OR a.actor_kind = 'user')
                      LEFT JOIN service_tokens st
                          ON st.id = a.actor_id
                          AND a.actor_kind = 'service'
                      WHERE a.org_id = @orgId AND a.scope = 'tenant'
                        AND a.action <> 'login.success'
                        AND (@action IS NULL OR a.action = @action)
                        AND (@scanFloor IS NULL OR a.created_at >= @scanFloor)
                        AND (lower(a.action) LIKE @searchPattern
                             OR lower(COALESCE(a.purl, '')) LIKE @searchPattern
                             OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                             OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                             OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                             OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
                      LIMIT @countProbe)
                """,
                new { orgId, action, searchPattern, scanFloor, countProbe = ListTotalCap + 1 });

        // A truncated scan window means older matches may exist that were never examined, so the
        // total is a floor even when it sits well under ListTotalCap.
        bool totalCapped = probed > ListTotalCap || scanFloor is not null;
        return (probed > ListTotalCap ? ListTotalCap : probed, totalCapped);
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
                   a.source_ip as SourceIp,
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
        // xtenant: system-scoped audit rows are operator-plane by definition (scope='system'
        // rows carry no tenant); this feeds the operator audit page's filter dropdown.
        var rows = await conn.QueryAsync<string>(
            "SELECT DISTINCT action FROM audit_log WHERE scope = 'system' ORDER BY action ASC");
        return rows.ToList();
    }

    /// <summary>
    /// Lists auth-relevant audit events for the SIEM events/auth endpoint.
    /// Filters by action prefix (e.g. "login.") and optional org scope.
    /// Paged by (created_at DESC, id DESC); cursor = base64(timestamp|id).
    ///
    /// <c>audit_log.created_at</c> is millisecond-precision text (<see cref="NowMs"/> is its only
    /// writer), so <paramref name="since"/>/<paramref name="until"/> and the cursor timestamp are
    /// all formatted through <see cref="UtcTimestamp.ToUtcIsoMillis"/> to match: comparing a
    /// second-precision bound against millisecond-precision rows misorders on <c>'.'</c> (0x2E)
    /// sorting before <c>'Z'</c> (0x5A), so a row at <c>:00.500Z</c> would fail
    /// <c>&gt;= :00Z</c> and one at <c>:00.000Z</c> would falsely fail <c>&lt;= :00Z</c>. The window
    /// stays closed on both ends (<c>&gt;=</c>/<c>&lt;=</c>) — <see cref="SiemController"/>'s
    /// default <paramref name="until"/> is "now", so a half-open upper bound would silently drop
    /// the instant the request was made; a poller re-supplying the previous page's <c>until</c> as
    /// the next <c>since</c> can see one event appear on both polls only when an event landed
    /// exactly on that millisecond, which the cursor's own strictly-less-than comparison already
    /// prevents from being returned twice within a single paged read.
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

        // Decode cursor. A cursor whose timestamp half doesn't parse as exact millisecond-precision
        // canonical UTC text is rejected outright (treated the same as no cursor — first page)
        // rather than bound as-is: a mismatched shape would silently mis-compare against the
        // millisecond-precision column instead of failing loudly.
        string? cursorTs = null;
        string? cursorId = null;
        if (afterCursor is not null)
        {
            try
            {
                string decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(afterCursor));
                string[] parts = decoded.Split('|', 2);
                if (parts.Length == 2
                    && DateTimeOffset.TryParseExact(
                        parts[0], UtcTimestamp.MillisecondFormat, System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal, out _))
                {
                    cursorTs = parts[0];
                    cursorId = parts[1];
                }
            }
            catch { /* invalid cursor — ignore, return first page */ }
        }

        // Action prefix filter passed as JSON array; json_each unfolds it inline so the
        // SQL stays static regardless of how many prefixes the caller supplies.
        string patternsJson = System.Text.Json.JsonSerializer.Serialize(patterns.Select(p => p + "%"));

        const string sql = """
            SELECT id, org_id as OrgId, actor_id as ActorId, action as Action,
                   ecosystem as Ecosystem, purl as Purl, detail as Detail,
                   source_ip as SourceIp,
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
            since = since.ToUtcIsoMillis(),
            until = until.ToUtcIsoMillis(),
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
                System.Text.Encoding.UTF8.GetBytes($"{last.CreatedAt.ToUtcIsoMillis()}|{last.Id}"));
        }

        return (rows, nextCursor);
    }

    /// <summary>
    /// Pages the activity feed. <paramref name="since"/> is an inclusive ISO-8601 UTC lower bound on
    /// created_at, which is stored as ISO-8601-Z text on both providers, so a lexicographic compare
    /// is a chronological one — the same form <see cref="ListAuditRangeAsync"/> uses. It is what
    /// scopes the feed to the dashboard's 30-day blocked-pull window; the caller resolves the
    /// instant from the injected clock.
    /// <para>
    /// The total follows the same strategy as <see cref="ListAuditAsync"/>: capped at
    /// <see cref="ListTotalCap"/>, counted join-free when no search is active, and skipped
    /// entirely when <paramref name="includeTotal"/> is false (CSV export). A search is likewise
    /// bounded to the newest <see cref="SearchScanCap"/> rows of the filtered window via
    /// <see cref="ResolveActivityScanFloorAsync"/>, which count and list share.
    /// </para>
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Optional named-arg filter/paging surface read at ~20 call sites; a wrapper "
            + "type would force every caller to allocate to skip a single field, for no cohesion "
            + "gain over the current named-argument reads.")]
    public async Task<(IReadOnlyList<ActivityEntry> Items, int Total, bool TotalCapped)> ListActivityAsync(
        string orgId, int limit, int offset, string? eventType = null, string? search = null,
        string? since = null, bool includeTotal = true, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? searchPattern = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim().ToLowerInvariant()}%";

        // Only a search needs bounding — the no-search path is already served by the index, and
        // bounding it would stop rows past the cap from being pageable. Every search is bounded,
        // including the total-less CSV export: see ListAuditAsync for why.
        string? scanFloor = searchPattern is not null
            ? await ResolveActivityScanFloorAsync(conn, orgId, eventType, since)
            : null;

        // With no total to compute, a truncated scan window is still what TotalCapped reports.
        var (total, totalCapped) = includeTotal
            ? await ComputeActivityTotalAsync(conn, orgId, eventType, since, searchPattern, scanFloor)
            : (0, scanFloor is not null);

        // See ListAuditAsync for the actor_kind branching rationale.
        var rows = await conn.QueryAsync<ActivityEntry>(
            """
            SELECT a.id, a.org_id as OrgId, a.ecosystem as Ecosystem, a.purl as Purl,
                   a.event_type as EventType, a.actor_id as ActorId,
                   CASE WHEN a.actor_kind = 'service'
                             THEN 'service:' || COALESCE(a.actor_label, st.name)
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
              AND (@since IS NULL OR a.created_at >= @since)
              AND (@scanFloor IS NULL OR a.created_at >= @scanFloor)
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
            new { orgId, limit, offset, eventType, searchPattern, since, scanFloor });
        return (rows.ToList(), total, totalCapped);
    }

    /// <summary>
    /// The row count backing <see cref="ListActivityAsync"/>'s <c>Total</c>, capped at
    /// <see cref="ListTotalCap"/>. The 'blocked' token selects the whole block-gate family
    /// (blocked, blocked_release_age, blocked_malicious, …) so the filter agrees with the
    /// dashboard's 'blocked%' tally; any specific 'blocked_&lt;gate&gt;' value still matches
    /// exactly. A search count carries the same actor joins, the same since bound, and the same
    /// <paramref name="scanFloor"/> as the list so the total stays in step (no paging drift); an
    /// inactive search skips those joins entirely.
    /// </summary>
    private static async Task<(int Total, bool Capped)> ComputeActivityTotalAsync(
        DbConnection conn, string orgId, string? eventType, string? since, string? searchPattern,
        string? scanFloor)
    {
        int probed = searchPattern is null
            ? await conn.ExecuteScalarAsync<int>(
                """
                SELECT COUNT(*)
                FROM (SELECT 1
                      FROM activity a
                      WHERE a.org_id = @orgId
                        AND (@eventType IS NULL
                             OR (@eventType = 'blocked' AND a.event_type LIKE 'blocked%')
                             OR (@eventType <> 'blocked' AND a.event_type = @eventType))
                        AND (@since IS NULL OR a.created_at >= @since)
                      LIMIT @countProbe)
                """,
                new { orgId, eventType, since, countProbe = ListTotalCap + 1 })
            : await conn.ExecuteScalarAsync<int>(
                """
                SELECT COUNT(*)
                FROM (SELECT 1
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
                        AND (@since IS NULL OR a.created_at >= @since)
                        AND (@scanFloor IS NULL OR a.created_at >= @scanFloor)
                        AND (lower(COALESCE(a.purl, '')) LIKE @searchPattern
                             OR lower(a.event_type) LIKE @searchPattern
                             OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern
                             OR lower(COALESCE(a.detail, '')) LIKE @searchPattern
                             OR lower(COALESCE(u.email, '')) LIKE @searchPattern
                             OR lower(COALESCE(st.name, '')) LIKE @searchPattern)
                      LIMIT @countProbe)
                """,
                new { orgId, eventType, searchPattern, since, scanFloor, countProbe = ListTotalCap + 1 });

        // A truncated scan window means older matches may exist that were never examined, so the
        // total is a floor even when it sits well under ListTotalCap.
        bool totalCapped = probed > ListTotalCap || scanFloor is not null;
        return (probed > ListTotalCap ? ListTotalCap : probed, totalCapped);
    }
}
