using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Infrastructure.Audit;

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
    // S107: the parameters are the audit row's own columns, all optional and all passed by name at
    // every call site. Bundling them into a record would only move the same list behind a
    // constructor, and the one thing a reader needs to see here — which columns this write fills —
    // would stop being visible in the signature.
    [SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters", Justification = "The parameters are the audit row's columns; callers pass them by name.")]
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
        string? searchPattern = LikePattern.ContainsLower(search);

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
                   OR lower(a.action) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern ESCAPE '\')
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
                        AND (lower(a.action) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(a.purl, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(a.detail, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(u.email, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(st.name, '')) LIKE @searchPattern ESCAPE '\')
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

        string? searchPattern = LikePattern.ContainsLower(search);
        string? actionFilter = string.IsNullOrWhiteSpace(action) ? null : action;

        // Single where clause shared by the count and list queries — both join system_admins
        // (for ActorEmail / email search) and orgs (for OrgSlug / tenant-name search), so the
        // total reflects the same slug matches the page shows.
        const string listWhereClause = """
            a.scope = 'system'
              AND (@action IS NULL OR a.action = @action)
              AND (@searchPattern IS NULL
                   OR lower(a.action) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.actor_id, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(sa.email, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.org_id, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(o.slug, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern ESCAPE '\')
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
    /// Upper bound on the number of distinct <c>action=</c> values <see cref="ListAuthEventsAsync"/>
    /// accepts from a caller. Each one is bound as its own parameter, and both providers cap a
    /// statement's bind parameters (Postgres at 65535, SQLite at 32766 by default), so an unbounded
    /// repeatable <c>action=</c> query string would otherwise reach the driver and fail there.
    /// <para>
    /// It is every value a caller has any reason to send: every action the instance declares, plus
    /// a full complement of the families the vocabulary implies. Those are two disjoint sets and a
    /// collector can legitimately want both at once — pinning all 138 declared actions *and*
    /// keeping <c>auth</c> so whatever the next release adds under it arrives without a config
    /// change is a better subscription than either half alone, so the bound is their sum rather
    /// than the larger of them. Naming them all is cheap: a declared leaf contributes one bound
    /// scalar to an <c>IN</c> list and no <c>LIKE</c> term (see <see cref="BuildActionPredicate"/>),
    /// and measured on 1M rows over a 90-day window, 100 matching filters cost 4.8 ms on Postgres
    /// and 14 ms on SQLite — *faster* than one filter, because more filters fill the page limit
    /// sooner. The count that actually costs anything is bounded separately by
    /// <see cref="MaxAuthEventFamilyFilters"/>.
    /// </para>
    /// <para>
    /// Because those two sets exhaust what a filter can be, this bound is reached exactly when the
    /// family bound is: a list longer than this necessarily carries more than
    /// <see cref="MaxAuthEventFamilyFilters"/> non-declared values, and is refused there first. It
    /// is kept as a backstop for the bind ceiling rather than as a second gate, and
    /// <c>AuditActionVocabularyComplianceTests</c> pins the composition so lowering one without the
    /// other cannot silently make a legitimate subscription unsendable.
    /// </para>
    /// <para>
    /// It bounds caller input only. The no-filter default (<see cref="AuditActions.DefaultFilters"/>)
    /// is code, not input, and is a subset of the same vocabulary by
    /// <c>AuditActionVocabularyComplianceTests</c>.
    /// </para>
    /// </summary>
    public static readonly int MaxAuthEventActionFilters =
        AuditActions.All.Length + AuditActions.ImpliedFamilyPrefixes.Length;

    /// <summary>
    /// Upper bound on how many of those filters may be ones that need a family <c>LIKE</c> term —
    /// a dotted family prefix, or a name outside the declared vocabulary. This is the half with a
    /// cost: the terms are OR'd into an unindexable disjunction evaluated per candidate row, and a
    /// filter set that matches *nothing* never short-circuits, so the whole window is scanned with
    /// every term applied. Measured on 1M rows over the widest window the endpoint allows, that
    /// costs about 5 ms per filter on Postgres and 23 ms per filter on SQLite, on top of a floor
    /// (~1.5 s on SQLite) that is the window scan itself and no cap can reduce.
    /// <para>
    /// The bound is the number of dotted-family prefixes the declared vocabulary actually implies
    /// (<see cref="AuditActions.ImpliedFamilyPrefixes"/>), so it tracks the vocabulary rather than
    /// being a figure someone picked for headroom. A caller has no reason to name more families
    /// than exist; one that does is either misconfigured or probing, and either way this is the
    /// count worth bounding.
    /// </para>
    /// <para>
    /// An index would be the alternative lever and was measured rather than assumed: on Postgres,
    /// <c>action text_pattern_ops</c> turns the disjunction into a <c>BitmapOr</c> of per-term
    /// index scans and collapses the worst case from 537 ms to 2.1 ms. It is deliberately not
    /// taken — it does nothing at all on SQLite (plain, <c>NOCASE</c>, and both were measured; the
    /// planner keeps the <c>created_at</c> scan), and it would cost a write-side index on the most
    /// append-heavy table in the schema to speed up a path only a platform admin can reach.
    /// </para>
    /// </summary>
    public static readonly int MaxAuthEventFamilyFilters = AuditActions.ImpliedFamilyPrefixes.Length;

    /// <summary>
    /// Lists auth-relevant audit events for the SIEM events/auth endpoint.
    /// Filters by action name or dotted family (e.g. "checksum_failure", "login.") and
    /// optional org scope.
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
    ///
    /// <para>Each entry of <paramref name="actionFilter"/> matches <see cref="AuditActions.Matches"/>'s
    /// rule — the action of exactly that name, plus every action in its dotted family unless the
    /// name is a declared leaf — and becomes one bound equality term, plus one bound <c>LIKE</c>
    /// term for the entries that keep the family half. The counts are bounded by
    /// <see cref="MaxAuthEventActionFilters"/> and <see cref="MaxAuthEventFamilyFilters"/>, and a
    /// caller supplying more is an <see cref="ArgumentException"/> rather than a bind-time failure
    /// against the provider's parameter ceiling. Filters are OR'd and deduplicated, so a row is returned at most once
    /// however many of them it matches. The page query and the <c>Matched</c> count share the one
    /// predicate, so the two can never diverge on which rows they consider matching.</para>
    /// <para>
    /// <see cref="ListAuthEventsAsync"/>'s <c>LatestEventAt</c> and <c>Matched</c> exist so a
    /// collector can tell "my filter matches nothing" from "the registry is quiet" from "the audit
    /// writer is broken" — all three otherwise present as an empty <c>items</c> array.
    /// <c>LatestEventAt</c> ignores <paramref name="actionFilter"/> and <paramref name="since"/>
    /// entirely — it is the most recent row visible to this caller at all, bounded only by the
    /// same org scoping (and deliberately no <c>scope</c> filter, matching this method's own main
    /// query — a tenant token already receives <c>scope='system'</c> rows carrying its
    /// <c>org_id</c>, and adding one here would silently understate "most recent") and the
    /// <paramref name="until"/> upper bound, computed via <c>MAX(created_at)</c>. Because
    /// <c>(@orgId IS NULL OR org_id = @orgId)</c> is not sargable, the query is two literal SQL
    /// bodies picked by <c>orgId is null</c> rather than one OR-guarded statement: the
    /// tenant-scoped body binds <c>org_id = @orgId</c> directly so <c>idx_audit_log_org</c> serves
    /// it as a covering index, and the unscoped (platform-admin) body omits <c>org_id</c> and
    /// falls back to <c>idx_audit_log_created_at</c> — neither ever scans the whole table.
    /// </para>
    /// <para>
    /// <c>Matched</c> is the total row count for the filtered window, independent of
    /// <paramref name="limit"/> paging — but unlike <c>LatestEventAt</c> it re-runs the
    /// unindexable <c>LIKE</c> disjunction across the whole window, so on the platform-admin
    /// (unscoped) path over a wide window it is capped the same way
    /// <see cref="ListAuditAsync"/>'s total is: probed one past <see cref="ListTotalCap"/> inside
    /// a <c>LIMIT</c>-bounded subquery, reported via its <c>MatchedCapped</c> companion rather
    /// than scanned to completion.
    /// </para>
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated fragment is DapperInClause's own parenthesized list and " +
                        "disjunction over individually-parameterized (@actionName0, @actionFamily0, " +
                        "…) values and a constant column name — no caller text reaches the " +
                        "statement. It replaces a JSON-array unfold that reached for a SQLite-only " +
                        "table-valued function and threw on Postgres.")]
    public async Task<(IReadOnlyList<AuditEntry> Items, string? NextCursor, DateTimeOffset? LatestEventAt, int Matched, bool MatchedCapped)> ListAuthEventsAsync(
        DateTimeOffset since,
        DateTimeOffset until,
        string? orgId,
        IReadOnlyList<string>? actionFilter,
        int limit,
        string? afterCursor,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        string[] filters = ResolveAuthEventFilters(actionFilter);

        var (cursorTs, cursorId) = DecodeEventCursor(afterCursor);

        var (actionPredicate, parameters) = BuildActionPredicate(filters);
        parameters.AddDynamicParams(new
        {
            since = since.ToUtcIsoMillis(),
            until = until.ToUtcIsoMillis(),
            orgId,
            fetch = limit + 1,
            cursorTs,
            cursorId,
        });

        // org_id is a 32-hex id and nothing else on this feed resolves it: a read:audit token has
        // no user- or tenant-lookup route, so an alert naming only the id is unactionable on a
        // multi-tenant instance. The slug is one indexed probe per returned row away and is not
        // personal data. `actor_email` is deliberately NOT joined here and is always null on this
        // surface — a user's display name is an email, and audit_log.actor_label is written for
        // service actors only precisely so the member-removal and retention scrubs' fixed column
        // list stays complete. See the SIEM reference in OPERATIONS.md.
        //
        // rawsql: actionPredicate is DapperInClause-built — a parenthesized list and disjunction of
        // (@actionName0, @actionFamily0, ...) bound parameters over a constant column name, not user text.
        string sql = $"""
            SELECT al.id, al.org_id as OrgId, o.slug as OrgSlug, al.actor_id as ActorId,
                   al.action as Action,
                   al.ecosystem as Ecosystem, al.purl as Purl, al.detail as Detail,
                   al.source_ip as SourceIp,
                   al.created_at as CreatedAt
            FROM audit_log al
            LEFT JOIN orgs o ON o.id = al.org_id
            WHERE {actionPredicate}
              AND al.created_at >= @since
              AND al.created_at <= @until
              AND (@orgId IS NULL OR al.org_id = @orgId)
              AND (@cursorTs IS NULL OR al.created_at < @cursorTs OR (al.created_at = @cursorTs AND al.id < @cursorId))
            ORDER BY al.created_at DESC, al.id DESC
            LIMIT @fetch
            """;

        var rows = (await conn.QueryAsync<AuditEntry>(sql, parameters)).ToList();

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            rows.RemoveAt(rows.Count - 1);
            var last = rows[^1];
            nextCursor = EncodeEventCursor(last.CreatedAt, last.Id);
        }

        // Total matches in the filtered window, independent of the page cursor/limit above —
        // this is what lets a collector notice its filter matched fewer rows than expected
        // without paging through the whole result set. It reuses the page query's own
        // actionPredicate, so the count and the rows can never disagree about what "matching"
        // means, and for the same portability reason: unfolding the filter list inside the
        // statement reaches for a SQLite-only table-valued JSON function that errors on Postgres,
        // where a bound IN list and LIKE disjunction are what both engines accept unchanged. The
        // parameters are a second bag because this statement binds a different set of scalars than
        // the page query does. It does not join orgs — it counts rows, and the slug is a rendering
        // concern. The family LIKE terms can't be served by an index, so — exactly like
        // ListAuditAsync's total — the count is a probe capped at ListTotalCap+1 inside a
        // LIMIT-bounded subquery rather than an uncapped COUNT(*), which on the platform-admin
        // (orgId NULL) path over a wide window would otherwise scan the whole table.
        var (_, matchedParameters) = BuildActionPredicate(filters);
        matchedParameters.AddDynamicParams(new
        {
            since = since.ToUtcIsoMillis(),
            until = until.ToUtcIsoMillis(),
            orgId,
            countProbe = ListTotalCap + 1,
        });

        // rawsql: actionPredicate is DapperInClause-built — a parenthesized list and disjunction of
        // (@actionName0, @actionFamily0, ...) bound parameters over a constant column name, not user text.
        string matchedSql = $"""
            SELECT COUNT(*)
            FROM (SELECT 1
                  FROM audit_log al
                  WHERE {actionPredicate}
                    AND al.created_at >= @since
                    AND al.created_at <= @until
                    AND (@orgId IS NULL OR al.org_id = @orgId)
                  LIMIT @countProbe)
            """;
        int probedMatched = await conn.ExecuteScalarAsync<int>(matchedSql, matchedParameters);
        bool matchedCapped = probedMatched > ListTotalCap;
        int matched = matchedCapped ? ListTotalCap : probedMatched;

        var latestEventAt = await ResolveLatestEventAtAsync(conn, orgId, until);

        return (rows, nextCursor, latestEventAt, matched, matchedCapped);
    }

    /// <summary>
    /// The normalized, bounded action-filter set backing <see cref="ListAuthEventsAsync"/>.
    ///
    /// <para>A caller-supplied filter matches by AuditActions.Matches's rule — the action of
    /// exactly that name, plus every action in its dotted family. With no filter the feed serves
    /// the declared security vocabulary (<c>AuditActions.DefaultFilters</c>), which is exact names
    /// rather than family prefixes: a prefix with nothing writing under it reads as coverage and
    /// matches nothing, the shape that ships a `token.` family for events actually written as
    /// `token_created`.</para>
    ///
    /// <para>Duplicates are folded: OR-ing a repeated filter matches exactly the same rows, so
    /// collapsing them only spends fewer bind parameters. Both counts are bounded for caller input
    /// only — the default set is code, and is held under the same figures by its own compliance
    /// gate rather than by a runtime throw nobody could act on. The family half is bounded
    /// separately because it is the half that costs: one unindexable LIKE per filter, evaluated
    /// against every candidate row of the window.</para>
    /// </summary>
    private static string[] ResolveAuthEventFilters(IReadOnlyList<string>? actionFilter)
    {
        bool callerSupplied = actionFilter?.Count > 0;
        string[] filters = callerSupplied
            ? [.. actionFilter!.Select(AuditActions.NormalizeFilter).Distinct(StringComparer.Ordinal)]
            : [.. AuditActions.DefaultFilters];

        if (callerSupplied)
        {
            ValidateAuthEventFilterBounds(filters, nameof(actionFilter));
        }

        return filters;
    }

    /// <summary>
    /// Both bounds apply to caller input only — the default set is code, held under the same
    /// figures by its own compliance gate rather than by a runtime throw nobody could act on.
    /// </summary>
    private static void ValidateAuthEventFilterBounds(string[] filters, string paramName)
    {
        if (filters.Length > MaxAuthEventActionFilters)
        {
            throw new ArgumentException(
                $"At most {MaxAuthEventActionFilters} distinct action filters may be supplied; " +
                $"got {filters.Length}.",
                paramName);
        }

        int familyFilters = filters.Count(f => !AuditActions.IsDeclaredLeaf(f));
        if (familyFilters > MaxAuthEventFamilyFilters)
        {
            throw new ArgumentException(
                $"At most {MaxAuthEventFamilyFilters} action filters may name a dotted family or " +
                $"an action outside the declared vocabulary; got {familyFilters}.",
                paramName);
        }
    }

    /// <summary>
    /// <see cref="ListAuthEventsAsync"/>'s <c>LatestEventAt</c>: deliberately ignores actionFilter
    /// and since — an indexed MAX bounded only by the same org scope and the until upper bound, so
    /// it answers "did anything land at all" rather than re-running the filtered question.
    ///
    /// <para><c>(@orgId IS NULL OR org_id = @orgId)</c> is NOT sargable: SQLite's planner won't use
    /// idx_audit_log_org through an OR'd bind parameter, so a quiet tenant on a busy instance —
    /// exactly who this field exists to serve — falls back to a created_at-only index scan across
    /// every org's rows. The tenant-scoped and unscoped (platform-admin) cases are therefore two
    /// literal SQL bodies: the tenant-scoped one binds org_id = @orgId directly, so
    /// idx_audit_log_org(org_id, created_at DESC) serves it as a covering index; the unscoped one
    /// omits org_id and uses idx_audit_log_created_at.</para>
    /// </summary>
    private static async Task<DateTimeOffset?> ResolveLatestEventAtAsync(
        DbConnection conn, string? orgId, DateTimeOffset until)
    {
        // xtenant: platform-admin unscoped read — orgId is null only when AuthenticateAsync
        // resolved a platform:* principal, mirroring ListAuthEventsAsync's own main query.
        const string latestSqlUnscoped = """
            SELECT MAX(created_at)
            FROM audit_log
            WHERE created_at <= @until
            """;
        const string latestSqlTenantScoped = """
            SELECT MAX(created_at)
            FROM audit_log
            WHERE org_id = @orgId
              AND created_at <= @until
            """;
        string latestSql = orgId is null ? latestSqlUnscoped : latestSqlTenantScoped;
        return await conn.ExecuteScalarAsync<DateTimeOffset?>(latestSql, new
        {
            until = until.ToUtcIsoMillis(),
            orgId,
        });
    }

    /// <summary>
    /// Builds the auth feed's action predicate: <c>al.action IN (@actionName0, …)</c> for the exact
    /// half of <see cref="AuditActions.Matches"/>'s rule, OR'd with one
    /// <c>al.action LIKE @actionFamilyN</c> term per filter for the dotted-family half.
    ///
    /// <para>
    /// Both halves are ordinary bound scalars, which is what makes the statement provider-neutral:
    /// unfolding the list inside SQL instead — the <c>EXISTS (SELECT 1 FROM json_each(@json) …)</c>
    /// this replaced — reached for a SQLite-only table-valued function, so the feed threw on every
    /// Postgres deployment while the SQLite-backed suite stayed green. A row satisfying several
    /// filters is still returned once: the fragment is a predicate on the row, not a join.
    /// </para>
    ///
    /// <para>
    /// A family term is emitted per filter, and only where one can match: a filter naming a
    /// declared leaf (<see cref="AuditActions.IsDeclaredLeaf"/>) has no declared action under it,
    /// so <c>&lt;filter&gt;.%</c> could only ever match outside the vocabulary, and the term is
    /// skipped. That keeps the no-filter default a single indexable <c>IN</c> list rather than 77
    /// unindexable <c>LIKE</c>s evaluated per row of the window, and gives a collector that names
    /// those same 77 actions explicitly — instead of inheriting a default that can widen under it
    /// — exactly the same query. What carries a <c>LIKE</c> is what genuinely needs one: a dotted
    /// family such as <c>auth</c> or <c>system_admin</c>, or a name this release does not
    /// declare.
    /// </para>
    /// </summary>
    private static (string Sql, DynamicParameters Parameters) BuildActionPredicate(
        IReadOnlyList<string> filters)
    {
        var (inList, parameters) = DapperInClause.Expand("actionName", filters);
        string predicate = "al.action IN " + inList;

        // like-escape-ok: the family patterns are deliberately unescaped, as the prefix patterns
        // they replaced were — a '%' or '_' in one only widens the caller's own already-authorized
        // feed within the org filter and time window, and the family separator is appended here.
        string[] familyPatterns =
            [.. filters.Where(f => !AuditActions.IsDeclaredLeaf(f)).Select(f => f + ".%")];
        if (familyPatterns.Length == 0)
        {
            return ("(" + predicate + ")", parameters);
        }

        var (familyDisjunction, familyParameters) = DapperInClause.ExpandLikeAny(
            "actionFamily", "al.action", familyPatterns);
        parameters.AddDynamicParams(familyParameters);

        return ("(" + predicate + " OR " + familyDisjunction + ")", parameters);
    }

    /// <summary>
    /// Lower bound of the <c>blocked</c> event-type family used by
    /// <see cref="ListActivityEventsAsync"/>. The family is matched as a half-open range
    /// (<c>&gt;= 'blocked' AND &lt; 'blockee'</c>) rather than as <c>LIKE 'blocked%'</c>, because a
    /// prefix LIKE reaches a b-tree index only under a pattern-ops opclass on Postgres.
    /// <para>
    /// The range is served by <c>idx_activity_org_event</c> on <em>Postgres, and only while
    /// blocked events are a small fraction of the table</em> — the normal shape, and the case the
    /// index exists for. Above that fraction Postgres prefers <c>idx_activity_org</c> with a
    /// filter, and SQLite's planner takes <c>idx_activity_org</c> for this query unconditionally
    /// (it already satisfies most of the <c>created_at DESC</c> ordering). Both plans are correct;
    /// the index is a Postgres-side selectivity win, not a cross-provider one. The schema comment
    /// beside the index carries the measured plans.
    /// </para>
    /// </summary>
    public const string BlockedFamilyLowerBound = "blocked";

    /// <summary>
    /// Exclusive upper bound of the <c>blocked</c> event-type family. <c>'blockee'</c> rather than
    /// the mechanical successor <c>'blocked' || char(96)</c> ('`'): under a linguistic collation
    /// (the Postgres default) punctuation is weighted below letters, so <c>'blocked`'</c> can sort
    /// at or below <c>'blocked_license'</c> and the range would return nothing. Comparing against
    /// the next alphabetic string instead orders identically under a byte collation and a
    /// linguistic one, since every character it is compared through is a lowercase letter.
    /// </summary>
    public const string BlockedFamilyUpperBound = "blockee";

    /// <summary>
    /// Lists <c>activity</c>-plane events for the SIEM events/activity endpoint, newest first,
    /// cursor-paged on <c>(created_at, id)</c> exactly as <see cref="ListAuthEventsAsync"/> is —
    /// an offset page drifts under a feed that is still being appended to, which is the only way
    /// this one is ever read. <paramref name="orgId"/> is deliberately non-nullable: unlike the
    /// audit plane there is no operator-facing all-tenant activity view, so a null-means-every-org
    /// parameter would make an unscoped read expressible. The caller resolves the org from the
    /// authenticated principal.
    /// <para>
    /// The selection is an allowlist, never a caller-supplied filter:
    /// <paramref name="includeBlockedFamily"/> selects the whole <c>blocked*</c> family as a range
    /// (see <see cref="BlockedFamilyLowerBound"/>), and <paramref name="eventTypes"/> is a set of
    /// exact event-type values. A new block-gate arm is therefore in the feed the moment it is
    /// written, with no allowlist to remember to extend.
    /// </para>
    /// <para>
    /// <c>activity.created_at</c> is millisecond-precision text written only by
    /// <see cref="NowMs"/>, so <paramref name="since"/>/<paramref name="until"/> and the cursor
    /// timestamp are formatted through <see cref="UtcTimestamp.ToUtcIsoMillis"/> for the same
    /// reason <see cref="ListAuthEventsAsync"/> does — a second-precision bound compares
    /// <c>'.'</c> (0x2E) against <c>'Z'</c> (0x5A) and silently misorders at the window edge.
    /// The window is closed on both ends (<c>&gt;=</c>/<c>&lt;=</c>), as the audit feed's is, so a
    /// row landing on exactly the <paramref name="until"/> millisecond is returned again when the
    /// caller supplies that value as its next <paramref name="since"/>: the feed is at-least-once
    /// at that one instant, and a collector dedupes on event id.
    /// </para>
    /// <para>
    /// No actor identity is joined in. The audit-plane feed resolves no email either, and the
    /// SIEM surface is a documented personal-data egress point: <c>actor_id</c> plus
    /// <c>source_ip</c> is what a collector needs to correlate, and a denormalized display name
    /// would put an address in the outbound stream that neither retention scrub covers.
    /// </para>
    /// </summary>
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The two interpolated fragments are compile-time-constant predicates plus "
            + "DapperInClause.Expand's own parenthesized, individually-parameterized (@evt0, "
            + "@evt1, ...) list - no caller text reaches the SQL. See DapperInClause for why "
            + "Dapper's own IN @list expansion cannot be used on Postgres.")]
    // S107: the one cohesive grouping here is the (since, until) window, and ListAuthEventsAsync
    // takes that same pair in the same shape. Bundling it on this method alone would split one
    // concept across two spellings of it; bundling it on both rewrites 61 call sites to come in one
    // parameter under the threshold. The rest are the feed's own scope, filter and paging
    // arguments, which share no concept with each other.
#pragma warning disable S107
    public async Task<(IReadOnlyList<ActivityEntry> Items, string? NextCursor)> ListActivityEventsAsync(
        DateTimeOffset since,
        DateTimeOffset until,
        string orgId,
        bool includeBlockedFamily,
        IReadOnlyList<string> eventTypes,
        int limit,
        string? afterCursor,
        CancellationToken ct = default)
#pragma warning restore S107
    {
        // An empty allowlist selects nothing. Reaching SQL with it would either mean an
        // `IN ()` syntax error or, worse, a predicate that matched everything.
        if (!includeBlockedFamily && eventTypes.Count == 0)
        {
            return ([], null);
        }

        var (cursorTs, cursorId) = DecodeEventCursor(afterCursor);

        var (inClause, parameters) = eventTypes.Count > 0
            ? DapperInClause.Expand("evt", eventTypes)
            : (string.Empty, new DynamicParameters());

        // Both arms are constant text. The unselected arm is `0 = 1` rather than an omitted
        // clause so the composed predicate keeps one shape, and so the selected arm stays a bare
        // range/IN the planner can serve from idx_activity_org_event instead of a parameterized
        // toggle it has to evaluate per row.
        string familyPredicate = includeBlockedFamily
            ? "(a.event_type >= @blockedLow AND a.event_type < @blockedHigh)"
            : "0 = 1";
        string exactPredicate = eventTypes.Count > 0
            ? "a.event_type IN " + inClause
            : "0 = 1";

        parameters.Add("orgId", orgId, System.Data.DbType.String);
        parameters.Add("since", since.ToUtcIsoMillis(), System.Data.DbType.String);
        parameters.Add("until", until.ToUtcIsoMillis(), System.Data.DbType.String);
        parameters.Add("cursorTs", cursorTs, System.Data.DbType.String);
        parameters.Add("cursorId", cursorId, System.Data.DbType.String);
        parameters.Add("fetch", limit + 1, System.Data.DbType.Int32);
        if (includeBlockedFamily)
        {
            parameters.Add("blockedLow", BlockedFamilyLowerBound, System.Data.DbType.String);
            parameters.Add("blockedHigh", BlockedFamilyUpperBound, System.Data.DbType.String);
        }

        await using var conn = await _db.OpenAsync(ct);

        // rawsql: familyPredicate and exactPredicate are compile-time-constant fragments; the IN
        // list is DapperInClause's parameterized (@evt0, @evt1, ...) form, not caller text.
        var rows = (await conn.QueryAsync<ActivityEntry>(new CommandDefinition(
            $"""
            SELECT a.id, a.org_id as OrgId, a.ecosystem as Ecosystem, a.purl as Purl,
                   a.event_type as EventType, a.actor_id as ActorId,
                   a.detail as Detail, a.source_ip as SourceIp, a.created_at as CreatedAt
            FROM activity a
            WHERE a.org_id = @orgId
              AND a.created_at >= @since
              AND a.created_at <= @until
              AND ({familyPredicate} OR {exactPredicate})
              AND (@cursorTs IS NULL OR a.created_at < @cursorTs OR (a.created_at = @cursorTs AND a.id < @cursorId))
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT @fetch
            """,
            parameters, cancellationToken: ct))).ToList();

        string? nextCursor = null;
        if (rows.Count > limit)
        {
            rows.RemoveAt(rows.Count - 1);
            var last = rows[^1];
            nextCursor = EncodeEventCursor(last.CreatedAt, last.Id);
        }

        return (rows, nextCursor);
    }

    /// <summary>
    /// Decodes a <c>base64(created_at|id)</c> keyset cursor. A cursor whose timestamp half does
    /// not parse as exact millisecond-precision canonical UTC text is rejected outright (treated
    /// the same as no cursor — first page) rather than bound as-is: a mismatched shape would
    /// silently mis-compare against the millisecond-precision column instead of failing loudly.
    /// </summary>
    private static (string? Timestamp, string? Id) DecodeEventCursor(string? afterCursor)
    {
        if (afterCursor is null)
        {
            return (null, null);
        }

        try
        {
            string decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(afterCursor));
            string[] parts = decoded.Split('|', 2);
            if (parts.Length == 2
                && DateTimeOffset.TryParseExact(
                    parts[0], UtcTimestamp.MillisecondFormat, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out _))
            {
                return (parts[0], parts[1]);
            }
        }
        catch (FormatException) { /* not base64 — ignore, return first page */ }

        return (null, null);
    }

    /// <summary>Encodes the keyset cursor <see cref="DecodeEventCursor"/> reads.</summary>
    private static string EncodeEventCursor(DateTimeOffset createdAt, string id) =>
        Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{createdAt.ToUtcIsoMillis()}|{id}"));

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
        string? searchPattern = LikePattern.ContainsLower(search);

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
                   OR lower(COALESCE(a.purl, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(a.event_type) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(a.detail, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(u.email, '')) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(st.name, '')) LIKE @searchPattern ESCAPE '\')
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
                        AND (lower(COALESCE(a.purl, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(a.event_type) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(a.ecosystem, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(a.detail, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(u.email, '')) LIKE @searchPattern ESCAPE '\'
                             OR lower(COALESCE(st.name, '')) LIKE @searchPattern ESCAPE '\')
                      LIMIT @countProbe)
                """,
                new { orgId, eventType, searchPattern, since, scanFloor, countProbe = ListTotalCap + 1 });

        // A truncated scan window means older matches may exist that were never examined, so the
        // total is a floor even when it sits well under ListTotalCap.
        bool totalCapped = probed > ListTotalCap || scanFloor is not null;
        return (probed > ListTotalCap ? ListTotalCap : probed, totalCapped);
    }
}
