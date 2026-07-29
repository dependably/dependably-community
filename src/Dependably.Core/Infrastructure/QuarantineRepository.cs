using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Review queue for policy-gate blocks. <see cref="UpsertPendingAsync"/> is called by the
/// block gate beside every automatic block: the UNIQUE(org_id, purl) constraint plus the
/// state-guarded ON CONFLICT update mean repeat blocks refresh the pending row (latest gate +
/// detail win) and never resurrect a decided one. Decisions flow through
/// <see cref="DecideAsync"/>; the manual block/unblock endpoints call
/// <see cref="ResolveForVersionAsync"/> so the two surfaces can't disagree.
/// </summary>
public sealed class QuarantineRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public QuarantineRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    private string NowIso() => _time.GetUtcNow().ToUtcIso();

    /// <summary>
    /// Records (or refreshes) the pending review row for a blocked purl. A decided row is
    /// left untouched — the conflict update's state predicate makes the upsert a no-op then.
    /// The RETURNING id is compared against the candidate GUID minted for this call to tell a
    /// fresh insert from a conflict-refresh: both a genuine insert and a pending-row refresh
    /// produce a RETURNING row, but only the insert's row id matches the candidate. A no-op
    /// against an already-decided row produces zero RETURNING rows on both SQLite and Postgres
    /// (the WHERE guard suppresses the row entirely, not just the update) — that case falls back
    /// to a plain lookup so the caller always gets a valid <see cref="QuarantineUpsertResult.RowId"/>.
    /// <see cref="BlockGateService"/> uses <see cref="QuarantineUpsertResult.Inserted"/> to raise
    /// an alert only on the fresh-insert case.
    /// </summary>
    public async Task<QuarantineUpsertResult> UpsertPendingAsync(
        string orgId, string ecosystem, string purl, string gate,
        string? detail, string? packageVersionId, CancellationToken ct = default)
    {
        string candidateId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        var returned = (await conn.QueryAsync<string>(
            """
            INSERT INTO quarantine (id, org_id, package_version_id, ecosystem, purl, gate, detail, state, updated_at)
            VALUES (@id, @orgId, @packageVersionId, @ecosystem, @purl, @gate, @detail, 'pending', @now)
            ON CONFLICT (org_id, purl) DO UPDATE SET
                gate = excluded.gate,
                detail = excluded.detail,
                package_version_id = COALESCE(excluded.package_version_id, quarantine.package_version_id),
                updated_at = excluded.updated_at
            WHERE quarantine.state = 'pending'
            RETURNING id
            """,
            new { id = candidateId, orgId, packageVersionId, ecosystem, purl, gate, detail, now = NowIso() }))
            .ToList();

        if (returned.Count > 0)
        {
            string rowId = returned[0];
            return new QuarantineUpsertResult(rowId, rowId == candidateId);
        }

        // WHERE guard suppressed the row (already decided) — look up the existing row directly.
        string? existingId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND purl = @purl",
            new { orgId, purl });
        return new QuarantineUpsertResult(existingId ?? candidateId, Inserted: false);
    }

    /// <summary>
    /// The review queue page, filtered and sorted per <paramref name="query"/>. The decider is
    /// resolved to an email through <c>users</c> so the queue shows who decided rather than an
    /// opaque id; the join is tenant-bound, so a decided_by pointing outside the org resolves to
    /// null rather than leaking a foreign tenant's address. <see cref="QuarantineEntry.DecidedBy"/>
    /// is kept alongside it for the erased-user case, where the email is gone but the id remains.
    /// </summary>
    public async Task<(IReadOnlyList<QuarantineEntry> Items, int Total)> ListAsync(
        QuarantineListQuery query, CancellationToken ct = default)
    {
        // Substring search over the queue's human-readable columns. The wildcards a package name
        // can legitimately contain are escaped first: PyPI names routinely carry '_', which LIKE
        // reads as "any single character", so an unescaped 'my_pkg' also matches 'myXpkg'.
        string? escapedSearch = query.Search
            ?.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        string? searchPattern = escapedSearch is not null ? $"%{escapedSearch.ToLowerInvariant()}%" : null;

        var sqlParams = new
        {
            orgId = query.OrgId,
            state = query.State,
            ecosystem = query.Ecosystem,
            gate = query.Gate,
            searchPattern,
            limit = query.Limit,
            offset = query.Offset,
        };

        await using var conn = await _db.OpenAsync(ct);
        // The count carries the same users join as the page: a search that matches only on the
        // decider's email must be reflected in the total, or the pager offers pages that hold
        // nothing.
        int total = await conn.ExecuteScalarAsync<int>(ListCountSql, sqlParams);
        var rows = await QueryListPageAsync(conn, sqlParams, BuildListOrderBy(query.Sort, query.Dir));
        return (rows, total);
    }

    // The FROM/WHERE block is spelled out in both this query and the page query below rather than
    // hoisted into a shared const fragment. OrgIdFilteringComplianceTests judges each SQL literal
    // on its own: a literal that interpolates its FROM/WHERE from elsewhere shows the scanner no
    // table reference and no org_id, so it is skipped rather than checked. Duplicating the block
    // keeps both statements inside the gate.
    private const string ListCountSql =
        """
        SELECT COUNT(*)
        FROM quarantine q
        LEFT JOIN users u ON u.id = q.decided_by AND u.tenant_id = q.org_id
        WHERE q.org_id = @orgId
          AND (@state IS NULL OR q.state = @state)
          AND (@ecosystem IS NULL OR q.ecosystem = @ecosystem)
          AND (@gate IS NULL OR q.gate = @gate)
          AND (@searchPattern IS NULL
               OR LOWER(q.purl) LIKE @searchPattern ESCAPE '\'
               OR LOWER(q.gate) LIKE @searchPattern ESCAPE '\'
               OR LOWER(COALESCE(q.detail, '')) LIKE @searchPattern ESCAPE '\'
               OR LOWER(COALESCE(q.note, '')) LIKE @searchPattern ESCAPE '\'
               OR LOWER(COALESCE(u.email, '')) LIKE @searchPattern ESCAPE '\')
        """;

    // The page itself. orderBy is a whitelisted SQL expression built by BuildListOrderBy from
    // compile-time constants only; every value is a bound parameter.
    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated ORDER BY fragment is composed exclusively from compile-time-constant SQL " +
                        "expressions in ListSortColumns plus the literal strings \"ASC\"/\"DESC\". Caller-supplied " +
                        "sort/dir values only select which constant to use (TryGetValue + case-insensitive equality " +
                        "against literals); they never reach the SQL string.")]
    private static async Task<List<QuarantineEntry>> QueryListPageAsync(
        DbConnection conn, object sqlParams, string orderBy) =>
        // rawsql: only the whitelisted ORDER BY column/direction are interpolated (see the S2077 justification above).
        (await conn.QueryAsync<QuarantineEntry>(
            $"""
            SELECT q.id, q.org_id AS OrgId, q.package_version_id AS PackageVersionId,
                   q.ecosystem, q.purl, q.gate, q.detail, q.state,
                   q.decided_by AS DecidedBy, u.email AS DecidedByEmail,
                   q.decided_at AS DecidedAt, q.note,
                   q.created_at AS CreatedAt, q.updated_at AS UpdatedAt
            FROM quarantine q
            LEFT JOIN users u ON u.id = q.decided_by AND u.tenant_id = q.org_id
            WHERE q.org_id = @orgId
              AND (@state IS NULL OR q.state = @state)
              AND (@ecosystem IS NULL OR q.ecosystem = @ecosystem)
              AND (@gate IS NULL OR q.gate = @gate)
              AND (@searchPattern IS NULL
                   OR LOWER(q.purl) LIKE @searchPattern ESCAPE '\'
                   OR LOWER(q.gate) LIKE @searchPattern ESCAPE '\'
                   OR LOWER(COALESCE(q.detail, '')) LIKE @searchPattern ESCAPE '\'
                   OR LOWER(COALESCE(q.note, '')) LIKE @searchPattern ESCAPE '\'
                   OR LOWER(COALESCE(u.email, '')) LIKE @searchPattern ESCAPE '\')
            -- The id tiebreaker is what makes LIMIT/OFFSET paging stable: gate and second-precision
            -- updated_at both tie freely, and an unbroken tie lets a row repeat on one page and
            -- vanish from the next.
            ORDER BY {orderBy}, q.id DESC
            LIMIT @limit OFFSET @offset
            """,
            sqlParams)).AsList();

    // Columns the review queue accepts as `sort=`. Values are SQL expressions composed from
    // compile-time constants only — nothing from the request reaches the SQL string. The key set
    // is deliberately the set of sortable column headers on the queue page: keeping the two equal
    // is what makes the accepted surface reviewable.
    //
    // Case-insensitive ordering uses LOWER(), not COLLATE NOCASE: NOCASE is a SQLite-only
    // collation name and Postgres has no collation by that name, so a sort on one of these
    // columns would error there. LOWER() folds ASCII case identically on both engines.
    private static readonly Dictionary<string, (string Expr, string DefaultDir)> ListSortColumns =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["package"] = ("LOWER(q.purl)", "asc"),
            ["gate"] = ("LOWER(q.gate)", "asc"),
            ["decidedBy"] = ("LOWER(COALESCE(u.email, q.decided_by, ''))", "asc"),
            ["updated"] = ("q.updated_at", "desc"),
        };

    private static string BuildListOrderBy(string? sort, string? dir)
    {
        if (sort is null || !ListSortColumns.TryGetValue(sort, out var col))
        {
            col = ListSortColumns["updated"];
        }

        return $"{col.Expr} {NormalizeSortDirection(dir, col.DefaultDir)}";
    }

    private static string NormalizeSortDirection(string? requested, string defaultDir)
    {
        return string.Equals(requested, "asc", StringComparison.OrdinalIgnoreCase)
            ? "ASC"
            : string.Equals(requested, "desc", StringComparison.OrdinalIgnoreCase)
            ? "DESC"
            : defaultDir.Equals("desc", StringComparison.OrdinalIgnoreCase) ? "DESC" : "ASC";
    }

    /// <summary>Org-scoped lookup — a cross-tenant id comes back null (BOLA guard).</summary>
    public async Task<QuarantineEntry?> GetByIdAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<QuarantineEntry>(
            """
            SELECT id, org_id AS OrgId, package_version_id AS PackageVersionId,
                   ecosystem, purl, gate, detail, state,
                   decided_by AS DecidedBy, decided_at AS DecidedAt, note,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM quarantine WHERE id = @id AND org_id = @orgId
            """,
            new { id, orgId });
    }

    /// <summary>
    /// Applies a decision to a pending row. Returns false when the row was already decided
    /// (the state predicate makes a double-decide update zero rows) — the controller maps
    /// that to 409.
    /// </summary>
    public async Task<bool> DecideAsync(
        string orgId, string id, string decision, string? decidedBy, string? note,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE quarantine
            SET state = @decision, decided_by = @decidedBy, decided_at = @now, note = @note, updated_at = @now
            WHERE id = @id AND org_id = @orgId AND state = 'pending'
            """,
            new { orgId, id, decision, decidedBy, note, now = NowIso() });
        return rows > 0;
    }

    /// <summary>
    /// Re-decides an already-decided row, or resets it to pending — the admin "change my mind"
    /// path. Unlike <see cref="DecideAsync"/> this is not pending-guarded; the controller calls
    /// it only for rows that are already decided. Resetting to pending clears the decision
    /// metadata so the row re-enters the queue clean. Returns false when no row matched (unknown
    /// or cross-tenant id).
    /// </summary>
    public async Task<bool> ChangeStateAsync(
        string orgId, string id, string newState, string? decidedBy, string? note,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = NowIso();
        int rows = newState == "pending"
            ? await conn.ExecuteAsync(
                """
                UPDATE quarantine
                SET state = 'pending', decided_by = NULL, decided_at = NULL, note = NULL, updated_at = @now
                WHERE id = @id AND org_id = @orgId
                """,
                new { orgId, id, now })
            : await conn.ExecuteAsync(
                """
                UPDATE quarantine
                SET state = @newState, decided_by = @decidedBy, decided_at = @now, note = @note, updated_at = @now
                WHERE id = @id AND org_id = @orgId
                """,
                new { orgId, id, newState, decidedBy, note, now });
        return rows > 0;
    }

    /// <summary>
    /// Resolves any pending row for a version when an operator uses the manual block/unblock
    /// endpoints directly, so the review queue can't disagree with the version's
    /// manual_block_state. Manual allow ⇒ approved; manual block ⇒ denied.
    /// </summary>
    public async Task ResolveForVersionAsync(
        string orgId, string packageVersionId, string manualState, string? decidedBy,
        CancellationToken ct = default)
    {
        string state = manualState == "allowed" ? "approved" : "denied";
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE quarantine
            SET state = @state, decided_by = @decidedBy, decided_at = @now,
                note = 'resolved via manual ' || @manualState, updated_at = @now
            WHERE org_id = @orgId AND package_version_id = @packageVersionId AND state = 'pending'
            """,
            new { orgId, packageVersionId, state, manualState, decidedBy, now = NowIso() });
    }

    /// <summary>
    /// Resolves any pending row for a purl when an operator uses the manual block/unblock
    /// endpoints against a proxy artifact (no <c>package_version_id</c> to key off — the
    /// quarantine row for a proxy block carries <c>package_version_id = NULL</c> and is unique
    /// per <c>(org_id, purl)</c> instead). Mirrors <see cref="ResolveForVersionAsync"/> so the
    /// hosted and proxy planes keep the review queue in sync the same way.
    /// </summary>
    public async Task ResolveForPurlAsync(
        string orgId, string purl, string manualState, string? decidedBy,
        CancellationToken ct = default)
    {
        string state = manualState == "allowed" ? "approved" : "denied";
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE quarantine
            SET state = @state, decided_by = @decidedBy, decided_at = @now,
                note = 'resolved via manual ' || @manualState, updated_at = @now
            WHERE org_id = @orgId AND purl = @purl AND state = 'pending'
            """,
            new { orgId, purl, state, manualState, decidedBy, now = NowIso() });
    }

    /// <summary>
    /// Deletes pending <c>release_age</c> quarantine rows whose version has now aged past the
    /// hold threshold, making them phantom entries in the review queue. The release-age gate is
    /// re-evaluated on every serve and index render against the current clock, so a held version
    /// serves again automatically once it ages past the threshold. This clears the now-stale
    /// pending review row so the queue stays accurate. Rows are deleted (not moved to a terminal
    /// state) so the UNIQUE(org_id, purl) slot remains free for a future re-block of the same
    /// purl. Only <c>release_age</c>+<c>pending</c> rows are touched — human decisions
    /// (<c>approved</c>/<c>denied</c>) and other gate types are never affected.
    /// </summary>
    /// <summary>
    /// Each pending release-age hold and the publish date it must be judged against.
    ///
    /// The gate blocks on either plane: a tag push queues the hold against a <c>package_versions</c>
    /// row, and a proxy fetch queues it with <c>package_version_id = NULL</c> — the artifact it
    /// blocked lives on the cache plane, and its publish date with it. Reading only
    /// <c>package_versions</c> therefore yields NULL for every proxied hold, which
    /// <see cref="IsReleaseHoldStale"/> reads as "publish date unknown, so the hold no longer
    /// applies" — and the hold the gate had just raised is purged before an admin ever sees it.
    ///
    /// <c>artifact_inventory</c> spans both catalogues, so the date is resolved from whichever plane
    /// owns the artifact. A hold whose artifact is not in the catalogue at all still yields NULL,
    /// which is the honest answer: there is no publish date to hold against.
    ///
    /// Shared by the queue's purge-on-load and the dashboard's pending count so the number can never
    /// disagree with the queue it describes.
    /// </summary>
    internal const string PendingReleaseHoldsSql =
        """
        SELECT q.id AS Id,
               COALESCE(
                   pv.published_at,
                   (SELECT MAX(ai.published_at)
                    FROM artifact_inventory ai
                    WHERE ai.org_id = q.org_id AND ai.purl = q.purl)
               ) AS PublishedAt
        FROM quarantine q
        LEFT JOIN package_versions pv ON pv.id = q.package_version_id
        WHERE q.org_id = @orgId
          AND q.gate = 'release_age'
          AND q.state = 'pending'
        """;

    public async Task<int> PurgeAgedReleaseHoldsAsync(
        string orgId, int? minReleaseAgeHours, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var candidates = await conn.QueryAsync<ReleaseHoldRow>(PendingReleaseHoldsSql, new { orgId });

        var now = _time.GetUtcNow();
        var ids = candidates
            .Where(row => IsReleaseHoldStale(row.PublishedAt, minReleaseAgeHours, now))
            .Select(row => row.Id)
            .ToList();

        if (ids.Count == 0)
        {
            return 0;
        }

        // IN (...) is built and parameterized in C#, not via Dapper's IN @ids auto-expansion —
        // see DapperInClause for why: Dapper special-cases Npgsql connections and binds the whole
        // list as one array parameter instead of expanding the SQL text, which IN never accepts.
        var (idsClause, idsParams) = DapperInClause.Expand("id", ids);
        idsParams.Add("orgId", orgId);
        // rawsql: idsClause is a DapperInClause-built parameterized IN (@id0, @id1, …) list, not user text.
        return await conn.ExecuteAsync(
            "DELETE FROM quarantine WHERE org_id = @orgId AND id IN " + idsClause,
            idsParams);
    }

    /// <summary>
    /// True when a pending <c>release_age</c> hold is now stale and would be deleted by
    /// <see cref="PurgeAgedReleaseHoldsAsync"/>: the release-age policy is off, the version's
    /// publish date is unknown, or the version has aged past the hold threshold. This is the single
    /// source of truth for "the queue no longer shows this hold" — <see cref="PurgeAgedReleaseHoldsAsync"/>
    /// uses it to choose rows to delete, and the dashboard pending count uses it to exclude the same
    /// rows, so the count can never disagree with the (purged-on-load) review queue.
    /// </summary>
    public static bool IsReleaseHoldStale(DateTimeOffset? publishedAt, int? minReleaseAgeHours, DateTimeOffset now)
    {
        if (minReleaseAgeHours is not { } m || m <= 0)
        {
            return true; // policy off → the hold no longer applies
        }
        if (publishedAt is not { } p)
        {
            return true; // unknown publish date → re-evaluated as serveable, so the hold is stale
        }
        return (now - p).TotalHours >= m;
    }

    internal sealed record ReleaseHoldRow(string Id, DateTimeOffset? PublishedAt);

    /// <summary>
    /// True when the purl has an approved review — the first-fetch analog of the manual allow
    /// override, for blocks recorded before any version row existed.
    /// </summary>
    public async Task<bool> HasApprovedForPurlAsync(string orgId, string purl, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId AND purl = @purl AND state = 'approved'",
            new { orgId, purl });
        return count > 0;
    }
}

/// <summary>
/// Outcome of <see cref="QuarantineRepository.UpsertPendingAsync"/>. <see cref="RowId"/> is the
/// pending row's id (freshly minted or the pre-existing one); <see cref="Inserted"/> is true only
/// when this call created a brand-new row — false for both a conflict-refresh of an existing
/// pending row and a no-op against an already-decided one.
/// </summary>
public sealed record QuarantineUpsertResult(string RowId, bool Inserted);

/// <summary>
/// Filter, sort, and pagination inputs for <see cref="QuarantineRepository.ListAsync"/>. Bundled
/// into a record rather than passed as nine positional parameters, and named so a call site reads
/// as the query it is. <c>Sort</c> selects a whitelisted column (see the repository's
/// ListSortColumns); an unknown value falls back to the default rather than erroring, so a stale
/// bookmark still renders.
/// </summary>
public sealed record QuarantineListQuery(
    string OrgId,
    string? State = null,
    string? Ecosystem = null,
    string? Gate = null,
    string? Search = null,
    int Limit = 50,
    int Offset = 0,
    string? Sort = null,
    string? Dir = null);

public sealed class QuarantineEntry
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string? PackageVersionId { get; init; }
    public string Ecosystem { get; init; } = "";
    public string Purl { get; init; } = "";
    public string Gate { get; init; } = "";
    public string? Detail { get; init; }
    public string State { get; init; } = "pending";
    public string? DecidedBy { get; init; }
    /// <summary>
    /// The decider's email, resolved from <see cref="DecidedBy"/> by the list query only. Null on
    /// the single-row lookups, and null for a decider whose account has since been erased — the
    /// id survives in <see cref="DecidedBy"/> either way, so the queue can fall back to it.
    /// </summary>
    public string? DecidedByEmail { get; init; }
    public DateTimeOffset? DecidedAt { get; init; }
    public string? Note { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
}
