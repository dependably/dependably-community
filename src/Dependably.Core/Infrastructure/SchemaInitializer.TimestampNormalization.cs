using System.Data.Common;
using System.Globalization;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Self-healing data-repair sweep for the <c>DateTimeOffsetHandler</c> fix in
/// <see cref="SchemaInitializer.OwnerPlane"/>: before <c>RemoveTypeMap</c> was ordered ahead of
/// <c>AddTypeHandler</c>, a raw <see cref="DateTimeOffset"/> bound as a Dapper parameter never
/// reached <c>SetValue</c> — Dapper's built-in type map claimed the parameter first, so the
/// ADO.NET provider serialized it directly instead: space-separated, offset preserved (e.g.
/// <c>2026-03-04 05:06:07.123+02:00</c> on Microsoft.Data.Sqlite, <c>2026-03-04 05:06:07.123+00</c>
/// on Npgsql), never the canonical <c>2026-03-04T05:06:07Z</c> form every other writer of these
/// columns uses.
///
/// Runs on <em>every boot</em>, unconditionally — deliberately not gated by the
/// <c>_applied_migrations</c> ledger. A blue-green cutover leaves the OLD binary's code (which
/// still writes the legacy shape) running against the NEW schema for the whole cutover window;
/// a one-shot, ledger-gated repair would apply once during green's boot and then never run
/// again, permanently re-poisoning <c>idx_cache_artifact_lru</c> eviction ordering, the
/// <c>(first_cached_at, id)</c> license-backfill keyset cursor, and
/// <c>AuditEventRepository.ListByTenantAsync</c>'s ordering with every row blue writes after
/// that point — with no recovery path, ever. Running the sweep every boot instead means blue's
/// legacy-shaped writes are repaired the next time either binary boots, for the lifetime of the
/// deployment.
///
/// Two mechanisms, chosen per column by how large and how fast-growing it is:
/// <list type="bullet">
/// <item><c>cache_artifact</c>, <c>tenant_artifact_access</c>, <c>audit_event</c>, <c>claim</c>,
/// and <c>claim_history</c> — the columns that grow with every proxy fetch, download, and audit
/// event — are repaired with one set-based <c>UPDATE</c> per column, using each provider's own
/// timestamp parser (SQLite's <c>strftime</c>, Postgres's <c>::timestamptz</c> cast) to do the
/// UTC shift, filtered to rows that are not already canonical. This is a single index-free scan
/// per column per boot, but a cheap one: it matches nothing on a database with no legacy rows,
/// and is ~100x faster than a per-row round trip on one that has them (see
/// <c>SchemaInitializerTimestampNormalizationTests</c> for a measured comparison).</item>
/// <item><c>package_versions.published_at</c> and <c>packages.upstream_latest_published_at</c>
/// are microsecond precision (<see cref="UtcTimestamp.PreciseFormat"/>), and neither SQLite's
/// <c>strftime</c> nor a portable cross-provider expression can format a 6-digit fractional
/// second — SQLite's finest built-in resolution is milliseconds. These two are swept row-by-row
/// in C# instead, using <see cref="Dapper.SqlMapper.QueryUnbufferedAsync{T}"/> so a legacy
/// backlog is never buffered in full, and only ever touching rows the same
/// not-already-canonical filter selects. Both columns are set once per package/version when an
/// upstream publish date is known — not per download or per proxy fetch — so their row count is
/// orders of magnitude smaller than the set-based columns above, and neither was reachable
/// through the DateTimeOffsetHandler in the first place (both were, and remain, written via an
/// explicit string conversion at the call site), so a legacy row here is bounded by however long
/// the OLD <c>ToUniversalTime().ToString("o")</c> writer shipped, not by the ongoing blue-green
/// cutover window the other nine columns are exposed to.</item>
/// </list>
/// </summary>
public sealed partial class SchemaInitializer
{
    // internal (not private) so timing/perf tests can invoke the sweep directly against a
    // pre-seeded connection without paying for a full fresh-schema InitializeAsync() pass.
    internal async Task NormalizeLegacyDateTimeOffsetColumnsAsync(DbConnection conn)
    {
        bool isPostgres = _db.Provider == DbProvider.Postgres;

        await SweepColumnSetBasedAsync(conn, isPostgres, "cache_artifact", "first_cached_at", millisecond: false);
        await SweepColumnSetBasedAsync(conn, isPostgres, "cache_artifact", "last_accessed_at", millisecond: false);

        await SweepColumnSetBasedAsync(conn, isPostgres, "claim", "created_at", millisecond: false);
        await SweepColumnSetBasedAsync(conn, isPostgres, "claim", "updated_at", millisecond: false);
        await SweepColumnSetBasedAsync(conn, isPostgres, "claim", "deleted_at", millisecond: false);
        await SweepColumnSetBasedAsync(conn, isPostgres, "claim_history", "occurred_at", millisecond: false);

        // Millisecond — matches AuditEventRepository.InsertAsync's explicit ToUtcIsoMillis() bind
        // and the schema DEFAULT (see Schema.sql / Schema.pg.sql), same family as audit_log/activity.
        await SweepColumnSetBasedAsync(conn, isPostgres, "audit_event", "occurred_at", millisecond: true);

        await SweepColumnSetBasedAsync(conn, isPostgres, "tenant_artifact_access", "first_accessed_at", millisecond: false);
        await SweepColumnSetBasedAsync(conn, isPostgres, "tenant_artifact_access", "last_accessed_at", millisecond: false);
        await SweepColumnSetBasedAsync(conn, isPostgres, "tenant_artifact_access", "last_used", millisecond: false);

        await SweepColumnRowByRowAsync(conn, "package_versions", "id", "published_at");
        await SweepColumnRowByRowAsync(conn, "packages", "id", "upstream_latest_published_at");
    }

    // SQLite: case-sensitive digit-position GLOB (no range validation — strftime returns NULL
    // rather than throwing on an out-of-range value, and COALESCE below falls back to the
    // original text). Postgres: POSIX regex with month/day/hour/minute/second ranges validated,
    // because an invalid ::timestamptz cast raises an error that would abort the whole
    // statement rather than just skipping the one bad row.
    private const string SqliteShapeGuard =
        "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]?[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*";

    private const string PostgresShapeGuard =
        "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01]).([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]";

    // xtenant: repair pass over every org's rows for a shared parameter-binding bug — not a
    // tenant-scoped read or write path. Runs unconditionally every boot (see class summary).
    private static async Task SweepColumnSetBasedAsync(
        DbConnection conn, bool isPostgres, string table, string column, bool millisecond)
    {
        string convertExpr = isPostgres
            ? $"to_char(({column}::timestamptz) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS{(millisecond ? ".MS" : "")}\"Z\"')"
            : millisecond
                ? $"strftime('%Y-%m-%dT%H:%M:%fZ', {column})"
                : $"strftime('%Y-%m-%dT%H:%M:%SZ', {column})";

        // SQLite's strftime returns NULL rather than throwing on an out-of-range value, so
        // COALESCE falls back to the original text there; Postgres's ::timestamptz cast throws
        // instead, so its shape guard validates month/day/hour/minute/second ranges up front —
        // see SqliteShapeGuard / PostgresShapeGuard above.
        string setClause = isPostgres ? $"{column} = {convertExpr}" : $"{column} = COALESCE({convertExpr}, {column})";
        string shapeGuardClause = isPostgres
            ? $"{column} ~ '{PostgresShapeGuard}'"
            : $"{column} GLOB '{SqliteShapeGuard}'";

        // The not-already-canonical filter (NOT LIKE '%Z') is what makes this a near no-op scan
        // on a database with no legacy rows; the shape guard keeps a value that is obviously not
        // a timestamp (empty string, free text, a stray non-text value) out of the cast/strftime
        // call entirely, so it is left untouched rather than raising an error mid-sweep.
        // rawsql: table/column/setClause/shapeGuardClause are all built from the fixed,
        // compile-time call-site list in NormalizeLegacyDateTimeOffsetColumnsAsync above — the
        // columns the DateTimeOffsetHandler fix touches — never caller-supplied input.
        string sql = $"""
            UPDATE {table} SET {setClause}
            WHERE {column} IS NOT NULL
              AND {column} NOT LIKE '%Z'
              AND {shapeGuardClause}
            """;

        await conn.ExecuteAsync(sql);
    }

    // xtenant: repair pass over every org's rows for a shared parameter-binding bug — not a
    // tenant-scoped read or write path. Runs unconditionally every boot (see class summary).
    // rawsql: table/idColumn/column are compile-time constants from the fixed call-site list
    // above, never caller-supplied input.
    private static async Task SweepColumnRowByRowAsync(DbConnection conn, string table, string idColumn, string column)
    {
        string selectSql =
            $"SELECT {idColumn} AS Id, {column} AS Value FROM {table} WHERE {column} IS NOT NULL AND {column} NOT LIKE '%Z'";

        // Collected rather than updated in-loop: an open unbuffered reader and a second command
        // cannot share one connection on either provider. The list this builds holds only the
        // small set of legacy-shaped (id, normalized-value) pairs — never the full table, and
        // never an already-canonical row — so it stays small even on a large table.
        var toUpdate = new List<(string Id, string Normalized)>();
        await foreach (var (id, value) in conn.QueryUnbufferedAsync<(string Id, string Value)>(selectSql))
        {
            if (TryNormalize(value, UtcTimestamp.PreciseFormat, out string? normalized))
            {
                toUpdate.Add((id, normalized!));
            }
        }

        foreach (var (id, normalized) in toUpdate)
        {
            // rawsql: see above.
            await conn.ExecuteAsync(
                $"UPDATE {table} SET {column} = @normalized WHERE {idColumn} = @id",
                new { normalized, id });
        }
    }

    /// <summary>
    /// Parses <paramref name="value"/> as any offset-bearing instant (space or <c>T</c>
    /// separator, any offset, with or without fractional seconds — every shape the legacy
    /// provider-native serialization or the canonical writer could have produced) and converts
    /// it to UTC before reformatting at <paramref name="format"/>. Returns <see langword="false"/>
    /// — leaving the row untouched rather than risk corrupting it further — for a value that
    /// doesn't parse as an instant at all, and for a value that already reformats to itself, so
    /// a row already normalized by a previous boot's sweep is never rewritten.
    /// </summary>
    private static bool TryNormalize(string value, string format, out string? normalized)
    {
        if (!DateTimeOffset.TryParse(
                value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            normalized = null;
            return false;
        }

        normalized = parsed.ToString(format, CultureInfo.InvariantCulture);
        if (string.Equals(normalized, value, StringComparison.Ordinal))
        {
            normalized = null;
            return false;
        }

        return true;
    }
}
