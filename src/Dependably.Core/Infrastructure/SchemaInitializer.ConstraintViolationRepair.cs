using System.Data.Common;
using System.Text.RegularExpressions;
using Dapper;
using Npgsql;

namespace Dependably.Infrastructure;

/// <summary>
/// What the constraint retrofits do with existing rows that break a constraint they add, on
/// Postgres. A constraint that existing rows violate stays <c>NOT VALID</c>, and Postgres checks a
/// <c>NOT VALID</c> CHECK on every UPDATE of a row as well as every INSERT: a violating legacy row
/// therefore rejects every later UPDATE with <c>23514</c>, from this release and the previous one
/// alike (an <c>org_settings</c> row in that state fails every settings save). Three things follow.
///
/// <para><b>The warning names the rows.</b> It gives the table, the column, how many rows violate
/// the constraint and up to <see cref="ViolatingKeysShown"/> of their primary keys, and states the
/// consequence, so an operator can find and repair them. The count is one scan under the same
/// statement timeout as <c>VALIDATE</c>.</para>
///
/// <para><b>Some vocabulary columns are repaired.</b> A column in
/// <see cref="RepairableVocabularyColumns"/> whose value lies outside its declared
/// <c>CHECK (col IN …)</c> set is set to the column's declared default, then validated again. The set
/// is an allowlist, so a column is repaired only once someone has decided its stray value means
/// nothing a gate reads: a policy mode, an account or org status, a role, an owner discriminator,
/// a licence disposition or an advisory signal is never rewritten, because the default can be
/// weaker than whatever the stray value was meant to be. Those rows are left and named.</para>
///
/// <para><b>Orphaned member-removal attributions are cleared.</b> The columns in
/// <see cref="MemberRemovalAttributionColumns"/> are exactly those
/// <c>OrgRepository.RemoveOrgMemberAsync</c> sets to NULL when it removes a member. On a database
/// where one reached its table without its <c>REFERENCES users(id)</c>, removing a member left the
/// value behind; nulling it is what removing the member does today, so it is done once the
/// <c>NOT VALID</c> key stops new orphans arriving, and the key is validated after.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    /// <summary>How many violating rows' primary keys the warning lists.</summary>
    internal const int ViolatingKeysShown = 5;

    /// <summary>
    /// Vocabulary columns whose out-of-vocabulary values are set to the declared default. Both are
    /// SBOM read-back flags that no gate reads, and both default to the "not asserted" value.
    /// </summary>
    internal static readonly IReadOnlySet<(string Table, string Column)> RepairableVocabularyColumns =
        new HashSet<(string, string)>
        {
            ("project_documents", "tool_version_explicit_unknown"),
            ("sbom_components", "containment_declared"),
        };

    /// <summary>
    /// The nullable attribution columns referencing <c>users(id)</c> that
    /// <c>OrgRepository.RemoveOrgMemberAsync</c> sets to NULL; <c>ColumnConstraintRetrofitTests</c>
    /// holds this set equal to that method's.
    /// </summary>
    internal static readonly IReadOnlySet<(string Table, string Column)> MemberRemovalAttributionColumns =
        new HashSet<(string, string)>
        {
            ("reserved_namespace", "created_by"),
            ("quarantine", "decided_by"),
            ("alert", "dismissed_by"),
            ("claim", "created_by"),
            ("claim_history", "actor_id"),
            ("install_script_allowlist", "created_by"),
            ("license_allowlist", "created_by"),
            ("license_blocklist", "created_by"),
            ("package_name_grant", "created_by"),
        };

    [GeneratedRegex(@"^CHECK\s*\(\s*(?:(?<c1>[A-Za-z_][A-Za-z0-9_]*)\s+IS\s+NULL\s+OR\s+)?(?<c2>[A-Za-z_][A-Za-z0-9_]*)\s+IN\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex VocabularyCheckRegex();

    internal static bool IsVocabularyCheck(DeclaredColumnConstraint constraint) =>
        constraint.Kind == ColumnConstraintKind.Check
        && VocabularyCheckRegex().Match(constraint.Definition) is { Success: true } m
        && string.Equals(m.Groups["c2"].Value, constraint.Column, StringComparison.Ordinal)
        && (!m.Groups["c1"].Success || string.Equals(m.Groups["c1"].Value, constraint.Column, StringComparison.Ordinal));

    private static bool IsRepairableVocabulary(DeclaredColumnConstraint constraint) =>
        constraint.DefaultLiteral is not null
        && RepairableVocabularyColumns.Contains((constraint.Table, constraint.Column))
        && IsVocabularyCheck(constraint);

    private static bool IsMemberRemovalAttribution(DeclaredColumnConstraint constraint) =>
        constraint.Kind == ColumnConstraintKind.ForeignKey
        && MemberRemovalAttributionColumns.Contains((constraint.Table, constraint.Column))
        && string.Equals(ParseForeignKeyShape(constraint.Definition).ReferencedTable, "users", StringComparison.Ordinal);

    /// <summary>The rows a CHECK body rejects: those for which it is false (NULL passes a CHECK).</summary>
    internal static string CheckViolationPredicate(string checkDefinition) =>
        "NOT " + checkDefinition["CHECK".Length..].TrimStart();

    /// <summary>
    /// A predicate selecting the rows of <paramref name="constraint"/>'s table that violate it, or
    /// null when it cannot be written (a foreign key that names no referenced column).
    /// </summary>
    internal static string? ViolationPredicate(DeclaredColumnConstraint constraint)
    {
        if (constraint.Kind == ColumnConstraintKind.Check)
        {
            return CheckViolationPredicate(constraint.Definition);
        }

        var shape = ParseForeignKeyShape(constraint.Definition);
        // rawsql: every identifier is derived from the embedded Schema.pg.sql text this boot applied;
        // none of it is caller-supplied, and Postgres has no parameter form for an identifier.
        return shape.ReferencedColumns is [string referencedColumn]
            ? $"{constraint.Table}.{constraint.Column} IS NOT NULL AND NOT EXISTS ("
                + $"SELECT 1 FROM {shape.ReferencedTable} r WHERE r.{referencedColumn} = {constraint.Table}.{constraint.Column})"
            : null;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The identifiers, the default literal and the predicate derive from the embedded schema text this "
                        + "boot applied; none is caller input, and Postgres cannot bind an identifier.")]
    private async Task<int> RepairVocabularyAsync(
        DbConnection conn, RetrofitPass pass, DeclaredColumnConstraint constraint)
    {
        // rawsql: table, column, default literal and predicate are derived from the embedded
        // Schema.pg.sql text this boot applied; none of it is caller-supplied.
        // xtenant: a one-shot repair of stray values across every tenant's rows, run as the owner at
        // boot; the predicate is the column's own vocabulary, not a tenant selection.
        string sql = $"UPDATE {constraint.Table} SET {constraint.Column} = {constraint.DefaultLiteral} "
            + $"WHERE {CheckViolationPredicate(constraint.Definition)}";
        var (ran, rows) = await RunBoundedAsync(
            conn, pass, "vocabulary_repair:" + constraint.Name,
            () => conn.ExecuteAsync(new CommandDefinition(sql, commandTimeout: 0)));
        if (ran && rows > 0)
        {
            _logger.LogWarning(
                "Repaired {Rows} row(s) of {Table}.{Column} holding a value outside the column's declared vocabulary: "
                + "each was set to the column default {Default} so constraint {Constraint} can be validated.",
                rows, constraint.Table, constraint.Column, constraint.DefaultLiteral, constraint.Name);
        }

        return ran ? rows : 0;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The identifiers and the predicate derive from the embedded schema text this boot applied; none is "
                        + "caller input, and Postgres cannot bind an identifier.")]
    private async Task ClearOrphanedMemberAttributionAsync(
        DbConnection conn, RetrofitPass pass, DeclaredColumnConstraint constraint)
    {
        if (ViolationPredicate(constraint) is not { } orphaned)
        {
            return;
        }

        // rawsql: table, column and predicate are derived from the embedded Schema.pg.sql text this
        // boot applied; none of it is caller-supplied.
        // xtenant: clears attributions to users that no longer exist, across every tenant, as
        // removing each member would have; a user id is unique instance-wide.
        string sql = $"UPDATE {constraint.Table} SET {constraint.Column} = NULL WHERE {orphaned}";
        var (ran, rows) = await RunBoundedAsync(
            conn, pass, "orphan_attribution_clear:" + constraint.Name,
            () => conn.ExecuteAsync(new CommandDefinition(sql, commandTimeout: 0)));
        if (ran && rows > 0)
        {
            _logger.LogWarning(
                "Cleared {Rows} orphaned {Table}.{Column} value(s) naming users that no longer exist, as removing a "
                + "member clears them, so foreign key {Constraint} can be validated.",
                rows, constraint.Table, constraint.Column, constraint.Name);
        }
    }

    /// <summary>
    /// Logs that <paramref name="constraintName"/> could not be validated, naming how many rows
    /// violate it and up to <see cref="ViolatingKeysShown"/> of their primary keys.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The table and predicate derive from the embedded schema text this boot applied, and the key "
                        + "columns are read back from pg_index and quoted as identifiers; none is caller input.")]
    private async Task WarnOnViolatingRowsAsync(
        DbConnection conn, RetrofitPass pass, string constraintName, string table, string column,
        string? violationPredicate, PostgresException violation)
    {
        bool isCheck = violation.SqlState == PostgresErrorCodes.CheckViolation;
        string consequence = isCheck
            ? "Postgres checks a NOT VALID CHECK on every INSERT and on every UPDATE of a row, so these rows "
              + "reject every UPDATE until repaired, from this release and the previous one alike."
            : "Postgres checks a NOT VALID foreign key on every INSERT and on every UPDATE that changes the "
              + "column, so these rows reject any such UPDATE until repaired.";

        (long Total, List<string> Keys)? described = null;
        if (violationPredicate is not null)
        {
            // xtenant: reads the Postgres system catalogue, not application data.
            var keyColumns = (await conn.QueryAsync<string>(
                """
                SELECT a.attname::text
                FROM pg_index i
                CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                WHERE i.indrelid = to_regclass(@table) AND i.indisprimary
                ORDER BY k.ord
                """,
                new { table })).Select(QuoteIdentifier).ToList();
            string key = keyColumns.Count switch
            {
                0 => "ctid::text",
                1 => keyColumns[0] + "::text",
                _ => "ROW(" + string.Join(", ", keyColumns) + ")::text",
            };

            // rawsql: table and predicate derive from the embedded Schema.pg.sql text this boot
            // applied; the key columns come from pg_index and are quoted; the limit is a constant.
            // xtenant: a boot-time diagnostic across every tenant's rows, run as the owner; it reads
            // only primary keys, which it logs for the operator to repair.
            string sql = $"SELECT COUNT(*) OVER () AS Total, {key} AS Key FROM {table} "
                + $"WHERE {violationPredicate} LIMIT {ViolatingKeysShown}";
            var (ran, rows) = await RunBoundedAsync(
                conn, pass, "violation_count:" + constraintName,
                async () => (await conn.QueryAsync<(long Total, string Key)>(new CommandDefinition(sql, commandTimeout: 0))).ToList());
            if (ran)
            {
                described = (rows.Count == 0 ? 0 : rows[0].Total, rows.Select(r => r.Key).ToList());
            }
        }

        if (described is { } d)
        {
            _logger.LogWarning(
                "Constraint {Constraint} on {Table}.{Column} could not be validated: {ViolatingRows} existing row(s) "
                + "violate it ({SqlState}); primary key(s) {Keys}{More}. The constraint remains in place but NOT VALID. "
                + "{Consequence} Repair those rows to have the next boot validate it.",
                constraintName, table, column, d.Total, violation.SqlState, string.Join(", ", d.Keys),
                d.Total > d.Keys.Count ? $" (first {d.Keys.Count} shown)" : "", consequence);
            return;
        }

        _logger.LogWarning(
            "Constraint {Constraint} on {Table}.{Column} could not be validated: existing rows violate it "
            + "({SqlState}); they could not be counted within the scan time limit. The constraint remains in place "
            + "but NOT VALID. {Consequence} Repair those rows to have the next boot validate it.",
            constraintName, table, column, violation.SqlState, consequence);
    }

    private static string QuoteIdentifier(string name) => "\"" + name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    // One statement under the session lock_timeout and statement_timeout the retrofit's other steps
    // use, both capped by what the pass has left and reset before returning. A spent deadline, a
    // cancelled scan, a lock that is not granted or a row the statement cannot write returns
    // Ran = false with a warning; the constraint it concerns stays NOT VALID and is re-attempted on
    // the next boot.
    private async Task<(bool Ran, T Value)> RunBoundedAsync<T>(
        DbConnection conn, RetrofitPass pass, string operation, Func<Task<T>> body)
    {
        if (pass.Expired)
        {
            return (false, default!);
        }

        await conn.ExecuteAsync(
            "SELECT set_config('lock_timeout', @value, false)",
            new { value = $"{(int)Capped(ConstraintLockRetry.LockTimeout, pass).TotalMilliseconds}ms" });
        await conn.ExecuteAsync(
            "SELECT set_config('statement_timeout', @value, false)",
            new { value = $"{(int)Capped(ValidateStatementTimeout, pass).TotalMilliseconds}ms" });
        try
        {
            return (true, await body());
        }
        catch (PostgresException ex) when (ex.SqlState is PostgresErrorCodes.QueryCanceled
            or PostgresErrorCodes.LockNotAvailable
            or PostgresErrorCodes.CheckViolation
            or PostgresErrorCodes.ForeignKeyViolation)
        {
            _logger.LogWarning(
                ex,
                "Schema step {Operation} did not complete ({SqlState}); the constraint it concerns stays NOT VALID "
                + "and is re-attempted on the next boot.",
                operation, ex.SqlState);
            return (false, default!);
        }
        finally
        {
            await ResetTimeoutsAsync(conn, statementTimeoutSet: true);
        }
    }
}
