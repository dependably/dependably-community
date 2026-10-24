using System.Data.Common;
using System.Text.RegularExpressions;
using Dapper;
using Npgsql;

namespace Dependably.Infrastructure;

/// <summary>
/// Retrofits the column-level <c>CHECK</c> and <c>REFERENCES</c> constraints that
/// <c>Schema.pg.sql</c> declares onto an EXISTING Postgres database, so an upgraded instance ends up
/// with the same constraints a fresh install gets from its <c>CREATE TABLE</c> blocks. Postgres only:
/// SQLite has no <c>ALTER TABLE … ADD CONSTRAINT</c>, and a fresh SQLite install already carries
/// them from <c>Schema.sql</c>.
///
/// <para><b>Why upgraded databases lack them.</b> A column that reaches an existing table through
/// <c>RunAdditiveMigrationsAsync</c> is added by a plain <c>ALTER TABLE … ADD COLUMN</c>, which on
/// SQLite cannot carry a <c>CHECK</c>; the shared additive list therefore adds none, and on Postgres
/// the column arrives unconstrained. The same holds for a <c>REFERENCES</c> clause the additive
/// statement omits. Only a fresh install, which creates the table from the schema file, gets them.</para>
///
/// <para><b>The constraint set is derived, never listed</b>, for the reason
/// <c>SchemaInitializer.TemporalCheckRetrofit.cs</c> gives: a hand-copied list drifts silently the
/// first time a column gains a constraint in the schema file and not in the list. Every column whose
/// <c>CREATE TABLE</c> declaration carries an inline <c>CHECK</c> or <c>REFERENCES</c> clause is
/// covered, so a constraint added in a future release is retrofitted with no new code. Canonical-
/// timestamp CHECKs are left to the temporal retrofit, which owns their repair sweep.</para>
///
/// <para><b>Names match a fresh install.</b> An inline constraint has no name in the schema file, so
/// Postgres names it <c>&lt;table&gt;_&lt;column&gt;_check</c> / <c>&lt;table&gt;_&lt;column&gt;_fkey</c>.
/// An added constraint reuses exactly that name, so a retrofitted database and a fresh install are the
/// same shape. A foreign key is also recognised by definition under any other name
/// (<see cref="FindExistingConstraint"/>): a renamed table keeps its constraints' old names, and one
/// of those is validated in place rather than duplicated. <c>ColumnConstraintRetrofitTests</c>
/// asserts no column carries two inline CHECKs (which Postgres would suffix <c>_check1</c>) and no
/// derived name exceeds Postgres's 63-byte identifier limit (which it would truncate).</para>
///
/// <para><b>Add is <c>NOT VALID</c>; validation is best-effort and per constraint</b>, as in the
/// temporal retrofit. New writes are enforced from the moment the boot completes; a legacy row that
/// fails <c>VALIDATE CONSTRAINT</c> leaves only that one constraint <c>NOT VALID</c> and is
/// re-attempted on the next boot. Because Postgres also checks a <c>NOT VALID</c> CHECK on every
/// UPDATE of a row, such a row rejects later writes: the warning names it, and a few columns are
/// repaired instead (<c>SchemaInitializer.ConstraintViolationRepair.cs</c>). Runs every boot:
/// idempotency is one <c>pg_constraint</c> read.</para>
///
/// <para><b>Boot time is bounded; the retrofit never blocks startup.</b> Both retrofits share one
/// <see cref="RetrofitPass"/>: a single deadline (<see cref="DefaultRetrofitPassBudget"/>) on the
/// injected <see cref="TimeProvider"/> and a set of tables whose lock could not be taken. Each
/// <c>ADD CONSTRAINT</c> (<c>ACCESS EXCLUSIVE</c>; a foreign key also locks the table it references)
/// runs under <c>lock_timeout</c> with TimeProvider back-off (<c>ConstraintLockRetry</c>). When that
/// budget is spent the table, and for a foreign key the referenced table, is skipped for the rest of
/// the pass, so a locked table costs one budget however many constraints it carries. <c>VALIDATE</c>
/// takes only <c>SHARE UPDATE EXCLUSIVE</c>; it has no client command timeout but runs under a session
/// <c>statement_timeout</c> (<see cref="DefaultValidateStatementTimeout"/>, capped by what the pass has
/// left). A cancelled scan, a spent deadline, or a skipped table leaves the constraint absent or
/// <c>NOT VALID</c> and defers it to the next boot; deferrals are reported in one summary warning.
/// A constraint that existing rows violate is rescanned every boot, and that cost is bounded by the
/// same statement timeout.</para>
///
/// <para><b>Blue-green.</b> A <c>NOT VALID</c> constraint still rejects the OLD binary's writes
/// during a cutover. That is safe here because <c>SchemaBackwardCompatibilityComplianceTests</c>
/// forbids narrowing or adding a <c>CHECK</c> on a column the previous release already had: every
/// value the previous release can write already satisfies its own schema file's CHECK, which is this
/// release's CHECK or a narrower one, and a fresh install of the previous release enforces it.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    internal enum ColumnConstraintKind
    {
        Check,
        ForeignKey,
    }

    /// <param name="DefaultLiteral">
    /// The column's declared <c>DEFAULT</c> when it is a plain literal (a quoted string or a number),
    /// otherwise null. Carried on CHECKs only, for the vocabulary repair.
    /// </param>
    internal sealed record DeclaredColumnConstraint(
        string Table, string Column, string Name, ColumnConstraintKind Kind, string Definition,
        string? DefaultLiteral = null);

    [GeneratedRegex(@"\bDEFAULT\s+(?<literal>'(?:[^']|'')*'|-?[0-9]+(?:\.[0-9]+)?)(?=\s|\z)", RegexOptions.IgnoreCase)]
    private static partial Regex DefaultLiteralRegex();

    // REFERENCES target [(cols)] followed by any of the referential-action / deferrability clauses,
    // in any order. Stops at the next token that is none of them (CHECK, NOT NULL, DEFAULT, …).
    [GeneratedRegex(
        @"\bREFERENCES\s+(?<target>[A-Za-z_][A-Za-z0-9_]*(?:\s*\([^)]*\))?)"
        + @"(?<actions>(?:\s+(?:ON\s+(?:DELETE|UPDATE)\s+(?:CASCADE|RESTRICT|NO\s+ACTION|SET\s+NULL|SET\s+DEFAULT)"
        + @"|MATCH\s+(?:FULL|PARTIAL|SIMPLE)|NOT\s+DEFERRABLE|DEFERRABLE|INITIALLY\s+(?:DEFERRED|IMMEDIATE)))*)",
        RegexOptions.IgnoreCase)]
    private static partial Regex ReferencesClauseRegex();

    /// <summary>
    /// Adds and validates every column-level CHECK and foreign key <paramref name="schemaSql"/>
    /// declares that the live database lacks. No-op on SQLite. Called from
    /// <c>ApplyPostMigrationConvergenceAsync</c>, which already holds the cross-process migration
    /// lock, so no additional serialization is needed.
    /// </summary>
    internal async Task RetrofitColumnConstraintsAsync(
        DbConnection conn, string schemaSql, RetrofitPass? sharedPass = null)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

        var pass = sharedPass ?? new RetrofitPass(_time, RetrofitPassBudget);

        // Every CHECK and foreign key in the schema this connection resolves to, with the shape needed
        // to recognise one by definition. One read instead of one probe per column.
        // xtenant: reads the Postgres system catalogue, not application data — there is no tenant
        // column to filter on.
        var existing = (await conn.QueryAsync<CatalogueConstraint>(
                """
                SELECT t.relname AS Table, c.conname AS Name, c.contype::text AS Kind,
                       c.convalidated AS Validated,
                       ARRAY(SELECT a.attname::text
                             FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
                             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
                             ORDER BY k.ord) AS Columns,
                       rt.relname AS ReferencedTable,
                       ARRAY(SELECT a.attname::text
                             FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord)
                             JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum
                             ORDER BY k.ord) AS ReferencedColumns,
                       ARRAY(SELECT a.attname::text
                             FROM pg_index i
                             CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
                             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                             WHERE i.indrelid = c.confrelid AND i.indisprimary
                             ORDER BY k.ord) AS ReferencedPrimaryKey,
                       c.confdeltype::text AS OnDelete
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                LEFT JOIN pg_class rt ON rt.oid = c.confrelid
                WHERE c.contype IN ('c', 'f')
                  AND n.nspname = current_schema()
                """))
            .ToList();

        foreach (var constraint in DeclaredColumnConstraints(schemaSql))
        {
            var match = FindExistingConstraint(constraint, existing);
            CatalogueConstraint? stale = null;
            if (match is null)
            {
                if (constraint.Kind == ColumnConstraintKind.Check)
                {
                    WarnOnDifferentlyNamedCheck(constraint, existing);
                }
                else
                {
                    stale = FindStaleForeignKey(constraint, existing);
                }
            }
            else if (match.Validated)
            {
                continue;
            }

            await EnsureColumnConstraintAsync(conn, pass, constraint, match?.Name, stale);
        }

        if (sharedPass is null)
        {
            pass.LogSummary(_logger);
        }
    }

    /// <summary>
    /// Every inline <c>CHECK</c> and <c>REFERENCES</c> clause on a column of a <c>CREATE TABLE</c>
    /// block in <paramref name="schemaSql"/>, with the name Postgres gives it on a fresh install.
    /// Canonical-timestamp CHECKs are excluded: <see cref="RetrofitTemporalChecksAsync"/> owns them.
    /// internal so a test can assert the derived set against the schema file directly.
    /// </summary>
    internal static List<DeclaredColumnConstraint> DeclaredColumnConstraints(string schemaSql)
    {
        var result = new List<DeclaredColumnConstraint>();
        foreach (var (table, definition) in SchemaSqlParser.ParseTableDefinitions(schemaSql))
        {
            foreach (var column in definition.Columns)
            {
                // CHECK bodies are removed first so a REFERENCES- or DEFAULT-looking word inside one
                // cannot match.
                string withoutChecks = SchemaSqlParser.WithoutCheckExpressions(column.Declaration);
                string temporal = TemporalCheckPredicate.ForPostgres(column.Name);
                if (!column.Declaration.Contains(temporal, StringComparison.Ordinal))
                {
                    var defaultLiteral = DefaultLiteralRegex().Match(withoutChecks);
                    foreach (string expression in SchemaSqlParser.CheckExpressions(column.Declaration))
                    {
                        result.Add(new DeclaredColumnConstraint(
                            table, column.Name, table + "_" + column.Name + "_check",
                            ColumnConstraintKind.Check, "CHECK (" + expression + ")",
                            defaultLiteral.Success ? defaultLiteral.Groups["literal"].Value : null));
                    }
                }

                var references = ReferencesClauseRegex().Match(withoutChecks);
                if (references.Success)
                {
                    result.Add(new DeclaredColumnConstraint(
                        table, column.Name, table + "_" + column.Name + "_fkey",
                        ColumnConstraintKind.ForeignKey,
                        "FOREIGN KEY (" + column.Name + ") REFERENCES "
                        + references.Groups["target"].Value.Trim() + references.Groups["actions"].Value));
                }
            }
        }

        return result;
    }

    /// <summary>One CHECK or foreign key as the Postgres catalogue records it.</summary>
    internal sealed class CatalogueConstraint
    {
        public string Table { get; init; } = "";
        public string Name { get; init; } = "";

        /// <summary><c>pg_constraint.contype</c>: <c>c</c> for a CHECK, <c>f</c> for a foreign key.</summary>
        public string Kind { get; init; } = "";

        public bool Validated { get; init; }
        public string[] Columns { get; init; } = [];
        public string? ReferencedTable { get; init; }
        public string[] ReferencedColumns { get; init; } = [];
        public string[] ReferencedPrimaryKey { get; init; } = [];

        /// <summary><c>pg_constraint.confdeltype</c>; a space for a CHECK.</summary>
        public string? OnDelete { get; init; }
    }

    /// <summary>The parts of a declared foreign key that identify it regardless of its name.</summary>
    internal sealed record ForeignKeyShape(
        string ReferencedTable, IReadOnlyList<string>? ReferencedColumns, char? OnDelete);

    [GeneratedRegex(
        @"\bREFERENCES\s+(?<table>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\((?<cols>[^)]*)\))?",
        RegexOptions.IgnoreCase)]
    private static partial Regex ReferencesTargetRegex();

    [GeneratedRegex(
        @"\bON\s+DELETE\s+(?<action>CASCADE|RESTRICT|NO\s+ACTION|SET\s+NULL|SET\s+DEFAULT)\b",
        RegexOptions.IgnoreCase)]
    private static partial Regex OnDeleteRegex();

    /// <summary>
    /// Parses the referenced table, the referenced column list (null when the clause names none, so
    /// the target's primary key applies) and the <c>ON DELETE</c> action as its
    /// <c>pg_constraint.confdeltype</c> code (null when the clause names none) out of a derived
    /// foreign-key definition.
    /// </summary>
    internal static ForeignKeyShape ParseForeignKeyShape(string definition)
    {
        var target = ReferencesTargetRegex().Match(definition);
        if (!target.Success)
        {
            throw new ArgumentException("Not a foreign-key definition: " + definition, nameof(definition));
        }

        IReadOnlyList<string>? columns = target.Groups["cols"].Success
            ? target.Groups["cols"].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            : null;

        char? onDelete = null;
        var action = OnDeleteRegex().Match(definition);
        if (action.Success)
        {
            onDelete = string.Join(' ', action.Groups["action"].Value.ToUpperInvariant()
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) switch
            {
                "CASCADE" => 'c',
                "RESTRICT" => 'r',
                "NO ACTION" => 'a',
                "SET NULL" => 'n',
                "SET DEFAULT" => 'd',
                _ => null,
            };
        }

        return new ForeignKeyShape(target.Groups["table"].Value, columns, onDelete);
    }

    /// <summary>
    /// The catalogue constraint that already implements <paramref name="declared"/>, or null.
    ///
    /// <para>A CHECK carrying the derived name is that constraint. A foreign key carrying it is that
    /// constraint only when its definition matches too — same referenced table and columns, and the
    /// same <c>ON DELETE</c> action — otherwise it is stale (<see cref="FindStaleForeignKey"/>) and is
    /// replaced, so a changed action or target converges on an upgraded database instead of reading
    /// as already present. A declaration that names no action matches <c>NO ACTION</c> or
    /// <c>RESTRICT</c>, which differ only in when a non-deferrable check fires. With no foreign key
    /// under the derived name, one is matched by that same definition, because Postgres keeps a
    /// constraint's name when its table is renamed: a table that reached its current name through
    /// <c>ALTER TABLE … RENAME TO</c> (<c>tokens</c> → <c>user_tokens</c>, <c>allowlist_new</c> →
    /// <c>allowlist</c>) carries its foreign keys under the old table's name, and adding the derived
    /// one beside it would put a second, redundant foreign key on the column. Among equivalent
    /// matches a validated one wins, so a NOT VALID duplicate never causes a rescan.</para>
    ///
    /// <para>A CHECK is matched by name only: whether two CHECK bodies are equivalent needs
    /// Postgres's own deparse of the declared expression, which it offers only for a constraint that
    /// exists. <see cref="WarnOnDifferentlyNamedCheck"/> reports the case instead.</para>
    /// </summary>
    internal static CatalogueConstraint? FindExistingConstraint(
        DeclaredColumnConstraint declared, IReadOnlyList<CatalogueConstraint> existing)
    {
        var byName = ByDerivedName(declared, existing);
        if (declared.Kind != ColumnConstraintKind.ForeignKey)
        {
            return byName;
        }

        var shape = ParseForeignKeyShape(declared.Definition);
        return byName is not null
            ? (ImplementsForeignKey(byName, declared, shape) ? byName : null)
            : existing
                .Where(c => c.Kind == "f" && ImplementsForeignKey(c, declared, shape))
                .OrderByDescending(c => c.Validated)
                .ThenBy(c => c.Name, StringComparer.Ordinal)
                .FirstOrDefault();
    }

    /// <summary>
    /// The foreign key carrying <paramref name="declared"/>'s derived name when its definition no
    /// longer matches the declaration (another target, other columns, another <c>ON DELETE</c>), or
    /// null. The retrofit replaces it with the declared one in a single <c>ALTER TABLE</c>, so the
    /// column is never left without a foreign key.
    /// </summary>
    internal static CatalogueConstraint? FindStaleForeignKey(
        DeclaredColumnConstraint declared, IReadOnlyList<CatalogueConstraint> existing)
    {
        if (declared.Kind != ColumnConstraintKind.ForeignKey)
        {
            return null;
        }

        var byName = ByDerivedName(declared, existing);
        return byName is not null && !ImplementsForeignKey(byName, declared, ParseForeignKeyShape(declared.Definition))
            ? byName
            : null;
    }

    private static CatalogueConstraint? ByDerivedName(
        DeclaredColumnConstraint declared, IReadOnlyList<CatalogueConstraint> existing)
    {
        string kind = declared.Kind == ColumnConstraintKind.ForeignKey ? "f" : "c";
        return existing.FirstOrDefault(c =>
            c.Kind == kind
            && string.Equals(c.Table, declared.Table, StringComparison.Ordinal)
            && string.Equals(c.Name, declared.Name, StringComparison.Ordinal));
    }

    private static bool ImplementsForeignKey(
        CatalogueConstraint candidate, DeclaredColumnConstraint declared, ForeignKeyShape shape) =>
        string.Equals(candidate.Table, declared.Table, StringComparison.Ordinal)
        && candidate.Columns.Length == 1
        && string.Equals(candidate.Columns[0], declared.Column, StringComparison.Ordinal)
        && string.Equals(candidate.ReferencedTable, shape.ReferencedTable, StringComparison.Ordinal)
        && candidate.ReferencedColumns.Length > 0
        && candidate.ReferencedColumns.SequenceEqual(
            shape.ReferencedColumns ?? candidate.ReferencedPrimaryKey, StringComparer.Ordinal)
        && candidate.OnDelete is { Length: 1 } code
        && (shape.OnDelete is { } action ? code[0] == action : code[0] is 'a' or 'r');

    // A CHECK on exactly this column under a different name may be the declared one carried over
    // from a renamed table, or a different rule. The declared one is added either way; the warning
    // makes a redundant pair visible rather than silent.
    private void WarnOnDifferentlyNamedCheck(
        DeclaredColumnConstraint declared, IReadOnlyList<CatalogueConstraint> existing)
    {
        var others = existing
            .Where(c => c.Kind == "c"
                && string.Equals(c.Table, declared.Table, StringComparison.Ordinal)
                && c.Columns.Length == 1
                && string.Equals(c.Columns[0], declared.Column, StringComparison.Ordinal))
            .Select(c => c.Name)
            .ToList();
        if (others.Count > 0)
        {
            _logger.LogWarning(
                "Adding CHECK {Constraint} on {Table}.{Column}, which already carries CHECK " +
                "{ExistingConstraints} under another name. If that constraint enforces the same rule " +
                "it is now redundant and can be dropped.",
                declared.Name, declared.Table, declared.Column, string.Join(", ", others));
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The DDL identifiers and bodies derive from the embedded schema text this boot applied or from a "
                        + "private constant array; none is caller input, and Postgres cannot bind a DDL identifier.")]
    private async Task EnsureColumnConstraintAsync(
        DbConnection conn, RetrofitPass pass, DeclaredColumnConstraint constraint, string? existingName,
        CatalogueConstraint? stale = null)
    {
        // rawsql: table, column, name and definition are all structurally derived from the fixed
        // embedded Schema.pg.sql text this same boot applied — none of it is caller-supplied, and
        // Postgres has no parameter form for a DDL identifier or a constraint body. A stale foreign
        // key's name is the derived one too (FindStaleForeignKey matches on it).
        string add = $"ALTER TABLE {constraint.Table} "
            + (stale is null ? "" : $"DROP CONSTRAINT {constraint.Name}, ")
            + $"ADD CONSTRAINT {constraint.Name} {constraint.Definition} NOT VALID";

        // A foreign key also locks the table it references, so a locked referenced table (every
        // org-scoped table references orgs) is charged once and skips every constraint that needs it.
        // Replacing a stale one also locks the table the old definition referenced.
        var tables = new List<string> { constraint.Table };
        if (constraint.Kind == ColumnConstraintKind.ForeignKey
            && ReferencedTableRegex().Match(constraint.Definition) is { Success: true } target)
        {
            tables.Add(target.Groups["table"].Value);
        }

        if (stale?.ReferencedTable is { } oldTarget && !tables.Contains(oldTarget, StringComparer.Ordinal))
        {
            tables.Add(oldTarget);
        }

        if (stale is not null)
        {
            _logger.LogInformation(
                "Replacing foreign key {Constraint} on {Table}.{Column}: it references {OldTarget} with ON DELETE "
                + "code '{OldOnDelete}', which differs from the schema's {Definition}.",
                constraint.Name, constraint.Table, constraint.Column, stale.ReferencedTable, stale.OnDelete,
                constraint.Definition);
        }

        // Member-removal attributions left orphaned by removals under a schema without this foreign
        // key are cleared once the NOT VALID key blocks new orphans, so VALIDATE can succeed.
        Func<Task>? beforeValidate = IsMemberRemovalAttribution(constraint)
            ? () => ClearOrphanedMemberAttributionAsync(conn, pass, constraint)
            : null;

        // An equivalent constraint already in place, under whatever name, is validated rather than
        // joined by a second one.
        string name = existingName ?? constraint.Name;
        string operation = "column_constraint_retrofit:" + constraint.Name;
        var violation = await ApplyConstraintAsync(
            conn, pass, tables, constraint.Table, name, existingName is null ? add : null, operation, beforeValidate);

        if (violation is not null && IsRepairableVocabulary(constraint)
            && await RepairVocabularyAsync(conn, pass, constraint) > 0)
        {
            violation = await ApplyConstraintAsync(conn, pass, tables, constraint.Table, name, null, operation);
        }

        if (violation is not null)
        {
            await WarnOnViolatingRowsAsync(
                conn, pass, name, constraint.Table, constraint.Column, ViolationPredicate(constraint), violation);
        }
    }

    [GeneratedRegex(@"\bREFERENCES\s+(?<table>[A-Za-z_][A-Za-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex ReferencedTableRegex();

    // Adds (when addSql is given) and validates one constraint within the pass. Returns the
    // violation when existing rows break it, otherwise null. Never throws for a lock, a deadline or a
    // timeout: those defer the step to the next boot and are counted for the pass's one summary.
    //
    // ADD CONSTRAINT takes ACCESS EXCLUSIVE (a foreign key also SHARE ROW EXCLUSIVE on the referenced
    // table), so unbounded it would queue behind a long query on the previous release's slot and stall
    // every later reader of the table: its lock wait is retried within the budget, and a table that
    // stays locked is skipped for the rest of the pass.
    //
    // VALIDATE CONSTRAINT takes only SHARE UPDATE EXCLUSIVE, so it does not block writes, but it scans
    // the table. It runs with no client command timeout and is bounded by the session statement_timeout
    // (the validate cap, itself capped by what the pass has left); a cancelled scan leaves the
    // constraint NOT VALID with a warning. A constraint that existing rows violate is re-validated, and
    // so rescanned, on every boot; the statement timeout bounds that cost.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The DDL identifiers and bodies derive from the embedded schema text this boot applied or from a "
                        + "private constant array; none is caller input, and Postgres cannot bind a DDL identifier. "
                        + "Constraint names read back from pg_constraint are quoted as identifiers.")]
    private async Task<PostgresException?> ApplyConstraintAsync(
        DbConnection conn,
        RetrofitPass pass,
        IReadOnlyList<string> tables,
        string table,
        string constraintName,
        string? addSql,
        string operation,
        Func<Task>? beforeValidate = null)
    {
        if (pass.ShouldDefer(tables))
        {
            pass.Defer(tables, lockExhausted: false);
            return null;
        }

        if (addSql is not null)
        {
            var added = await AlterWithLockRetryAsync(
                conn, table, addSql, operation, ConstraintLockRetry, failOnExhaustion: false, pass);
            if (added != LockRetryOutcome.Ran)
            {
                pass.Defer(tables, lockExhausted: added == LockRetryOutcome.LockExhausted);
                return null;
            }
        }

        if (beforeValidate is not null)
        {
            await beforeValidate();
        }

        try
        {
            // rawsql: the table is derived from the embedded schema text; the constraint name is either
            // derived the same way or read back from pg_constraint, and is quoted as an identifier.
            var validated = await AlterWithLockRetryAsync(
                conn, table,
                $"ALTER TABLE {table} VALIDATE CONSTRAINT \"{constraintName.Replace("\"", "\"\"", StringComparison.Ordinal)}\"",
                operation, ConstraintLockRetry, failOnExhaustion: false, pass, ValidateStatementTimeout);
            if (validated != LockRetryOutcome.Ran)
            {
                pass.Defer(tables, lockExhausted: validated == LockRetryOutcome.LockExhausted);
            }

            return null;
        }
        catch (PostgresException ex) when (
            ex.SqlState is PostgresErrorCodes.CheckViolation or PostgresErrorCodes.ForeignKeyViolation)
        {
            return ex;
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.QueryCanceled)
        {
            _logger.LogWarning(
                ex,
                "Constraint {Constraint} on {Table} could not be validated within the scan time limit. It is " +
                "left NOT VALID — new writes are still checked — and re-attempted on the next boot.",
                constraintName, table);
            pass.Defer(tables, lockExhausted: false);
            return null;
        }
    }
}
